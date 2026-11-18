"""Metadata-only matching proposals from completed90V0+225B and new172disarmed.

No PE reads, hashes of sample bytes, feature encoding, restoration or training.
Disarmed observations retain their actual content digest and NEVER become V0.
"""
from collections import Counter, defaultdict, deque
from pathlib import Path
import csv
import hashlib
import importlib.util
import io
import json
import math
import re
import shutil
import tempfile
import zipfile

NEW_SOURCE_SHA="fc8d10884d0222bd7abf5e0b696df071227d506dccb5da4171090eae5df1cece"
OLD_SOURCE_SHA="4486089fbffea6c45bf0451686a7ec6aaf6cf38512d0c0c4aa99732dd9ec705a"
FAMILY_SHA="fb34221d64c808bdcf0935f042a821a9ffb0ee0f0a2132b38eccc8b8b375ba6b"
PLAN_SHA="63cc0ec5abcc3bb83e3bb6b0f86bf9e590f6c00e4136fb856797345cf21184b8"
SCHEMES=("linker_major_minor","rich_products_linker","rich_product_builds_linker")


def sha(raw):return hashlib.sha256(raw).hexdigest()


def canonical_family(value):
    label=str(value or "").strip().casefold()
    return "" if label in {"","unknown","nan","none","null","malware","bodmas","unknown_family","unclassified"} else label


def save(path,data):
    with Path(path).open("x",encoding="utf-8") as f:json.dump(data,f,indent=2,allow_nan=False)


def load(base,name):
    scope=json.loads((base/"PLAN_SCOPE.json").read_text())
    path=base/name
    if sha(path.read_bytes())!=scope["helper_sha256"][name]:raise ValueError("Reviewed metadata helper differs")
    spec=importlib.util.spec_from_file_location("plan_"+path.stem,path)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


def validate_observation(r):
    for k in ("parent_sha256","sha256","observed_prefix_sha256"):
        if not re.fullmatch("[0-9a-f]{64}",r[k]):raise ValueError("Invalid observed identity")
    if r["label"] not in {"0","1"} or r["split"] not in {"train","val","test","pool_unassigned"}:
        raise ValueError("Invalid cached label/split")
    if not 15000<=int(r["size_bytes"])<=2_000_000 or int(r["signed"]) not in {0,1}:
        raise ValueError("Metadata outside fixed size/signature gate")
    if r["variant"]=="V0":
        if r["sha256"]!=r["parent_sha256"]:raise ValueError("Original V0 hash differs")
    elif r["variant"]=="DISARMED_HEADER_OBSERVATION":
        if (r["label"]!="1" or r["sha256"]!=r["disarmed_sha256"]
            or r["V0_hash_verification"]!="NOT_PERFORMED" or r["training_admitted"]!=0):
            raise ValueError("Disarmed observation misrepresented as verified V0")
    else:raise ValueError("Unsupported observation state")


def family_order(rows):
    families=defaultdict(list)
    for r in rows:families[r.get("family","")].append(r)
    queues={f:deque(sorted(v,key=lambda r:r["parent_sha256"])) for f,v in families.items()}
    order=sorted(queues,key=lambda f:sha(("G6_METADATA_FAMILY_ORDER:"+f).encode()))
    result=[]
    while any(queues.values()):
        for f in order:
            if queues[f]:result.append(queues[f].popleft())
    return result


def match(rows,profile,constrained,max_ratio=2,match_truncation=True,match_signature=True):
    """Maximum cardinality, deterministic family-round-robin tie breaking.

    The tie break encourages diversity; it is not an optimal-family-count claim.
    No model scores or old test predictions enter this matching.
    """
    if len({r["parent_sha256"] for r in rows})!=len(rows):raise ValueError("Repeated parent")
    grouped=defaultdict(list)
    for r in rows:
        validate_observation(r)
        if r["label"]=="1" and not canonical_family(r.get("family","")):continue
        key=profile(r)
        if key is not None:grouped[key].append(r)
    pairs=[]
    for key,members in sorted(grouped.items()):
        malware=family_order([r for r in members if r["label"]=="1"])
        benign=sorted([r for r in members if r["label"]=="0"],key=lambda r:r["parent_sha256"])
        edges=[]
        for m in malware:
            a=int(m["size_bytes"]);possible=[]
            for j,b in enumerate(benign):
                n=int(b["size_bytes"]);ratio=max(a,n)/min(a,n)
                if constrained and ((max_ratio is not None and ratio>max_ratio)
                    or (match_truncation and (a>65536)!=(n>65536))
                    or (match_signature and int(m["signed"])!=int(b["signed"]))):continue
                possible.append((abs(math.log2(a/n)),b["parent_sha256"],j))
            edges.append([j for _,_,j in sorted(possible)])
        assigned={}
        def augment(i,seen):
            for j in edges[i]:
                if j in seen:continue
                seen.add(j)
                if j not in assigned or augment(assigned[j],seen):assigned[j]=i;return True
            return False
        for i in range(len(malware)):augment(i,set())
        for j,i in sorted(assigned.items()):
            m,b=malware[i],benign[j]
            pairs.append(dict(pair_id=f"P{len(pairs)+1:03}",profile=list(key),malware=m,benign=b,
                size_ratio=max(int(m["size_bytes"]),int(b["size_bytes"]))/min(int(m["size_bytes"]),int(b["size_bytes"]))))
    return pairs


def new_observations(headers,audited,plan):
    lookup={r["parent_sha256"]:r for r in audited};planned={r["parent_sha256"]:r for r in plan}
    if len(audited)!=256 or len(lookup)!=256 or set(lookup)!=set(planned):raise ValueError("Full256 audit rows differ")
    if len(headers)!=255 or len({r["parent_sha256"] for r in headers})!=255:raise ValueError("Cached255 header rows differ")
    prefixes=Counter(r["observed_disarmed_prefix_sha256"] for r in headers)
    result=[]
    for h in headers:
        parent=h["parent_sha256"];a=lookup[parent];p=planned[parent]
        if (h.get("pe_status")!="parsed" or a["pe_status"]!="parsed" or a["die_status"]!="clean"
            or json.loads(a["structure_warnings"]) or h["is_dll"]
            or prefixes[h["observed_disarmed_prefix_sha256"]]!=1
            or (h["original_machine_from_provider"],h["original_subsystem_from_provider"])!=(332,2)):continue
        if (a["disarmed_hash_check"]!="match" or a["disarmed_sha256"]!=h["disarmed_sha256"]
            or h["family"]!=p["family"] or int(a["actual_size"])!=int(p["file_size"])):
            raise ValueError("Cached content identity/family/size differs")
        r=dict(h,label="1",source_project="BODMAS",split="pool_unassigned",sha256=h["disarmed_sha256"],
            variant="DISARMED_HEADER_OBSERVATION",signed=int(a["certificate_present"]),
            observed_prefix_sha256=h["observed_disarmed_prefix_sha256"],prefix_byte_state="DISARMED_NOT_ORIGINAL_V0",
            software_lineage="",training_admitted=0)
        r["family_original"]=r["family"];r["family"]=canonical_family(r["family"])
        validate_observation(r);result.append(r)
    if len(result)!=172:raise ValueError("Previously verified172static candidates not reproduced")
    return result


def main():
    base=Path(__file__).resolve().parent;legacy=load(base,"NEW256_STATIC_HANDOFF.py")
    freeze=load(base,"FREEZE_MATCHED_COHORT_VM.py");rich=load(base,"rich_linker_control.py")
    rich.isolated();project=Path.home()/"IAM302t";protected={}
    def read(path):
        if path.stat().st_size>16*1024**2:raise ValueError("Oversized cached metadata")
        raw=path.read_bytes();protected[path]=sha(raw);return raw
    def exact(pattern,expected):
        paths=[p for p in (project/"runs").glob(pattern) if p.stat().st_size<128*1024 and sha(p.read_bytes())==expected]
        if len(paths)!=1:raise ValueError("Exact completed source metadata missing/ambiguous")
        read(paths[0]);return paths[0]
    source=exact("new256-static-*/safe/RESULTS_FOR_CODEX.json",NEW_SOURCE_SHA);new_root=source.parent.parent
    headers=json.loads(read(new_root/"HEADERS_PRIVATE.json"))
    audited=list(csv.DictReader(io.StringIO(read(new_root/"e0_audit_private.csv").decode("utf-8-sig"))))
    raw=read(base/"CANDIDATES_PRIVATE.csv")
    if sha(raw)!=PLAN_SHA:raise ValueError("Original candidate CSV differs")
    plan=list(csv.DictReader(io.StringIO(raw.decode("utf-8-sig"))))
    fresh=new_observations(headers,audited,plan)
    old_source=exact("legacy-benign-recovery-*/safe/RESULTS_FOR_CODEX.json",OLD_SOURCE_SHA)
    old=json.loads(read(old_source.parent.parent/"private/MERGED_PROSPECTIVE_HEADERS_PRIVATE.json"))
    if Counter(r["label"] for r in old)!={"0":225,"1":90}:raise ValueError("Old verified pool differs")
    benign=[r for r in old if r["label"]=="0"]
    reproduced,_=legacy.static_support(headers,audited,benign)
    if reproduced["static_eligible_candidates"]!=172 or [r["static_candidate_pairs_upper_bound"] for r in reproduced["support_by_scheme"]]!=[62,31,20]:
        raise ValueError("Completed header support not reproduced")
    # Existing pilot metadata member only; never read original sample members.
    with zipfile.ZipFile(base.parent/"static182_disarmed_for_vm.zip") as z:family_raw=z.read("bodmas_pilot_258_metadata_readiness.csv")
    if sha(family_raw)!=FAMILY_SHA:raise ValueError("Existing family metadata differs")
    family={r["parent_sha256"]:canonical_family(r["family"]) for r in csv.DictReader(io.StringIO(family_raw.decode("utf-8-sig")))}
    for r in old:
        r["training_admitted"]=0
        if r["label"]=="1":
            if r["parent_sha256"] not in family:raise ValueError("Old malware family unavailable")
            r["family"]=family[r["parent_sha256"]]
    study=old+fresh
    if len({r["parent_sha256"] for r in study})!=len(study):raise ValueError("Old/new identity overlap")
    out=Path(tempfile.mkdtemp(prefix="new256-matched-plan-",dir=project/"runs"));private=out/"private";private.mkdir();safe=out/"safe";safe.mkdir()
    plans={};table=[]
    for scheme in SCHEMES:
        for policy in ("HEADER_ONLY","SIZE2X_SAME_TRUNCATION_SIGNED"):
            pairs=match(study,lambda r:legacy.profile(r,scheme),constrained=policy!="HEADER_ONLY")
            folds,info=freeze.plan_readiness(pairs)
            info.update(new_disarmed_parents_requiring_V0_verification=sum(p["malware"]["variant"]!="V0" for p in pairs),
                original_V0_prefix_leakage_verification_pending=True,training_admitted=0)
            if folds:info["status"]="METADATA_FOLDS_PROPOSED_V0_HASH_PREFIX_AND_TRAINING_APPROVAL_REQUIRED"
            key=scheme+"__"+policy;plans[key]=dict(pairs=pairs,proposed_folds=folds,readiness=info)
            table.append(dict(scheme=scheme,policy=policy,**info))
    primary=plans["rich_product_builds_linker__SIZE2X_SAME_TRUNCATION_SIGNED"]
    proposed=[p["malware"] for p in primary["pairs"] if p["malware"]["variant"]!="V0"] if primary["proposed_folds"] else []
    save(private/"MATCHED_PROPOSALS_PRIVATE.json",plans)
    save(private/"POTENTIAL_RESTORE_SCOPE_PRIVATE.json",dict(status="NOT_AUTHORIZED_NOT_EXECUTED",parents=proposed,
        rationale="Only new parents needed by prespecified strictRich/build+size/truncation/signature proposal, if metadata folds feasible",
        restoration_requires_new_explicit_approval=True,training_admitted=0))
    if any(sha(p.read_bytes())!=h for p,h in protected.items()):raise ValueError("Protected metadata changed")
    save(private/"PROVENANCE_PRIVATE.json",{str(p):h for p,h in protected.items()})
    summary=dict(status="METADATA_MATCHING_PROPOSALS_ONLY_NOT_V0_OR_TRAINING",new_static_candidates=172,existing_verified_V0_malware=90,existing_benign=225,
        new_static_candidates_with_known_family=sum(bool(r["family"]) for r in fresh),
        missing_or_generic_family_excluded_from_matching=sum(r["label"]=="1" and not canonical_family(r.get("family","")) for r in study),
        strict_size_controlled=next(r for r in table if r["scheme"]=="rich_product_builds_linker" and r["policy"]!="HEADER_ONLY"),
        strict_header_only=next(r for r in table if r["scheme"]=="rich_product_builds_linker" and r["policy"]=="HEADER_ONLY"),
        potential_new_restore_scope_count=len(proposed),restoration_approved=False,restoration_performed=False,
        PE_bytes_read=False,features_encoded=False,training_performed=False,original_splits_changed=False,
        Drive_submission_documents_modified=False,teacher100_per_class_reached=any(r["pairs"]>=100 for r in table),
        limitations=["Family/lineage folds are metadata proposals; original V0 hashes and cross-source prefix checks remain pending",
            "Rich/linker matching is not verified common publisher/time and does not eliminate all provenance confounding",
            "Original fixed pilot test parents can enter a new exploratory study; no unseen blind test claimed",
            "Operational12pairs/3groups/4train gate is not statistical power or training admission",
            "Header-only rows do not meet the size/truncation/signature sensitivity controls"])
    save(safe/"RESULTS_FOR_CODEX.json",summary)
    with (safe/"MATCHED_NEW256_READINESS.csv").open("x",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=list(table[0]));w.writeheader();w.writerows(table)
    names=["RESULTS_FOR_CODEX.json","MATCHED_NEW256_READINESS.csv"]
    if any(re.search(rb"[0-9a-fA-F]{64}",(safe/n).read_bytes()) for n in names):raise ValueError("Private sample-like identity in aggregate")
    save(safe/"SAFE_CHECKSUMS.json",{n:sha((safe/n).read_bytes()) for n in names})
    packet=out/"NEW256_MATCHED_PLAN_SAFE.zip"
    with zipfile.ZipFile(packet,"x",zipfile.ZIP_DEFLATED) as z:
        for n in names+["SAFE_CHECKSUMS.json"]:z.write(safe/n,n)
    dest=base.parent/packet.name
    if dest.exists():raise FileExistsError("Preserve existing SAFE result on USB")
    with packet.open("rb") as a,dest.open("xb") as b:shutil.copyfileobj(a,b)
    if sha(dest.read_bytes())!=sha(packet.read_bytes()):raise ValueError("SAFE USB copy differs")
    print(json.dumps(dict(output=str(out),**summary),indent=2))
    print("Return NEW256_MATCHED_PLAN_SAFE.zip only; all pair identities stay VM. No new restore/training authorized.")


if __name__=="__main__":main()
