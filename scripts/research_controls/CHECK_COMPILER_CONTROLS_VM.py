"""Read cached metadata/DiE logs only; inspect teacher compiler/linker controls.

Exact Rich-build fingerprint remains a sensitivity. Primary candidate control
requires an explicit typed DiE compiler name AND numeric version plus linker,
2x size, same truncation/signature flags and family/publisher blocked proposals.
These are metadata proposals, not verified V0, classifier results or100/class.
"""
from collections import Counter, defaultdict
from pathlib import Path
import copy
import csv
import hashlib
import importlib.util
import io
import json
import re
import shutil
import tempfile
import zipfile

NEW_SHA="fc8d10884d0222bd7abf5e0b696df071227d506dccb5da4171090eae5df1cece"
OLD_SHA="4486089fbffea6c45bf0451686a7ec6aaf6cf38512d0c0c4aa99732dd9ec705a"
PLAN_SHA="63cc0ec5abcc3bb83e3bb6b0f86bf9e590f6c00e4136fb856797345cf21184b8"
FAMILY_SHA="fb34221d64c808bdcf0935f042a821a9ffb0ee0f0a2132b38eccc8b8b375ba6b"


def sha(raw):return hashlib.sha256(raw).hexdigest()


def save(path,data):
    with Path(path).open("x",encoding="utf-8") as f:json.dump(data,f,indent=2,allow_nan=False)


def load(base,name):
    path=base/name;scope=json.loads((base/"CONTROL_SCOPE.json").read_text())
    if sha(path.read_bytes())!=scope["helper_sha256"][name]:raise ValueError("Reviewed metadata helper differs")
    spec=importlib.util.spec_from_file_location("compiler_control_"+path.stem,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def compiler_key(text):
    """One explicit compiler/version; missing, ranges, errors or ambiguity fail.

    This is detector evidence, never independent proof of the compiler/build.
    """
    try:
        document=json.loads(text)
    except (ValueError,TypeError):return None
    found=set();bad=False
    def visit(node):
        nonlocal bad
        if isinstance(node,dict):
            if any(str(k).casefold() in {"error","errors"} and bool(v) for k,v in node.items()):bad=True
            if str(node.get("type","")).strip().casefold()=="compiler":
                name=node.get("name");version=node.get("version")
                if (not isinstance(name,str) or not name.strip() or len(name)>200
                    or not isinstance(version,str) or not re.fullmatch(r"\d+(?:\.\d+){0,3}",version.strip())):
                    bad=True
                else:found.add((" ".join(name.casefold().split()),version.strip()))
            for value in node.values():visit(value)
        elif isinstance(node,list):
            for value in node:visit(value)
    visit(document)
    return next(iter(found)) if not bad and len(found)==1 else None


def publisher_groups(rows):
    """Coarsen to publisher blocks; merge publishers sharing known lineage.

    Unknown software lineage is never invented or counted as independent. Entire
    verified publishers are held together, even when lineage is incomplete.
    """
    def publisher(r):
        value="".join(c for c in str(r.get("source_project","") or "").casefold() if c.isalnum())
        return "" if value in {"unknown","none","null","notset"} else value
    publishers={publisher(r) for r in rows if r["label"]=="0"}
    pubs={p:p for p in publishers if p};lineages={}
    def root(p):
        while pubs[p]!=p:pubs[p]=pubs[pubs[p]];p=pubs[p]
        return p
    for r in rows:
        if r["label"]!="0":continue
        pub=publisher(r);lineage=str(r.get("software_lineage","") or "").strip().casefold()
        if pub and lineage:
            if lineage in lineages:pubs[root(pub)]=root(lineages[lineage])
            else:lineages[lineage]=pub
    return {r["parent_sha256"]:(root(publisher(r)) if publisher(r) else "")
            for r in rows if r["label"]=="0"}


def blocked_folds(pairs,groups,freeze):
    # Temporary fold tokens, never source metadata or claims about software lineage.
    tokens=copy.deepcopy(pairs)
    missing=sum(not p["benign"].get("software_lineage","") for p in pairs)
    for p in tokens:p["benign"]["software_lineage"]=groups[p["benign"]["parent_sha256"]]
    folds,info=freeze.plan_readiness(tokens)
    info["missing_benign_publisher_group"]=info.pop("missing_benign_lineage")
    info["original_missing_benign_software_lineage"]=missing
    info["fold_grouping"]="malware family + conservative benign publisher; shared known lineages merge publishers"
    info["V0_hash_and_original_prefix_checks_pending"]=True
    if folds:info["status"]="METADATA_PROPOSAL_ONLY_PENDING_V0_AND_EXPLICIT_TRAINING_APPROVAL"
    return folds,info


def read_study(base,project,planner,protected):
    def read(path):
        if path.stat().st_size>32*1024**2:raise ValueError("Oversized cached metadata")
        raw=path.read_bytes();protected[path]=sha(raw);return raw
    def exact(pattern,digest):
        paths=[p for p in (project/"runs").glob(pattern) if p.stat().st_size<128*1024 and sha(p.read_bytes())==digest]
        if len(paths)!=1:raise ValueError("Pinned metadata source missing/ambiguous")
        read(paths[0]);return paths[0]
    source=exact("new256-static-*/safe/RESULTS_FOR_CODEX.json",NEW_SHA);newroot=source.parent.parent
    h=json.loads(read(newroot/"HEADERS_PRIVATE.json"))
    audit=list(csv.DictReader(io.StringIO(read(newroot/"e0_audit_private.csv").decode("utf-8-sig"))))
    raw=read(base/"CANDIDATES_PRIVATE.csv")
    if sha(raw)!=PLAN_SHA:raise ValueError("Approved candidate CSV differs")
    plan=list(csv.DictReader(io.StringIO(raw.decode("utf-8-sig"))))
    fresh=planner.new_observations(h,audit,plan)
    previous=exact("legacy-benign-recovery-*/safe/RESULTS_FOR_CODEX.json",OLD_SHA)
    old=json.loads(read(previous.parent.parent/"private/MERGED_PROSPECTIVE_HEADERS_PRIVATE.json"))
    if Counter(r["label"] for r in old)!={"0":225,"1":90}:raise ValueError("Old pool differs")
    with zipfile.ZipFile(base.parent/"static182_disarmed_for_vm.zip") as z:family=z.read("bodmas_pilot_258_metadata_readiness.csv")
    if sha(family)!=FAMILY_SHA:raise ValueError("Original family CSV differs")
    labels={r["parent_sha256"]:planner.canonical_family(r["family"]) for r in csv.DictReader(io.StringIO(family.decode("utf-8-sig")))}
    for r in old:
        r["training_admitted"]=0
        if r["label"]=="1":r["family"]=labels[r["parent_sha256"]]
    rows=old+fresh
    if len({r["parent_sha256"] for r in rows})!=487:raise ValueError("Combined parent count differs")
    return rows,audit


def cached_compilers(project,rows,new_audit,protected):
    wanted={r["parent_sha256"]:r for r in rows};evidence=defaultdict(set);sources=Counter()
    def accept(parent,text,kind):
        key=compiler_key(text)
        if key is not None:evidence[parent].add(key);sources[kind]+=1
    for a in new_audit:
        if a["parent_sha256"] in wanted and a.get("die_tool_status")=="ok" and a.get("die_status")=="clean":
            accept(a["parent_sha256"],a.get("die_stdout",""),"pinned_new_audit")
    # Look only at bounded text metadata; never samples, NPZ or checkpoints.
    for p in sorted((project/"runs").rglob("*audit*.csv")):
        if p.is_symlink() or not p.resolve().is_relative_to(project/"runs") or p.stat().st_size>32*1024**2:continue
        with p.open(encoding="utf-8-sig",newline="",errors="replace") as f:
            reader=csv.DictReader(f)
            if not {"parent_sha256","die_stdout","disarmed_sha256"}.issubset(reader.fieldnames or []):continue
            before=sha(p.read_bytes())
            for a in reader:
                parent=a.get("parent_sha256","");r=wanted.get(parent)
                if r and a.get("die_status")=="clean" and a.get("die_tool_status")=="ok" and a.get("disarmed_sha256")==r["sha256"]:
                    accept(parent,a.get("die_stdout",""),"hash_bound_cached_audit")
            protected[p]=before
    # Original benign intake writes DiE JSON/stdout to <parent>.log. Already
    # verified benign cached headers establish parent binding; no new detector.
    benign={r["parent_sha256"] for r in rows if r["label"]=="0"}
    for p in sorted((project/"runs").rglob("*.log")):
        if p.stem not in benign or p.parent.name!="die" or p.is_symlink():continue
        if not p.resolve().is_relative_to(project/"runs") or p.stat().st_size>1024**2:continue
        raw=p.read_bytes();protected[p]=sha(raw)
        accept(p.stem,raw.decode("utf-8-sig",errors="replace"),"cached_benign_DiE_log_by_verified_parent")
    keys={parent:next(iter(values)) for parent,values in evidence.items() if len(values)==1}
    return keys,dict(compiler_evidence_records_by_source=dict(sources),
        compiler_ambiguous_parents=sum(len(v)>1 for v in evidence.values()),
        compiler_name_version_available_by_label={label:sum(r["parent_sha256"] in keys for r in rows if r["label"]==label) for label in ["0","1"]})


def merge_verified_benign(rows,incoming,approved_publishers=('NirSoft',)):
    """Append audited originals without modifying cached study identities."""
    merged=copy.deepcopy(rows)
    parents={r["parent_sha256"] for r in rows};prefixes={r["observed_prefix_sha256"] for r in rows}
    lineages={r.get("software_lineage") for r in rows if r["label"]=="0" and r.get("software_lineage")}
    for r in incoming:
        if (r.get("label")!="0" or r.get("variant")!="V0" or r.get("split")!="pool_unassigned"
            or r.get("status")!="ok" or r.get("pe_status")!="parsed" or r.get("die_status")!="clean"
            or r.get("sha256")!=r.get("parent_sha256") or r.get("disarmed_sha256")!=""
            or r.get("machine")!="0x014c" or str(r.get("subsystem"))!="2" or r.get("is_dll") is not False
            or r.get("structural_warning_count")!=0 or not 15000<=int(r.get("size_bytes",0))<=2000000
            or r.get("source_project") not in approved_publishers or not r.get("software_lineage")
            or r.get("signed") not in (0,1) or r.get("training_admitted",0)!=0
            or any(not re.fullmatch(r"[0-9a-f]{64}",str(r.get(k,""))) for k in ["parent_sha256","observed_prefix_sha256"])):
            raise ValueError("Unverified new benign metadata")
        if r["parent_sha256"] in parents or r["observed_prefix_sha256"] in prefixes or r["software_lineage"] in lineages:
            raise ValueError("New benign duplicates existing identity, prefix or lineage")
        parents.add(r["parent_sha256"]);prefixes.add(r["observed_prefix_sha256"]);lineages.add(r["software_lineage"])
        item=copy.deepcopy(r);item["training_admitted"]=0;merged.append(item)
    return merged


def main(output_name="COMPILER_CONTROLS_SAFE.zip",supplement=None,extra_verified_benign=None,approved_benign_publishers=('NirSoft',)):
    if Path(output_name).name!=output_name or not output_name.endswith(".zip"):raise ValueError("Invalid SAFE output name")
    csv.field_size_limit(2*1024**2)
    base=Path(__file__).resolve().parent;planner=load(base,"PLAN_NEW256_MATCHED_VM.py")
    freeze=load(base,"FREEZE_MATCHED_COHORT_VM.py");legacy=load(base,"NEW256_STATIC_HANDOFF.py");isolation=load(base,"rich_linker_control.py")
    isolation.isolated();project=Path.home()/"IAM302t";protected={}
    rows,new_audit=read_study(base,project,planner,protected)
    if extra_verified_benign is not None:rows=merge_verified_benign(rows,extra_verified_benign,approved_benign_publishers)
    compilers,evidence=cached_compilers(project,rows,new_audit,protected)
    groups=publisher_groups(rows);table=[];plans={}
    profiles={s:(lambda r,s=s:legacy.profile(r,s)) for s in ["linker_major_minor","rich_products_linker","rich_product_builds_linker"]}
    profiles["DIE_COMPILER_VERSION_AND_LINKER"]=lambda r:((int(r["linker_major"]),int(r["linker_minor"]),compilers[r["parent_sha256"]]) if r["parent_sha256"] in compilers else None)
    eligible=[r for r in rows if r["label"]=="1" or groups[r["parent_sha256"]]]
    for scheme,profile in profiles.items():
        for policy,controls in [("HEADER_ONLY",dict(constrained=False)),
            ("SIZE2X_ONLY",dict(constrained=True,match_truncation=False,match_signature=False)),
            ("SIZE2X_SAME_TRUNCATION",dict(constrained=True,match_signature=False)),
            ("SIZE2X_SAME_TRUNCATION_SIGNED",dict(constrained=True))]:
            pairs=planner.match(eligible,profile,**controls)
            folds,info=blocked_folds(pairs,groups,freeze)
            info.update(new_unverified_disarmed_parents=sum(p["malware"]["variant"]!="V0" for p in pairs),training_admitted=0)
            key=scheme+"__"+policy;plans[key]=dict(pairs=pairs,proposed_folds=folds,readiness=info)
            table.append(dict(scheme=scheme,policy=policy,**info))
    primary=plans["DIE_COMPILER_VERSION_AND_LINKER__SIZE2X_SAME_TRUNCATION_SIGNED"]
    requested=[p["malware"] for p in primary["pairs"] if p["malware"]["variant"]!="V0"] if primary["proposed_folds"] else []
    out=Path(tempfile.mkdtemp(prefix="compiler-controls-",dir=project/"runs"));private=out/"private";private.mkdir();safe=out/"safe";safe.mkdir()
    save(private/"CONTROL_PROPOSALS_PRIVATE.json",plans)
    save(private/"POTENTIAL_RESTORE_SCOPE_PRIVATE.json",dict(status="NOT_AUTHORIZED_NOT_EXECUTED",parents=requested,training_admitted=0))
    save(private/"COMPILER_EVIDENCE_PRIVATE.json",{k:list(v) for k,v in compilers.items()})
    if any(sha(p.read_bytes())!=h for p,h in protected.items()):raise ValueError("Cached source metadata changed")
    save(private/"PROVENANCE_PRIVATE.json",{str(p):h for p,h in protected.items()})
    summary=dict(status="COMPILER_PUBLISHER_CONTROL_METADATA_ONLY",**evidence,
        primary_compiler_linker_size_controlled=next(r for r in table if r["scheme"]=="DIE_COMPILER_VERSION_AND_LINKER" and r["policy"]=="SIZE2X_SAME_TRUNCATION_SIGNED"),
        linker_only_sensitivity=next(r for r in table if r["scheme"]=="linker_major_minor" and r["policy"]=="SIZE2X_SAME_TRUNCATION_SIGNED"),
        unknown_software_lineage_not_fabricated=True,benign_publisher_blocking_used=True,
        potential_restore_scope_count=len(requested),restoration_approved=False,restoration_performed=False,
        PE_bytes_read=False,new_DiE_scan=False,training_performed=False,original_splits_changed=False,Drive_submission_documents_modified=False,
        teacher100_per_class_reached=primary["readiness"]["pairs"]>=100,
        limits=["Typed DiE compiler is static detector evidence, not independently verified build provenance",
            "Original V0 hash and cross-source prefix checks still required; no training admitted",
            "Exact Rich fingerprints remain sensitivity controls; linker-only is not same-compiler proof",
            "Publisher blocking coarsens groups without inventing missing application lineage",
            "Dataset source/time confounding may remain; operational fold gate is not a power calculation"])
    if supplement is not None:
        summary["status"]="EXISTING_BENIGN_COMPILER_EVIDENCE_ENRICHED_NOT_TRAINING"
        summary["existing_benign_compiler_supplement"]=supplement
        summary["new_DiE_scan"]=bool(supplement["detector_calls"])
        summary["PE_bytes_read"]=bool(supplement["verified_benign_copies_read"])
        summary["byte_read_scope"]="Existing verified benign only; no malware read or restoration"
        if extra_verified_benign is not None:
            summary["status"]="NEW_BENIGN_STATIC_AUDIT_AND_CONTROL_PROPOSAL_NOT_TRAINING"
            summary.pop("existing_benign_compiler_supplement",None)
            summary["new_benign_acquisition_audit"]=supplement
            summary["new_verified_benign_added"]=len(extra_verified_benign)
            summary["study_metadata_rows_by_label"]=dict(Counter(r["label"] for r in rows))
            summary["byte_read_scope"]="Approved new benign only; old study metadata reused; no malware read or restoration"
    save(safe/"RESULTS_FOR_CODEX.json",summary)
    with (safe/"CONTROL_READINESS.csv").open("x",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=list(table[0]));w.writeheader();w.writerows(table)
    names=["RESULTS_FOR_CODEX.json","CONTROL_READINESS.csv"]
    if any(re.search(rb"[0-9a-fA-F]{64}",(safe/n).read_bytes()) for n in names):raise ValueError("Private sample identity in aggregate")
    save(safe/"SAFE_CHECKSUMS.json",{n:sha((safe/n).read_bytes()) for n in names})
    packet=out/output_name
    with zipfile.ZipFile(packet,"x",zipfile.ZIP_DEFLATED) as z:
        for n in names+["SAFE_CHECKSUMS.json"]:z.write(safe/n,n)
    target=base.parent/packet.name
    if target.exists():raise FileExistsError("Preserve existing SAFE USB output")
    with packet.open("rb") as a,target.open("xb") as b:shutil.copyfileobj(a,b)
    if sha(target.read_bytes())!=sha(packet.read_bytes()):raise ValueError("SAFE copy differs")
    print(json.dumps(dict(output=str(out),**summary),indent=2));print("Return "+output_name+" only; no restoration or training authorized.")


if __name__=="__main__":main()
