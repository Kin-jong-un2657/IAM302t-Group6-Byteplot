"""Freeze prospective matching/family folds from existing metadata only; no training."""
from collections import Counter, defaultdict
from pathlib import Path
import copy
import csv
import hashlib
import importlib.util
import io
import json
import math
import os
import shutil
import statistics
import tempfile
import zipfile

SOURCE_SHA="4486089fbffea6c45bf0451686a7ec6aaf6cf38512d0c0c4aa99732dd9ec705a"
FAMILY_CSV_SHA="fb34221d64c808bdcf0935f042a821a9ffb0ee0f0a2132b38eccc8b8b375ba6b"
OVERLAP_SHA="259dfa8e3a7d50b7c795b973bc33dfb5cace0ffc1e9395a07d9ae51ed50f860a"


def sha(data):return hashlib.sha256(data).hexdigest()


def save(p,data):
    with Path(p).open("x",encoding="utf-8") as f:json.dump(data,f,indent=2,allow_nan=False)


def match(rows,profile,ratio=None,same_truncation=False,same_signed=False):
    """Maximum-cardinality bipartite matching, deterministic; never use CNN scores."""
    if len({r["parent_sha256"] for r in rows})!=len(rows):raise ValueError("Duplicate original parent")
    groups=defaultdict(list)
    for r in rows:
        if r["variant"]!="V0" or r["sha256"]!=r["parent_sha256"]:raise ValueError("Original hash contract differs")
        key=profile(r)
        if key is not None:groups[key].append(r)
    pairs=[]
    for key,members in sorted(groups.items()):
        malware=sorted([r for r in members if r["label"]=="1"],key=lambda r:r["parent_sha256"])
        benign=sorted([r for r in members if r["label"]=="0"],key=lambda r:r["parent_sha256"])
        edges=[]
        for m in malware:
            a=int(m["size_bytes"])
            if a<=0:raise ValueError("Invalid original size")
            possible=[]
            for j,b in enumerate(benign):
                n=int(b["size_bytes"])
                if n<=0:raise ValueError("Invalid original size")
                distance=max(a,n)/min(a,n)
                if ratio is not None and distance>ratio:continue
                if same_truncation and (a>65536)!=(n>65536):continue
                if same_signed and int(m["signed"])!=int(b["signed"]):continue
                possible.append((abs(math.log2(a/n)),b["parent_sha256"],j))
            edges.append([j for _,_,j in sorted(possible)])
        assigned={}
        def augment(i,visited):
            for j in edges[i]:
                if j in visited:continue
                visited.add(j)
                if j not in assigned or augment(assigned[j],visited):
                    assigned[j]=i;return True
            return False
        for i in range(len(malware)):augment(i,set())
        for j,i in sorted(assigned.items(),key=lambda item:malware[item[1]]["parent_sha256"]):
            m,b=malware[i],benign[j]
            pairs.append(dict(pair_id=f"P{len(pairs)+1:03}",profile=list(key),malware=m,benign=b,
                size_ratio=max(int(m["size_bytes"]),int(b["size_bytes"]))/min(int(m["size_bytes"]),int(b["size_bytes"]))))
    return pairs


def family_folds(pairs):
    """Block paired parents and known family/benign lineage in the same fold."""
    n=len(pairs);parent=list(range(n));seen={}
    def root(i):
        while parent[i]!=i:parent[i]=parent[parent[i]];i=parent[i]
        return i
    def union(a,b):parent[root(a)]=root(b)
    identities=[];missing_family=missing_lineage=0
    for i,p in enumerate(pairs):
        m,b=p["malware"],p["benign"]
        family=m.get("family","");lineage=b.get("software_lineage","")
        missing_family+=not bool(family);missing_lineage+=not bool(lineage)
        tokens=[("family",family),("lineage",lineage)]
        for r in (m,b):
            tokens += [("parent",r["parent_sha256"]),("prefix",r["observed_prefix_sha256"])]
            identities.append(r["parent_sha256"])
        for token in tokens:
            if not token[1]:continue
            if token in seen:union(i,seen[token])
            seen[token]=i
    if len(set(identities))!=len(identities):raise ValueError("One parent used in multiple pairs")
    groups=defaultdict(list)
    for i,p in enumerate(pairs):groups[root(i)].append(p["pair_id"])
    info=dict(pairs=n,missing_malware_family=missing_family,missing_benign_lineage=missing_lineage,
              connected_family_lineage_groups=len(groups),minimum_pairs_operational_gate=12,
              cv_folds=0,min_train_pairs=None,min_validation_pairs=None,min_test_pairs=None,
              gate_is_not_a_power_calculation=True,source_original_splits_preserved=True)
    if n<12 or len(groups)<3 or missing_family or missing_lineage:
        return [],dict(info,status="NOT_READY_FOR_REVIEWED_FAMILY_GROUPED_CV")
    ordered=sorted(groups.values(),key=lambda g:(-len(g),sha(("G6_MATCHED_FAMILY_CV20261104:"+"|".join(sorted(g))).encode())))
    bins=[[],[],[]];bin_groups=[[],[],[]]
    for group in ordered:
        k=min(range(3),key=lambda k:(len(bins[k]),k));bins[k].extend(group);bin_groups[k].append(group)
    folds=[]
    for k in range(3):
        remaining=[g for j,groups_here in enumerate(bin_groups) if j!=k for g in groups_here]
        if len(remaining)<2:return [],dict(info,status="NOT_ENOUGH_GROUPS_FOR_DISJOINT_TRAIN_VALIDATION")
        val=min(remaining,key=lambda g:(abs(len(g)-2),sha(("VAL:"+"|".join(sorted(g))).encode())))
        train=[p for g in remaining if g is not val for p in g]
        folds.append(dict(fold=k,train_pair_ids=sorted(train),validation_pair_ids=sorted(val),test_pair_ids=sorted(bins[k])))
    info.update(cv_folds=3,min_train_pairs=min(len(f["train_pair_ids"]) for f in folds),
                min_validation_pairs=min(len(f["validation_pair_ids"]) for f in folds),min_test_pairs=min(len(f["test_pair_ids"]) for f in folds))
    if info["min_train_pairs"]<4:
        return [],dict(info,status="NOT_ENOUGH_TRAIN_PAIRS_AFTER_FAMILY_BLOCKING")
    return folds,dict(info,status="EXPLORATORY_CV_FEASIBLE_PENDING_TRAINING_APPROVAL")


def plan_readiness(pairs):
    folds,info=family_folds(pairs)
    ratios=[p["size_ratio"] for p in pairs]
    info.update(size_ratio_median=statistics.median(ratios) if ratios else None,size_ratio_max=max(ratios) if ratios else None,
        benign_publishers=len({p["benign"].get("source_project","") for p in pairs}),
        malware_families=len({p["malware"].get("family","") for p in pairs if p["malware"].get("family","")}),
        known_old_malware_test_parents=sum(p["malware"]["split"]=="test" for p in pairs),
        teacher100_per_class=len(pairs)>=100)
    return folds,info


def main():
    base=Path(__file__).resolve().parent
    helper=base/"AUDIT_SOURCE_OVERLAP.py"
    if sha(helper.read_bytes())!=OVERLAP_SHA:raise ValueError("Reviewed profile definitions differ")
    spec=importlib.util.spec_from_file_location("frozen_profiles",helper);overlap=importlib.util.module_from_spec(spec);spec.loader.exec_module(overlap)
    overlap.check_vm();project=Path.home()/"IAM302t"
    matches=[p for p in (project/"runs").glob("legacy-benign-recovery-*/safe/RESULTS_FOR_CODEX.json")
             if p.stat().st_size<128*1024 and sha(p.read_bytes())==SOURCE_SHA]
    if len(matches)!=1:raise ValueError("Exact finished90M225B metadata missing/ambiguous")
    source=matches[0];headers=source.parent.parent/"private/MERGED_PROSPECTIVE_HEADERS_PRIVATE.json"
    if headers.stat().st_size>4*1024**2:raise ValueError("Unexpected metadata size")
    before=sha(headers.read_bytes());rows=json.loads(headers.read_text())
    if Counter(r["label"] for r in rows)!={"0":225,"1":90}:raise ValueError("Verified pool membership differs")
    if len({r["observed_prefix_sha256"] for r in rows})!=len(rows):raise ValueError("Observed-prefix duplicates require grouping before matching")
    archive=base.parent/"static182_disarmed_for_vm.zip"
    with zipfile.ZipFile(archive) as z:
        name="bodmas_pilot_258_metadata_readiness.csv"
        if z.getinfo(name).file_size>512*1024:raise ValueError("Family metadata size differs")
        raw=z.read(name)  # Only this metadata member is read; no sample/archive-wide scan.
    if sha(raw)!=FAMILY_CSV_SHA:raise ValueError("Existing family metadata CSV differs")
    family_rows=list(csv.DictReader(io.StringIO(raw.decode("utf-8-sig"))))
    family={r["parent_sha256"]:r["family"].strip() for r in family_rows}
    if len(family_rows)!=258 or len(family)!=258:raise ValueError("Existing family mapping membership differs")
    unknown={"","unknown","nan","none","null","malware","bodmas","unknown_family"}
    study=copy.deepcopy(rows)
    for r in study:
        if r["label"]=="1":
            label=family.get(r["parent_sha256"],"")
            r["family_original"]=label
            r["family"]=label.casefold() if label.casefold() not in unknown else ""
    os.umask(0o077);out=Path(tempfile.mkdtemp(prefix="matched-cohort-freeze-",dir=project/"runs"));private=out/"private";private.mkdir();safe=out/"safe";safe.mkdir()
    print("NEW_OUTPUT="+str(out),flush=True)
    results=[];plans={};expected=dict(linker_major_minor=33,rich_products_linker=15,rich_product_builds_linker=14)
    for scheme in overlap.SCHEMES:
        for policy in ("HEADER_PROFILE_ONLY","SIZE2X_SAME_TRUNCATION_SIGNED"):
            constrained=policy!="HEADER_PROFILE_ONLY"
            pairs=match(study,lambda r:overlap.profile(r,scheme),ratio=2 if constrained else None,
                        same_truncation=constrained,same_signed=constrained)
            if not constrained and len(pairs)!=expected[scheme]:raise ValueError("Frozen matching does not reproduce verified support")
            folds,info=plan_readiness(pairs)
            key=scheme+"__"+policy
            plans[key]=dict(status="PRIVATE_PROSPECTIVE_PLAN_NOT_TRAINING",scheme=scheme,policy=policy,pairs=pairs,proposed_family_folds=folds,readiness=info)
            results.append(dict(scheme=scheme,policy=policy,**info))
    if sha(headers.read_bytes())!=before or sha(source.read_bytes())!=SOURCE_SHA:raise ValueError("Input metadata changed; no plan release")
    save(private/"FROZEN_MATCHED_PLANS_PRIVATE.json",plans)
    save(private/"PROVENANCE_PRIVATE.json",dict(source_summary_sha256=SOURCE_SHA,headers_sha256=before,family_csv_sha256=FAMILY_CSV_SHA))
    primary=next(r for r in results if r["scheme"]=="rich_product_builds_linker" and r["policy"]=="HEADER_PROFILE_ONLY")
    sensitivity=next(r for r in results if r["scheme"]=="rich_product_builds_linker" and r["policy"]!="HEADER_PROFILE_ONLY")
    summary=dict(status="MATCHED_METADATA_PLANS_FROZEN_NOT_TRAINED",input_pool_malware=90,input_pool_benign=225,
        family_metadata_joined_malware=sum(bool(r.get("family")) for r in study if r["label"]=="1"),
        strongest_header_matched=primary,strongest_size_controlled=sensitivity,
        training_performed=False,features_encoded=False,PE_bytes_read=False,new_restorations=0,
        original_splits_changed=False,Drive_modified=False,protected_metadata_unchanged=True,
        teacher100_per_class_reached=False,all_teacher_requirements_completed=False,
        limits=["Exact header product/build matching is not verified publisher/time equality",
                "Metadata-only proposals and CV feasibility are not classifier results",
                "Header-only policy does not control size/truncation/signature; separate constrained sensitivity is reported",
                "Old test parents may enter an exploratory new study; no new blind holdout claimed",
                "Family labels are reused from unchanged BODMAS pilot metadata; not an independent relabeling",
                "Ten extra malware is only a class-count lower bound, not enough to guarantee100 matched pairs"])
    save(safe/"RESULTS_FOR_CODEX.json",summary)
    with (safe/"MATCHED_READINESS.csv").open("x",encoding="utf-8",newline="") as f:
        w=csv.DictWriter(f,fieldnames=list(results[0]));w.writeheader();w.writerows(results)
    names=["RESULTS_FOR_CODEX.json","MATCHED_READINESS.csv"]
    save(safe/"SAFE_CHECKSUMS.json",{n:sha((safe/n).read_bytes()) for n in names})
    packet=out/"MATCHED_COHORT_READINESS_SAFE.zip"
    with zipfile.ZipFile(packet,"x",zipfile.ZIP_DEFLATED) as z:
        for n in names+["SAFE_CHECKSUMS.json"]:z.write(safe/n,n)
    dest=base.parent/packet.name
    if dest.exists():dest=dest.with_name(dest.stem+"_"+sha(packet.read_bytes())[:12]+".zip")
    with packet.open("rb") as src,dest.open("xb") as dst:shutil.copyfileobj(src,dst)
    if sha(dest.read_bytes())!=sha(packet.read_bytes()):raise ValueError("SAFE transfer differs")
    print(json.dumps(summary,indent=2));print("USB_RESULT="+str(dest))
    print("Return MATCHED_COHORT_READINESS_SAFE.zip only; private pair/family identities stay VM.")


if __name__=="__main__":main()
