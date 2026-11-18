"""Approval-gated original publisher ZIP intake; never parse/extract/execute PE."""
from concurrent.futures import ThreadPoolExecutor,as_completed
from pathlib import Path
from urllib.parse import urlparse
import hashlib,json
import ACQUIRE_BENIGN_ARCHIVES as intake

HERE=Path(__file__).resolve().parent
REVIEW=HERE/"BENIGN_EXPANSION_REVIEW_20261105"


def validate_list(raw,digest):
    if hashlib.sha256(raw).hexdigest()!=digest:raise ValueError("Reviewed candidate list differs")
    specs=json.loads(raw)
    if not 1<=len(specs)<=100 or len({r["slug"] for r in specs})!=len(specs):raise ValueError("Reviewed program bound differs")
    for r in specs:
        if r["publisher"]!="NirSoft" or r["lineage"]!="NirSoft:"+r["slug"] or r["PE_or_ZIP_fetched"] is not False:
            raise ValueError("Publisher/source lineage differs")
        intake.valid_url(r["page"],{"www.nirsoft.net","nirsoft.net"})
        intake.valid_url(r["reviewed_download"],{"www.nirsoft.net","nirsoft.net"})
        if not urlparse(r["reviewed_download"]).path.lower().endswith(".zip"):raise ValueError("Only reviewed original ZIPs")
    return specs


def locked_download_selector(specs,original):
    mapping={urlparse(r["page"]).path:r["reviewed_download"] for r in specs}
    if len(mapping)!=len(specs):raise ValueError("Ambiguous publisher page mapping")
    def choose(page,parsed):
        observed=original(page,parsed)
        if mapping.get(urlparse(page).path)!=observed:raise ValueError("Publisher ZIP link changed; review required")
        return observed
    return choose


def main():
    approval_path=REVIEW/"APPROVAL.json"
    approval=json.loads(approval_path.read_text()) if approval_path.is_file() else {}
    if approval.get("approved") is not True or approval.get("scope")!="REVIEWED_ADDITIONAL_BENIGN_PUBLISHER_ZIPS_ONLY":
        raise SystemExit("Pending explicit benign dataset expansion approval; no archive downloaded")
    specs=validate_list((REVIEW/"CANDIDATE_ALLOWLIST.json").read_bytes(),approval["allowlist_sha256"])
    out=HERE/"BENIGN_ARCHIVES_EXPANSION_20261105";out.mkdir(exist_ok=False);(out/"sources").mkdir()
    intake.nir_download=locked_download_selector(specs,intake.nir_download)
    records=[];errors=[]
    with ThreadPoolExecutor(max_workers=3) as pool:
        jobs={pool.submit(intake.acquire,r,out):r for r in specs}
        for f in as_completed(jobs):
            spec=jobs[f]
            try:records.append(f.result());print("Publisher archive retained: "+spec["program"],flush=True)
            except Exception as exc:errors.append(dict(program=spec["program"],error_type=type(exc).__name__,error=str(exc)))
    manifest=dict(status="BENIGN_CANDIDATE_ARCHIVES_PENDING_ISOLATED_VM_AUDIT",archives=sorted(records,key=lambda r:r["software_lineage"]),
        acquisition_errors=errors,programs_planned=len(specs),archives_acquired=len(records),
        provenance="Original publisher HTTPS pages/ZIPs; published SHA256 checked when provided; notices preserved",
        candidate_count_is_not_research_sample_count=True,toolchain_match_not_yet_verified=True,
        PE_parsed=False,PE_executed=False,malware_downloaded=False,restore=False,pack_unpack=False,training=False,
        old_data_modified=False,Drive_submission_documents_modified=False)
    intake.save(out/"ACQUISITION_MANIFEST.json",json.dumps(manifest,indent=2).encode())
    print(json.dumps({k:v for k,v in manifest.items() if k not in {"archives","acquisition_errors"}},indent=2))


if __name__=="__main__":main()
