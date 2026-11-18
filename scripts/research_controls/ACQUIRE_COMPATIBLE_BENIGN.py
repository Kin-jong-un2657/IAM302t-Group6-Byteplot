"""Bounded, approval-gated publisher containers; never extract or execute PE."""
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse
import argparse
import hashlib
import json
import re
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'teacher_v3_completion_20261104'))
import ACQUIRE_BENIGN_ARCHIVES as intake
from ACQUIRE_REVIEWED_BENIGN import locked_download_selector
from COPY_COMPATIBLE_BATCH import SCOPE


def validate_allowlist(raw, approval):
    if approval.get('approved') is not True or approval.get('scope') != SCOPE:
        raise ValueError('New dataset intake scope not yet approved')
    if hashlib.sha256(raw).hexdigest() != approval.get('benign_allowlist_sha256'):
        raise ValueError('Reviewed publisher list differs')
    specs = json.loads(raw)
    if len(specs) != approval.get('benign_candidates') or not 1 <= len(specs) <= 55:
        raise ValueError('Approved benign count differs')
    seen = set()
    for s in specs:
        if (not re.fullmatch('[a-z0-9]+', s['slug']) or s['slug'] in seen
            or s['publisher'] != 'NirSoft' or s['lineage'] != 'NirSoft:' + s['slug']
            or s['PE_or_ZIP_fetched'] is not False
            or set(s['hosts']) != {'www.nirsoft.net','nirsoft.net'}):
            raise ValueError('Publisher/lineage identity differs')
        seen.add(s['slug'])
        for field in ('page', 'reviewed_download'):
            intake.valid_url(s[field], {'www.nirsoft.net','nirsoft.net'})
        p = urlparse(s['reviewed_download'])
        if not p.path.startswith('/utils/') or not p.path.lower().endswith('.zip') or p.query or p.fragment:
            raise ValueError('Only the exact reviewed original program ZIP')
    return specs


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('allowlist', 'approval', 'out'): p.add_argument('--'+name, type=Path, required=True)
    args = p.parse_args()
    approval = json.loads(args.approval.read_text(encoding='utf-8'))
    specs = validate_allowlist(args.allowlist.read_bytes(), approval)
    args.out.mkdir(parents=True, exist_ok=False); (args.out/'sources').mkdir(); (args.out/'journal').mkdir()
    intake.nir_download = locked_download_selector(specs, intake.nir_download)
    records = []; errors = []
    with ThreadPoolExecutor(max_workers=3) as pool:
        jobs = {pool.submit(intake.acquire, s, args.out): s for s in specs}
        for i,f in enumerate(as_completed(jobs),1):
            s=jobs[f]
            try:
                result=f.result(); records.append(result)
                state=dict(program=s['program'],status='ORIGINAL_ZIP_RETAINED_PENDING_VM_AUDIT')
            except Exception as exc:
                state=dict(program=s['program'],status='FAILED',error_type=type(exc).__name__)
                errors.append(state)
            intake.save(args.out/'journal'/(s['slug']+'.json'), json.dumps(state,indent=2).encode())
            if i%10==0 or i==len(specs):print(f'Benign container intake {i}/{len(specs)}',flush=True)
    summary=dict(status='BENIGN_CONTAINER_INTAKE_PENDING_ISOLATED_VM_AUDIT',programs_planned=len(specs),
        archives_acquired=len(records),archives=sorted(records,key=lambda r:r['software_lineage']),
        acquisition_errors=errors,independent_publishers=1,PE_parsed=False,PE_executed=False,
        malware_downloaded=False,restore=False,pack_unpack=False,training=False,training_admitted=0,
        old_data_modified=False,Drive_submission_documents_modified=False,
        limitation='Publisher original ZIP/provenance only; candidate count does not establish compiler match, benign behavior or cohort size')
    intake.save(args.out/'ACQUISITION_MANIFEST.json',json.dumps(summary,indent=2).encode())
    print(json.dumps({k:v for k,v in summary.items() if k not in {'archives','acquisition_errors'}},indent=2))


if __name__=='__main__':main()
