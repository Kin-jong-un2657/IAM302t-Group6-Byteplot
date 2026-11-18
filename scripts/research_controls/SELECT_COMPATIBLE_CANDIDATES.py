"""Metadata-only retrieval plan; never read PE bytes or declare a training cohort.

Reuse the four verified EMBER columns instead of loading the 41 GB X array.
The plan deliberately targets linker versions supported by existing benign.
Compiler, PE, packing and V0 gates must still be checked in the isolated VM.
"""
from collections import Counter, defaultdict, deque
from pathlib import Path
import argparse
import csv
import hashlib
import io
import json
import re
import zipfile

import numpy as np
import SCREEN_BODMAS_NUMERIC as numeric

QUOTAS = ((8, 0, 320), (6, 0, 576), (9, 0, 128))
GENERIC = {'', 'unknown', 'unknown_family', 'unclassified', 'generic', 'other',
           'none', 'null', 'nan', 'malware', 'bodmas', '-'}
PREVIOUS_PLAN_SHA = '63cc0ec5abcc3bb83e3bb6b0f86bf9e590f6c00e4136fb856797345cf21184b8'


def family(value):
    value = str(value or '').strip().casefold()
    return '' if value in GENERIC else value


def stable(value):
    return hashlib.sha256(('G6-compatible-retrieval-v1:' + value).encode()).hexdigest()


def size_cell(row):
    n = int(row['file_size'])
    # Preserve the 64 KiB boundary. Balance retrieval strata, not research labels.
    bounds = (65536, 131072, 262144, 524288, 1048576, 2000000)
    return int(row['reported_has_signature']), next(i for i, bound in enumerate(bounds) if n <= bound)


def select(rows, quotas=QUOTAS, per_family=16):
    if not 1 <= per_family <= 16 or not quotas or sum(q[2] for q in quotas) > 1024:
        raise ValueError('Retrieval cap exceeded')
    if len({(q[0], q[1]) for q in quotas}) != len(quotas) or any(q[2] < 1 for q in quotas):
        raise ValueError('Invalid linker quotas')
    identities = [r['parent_sha256'] for r in rows]
    if len(set(identities)) != len(rows) or any(not re.fullmatch('[0-9a-f]{64}', p) for p in identities):
        raise ValueError('Duplicate/invalid candidate parent')
    counts = Counter(); selected = []
    for major, minor, quota in quotas:
        groups = defaultdict(lambda: defaultdict(list))
        for r in rows:
            if (int(r['linker_major']), int(r['linker_minor'])) != (major, minor) or not family(r['family']):
                continue
            if not 15000 <= int(r['file_size']) <= 2000000 or int(r['reported_has_signature']) not in (0, 1):
                raise ValueError('Candidate outside unchanged controls')
            if r.get('disarmed_sha256') or str(r.get('training_admitted')) != '0' or r.get('V0_hash_verification') != 'NOT_PERFORMED':
                raise ValueError('Retrieval plan cannot claim verified content or admission')
            groups[family(r['family'])][size_cell(r)].append(r)
        queues = {}
        for name, cells in groups.items():
            cells = {k: deque(sorted(v, key=lambda r: stable(r['parent_sha256']))) for k, v in cells.items()}
            queue = deque()
            while any(cells.values()):
                for key in sorted(cells):
                    if cells[key]: queue.append(cells[key].popleft())
            queues[name] = queue
        order = sorted(queues, key=stable); added = 0
        while added < quota:
            progress = False
            for name in order:
                if queues[name] and counts[name] < per_family:
                    selected.append(queues[name].popleft()); counts[name] += 1
                    added += 1; progress = True
                    if added == quota: break
            if not progress:
                raise ValueError(f'Insufficient eligible families for frozen linker quota {major}.{minor}: {added}/{quota}')
    return selected


def csv_rows(raw):
    return list(csv.DictReader(io.StringIO(raw.decode('utf-8-sig'))))


def read_member(path, name, cap=16 * 1024**2):
    # Read only the named metadata file, never any sample member.
    with zipfile.ZipFile(path) as z:
        matches = [i for i in z.infolist() if i.filename == name]
        if len(matches) != 1 or matches[0].file_size > cap or matches[0].flag_bits & 1:
            raise ValueError('Unexpected metadata member')
        return z.read(matches[0])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('cache', 'cache-receipt', 'metadata', 'disarm-kit', 'pilot-packet', 'previous-plan', 'out'):
        p.add_argument('--' + name, type=Path, required=True)
    args = p.parse_args()
    if args.out.exists(): raise FileExistsError('Choose a new output directory')
    receipt = json.loads(args.cache_receipt.read_text(encoding='utf-8'))
    if (receipt['source_sha256'] != numeric.NPZ_SHA or numeric.file_sha(args.cache) != receipt['cache_sha256']
        or receipt['schema']['retained_columns'] != list(numeric.COLUMNS)
        or numeric.file_sha(args.metadata) != numeric.META_SHA):
        raise ValueError('Verified numeric cache/metadata differs')
    with np.load(args.cache, allow_pickle=False) as f:
        cols, labels = f['columns'], f['labels']
    if cols.shape != (134435, 4) or labels.shape != (134435,) or Counter(map(int, labels)) != {0:77142, 1:57293}:
        raise ValueError('Grounded BODMAS cache schema differs')
    metadata = numeric.metadata_join(args.metadata.read_bytes(), labels, quarantine_invalid_benign=True)
    anchor_raw = read_member(args.pilot_packet, 'bodmas_pilot_258_metadata_readiness.csv')
    if numeric.sha(anchor_raw) != numeric.ANCHOR_SHA: raise ValueError('Original pilot metadata differs')
    anchors = csv_rows(anchor_raw)
    checked = numeric.validate_anchors(metadata, cols, anchors)
    previous_raw = args.previous_plan.read_bytes()
    if numeric.sha(previous_raw) != PREVIOUS_PLAN_SHA: raise ValueError('Previous selection differs')
    previous = csv_rows(previous_raw)
    if len(anchors) != 258 or len(previous) != 256: raise ValueError('Previous scope counts differ')
    disarm_raw = read_member(args.disarm_kit, 'meta_disarm.csv')
    disarm_rows = csv_rows(disarm_raw)
    disarm = {r['sha256']: r for r in disarm_rows}
    if len(disarm) != 57293 or len(disarm_rows) != 57293: raise ValueError('Official metadata count differs')
    excluded = {r['parent_sha256'] for r in anchors + previous}
    eligible, rejects = numeric.eligible(metadata, cols, labels, disarm, excluded, {(a,b) for a,b,_ in QUOTAS})
    chosen = select(eligible)
    if set(r['parent_sha256'] for r in chosen) & excluded: raise AssertionError('Previous scope overlap')
    args.out.mkdir(parents=True, exist_ok=False)
    private = args.out / 'private'; private.mkdir()
    plan = private / 'CANDIDATES_PRIVATE.csv'
    with plan.open('x', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=list(chosen[0])); w.writeheader(); w.writerows(chosen)
    inputs = dict(cache=numeric.file_sha(args.cache), metadata=numeric.META_SHA,
                  original_pilot=numeric.ANCHOR_SHA, previous_selection=PREVIOUS_PLAN_SHA,
                  official_disarm_metadata=numeric.sha(disarm_raw))
    numeric.write_json(private / 'INPUT_PROVENANCE.json', inputs)
    summary = dict(status='PENDING_NEW_SCOPE_APPROVAL_METADATA_ONLY', selected_candidates=len(chosen),
        selected_families=len({family(r['family']) for r in chosen}), per_family_cap=16,
        linker_quotas=[dict(major=a, minor=b, selected=n) for a,b,n in QUOTAS],
        original_size_anchors=checked, excluded_previous_parents=len(excluded),
        candidate_payload_bytes=sum(int(r['file_size']) for r in chosen),
        private_plan_sha256=numeric.file_sha(plan), selected_certificate_presence=dict(Counter(str(r['reported_has_signature']) for r in chosen)),
        generic_families_selected=0, approved=False, malware_copied=False, PE_analysis=False,
        restoration=False, packing_unpacking=False, training=False, Drive_changed=False,
        verified_new_V0=0, training_admitted=0, teacher100_per_class_reached=False,
        limitation='Linker is only a retrieval filter. Typed compiler, PE/DiE, prefix, full controls and original V0 hashes remain unverified; no guarantee of 100 pairs.',
        exclusions=rejects)
    numeric.write_json(args.out / 'REVIEW_SCOPE.json', summary)
    print(json.dumps(summary, indent=2))


if __name__ == '__main__': main()
