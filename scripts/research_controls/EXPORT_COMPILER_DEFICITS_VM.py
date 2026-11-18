"""Aggregate exact compiler/version coverage from completed cached metadata only.

No binary reads, external process, network, detector, restoration or training.
"""
from collections import Counter,defaultdict
from pathlib import Path
import csv,hashlib,importlib.util,json,math,re,shutil,tempfile,zipfile

EXPECTED_SUMMARY='646af4c714d680a1e8efc4e7220b111c6d6ce5850b6c246518c4ffe26256c30d'


def sha(raw):return hashlib.sha256(raw).hexdigest()
def save(p,d):
    with p.open('x',encoding='utf-8') as f:json.dump(d,f,indent=2,allow_nan=False)


def profile(row,compilers):
    key=compilers.get(row['parent_sha256'])
    if key is None:return None
    if (not isinstance(key,(list,tuple)) or len(key)!=2 or not all(isinstance(x,str) and x for x in key)
        or not re.fullmatch(r'\d+(?:\.\d+){0,3}',key[1])):raise ValueError('Invalid typed compiler evidence')
    return int(row['linker_major']),int(row['linker_minor']),tuple(key)


def size_interval(m):
    n=int(m['size_bytes'])
    if not 15000<=n<=2000000:raise ValueError('Size outside reviewed observation bounds')
    lo=max(15000,math.ceil(n/2));hi=min(2000000,n*2)
    if n>65536:lo=max(65537,lo)
    else:hi=min(65536,hi)
    if lo>hi:raise ValueError('Empty fixed-control size interval')
    return lo,hi


def deficit_tables(rows,compilers,pairs):
    paired={p['malware']['parent_sha256'] for p in pairs}
    groups=defaultdict(list)
    for r in rows:
        key=profile(r,compilers)
        if key is not None and (r['label']=='0' or r.get('family')):groups[key].append(r)
    coverage=[];targets=[]
    for key,rs in sorted(groups.items()):
        major,minor,(name,version)=key
        common=dict(compiler_name=name,compiler_version=version,linker_major=major,linker_minor=minor)
        ms=[r for r in rs if r['label']=='1'];bs=[r for r in rs if r['label']=='0']
        unmatched=[m for m in ms if m['parent_sha256'] not in paired]
        coverage.append(dict(common,malware=len(ms),benign=len(bs),full_controls_pairs=len(ms)-len(unmatched),
            unmatched_malware=len(unmatched),malware_families=len({m['family'] for m in ms}),
            benign_publishers=len({b['source_project'] for b in bs})))
        # Required intervals are aggregated, never sample identities. One candidate
        # can match at most one parent, even when intervals overlap.
        strata=defaultdict(list)
        for m in unmatched:strata[(int(m['signed']),int(m['size_bytes'])>65536,size_interval(m))].append(m)
        for (signed,truncated,(lo,hi)),members in strata.items():
            candidates=[b for b in bs if int(b['signed'])==signed and (int(b['size_bytes'])>65536)==truncated
                and lo<=int(b['size_bytes'])<=hi]
            targets.append(dict(common,certificate_table_present=signed,prefix_truncated=truncated,
                candidate_size_min_bytes=lo,candidate_size_max_bytes=hi,unmatched_malware=len(members),
                unmatched_families=len({m['family'] for m in members}),
                existing_benign_in_interval=len(candidates),
                candidate_count_is_not_guaranteed_matching_gain=True))
    coverage.sort(key=lambda r:(-r['unmatched_malware'],-r['malware_families'],r['compiler_name'],r['compiler_version'],r['linker_major'],r['linker_minor']))
    targets.sort(key=lambda r:(-r['unmatched_families'],-r['unmatched_malware'],r['compiler_name'],r['compiler_version'],
        r['linker_major'],r['linker_minor'],r['certificate_table_present'],r['candidate_size_min_bytes']))
    return coverage,targets


def read_metadata(path,protected):
    if path.is_symlink() or path.stat().st_size>32*1024**2:raise ValueError('Unexpected cached metadata')
    raw=path.read_bytes();protected[path]=sha(raw);return json.loads(raw)


def verify_provenance(provenance,project,base,candidate_csv_sha,protected):
    candidate_roots=set()
    for name,digest in provenance.items():
        p=Path(name)
        cached=p.resolve().is_relative_to(project/'runs')
        approved_csv=(p.name=='CANDIDATES_PRIVATE.csv' and digest==candidate_csv_sha
            and p.resolve().is_relative_to(base.parent.resolve()))
        if not (cached or approved_csv) or p.suffix not in {'.csv','.json','.log'}:
            raise ValueError('Provenance must contain cached text metadata only')
        if p.is_symlink() or p.stat().st_size>32*1024**2 or sha(p.read_bytes())!=digest:
            raise ValueError('Protected cached evidence changed')
        protected[p]=digest
        if cached and p.parent.name=='die' and p.parent.parent.parent.name.startswith('benign-expansion97-'):
            candidate_roots.add(p.parent.parent)
    return candidate_roots


def main():
    base=Path(__file__).resolve().parent
    scope=json.loads((base/'DEFICIT_SCOPE.json').read_text())
    for n,h in scope['files'].items():
        if sha((base/n).read_bytes())!=h:raise ValueError('Reviewed helper changed')
    def load(n):
        p=base/n;spec=importlib.util.spec_from_file_location('deficit_'+p.stem,p)
        m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
    isolation=load('rich_linker_control.py');isolation.isolated()
    controls=load('CHECK_COMPILER_CONTROLS_VM.py');planner=controls.load(base,'PLAN_NEW256_MATCHED_VM.py')
    project=Path.home()/'IAM302t';protected={}
    summaries=[p for p in (project/'runs').glob('compiler-controls-*/safe/RESULTS_FOR_CODEX.json')
        if p.stat().st_size<128*1024 and sha(p.read_bytes())==EXPECTED_SUMMARY]
    if len(summaries)!=1:raise ValueError('Exact completed benign97 control result missing/ambiguous')
    summary=read_metadata(summaries[0],protected);root=summaries[0].parent.parent
    provenance=read_metadata(root/'private/PROVENANCE_PRIVATE.json',protected)
    candidate_roots=verify_provenance(provenance,project,base,controls.PLAN_SHA,protected)
    if len(candidate_roots)!=1:raise ValueError('Cannot bind new benign rows to completed audit')
    added=read_metadata(next(iter(candidate_roots))/'ADDED_BENIGN_ROWS_PRIVATE.json',protected)
    old,audit=controls.read_study(base,project,planner,protected)
    rows=controls.merge_verified_benign(old,added)
    compilers=read_metadata(root/'private/COMPILER_EVIDENCE_PRIVATE.json',protected)
    publishers=controls.publisher_groups(rows)
    eligible=[r for r in rows if r['label']=='1' or publishers[r['parent_sha256']]]
    pairs=planner.match(eligible,lambda r:profile(r,compilers),constrained=True)
    if len(pairs)!=summary['primary_compiler_linker_size_controlled']['pairs'] or len(pairs)!=11:
        raise ValueError('Primary eleven pairs not reproduced')
    if Counter(r['label'] for r in rows)!=Counter({'0':259,'1':262}):raise ValueError('Study membership differs')
    if {label:sum(r['parent_sha256'] in compilers for r in rows if r['label']==label) for label in ['0','1']}!=summary['compiler_name_version_available_by_label']:
        raise ValueError('Compiler evidence counts differ')
    coverage,targets=deficit_tables(eligible,compilers,pairs)
    if sum(r['full_controls_pairs'] for r in coverage)!=11:raise ValueError('Coverage accounting differs')
    if any(sha(p.read_bytes())!=h for p,h in protected.items()):raise ValueError('Cached inputs changed')
    out=Path(tempfile.mkdtemp(prefix='compiler-deficits-',dir=project/'runs'));safe=out/'safe';safe.mkdir()
    for name,table in [('COMPILER_COVERAGE.csv',coverage),('BENIGN_REQUIRED_INTERVALS.csv',targets)]:
        if not table:raise ValueError('Missing compiler coverage/deficits')
        with (safe/name).open('x',encoding='utf-8',newline='') as f:
            w=csv.DictWriter(f,fieldnames=list(table[0]));w.writeheader();w.writerows(table)
    report=dict(status='VERIFIED_COMPILER_COVERAGE_TARGETS_NOT_A_NEW_COHORT',primary_pairs=11,
        compiler_profiles=len(coverage),unmatched_malware_with_known_family=sum(r['unmatched_malware'] for r in coverage),
        required_interval_rows=len(targets),PE_bytes_read=False,new_audit=False,new_downloads=False,
        restore=False,pack_unpack=False,training=False,old_data_unchanged=True,Drive_changed=False,
        instruction='Acquire originals with these exact typed compiler/linker keys and size/certificate/truncation requirements; do not infer compiler from product age or linker alone',
        limits=['Counts are conditional on static detector evidence and current disarmed metadata; V0 hash/prefix verification remains required',
            'Overlapping intervals are alternative eligibility requirements, not additive guaranteed matching gains',
            'Minimum twelve pairs is an operational gate, not the teacher100/class target or statistical adequacy',
            'Do not relax controls to make a training cohort appear feasible'])
    save(safe/'RESULTS_FOR_CODEX.json',report)
    names=['RESULTS_FOR_CODEX.json','COMPILER_COVERAGE.csv','BENIGN_REQUIRED_INTERVALS.csv']
    if any(re.search(rb'[0-9a-fA-F]{64}',(safe/n).read_bytes()) for n in names):raise ValueError('Private identity in aggregate')
    save(safe/'SAFE_CHECKSUMS.json',{n:sha((safe/n).read_bytes()) for n in names})
    packet=out/'COMPILER_DEFICITS_SAFE.zip'
    with zipfile.ZipFile(packet,'x',zipfile.ZIP_DEFLATED) as z:
        for n in names+['SAFE_CHECKSUMS.json']:z.write(safe/n,n)
    target=base.parent/packet.name
    if target.exists():raise FileExistsError('Preserve existing USB output')
    with packet.open('rb') as a,target.open('xb') as b:shutil.copyfileobj(a,b)
    if sha(packet.read_bytes())!=sha(target.read_bytes()):raise ValueError('USB result differs')
    print(json.dumps(report,indent=2));print('USB_RESULT='+str(target))


if __name__=='__main__':main()
