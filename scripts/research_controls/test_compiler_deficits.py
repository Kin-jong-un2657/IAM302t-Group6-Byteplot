"""Safe cached metadata fixtures; no PE parsing or execution."""
import copy,hashlib,json,math
from pathlib import Path
import pytest
from types import SimpleNamespace
import EXPORT_COMPILER_DEFICITS_VM as e
import PLAN_NEW256_MATCHED_VM as p


def row(n,label='1',size=100000,signed=0):
    return dict(parent_sha256=f'{n:064x}',sha256=f'{n:064x}',observed_prefix_sha256=f'{n+1000:064x}',
        label=label,size_bytes=size,signed=signed,variant='V0',split='pool_unassigned',
        linker_major=6,linker_minor=0,family='fixture'+str(n) if label=='1' else '',source_project='fixture publisher')


@pytest.mark.parametrize('n',[15000,30001,65536,65537,100000,2000000])
def test_required_intervals_exactly_match_existing_ratio_and_truncation_controls(n):
    lo,hi=e.size_interval(row(1,size=n))
    for candidate in {14999,15000,lo-1,lo,hi,hi+1,65536,65537,2000000,2000001}:
        predicate=15000<=candidate<=2000000 and max(n,candidate)/min(n,candidate)<=2 and (n>65536)==(candidate>65536)
        assert (lo<=candidate<=hi)==predicate


@pytest.mark.parametrize('n',[0,14999,2000001])
def test_invalid_observation_size_fails_closed(n):
    with pytest.raises(ValueError):e.size_interval(row(1,size=n))


def test_compiler_evidence_requires_explicit_version_not_linker_only():
    r=row(1)
    assert e.profile(r,{}) is None
    with pytest.raises(ValueError):e.profile(r,{r['parent_sha256']:['compiler','6.0-8.0']})


def test_deficits_keep_signature_truncation_and_compiler_separate_and_inputs_unchanged():
    rows=[row(1),row(2,size=200000,signed=1),row(3,'0'),row(4,'0',signed=0)]
    compilers={r['parent_sha256']:['compiler','6.0'] for r in rows}
    before=copy.deepcopy(rows)
    pairs=p.match(rows,lambda r:e.profile(r,compilers),constrained=True)
    assert len(pairs)==1
    coverage,targets=e.deficit_tables(rows,compilers,pairs)
    assert rows==before and coverage[0]['full_controls_pairs']==1 and coverage[0]['unmatched_malware']==1
    assert len(targets)==1 and targets[0]['certificate_table_present']==1
    assert targets[0]['candidate_size_min_bytes']==100000 and targets[0]['candidate_size_max_bytes']==400000
    assert targets[0]['existing_benign_in_interval']==0
    assert targets[0]['candidate_count_is_not_guaranteed_matching_gain'] is True
    assert not any(len(str(x))==64 for r in targets+coverage for x in r.values())


def test_absent_compilers_and_unknown_family_not_guessed():
    r=row(1);r['family']=''
    coverage,targets=e.deficit_tables([r],{r['parent_sha256']:['compiler','6.0']},[])
    assert not coverage and not targets
    assert e.deficit_tables([row(2)],{},[])==([],[])


def test_old_usb_metadata_csv_allowed_only_by_its_pinned_identity(tmp_path):
    project=tmp_path/'vm';(project/'runs').mkdir(parents=True)
    usb=tmp_path/'usb';old=usb/'old';old.mkdir(parents=True);base=usb/'new';base.mkdir()
    path=old/'CANDIDATES_PRIVATE.csv';path.write_text('safe metadata')
    digest=hashlib.sha256(path.read_bytes()).hexdigest();protected={}
    assert e.verify_provenance({str(path):digest},project,base,digest,protected)==set()
    assert protected[path]==digest
    with pytest.raises(ValueError):e.verify_provenance({str(path):digest},project,base,'0'*64,{})


def test_cached_binary_extension_rejected_without_reading_it(tmp_path):
    project=tmp_path/'vm';runs=project/'runs';runs.mkdir(parents=True)
    binary=runs/'fixture.bin';binary.write_bytes(b'safe placeholder')
    with pytest.raises(ValueError):e.verify_provenance({str(binary):'0'*64},project,tmp_path/'usb'/'new','0'*64,{})


def test_changed_cached_text_rejected(tmp_path):
    project=tmp_path/'vm';runs=project/'runs';runs.mkdir(parents=True)
    path=runs/'cached.json';path.write_text('{}')
    with pytest.raises(ValueError):e.verify_provenance({str(path):'0'*64},project,tmp_path/'usb'/'new','1'*64,{})


def test_existing_metadata_log_binds_exact_new_audit_run(tmp_path):
    project=tmp_path/'vm';private=project/'runs'/'benign-expansion97-fixture'/'private'
    path=private/'die'/'fixture.log';path.parent.mkdir(parents=True);path.write_text('{}')
    h=hashlib.sha256(path.read_bytes()).hexdigest()
    assert e.verify_provenance({str(path):h},project,tmp_path/'usb'/'new','0'*64,{})=={private}


def test_end_to_end_safe_export_uses_cached_rows_and_writes_only_aggregates(tmp_path,monkeypatch):
    """VM/historical read backend stubbed; real merge/matching/output exercised."""
    import CHECK_COMPILER_CONTROLS_VM as controls
    base=tmp_path/'usb'/'new';base.mkdir(parents=True)
    monkeypatch.setattr(e,'__file__',str(base/'EXPORT_COMPILER_DEFICITS_VM.py'))
    project=tmp_path/'home'/'IAM302t';runs=project/'runs';runs.mkdir(parents=True)
    monkeypatch.setattr(Path,'home',classmethod(lambda cls:project.parent))
    def benign(n):
        r=row(n,'0');r.update(status='ok',pe_status='parsed',die_status='clean',disarmed_sha256='',
            machine='0x014c',subsystem='2',is_dll=False,structural_warning_count=0,
            source_project='NirSoft',software_lineage='NirSoft:fixture'+str(n),training_admitted=0)
        return r
    old=[benign(i) for i in range(1,226)]+[row(i) for i in range(1001,1263)]
    added=[benign(i) for i in range(226,260)]
    new_private=runs/'benign-expansion97-fixture'/'private';(new_private/'die').mkdir(parents=True)
    (new_private/'ADDED_BENIGN_ROWS_PRIVATE.json').write_text(json.dumps(added))
    log=new_private/'die'/'fixture.log';log.write_text('{}')
    original_log=log.read_bytes()
    completed=runs/'compiler-controls-fixture';(completed/'safe').mkdir(parents=True);(completed/'private').mkdir()
    summary=dict(primary_compiler_linker_size_controlled=dict(pairs=11),compiler_name_version_available_by_label={'0':89,'1':139})
    sraw=json.dumps(summary).encode();(completed/'safe'/'RESULTS_FOR_CODEX.json').write_bytes(sraw)
    monkeypatch.setattr(e,'EXPECTED_SUMMARY',hashlib.sha256(sraw).hexdigest())
    provenance={str(log):hashlib.sha256(original_log).hexdigest()}
    (completed/'private'/'PROVENANCE_PRIVATE.json').write_text(json.dumps(provenance))
    compiler={}
    for i in range(1,90):compiler[f'{i:064x}']=['compiler','6.0' if i<=11 else '8.0']
    for i in range(1001,1140):compiler[f'{i:064x}']=['compiler','6.0' if i<=1011 else '7.0']
    (completed/'private'/'COMPILER_EVIDENCE_PRIVATE.json').write_text(json.dumps(compiler))
    monkeypatch.setattr(controls,'read_study',lambda *args:(copy.deepcopy(old),[]))
    monkeypatch.setattr(controls,'load',lambda *args:p)
    fake_modules={'deficit_rich_linker_control':SimpleNamespace(isolated=lambda:None),
        'deficit_CHECK_COMPILER_CONTROLS_VM':controls}
    for name in ['rich_linker_control.py','CHECK_COMPILER_CONTROLS_VM.py']:(base/name).write_text('# fixture backend only')
    (base/'DEFICIT_SCOPE.json').write_text(json.dumps(dict(files={name:hashlib.sha256((base/name).read_bytes()).hexdigest() for name in ['rich_linker_control.py','CHECK_COMPILER_CONTROLS_VM.py']})))
    monkeypatch.setattr(e.importlib.util,'spec_from_file_location',lambda name,path:SimpleNamespace(name=name,loader=SimpleNamespace(exec_module=lambda mod:None)))
    monkeypatch.setattr(e.importlib.util,'module_from_spec',lambda spec:fake_modules[spec.name])
    e.main()
    result=base.parent/'COMPILER_DEFICITS_SAFE.zip'
    import zipfile
    with zipfile.ZipFile(result) as z:
        assert len(z.namelist())==4
        report=json.loads(z.read('RESULTS_FOR_CODEX.json'))
        assert report['primary_pairs']==11 and report['unmatched_malware_with_known_family']==128
        assert report['PE_bytes_read'] is False and report['training'] is False
        assert b'fixture.log' not in z.read('COMPILER_COVERAGE.csv')
    assert log.read_bytes()==original_log
    with pytest.raises(FileExistsError):e.main() # existing USB result preserved
