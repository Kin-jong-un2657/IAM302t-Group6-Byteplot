"""Safe metadata-only tests; no PE execution, restored sample or training."""
import copy,csv,json
from pathlib import Path
import pytest
import CHECK_COMPILER_CONTROLS_VM as c
import PLAN_NEW256_MATCHED_VM as planner
import FREEZE_MATCHED_COHORT_VM as freeze
from test_matched_freeze import row


def doc(name='Microsoft Visual C/C++',version='6.0',kind='Compiler'):
    return json.dumps(dict(detects=[dict(type=kind,name=name,version=version)]))


def test_compiler_requires_typed_explicit_numeric_version():
    assert c.compiler_key(doc())==('microsoft visual c/c++','6.0')
    assert c.compiler_key(doc(kind='Linker')) is None
    assert c.compiler_key('{invalid JSON') is None


@pytest.mark.parametrize('version',['','unknown','6.0-8.0','?','6.0 beta',None])
def test_unknown_or_range_version_never_becomes_verified_same_compiler(version):
    assert c.compiler_key(doc(version=version)) is None


def test_ambiguous_or_errored_detector_evidence_fails_closed():
    d=json.loads(doc());d['detects'].append(dict(type='Compiler',name='Different compiler',version='6.0'))
    assert c.compiler_key(json.dumps(d)) is None
    d=json.loads(doc());d['errors']=['fixture failure']
    assert c.compiler_key(json.dumps(d)) is None


def test_duplicate_identical_detection_is_not_ambiguity():
    d=json.loads(doc());d['detects']*=2
    assert c.compiler_key(json.dumps(d))==c.compiler_key(doc())


def test_publisher_blocks_conservatively_merge_known_shared_lineage_without_invention():
    rows=[dict(row(1,'0'),source_project='Publisher A',software_lineage='same-app'),
          dict(row(2,'0'),source_project='Publisher B',software_lineage='same-app'),
          dict(row(3,'0'),source_project='Publisher B',software_lineage=''),
          dict(row(4,'0'),source_project='Publisher C',software_lineage='')]
    before=copy.deepcopy(rows);groups=c.publisher_groups(rows)
    assert groups[rows[0]['parent_sha256']]==groups[rows[1]['parent_sha256']]==groups[rows[2]['parent_sha256']]
    assert groups[rows[3]['parent_sha256']]!=groups[rows[0]['parent_sha256']]
    assert rows==before and rows[2]['software_lineage']==''


def test_null_lineage_stays_unknown_inside_conservative_publisher_block():
    a=dict(row(1,'0'),source_project='Publisher A',software_lineage=None)
    b=dict(row(2,'0'),source_project='Publisher A',software_lineage='')
    groups=c.publisher_groups([a,b])
    assert groups[a['parent_sha256']]==groups[b['parent_sha256']]
    assert a['software_lineage'] is None and b['software_lineage']==''


@pytest.mark.parametrize('publisher',['','unknown','...',None])
def test_missing_publisher_does_not_create_fake_provenance(publisher):
    r=dict(row(1,'0'),source_project=publisher,software_lineage='')
    assert c.publisher_groups([r])[r['parent_sha256']]==''


def test_publisher_family_fold_proposals_never_split_a_publisher_or_invent_lineage():
    pairs=[]
    for i in range(15):
        m=row(i+1,'1',family=f'family-{i}');b=dict(row(i+101,'0'),source_project=f'publisher-{i%3}',software_lineage='')
        pairs.append(dict(pair_id=f'P{i:03}',malware=m,benign=b,size_ratio=1))
    before=copy.deepcopy(pairs);groups=c.publisher_groups([p['benign'] for p in pairs])
    folds,info=c.blocked_folds(pairs,groups,freeze)
    assert len(folds)==3 and info['original_missing_benign_software_lineage']==15
    assert info['missing_benign_publisher_group']==0 and 'missing_benign_lineage' not in info
    byid={p['pair_id']:p for p in pairs}
    for f in folds:
        pubsets=[{byid[i]['benign']['source_project'] for i in f[key]} for key in ['train_pair_ids','validation_pair_ids','test_pair_ids']]
        assert not(pubsets[0]&pubsets[1] or pubsets[0]&pubsets[2] or pubsets[1]&pubsets[2])
    assert pairs==before and info['V0_hash_and_original_prefix_checks_pending'] is True


def test_constraint_attrition_does_not_change_default_matching_or_source_flags():
    rows=[row(1,'1',size=70000),row(101,'0',size=60000)];rows[1]['signed']=1
    before=copy.deepcopy(rows)
    assert len(planner.match(rows,lambda r:r['profile'],True,match_truncation=False,match_signature=False))==1
    assert not planner.match(rows,lambda r:r['profile'],True)
    assert rows==before


def test_cached_audit_compiler_requires_matching_observed_content_hash(tmp_path):
    runs=tmp_path/'runs';runs.mkdir();r=row(1,'0');r2=row(2,'0')
    path=runs/'safe_fixture_audit.csv'
    with path.open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=['parent_sha256','disarmed_sha256','die_stdout','die_status','die_tool_status'])
        w.writeheader();w.writerow(dict(parent_sha256=r['parent_sha256'],disarmed_sha256=r['sha256'],die_stdout=doc(),die_status='clean',die_tool_status='ok'))
        w.writerow(dict(parent_sha256=r2['parent_sha256'],disarmed_sha256='f'*64,die_stdout=doc(),die_status='clean',die_tool_status='ok'))
    protected={};keys,info=c.cached_compilers(tmp_path,[r,r2],[],protected)
    assert keys=={r['parent_sha256']:('microsoft visual c/c++','6.0')}
    assert info['compiler_name_version_available_by_label']=={'0':1,'1':0}
    assert path in protected
