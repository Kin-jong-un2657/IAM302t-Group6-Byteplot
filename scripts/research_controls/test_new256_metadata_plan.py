"""Artificial metadata only; never read PE or modify the old hash contract."""
import copy
from collections import Counter
import pytest
import PLAN_NEW256_MATCHED_VM as p
import FREEZE_MATCHED_COHORT_VM as old
from test_matched_freeze import row


def pending(i,family='new-family',size=20000):
    r=row(i,'1',size=size,family=family)
    r.update(variant='DISARMED_HEADER_OBSERVATION',sha256=f'{i+2000:064x}',
             disarmed_sha256=f'{i+2000:064x}',V0_hash_verification='NOT_PERFORMED',training_admitted=0)
    return r


def test_pending_digest_is_not_replaced_by_parent_to_make_matching_work():
    r=pending(1);b=row(101,'0');before=copy.deepcopy([r,b])
    pairs=p.match([r,b],lambda x:x['profile'],True)
    assert len(pairs)==1
    assert pairs[0]['malware']['sha256']!=pairs[0]['malware']['parent_sha256']
    assert pairs[0]['malware']['variant']=='DISARMED_HEADER_OBSERVATION'
    assert [r,b]==before
    with pytest.raises(ValueError):old.match([r,b],lambda x:x['profile'])


@pytest.mark.parametrize('mode',['mislabelV0','fakeContent','training','fakeVerified'])
def test_hash_state_or_admission_cannot_be_faked(mode):
    r=pending(1)
    if mode=='mislabelV0':r['variant']='V0'
    elif mode=='fakeContent':r['sha256']=r['parent_sha256']
    elif mode=='training':r['training_admitted']=1
    else:r['V0_hash_verification']='MATCH'
    with pytest.raises(ValueError):p.match([r,row(101,'0')],lambda x:x['profile'],True)


def test_augmenting_matching_size_truncation_signature_and_missing_rich():
    rows=[pending(1,size=20000),pending(2,size=40000),row(101,'0',20000),row(102,'0',15000)]
    assert len(p.match(rows,lambda x:x['profile'],True))==2
    values=[pending(1,size=70000),row(101,'0',60000)]
    assert len(p.match(values,lambda x:x['profile'],False))==1
    assert p.match(values,lambda x:x['profile'],True)==[]
    values[1]['size_bytes']=70000;values[1]['signed']=1
    assert p.match(values,lambda x:x['profile'],True)==[]
    assert p.match(rows,lambda x:None,True)==[]


def test_family_round_robin_does_not_fill_all_pairs_with_one_old_family():
    malware=[pending(i,family='old-family') for i in range(1,9)]
    malware += [pending(i+20,family=f'new-family-{i}') for i in range(3)]
    benign=[row(i+101,'0') for i in range(3)]
    rows=malware+benign
    pairs=p.match(rows,lambda x:x['profile'],True)
    assert len(pairs)==3 and len({r['malware']['family'] for r in pairs})==3
    assert pairs==p.match(list(reversed(rows)),lambda x:x['profile'],True)


@pytest.mark.parametrize('label',['unknown','UNKNOWN','unclassified','nan',''])
def test_generic_family_labels_cannot_create_fake_independent_families(label):
    r=pending(1,family=label)
    assert p.canonical_family(label)==''
    assert p.match([r,row(101,'0')],lambda x:x['profile'],True)==[]


def metadata_fixture():
    headers=[];audits=[];plan=[]
    for i in range(256):
        parent=f'{i:064x}';digest=f'{i+1000:064x}'
        plan.append(dict(parent_sha256=parent,family=f'family-{i}',file_size='20000'))
        audits.append(dict(parent_sha256=parent,pe_status='parsed' if i<255 else 'missing_file',
            die_status='clean' if i<189 else 'packed' if i<253 else 'unknown',
            structure_warnings='[]',disarmed_sha256=digest,disarmed_hash_check='match',
            actual_size='20000',certificate_present='0'))
        if i==255:continue
        headers.append(dict(parent_sha256=parent,disarmed_sha256=digest,family=f'family-{i}',
            pe_status='parsed',is_dll=13<=i<=16,
            observed_disarmed_prefix_sha256=f'{9999 if i<13 else i+5000:064x}',
            original_machine_from_provider=332,original_subsystem_from_provider=2,
            size_bytes=20000,V0_hash_verification='NOT_PERFORMED',training_admitted=0))
    return headers,audits,plan


def test_reproduce172_gate_from256_rows_and_preserve_unverified_identity():
    h,a,plan=metadata_fixture();before=copy.deepcopy((h,a,plan))
    rows=p.new_observations(h,a,plan)
    assert len(rows)==172 and all(r['sha256']==r['disarmed_sha256'] for r in rows)
    assert all(r['variant']=='DISARMED_HEADER_OBSERVATION' and r['training_admitted']==0 for r in rows)
    assert (h,a,plan)==before


@pytest.mark.parametrize('mode',['hash','family','lostFailureRow'])
def test_cached_metadata_inconsistency_fails_closed(mode):
    h,a,plan=metadata_fixture()
    if mode=='hash':a[20]['disarmed_sha256']='f'*64
    elif mode=='family':plan[20]['family']='wrong family'
    else:a.pop()
    with pytest.raises(ValueError):p.new_observations(h,a,plan)
