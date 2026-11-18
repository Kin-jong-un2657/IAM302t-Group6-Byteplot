"""Safe artificial metadata; maximum matching and family-fold leakage regressions."""
from pathlib import Path
import copy
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parent))
import FREEZE_MATCHED_COHORT_VM as m


def row(i,label,size=20000,family='family-a',lineage=None):
    h=f'{i:064x}'
    return dict(parent_sha256=h,sha256=h,observed_prefix_sha256=f'{i+1000:064x}',variant='V0',label=label,
        size_bytes=size,signed=0,split='pool_unassigned',family=family if label=='1' else '',
        software_lineage=lineage or f'publisher:program-{i}',source_project='source-'+label,profile=(6,0))


def test_augmenting_path_recovers_pair_greedy_choice_would_lose():
    rows=[row(1,'1',20000),row(2,'1',40000),row(3,'0',20000),row(4,'0',10000)]
    original=copy.deepcopy(rows)
    pairs=m.match(rows,lambda r:r['profile'],ratio=2)
    assert len(pairs)==2 and all(p['size_ratio']<=2 for p in pairs)
    assert len({p['malware']['parent_sha256'] for p in pairs})==2
    assert rows==original


def test_profile_padding_and_signature_constraints_are_enforced():
    rows=[row(1,'1',70000),row(2,'0',60000)]
    assert len(m.match(rows,lambda r:r['profile'],ratio=2))==1
    assert not m.match(rows,lambda r:r['profile'],ratio=2,same_truncation=True)
    rows[1]['size_bytes']=70000;rows[1]['signed']=1
    assert not m.match(rows,lambda r:r['profile'],same_signed=True)
    rows[1]['profile']=(9,0)
    assert not m.match(rows,lambda r:r['profile'])


def test_unavailable_rich_profile_is_not_a_match():
    assert not m.match([row(1,'1'),row(2,'0')],lambda r:None)


def test_duplicate_identity_or_nonoriginal_hash_blocks():
    a=row(1,'1')
    with pytest.raises(ValueError):m.match([a,a],lambda r:r['profile'])
    a['variant']='V1'
    with pytest.raises(ValueError):m.match([a],lambda r:r['profile'])


def pairs(n=15,families=3):
    out=[]
    for i in range(n):
        out.append(dict(pair_id=f'P{i:03}',malware=row(i+1,'1',family=f'family-{i%families}'),benign=row(i+101,'0'),size_ratio=1))
    return out


def test_families_and_matched_pairs_never_cross_train_val_test():
    values=pairs();before=copy.deepcopy(values)
    folds,info=m.family_folds(values)
    assert info['status']=='EXPLORATORY_CV_FEASIBLE_PENDING_TRAINING_APPROVAL' and len(folds)==3
    by_id={p['pair_id']:p for p in values}
    all_test=[]
    for fold in folds:
        selected=[set(fold[k]) for k in ['train_pair_ids','validation_pair_ids','test_pair_ids']]
        assert all(selected) and set.union(*selected)==set(by_id)
        assert not(selected[0]&selected[1] or selected[0]&selected[2] or selected[1]&selected[2])
        groups=[{by_id[i]['malware']['family'] for i in ids} for ids in selected]
        assert not(groups[0]&groups[1] or groups[0]&groups[2] or groups[1]&groups[2])
        all_test+=fold['test_pair_ids']
    assert sorted(all_test)==sorted(by_id) and values==before


@pytest.mark.parametrize('kind',['one_family','unknown_family','unknown_lineage','same_lineage_everywhere','too_few_pairs'])
def test_insufficient_independence_or_counts_do_not_produce_fake_ready_folds(kind):
    values=pairs()
    if kind=='one_family':
        for p in values:p['malware']['family']='one'
    if kind=='unknown_family':values[0]['malware']['family']=''
    if kind=='unknown_lineage':values[0]['benign']['software_lineage']=''
    if kind=='same_lineage_everywhere':
        for p in values:p['benign']['software_lineage']='same-program'
    if kind=='too_few_pairs':values=values[:6]
    folds,info=m.family_folds(values)
    assert not folds and info['status']!='EXPLORATORY_CV_FEASIBLE_PENDING_TRAINING_APPROVAL'


def test_skewed_family_groups_cannot_leave_one_training_pair_and_pass_gate():
    values=pairs(14,1)
    values[-2]['malware']['family']='two';values[-1]['malware']['family']='three'
    folds,info=m.family_folds(values)
    assert not folds and info['status']=='NOT_ENOUGH_TRAIN_PAIRS_AFTER_FAMILY_BLOCKING'


def test_reused_parent_across_pairs_is_not_independent_data():
    values=pairs();values[-1]['malware']=dict(values[0]['malware'])
    with pytest.raises(ValueError):m.family_folds(values)
