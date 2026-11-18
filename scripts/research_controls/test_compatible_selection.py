"""Harmless numeric metadata only; no sample, network or training."""
from collections import Counter
import copy
import io
import zipfile
import pytest
import SELECT_COMPATIBLE_CANDIDATES as s


def row(i, fam=None, major=8, size=100000):
    return dict(parent_sha256=f'{i:064x}', family=fam or f'family{i%20}',
        linker_major=major, linker_minor=0, file_size=size, reported_has_signature=i%2,
        disarmed_sha256='', training_admitted=0, V0_hash_verification='NOT_PERFORMED')


def test_deterministic_family_capped_selection_does_not_modify_metadata():
    rows=[row(i) for i in range(1000)]; before=copy.deepcopy(rows)
    result=s.select(rows,((8,0,256),))
    assert len(result)==256 and max(Counter(r['family'] for r in result).values())<=16
    assert result==s.select(list(reversed(rows)),((8,0,256),)) and rows==before
    assert all(r['disarmed_sha256']=='' and r['training_admitted']==0 for r in result)


def test_family_cap_applies_across_linker_quotas():
    rows=[row(i,'one-family',major=8 if i<30 else 6) for i in range(60)]
    assert len(s.select(rows,((8,0,8),(6,0,8))))==16
    with pytest.raises(ValueError,match='Insufficient'):s.select(rows,((8,0,9),(6,0,8)))


@pytest.mark.parametrize('name', sorted(s.GENERIC))
def test_generic_family_not_counted_as_independent(name):
    with pytest.raises(ValueError,match='Insufficient'):s.select([row(1,name or 'UNKNOWN')],((8,0,1),))


@pytest.mark.parametrize('key,value', [('parent_sha256','../path'),('file_size',14999),
    ('file_size',2000001),('reported_has_signature',2),('training_admitted',1),
    ('V0_hash_verification','MATCH'),('disarmed_sha256','a'*64)])
def test_invalid_or_admitted_metadata_rejected(key,value):
    r=row(1);r[key]=value
    with pytest.raises(ValueError):s.select([r],((8,0,1),))


def test_duplicate_parent_and_quota_rejected():
    r=row(1)
    with pytest.raises(ValueError):s.select([r,r],((8,0,1),))
    for quota in [((8,0,1025),),((8,0,0),),((8,0,1),(8,0,1))]:
        with pytest.raises(ValueError):s.select([r],quota)


def test_size_strata_keep_truncation_boundary():
    assert s.size_cell(row(1,size=65536)) != s.size_cell(row(1,size=65537))


def test_metadata_member_read_is_exact_and_bounded(tmp_path):
    p=tmp_path/'fixture.zip'
    with zipfile.ZipFile(p,'w') as z:
        z.writestr('meta.csv',b'safe metadata');z.writestr('do_not_read.bin',b'harmless fixture')
    assert s.read_member(p,'meta.csv')==b'safe metadata'
    with pytest.raises(ValueError):s.read_member(p,'meta.csv',cap=1)
    with zipfile.ZipFile(p,'a') as z:
        with pytest.warns(UserWarning):z.writestr('meta.csv',b'duplicate')
    with pytest.raises(ValueError):s.read_member(p,'meta.csv')
