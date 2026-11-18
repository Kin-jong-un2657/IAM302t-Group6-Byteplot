"""Frozen publisher-list fixtures only; no downloads."""
import hashlib
import json
import pytest
import ACQUIRE_COMPATIBLE_BENIGN as a


def planned():
    r=dict(program='Harmless fixture',slug='harmlessfixture',publisher='NirSoft',lineage='NirSoft:harmlessfixture',
        PE_or_ZIP_fetched=False,hosts=['www.nirsoft.net','nirsoft.net'],page='https://www.nirsoft.net/utils/fixture.html',
        reviewed_download='https://www.nirsoft.net/utils/fixture.zip')
    return [r]


def encode(rows):
    raw=json.dumps(rows).encode()
    return raw,dict(approved=True,scope=a.SCOPE,benign_allowlist_sha256=hashlib.sha256(raw).hexdigest(),benign_candidates=len(rows))


def test_exact_publisher_lineage_retained():
    rows=planned();raw,approval=encode(rows)
    assert a.validate_allowlist(raw,approval)==rows


@pytest.mark.parametrize('key,value',[('slug','../escape'),('publisher','unreviewed'),
    ('lineage','invented:independent'),('PE_or_ZIP_fetched',True),('hosts',['evil.example']),
    ('reviewed_download','http://www.nirsoft.net/utils/fixture.zip'),
    ('reviewed_download','https://www.nirsoft.net/utils/fixture.exe'),
    ('reviewed_download','https://www.nirsoft.net/utils/fixture.zip?changed=1')])
def test_unreviewed_payload_cannot_replace_reviewed_spec(key,value):
    rows=planned();rows[0][key]=value;raw,approval=encode(rows)
    with pytest.raises(ValueError):a.validate_allowlist(raw,approval)


def test_no_new_scope_approval_or_different_hash_stops_before_network():
    raw,approval=encode(planned());approval['approved']=False
    with pytest.raises(ValueError):a.validate_allowlist(raw,approval)
    approval['approved']=True;approval['benign_allowlist_sha256']='0'*64
    with pytest.raises(ValueError):a.validate_allowlist(raw,approval)


def test_duplicate_program_not_independent_benign_parent():
    rows=planned()*2;raw,approval=encode(rows)
    with pytest.raises(ValueError):a.validate_allowlist(raw,approval)
