"""Static metadata and harmless ASCII ZIP fixtures; no PE execution/real samples."""
from pathlib import Path
import copy
import json
import sqlite3
import zipfile
import pytest
import AUDIT_COHORT100_VM as v
import COPY_COMPATIBLE_BATCH as c
from test_copy_compatible_batch import fixture


@pytest.mark.parametrize('missing',[False,True])
def test_packet_validation_retains_full_selected_set_including_missing(tmp_path,missing):
    rows,raw,archive,a,out=fixture(tmp_path,missing=missing)
    receipt=c.copy_selected(archive,raw,a,out,min_free_bytes=0)
    selected,checks=v.validate_packet(Path(receipt['packet']),raw,a,receipt,c)
    assert selected==v.read_csv(raw) and len(checks)==2
    assert sum(r['status']=='FAILED' for r in checks.values())==int(missing)


def test_packet_rejects_extra_member_and_checksum_changes(tmp_path):
    _,raw,archive,a,out=fixture(tmp_path)
    receipt=c.copy_selected(archive,raw,a,out,min_free_bytes=0);packet=Path(receipt['packet'])
    with zipfile.ZipFile(packet,'a') as z:z.writestr('../unexpected',b'harmless extra')
    with pytest.raises(ValueError,match='checksum'):v.validate_packet(packet,raw,a,receipt,c)
    receipt['packet_sha256']=v.file_sha(packet)
    with pytest.raises(ValueError,match='allowlist'):v.validate_packet(packet,raw,a,receipt,c)


def test_packet_checks_parent_set_even_with_recomputed_outer_checksum(tmp_path):
    _,raw,archive,a,out=fixture(tmp_path)
    receipt=c.copy_selected(archive,raw,a,out,min_free_bytes=0);packet=Path(receipt['packet'])
    altered=tmp_path/'altered-fixture.zip'
    with zipfile.ZipFile(packet) as src,zipfile.ZipFile(altered,'x') as dst:
        for name in src.namelist():
            data=src.read(name)
            if name=='TRANSFER_CHECKS_PRIVATE.csv':data=data.replace(b'0000000000000000000000000000000000000000000000000000000000000001',b'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
            dst.writestr(name,data)
    receipt['packet_sha256']=v.file_sha(altered)
    with pytest.raises(ValueError,match='identity'):v.validate_packet(altered,raw,a,receipt,c)


def test_sqlite_resume_skips_committed_items_and_isolates_per_sample_errors(tmp_path):
    db=sqlite3.connect(tmp_path/'safe.sqlite');calls=[]
    def work(i):
        calls.append(i)
        if i==2:raise ValueError('safe fixture failure')
        return dict(status='ok',n=i)
    def stop(i):
        if i==2:raise KeyboardInterrupt()
    try:
        with pytest.raises(KeyboardInterrupt):v.run_tasks(db,'fixture',[1,2,3],str,work,after_commit=stop)
        assert db.execute('SELECT COUNT(*) FROM outcomes').fetchone()[0]==2
        result=v.run_tasks(db,'fixture',[1,2,3],str,work)
        assert calls==[1,2,3] and len(result)==3 and result[1]==dict(status='ERROR',error_type='ValueError')
        assert v.run_tasks(db,'fixture',[1,2,3],str,work)==result and calls==[1,2,3]
    finally:db.close()


def test_sqlite_scope_does_not_accept_new_unexpected_identity(tmp_path):
    db=sqlite3.connect(tmp_path/'safe.sqlite')
    try:
        v.run_tasks(db,'fixture',[1],str,lambda i:{'status':'ok'})
        with pytest.raises(ValueError):v.run_tasks(db,'fixture',[2],str,lambda i:{'status':'ok'})
        with pytest.raises(ValueError):v.run_tasks(db,'other',[2,2],str,lambda i:{'status':'ok'})
    finally:db.close()


def test_resource_pause_keeps_pending_items_uncommitted(tmp_path):
    db=sqlite3.connect(tmp_path/'safe.sqlite')
    def worker(i):
        if i==2:raise v.AuditPaused('safe low-disk fixture')
        return {'status':'ok'}
    try:
        with pytest.raises(v.AuditPaused):v.run_tasks(db,'fixture',[1,2,3],str,worker)
        assert db.execute('SELECT id FROM outcomes').fetchall()==[('1',)]
    finally:db.close()


def evidence():
    source=dict(parent_sha256='1'*64,family='safe-fixture',file_size='100000')
    header=dict(parent_sha256='1'*64,disarmed_sha256='2'*64,family='safe-fixture',size_bytes=100000,
        pe_status='parsed',is_dll=False,observed_disarmed_prefix_sha256='3'*64,
        original_machine_from_provider=332,original_subsystem_from_provider=2)
    audit=dict(pe_status='parsed',die_status='clean',structure_warnings='[]',disarmed_hash_check='match',
        disarmed_sha256='2'*64,actual_size='100000',certificate_present='0')
    return source,audit,header


def test_disarmed_observation_never_becomes_V0_or_original_content_hash():
    source,audit,header=evidence();before=copy.deepcopy((source,audit,header))
    r=v.observation(source,audit,header)
    assert r['parent_sha256']=='1'*64 and r['sha256']==r['disarmed_sha256']=='2'*64
    assert r['variant']=='DISARMED_HEADER_OBSERVATION' and r['training_admitted']==0 and r['V0_hash_verification']=='NOT_PERFORMED'
    assert (source,audit,header)==before


@pytest.mark.parametrize('mode',['missing','packed','warnings','dll','parse'])
def test_ineligible_static_evidence_is_not_admitted(mode):
    source,audit,header=evidence()
    if mode=='missing':header=None
    elif mode=='packed':audit['die_status']='packed'
    elif mode=='warnings':audit['structure_warnings']='["fixture structural warning"]'
    elif mode=='dll':header['is_dll']=True
    elif mode=='parse':audit['pe_status']='parse_error'
    assert v.observation(source,audit,header) is None


@pytest.mark.parametrize('field,value',[('disarmed_hash_check','mismatch'),('disarmed_sha256','4'*64),('actual_size','99999')])
def test_wrong_content_contract_cannot_be_relabelled(field,value):
    source,audit,header=evidence();audit[field]=value
    with pytest.raises(ValueError):v.observation(source,audit,header)


def test_global_prefix_dedup_holds_both_labels_and_preserves_original_rows():
    rows=[dict(parent_sha256='1'*64,observed_prefix_sha256='3'*64,label='0'),
          dict(parent_sha256='2'*64,observed_prefix_sha256='3'*64,label='1'),
          dict(parent_sha256='4'*64,observed_prefix_sha256='5'*64,label='1')]
    before=copy.deepcopy(rows);eligible,report=v.unique_proposal(rows)
    assert eligible==rows[2:] and report['repeated_or_cross_label_prefix_rows']==2 and rows==before


def test_ragged_per_sample_error_rows_keep_one_line_each(tmp_path):
    path=tmp_path/'safe.csv';v.table(path,[{'parent':'fixture1','pe_status':'parsed'},{'parent':'fixture2','error_type':'ValueError'}])
    assert len(v.read_csv(path.read_bytes()))==2
