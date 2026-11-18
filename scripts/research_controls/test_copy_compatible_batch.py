"""Artificial repeated ASCII bytes only, no executable or real sample identities."""
from pathlib import Path
import csv
import io
import json
import sqlite3
import zipfile
import pytest
import COPY_COMPATIBLE_BATCH as c


def fixture(tmp_path, missing=False):
    rows=[dict(parent_sha256=f'{i:064x}',disarmed_sha256='',family=f'fixture{i}',file_size=15000,
        original_machine=332,original_subsystem=2,V0_hash_verification='NOT_PERFORMED',training_admitted=0) for i in (1,2)]
    raw=c.csv_bytes(rows,list(rows[0])); archive=tmp_path/'harmless.zip'
    with zipfile.ZipFile(archive,'w') as z:
        for i,r in enumerate(rows):
            if missing and i==1:continue
            z.writestr('altered/'+r['parent_sha256']+'.exe',bytes([65+i])*15000)
    approval=dict(approved=True,scope=c.SCOPE,plan_sha256=c.sha(raw),selected_records=2,payload_bytes=30000)
    out=tmp_path/'private';out.mkdir()
    return rows,raw,archive,approval,out


def test_unchanged_copy_retains_original_and_disarmed_hash_separately(tmp_path):
    rows,raw,archive,a,out=fixture(tmp_path); original=c.file_sha(archive)
    result=c.copy_selected(archive,raw,a,out,min_free_bytes=0)
    assert result['copied_records']==2 and result['failed_records']==0 and c.file_sha(archive)==original
    with zipfile.ZipFile(result['packet']) as z:
        assert z.read('SOURCE_PLAN_PRIVATE.csv')==raw
        checks=list(csv.DictReader(io.StringIO(z.read('TRANSFER_CHECKS_PRIVATE.csv').decode())))
        assert [r['parent_sha256'] for r in checks]==[r['parent_sha256'] for r in rows]
        for r in checks:assert r['disarmed_sha256']==c.sha(z.read(r['member'])) and r['disarmed_sha256']!=r['parent_sha256']


def test_missing_sample_stays_one_error_no_replacement(tmp_path):
    rows,raw,archive,a,out=fixture(tmp_path,missing=True)
    result=c.copy_selected(archive,raw,a,out,min_free_bytes=0)
    assert result['copied_records']==1 and result['failed_records']==1
    with zipfile.ZipFile(result['packet']) as z:
        audit=list(csv.DictReader(io.StringIO(z.read('AUDIT_INPUT_PRIVATE.csv').decode())))
        assert len(audit)==2 and audit[1]['expected_disarmed_sha256']==''
        assert len(z.namelist())==4


def test_resume_does_not_extract_committed_rows_again(tmp_path,monkeypatch):
    rows,raw,archive,a,out=fixture(tmp_path)
    def stop(n):
        if n==1:raise KeyboardInterrupt()
    with pytest.raises(KeyboardInterrupt):c.copy_selected(archive,raw,a,out,min_free_bytes=0,after_commit=stop)
    checkpoint=next(out.iterdir());original=zipfile.ZipFile.read;seen=[]
    def read(self,name,*args,**kw):
        seen.append(name.filename if isinstance(name,zipfile.ZipInfo) else name)
        return original(self,name,*args,**kw)
    monkeypatch.setattr(zipfile.ZipFile,'read',read)
    result=c.copy_selected(archive,raw,a,out,resume=checkpoint,min_free_bytes=0)
    assert result['copied_records']==2 and seen==['altered/'+rows[1]['parent_sha256']+'.exe']


def test_changed_committed_content_stops_without_overwrite(tmp_path):
    rows,raw,archive,a,out=fixture(tmp_path)
    result=c.copy_selected(archive,raw,a,out,min_free_bytes=0)
    checkpoint=Path(result['checkpoint']).parent;sample=checkpoint/'samples'/(rows[0]['parent_sha256']+'.bin')
    sample.write_bytes(b'changed harmless fixture')
    with pytest.raises(ValueError,match='Committed copy changed'):
        c.copy_selected(archive,raw,a,out,resume=checkpoint,min_free_bytes=0)
    assert sample.read_bytes()==b'changed harmless fixture'


@pytest.mark.parametrize('mode',['scope','approval','sha','count','bytes','duplicate','admitted','parent'])
def test_scope_and_identity_gates_fail_before_copy(tmp_path,mode):
    rows,raw,archive,a,out=fixture(tmp_path)
    if mode=='scope':a['scope']='old256'
    elif mode=='approval':a['approved']=False
    elif mode=='sha':a['plan_sha256']='0'*64
    elif mode=='count':a['selected_records']=3
    elif mode=='bytes':a['payload_bytes']=1
    else:
        if mode=='duplicate':rows[1]['parent_sha256']=rows[0]['parent_sha256']
        elif mode=='admitted':rows[0]['training_admitted']=1
        elif mode=='parent':rows[0]['parent_sha256']='../escape'
        raw=c.csv_bytes(rows,list(rows[0]));a['plan_sha256']=c.sha(raw)
    with pytest.raises(ValueError):c.copy_selected(archive,raw,a,out,min_free_bytes=0)
    assert list(out.iterdir())==[]


def test_low_disk_fails_before_output_creation(tmp_path,monkeypatch):
    _,raw,archive,a,out=fixture(tmp_path)
    from types import SimpleNamespace
    monkeypatch.setattr(c.shutil,'disk_usage',lambda p:SimpleNamespace(free=1))
    with pytest.raises(OSError):c.copy_selected(archive,raw,a,out,min_free_bytes=1000)
    assert list(out.iterdir())==[]


def test_corrupt_local_header_is_independent_failure_not_repaired(tmp_path):
    rows,raw,archive,a,out=fixture(tmp_path)
    data=bytearray(archive.read_bytes());data[:4]=b'BAD!';archive.write_bytes(data)
    result=c.copy_selected(archive,raw,a,out,min_free_bytes=0)
    assert result['failed_records']==1 and result['copied_records']==1


def test_new_export_never_overwrites_old_ready_packet(tmp_path):
    _,raw,archive,a,out=fixture(tmp_path)
    first=c.copy_selected(archive,raw,a,out,min_free_bytes=0);old=c.file_sha(first['packet'])
    second=c.copy_selected(archive,raw,a,out,resume=Path(first['checkpoint']).parent,min_free_bytes=0)
    assert first['packet']!=second['packet'] and c.file_sha(first['packet'])==old


def test_resume_rejects_different_plan_without_new_copy(tmp_path):
    rows,raw,archive,a,out=fixture(tmp_path)
    result=c.copy_selected(archive,raw,a,out,min_free_bytes=0)
    rows[0]['family']='changed-selection';changed=c.csv_bytes(rows,list(rows[0]));a['plan_sha256']=c.sha(changed)
    with pytest.raises(ValueError,match='Resume binding differs'):
        c.copy_selected(archive,changed,a,out,resume=Path(result['checkpoint']).parent,min_free_bytes=0)


def test_failed_rows_are_terminal_and_not_retried_on_resume(tmp_path,monkeypatch):
    _,raw,archive,a,out=fixture(tmp_path,missing=True)
    result=c.copy_selected(archive,raw,a,out,min_free_bytes=0)
    def no_read(*args,**kw):raise AssertionError('Already committed rows must not be extracted again')
    monkeypatch.setattr(zipfile.ZipFile,'read',no_read)
    again=c.copy_selected(archive,raw,a,out,resume=Path(result['checkpoint']).parent,min_free_bytes=0)
    assert again['failed_records']==1 and again['copied_records']==1


def test_uncommitted_file_after_crash_is_checked_against_source_crc(tmp_path,monkeypatch):
    rows,raw,archive,a,out=fixture(tmp_path)
    def stop(n):raise KeyboardInterrupt()
    with pytest.raises(KeyboardInterrupt):c.copy_selected(archive,raw,a,out,min_free_bytes=0,after_commit=stop)
    checkpoint=next(out.iterdir())
    connection=sqlite3.connect(checkpoint/'copy_checkpoint.sqlite');connection.execute('DELETE FROM results');connection.commit();connection.close()
    original=zipfile.ZipFile.read;seen=[]
    def read(self,info,*args,**kw):
        seen.append(info.filename);return original(self,info,*args,**kw)
    monkeypatch.setattr(zipfile.ZipFile,'read',read)
    result=c.copy_selected(archive,raw,a,out,resume=checkpoint,min_free_bytes=0)
    assert result['copied_records']==2 and seen==['altered/'+rows[1]['parent_sha256']+'.exe']


def test_drive_journal_resume_works_without_fsync_or_sqlite_on_drive(tmp_path,monkeypatch):
    rows,raw,archive,a,out=fixture(tmp_path)
    def no_fsync(*args):raise AssertionError('FUSE fsync must not be required')
    monkeypatch.setattr(c.os,'fsync',no_fsync)
    def stop(n):
        if n==1:raise KeyboardInterrupt()
    with pytest.raises(KeyboardInterrupt):
        c.copy_selected(archive,raw,a,out,min_free_bytes=0,portable_journal=True,after_commit=stop)
    checkpoint=next(out.iterdir())
    assert len(list((checkpoint/'checkpoint_rows').glob('*.json')))==1
    assert not (checkpoint/'copy_checkpoint.sqlite').exists()
    result=c.copy_selected(archive,raw,a,out,resume=checkpoint,min_free_bytes=0,portable_journal=True)
    assert result['copied_records']==2 and result['durable_row_journal'] is True
    db=sqlite3.connect(result['checkpoint'])
    try:assert db.execute('SELECT COUNT(*) FROM results').fetchone()[0]==2
    finally:db.close()
