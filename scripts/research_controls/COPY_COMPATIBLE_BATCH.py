"""Approval-gated unchanged ZIP-member copy; no PE tools or sample execution.

SQLite commits each selected member independently. Missing/corrupt members stay
errors without replacements. Explicit resume verifies committed copies first.
The original archive and selection CSV are always opened read-only.
"""
from collections import Counter
from pathlib import Path
import argparse
import csv
import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import zipfile
import zlib

SCOPE = 'COMPATIBLE1024_COPY_STATIC_AND_BENIGN55_INTAKE'
MAX_PAYLOAD = 2 * 1024**3


def sha(raw): return hashlib.sha256(raw).hexdigest()


def file_sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1024**2), b''): h.update(block)
    return h.hexdigest()


def csv_bytes(rows, fields):
    f = io.StringIO(newline=''); w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader(); w.writerows(rows); return f.getvalue().encode('utf-8')


def write_json(path, value):
    raw = json.dumps(value, indent=2, allow_nan=False).encode('utf-8')
    with Path(path).open('xb') as f:
        f.write(raw); f.flush()
    if Path(path).read_bytes() != raw: raise OSError('Checkpoint JSON readback differs')


def validate_plan(raw, approval):
    if approval.get('approved') is not True or approval.get('scope') != SCOPE:
        raise ValueError('Explicit new scope approval required; no sample copied')
    if sha(raw) != approval.get('plan_sha256'): raise ValueError('Frozen plan checksum differs')
    rows = list(csv.DictReader(io.StringIO(raw.decode('utf-8-sig'))))
    if not 1 <= len(rows) <= 1024 or len(rows) != approval.get('selected_records'):
        raise ValueError('Approved count differs')
    ids = set()
    for r in rows:
        parent = r['parent_sha256']
        if (not re.fullmatch('[0-9a-f]{64}', parent) or parent in ids
            or r['disarmed_sha256'] or r['training_admitted'] != '0'
            or r['V0_hash_verification'] != 'NOT_PERFORMED'
            or not 15000 <= int(r['file_size']) <= 2000000
            or (int(r['original_machine']), int(r['original_subsystem'])) != (332, 2)):
            raise ValueError('Original identity/observation contract differs')
        ids.add(parent)
    payload = sum(int(r['file_size']) for r in rows)
    if payload != approval.get('payload_bytes') or payload > MAX_PAYLOAD:
        raise ValueError('Approved payload differs')
    return rows


def copy_selected(source, plan_raw, approval, output_parent, resume=None,
                  min_free_bytes=1024**3, after_commit=None, portable_journal=False):
    rows = validate_plan(plan_raw, approval)
    source = Path(source).resolve(strict=True); root = Path(output_parent).resolve(strict=True)
    if root.is_relative_to(source): raise ValueError('Source/output overlap')
    if shutil.disk_usage(root).free < min_free_bytes + 2 * sum(int(r['file_size']) for r in rows):
        raise OSError('Insufficient free reserve for staged members and transfer packet')
    initial_stat = source.stat()
    with zipfile.ZipFile(source) as z:
        infos = z.infolist()
        if len({i.filename for i in infos}) != len(infos): raise ValueError('Duplicate source ZIP names')
        index = {i.filename: i for i in infos}
        identity = []
        for r in rows:
            name = 'altered/' + r['parent_sha256'] + '.exe'; info = index.get(name)
            identity.append([name, None if info is None else
                [info.file_size, info.compress_size, info.CRC, info.header_offset, info.flag_bits]])
        binding = dict(plan_sha256=sha(plan_raw), source_path=str(source), source_bytes=initial_stat.st_size,
                       selected_central_directory_sha256=sha(json.dumps(identity, separators=(',', ':')).encode()))
        if resume is None:
            out = Path(tempfile.mkdtemp(prefix='compatible1024-copy-', dir=root))
            samples = out / 'samples'; samples.mkdir(mode=0o700)
            write_json(out / 'BINDING_PRIVATE.json', binding)
        else:
            given = Path(resume)
            if given.is_symlink(): raise ValueError('Symlink resume directory')
            out = given.resolve(strict=True)
            if out.parent != root or not out.name.startswith('compatible1024-copy-'):
                raise ValueError('Resume outside approved output parent')
            if json.loads((out / 'BINDING_PRIVATE.json').read_text()) != binding:
                raise ValueError('Resume binding differs; preserve checkpoint')
            samples = out / 'samples'
        if samples.is_symlink() or not samples.resolve().is_relative_to(out): raise ValueError('Sample path escaped')
        print('CHECKPOINT_OUTPUT=' + str(out), flush=True)
        database = out / 'copy_checkpoint.sqlite'
        if database.is_symlink(): raise ValueError('Symlink checkpoint')
        # Drive FUSE does not promise SQLite locking/fsync semantics. Keep SQLite
        # in memory there, with an exclusive, read-back-verified JSON row journal
        # as the durable source of truth. Export an immutable SQLite snapshot.
        journal = out / 'checkpoint_rows'
        if portable_journal:
            if resume is None: journal.mkdir()
            if journal.is_symlink() or not journal.is_dir(): raise ValueError('Invalid checkpoint journal')
        connection = sqlite3.connect(':memory:' if portable_journal else database)
        try:
            connection.execute('PRAGMA synchronous=FULL')
            connection.execute('CREATE TABLE IF NOT EXISTS results(parent TEXT PRIMARY KEY, status TEXT NOT NULL, digest TEXT NOT NULL, bytes INTEGER NOT NULL, error TEXT NOT NULL)')
            if portable_journal:
                allowed = {r['parent_sha256'] for r in rows}
                for path in journal.iterdir():
                    if path.is_symlink() or path.suffix != '.json' or path.stem not in allowed or path.stat().st_size > 4096:
                        raise ValueError('Unexpected checkpoint journal member')
                    record = json.loads(path.read_text(encoding='utf-8'))
                    if not isinstance(record, list) or len(record) != 5 or record[0] != path.stem:
                        raise ValueError('Invalid durable checkpoint record')
                    connection.execute('INSERT INTO results VALUES (?,?,?,?,?)', record)
            connection.commit()
            done = {r[0]: r for r in connection.execute('SELECT parent,status,digest,bytes,error FROM results')}
            if not set(done).issubset({r['parent_sha256'] for r in rows}): raise ValueError('Unexpected checkpoint identities')
            for r in rows:
                parent = r['parent_sha256']; target = samples / (parent + '.bin')
                if target.is_symlink(): raise ValueError('Symlink copy')
                if parent in done:
                    _, status, digest, size, error = done[parent]
                    if status not in ('COPIED', 'FAILED'): raise ValueError('Invalid checkpoint state')
                    if status == 'COPIED' and (target.stat().st_size != size or file_sha(target) != digest):
                        raise ValueError('Committed copy changed; no overwrite or extraction retry')
                    if status == 'FAILED' and target.exists(): raise ValueError('Unexpected file for committed failure')
                    continue
                name = 'altered/' + parent + '.exe'; info = index.get(name)
                status = 'FAILED'; digest = ''; size = 0; error = ''
                try:
                    if info is None: raise KeyError('Selected source member missing')
                    if info.is_dir() or info.flag_bits & 1 or info.file_size != int(r['file_size']):
                        raise ValueError('Selected member size/encryption differs')
                    if target.exists():
                        # A crash may occur after exclusive copy but before SQLite commit.
                        # Check against the source central CRC; never overwrite this file.
                        if target.stat().st_size != info.file_size:
                            raise RuntimeError('Uncommitted file size differs; manual review required')
                        data = target.read_bytes()
                        if len(data) != info.file_size or zlib.crc32(data) != info.CRC:
                            raise RuntimeError('Uncommitted file differs; manual review required')
                    else:
                        data = z.read(info)  # Read one selected member; zipfile checks CRC.
                        if len(data) != info.file_size: raise ValueError('Incomplete member')
                        with target.open('xb') as f:
                            f.write(data); f.flush()
                            if not portable_journal: os.fsync(f.fileno())
                        if not portable_journal: target.chmod(0o600)
                        if file_sha(target) != sha(data): raise OSError('Copied member readback differs')
                    status = 'COPIED'; digest = sha(data); size = len(data)
                except RuntimeError:
                    raise
                except (KeyError, ValueError, OSError, zipfile.BadZipFile, NotImplementedError) as exc:
                    if target.exists():
                        # Keep any interrupted file for review rather than mark it safely copied.
                        raise RuntimeError('Copy file exists after an error; preserved for review') from exc
                    error = type(exc).__name__
                connection.execute('INSERT INTO results VALUES (?,?,?,?,?)', (parent, status, digest, size, error))
                connection.commit()
                done[parent] = (parent, status, digest, size, error)
                if portable_journal: write_json(journal / (parent + '.json'), list(done[parent]))
                if after_commit is not None: after_commit(len(done))
                if len(done) % 32 == 0 or len(done) == len(rows): print(f'COMMITTED {len(done)}/{len(rows)}', flush=True)
            stat_after = source.stat()
            if (stat_after.st_size, stat_after.st_mtime_ns) != (initial_stat.st_size, initial_stat.st_mtime_ns):
                raise ValueError('Read-only source archive changed during copy')
            export = Path(tempfile.mkdtemp(prefix='export-', dir=out))
            if portable_journal:
                with tempfile.TemporaryDirectory(prefix='compatible-copy-snapshot-') as local:
                    snapshot = Path(local) / 'checkpoint.sqlite'
                    snapshot_db = sqlite3.connect(snapshot)
                    try: connection.backup(snapshot_db)
                    finally: snapshot_db.close()
                    database = export / 'copy_checkpoint.sqlite'
                    with snapshot.open('rb') as src, database.open('xb') as dst: shutil.copyfileobj(src, dst)
                    if file_sha(snapshot) != file_sha(database): raise OSError('SQLite snapshot readback differs')
            packet = export / 'compatible1024_disarmed_for_vm.zip'
            checks = []; inputs = []
            with zipfile.ZipFile(packet, 'x', zipfile.ZIP_STORED) as dest:
                for r in rows:
                    parent, status, digest, size, error = done[r['parent_sha256']]
                    member = 'samples/' + parent + '.bin'
                    if status == 'COPIED':
                        target = samples / (parent + '.bin')
                        if file_sha(target) != digest: raise ValueError('Copy changed before packet export')
                        dest.write(target, member)
                    checks.append(dict(parent_sha256=parent, status=status, disarmed_sha256=digest,
                                       bytes=size, member=member if status == 'COPIED' else '', error_type=error))
                    inputs.append(dict(parent_sha256=parent, family=r['family'], zip_member=parent+'.bin',
                                       expected_disarmed_sha256=digest, file_size=r['file_size']))
                dest.writestr('SOURCE_PLAN_PRIVATE.csv', plan_raw)
                dest.writestr('TRANSFER_CHECKS_PRIVATE.csv', csv_bytes(checks, list(checks[0])))
                dest.writestr('AUDIT_INPUT_PRIVATE.csv', csv_bytes(inputs, list(inputs[0])))
            counts = Counter(r['status'] for r in checks)
            summary = dict(status='TRANSFER_READY' if counts['FAILED'] == 0 else 'PARTIAL_TRANSFER_READY_ERRORS_RETAINED',
                selected_records=len(rows), copied_records=counts['COPIED'], failed_records=counts['FAILED'],
                payload_bytes=sum(r['bytes'] for r in checks), packet=str(packet), packet_sha256=file_sha(packet),
                checkpoint=str(database), sample_replacements=0, original_selection_preserved=True,
                resume_directory=str(out), durable_row_journal=portable_journal,
                plan_sha256=sha(plan_raw), approval_scope=SCOPE,
                source_archive_modified=False, PE_analysis=False, restoration=False, PE_execution=False,
                packing_unpacking=False, training=False, training_admitted=0,
                checksum_limit='Per-member ZIP CRC and newly recorded disarmed SHA; original parent SHA is NOT a content hash check of disarmed bytes.')
            write_json(export / 'transfer_status.json', summary)
            print(json.dumps(summary, indent=2)); return summary
        finally:
            connection.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('plan', 'approval', 'archive', 'output-parent'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--resume', type=Path)
    args = p.parse_args()
    if sys.platform != 'linux' or not Path('/content/drive/MyDrive').is_dir():
        raise SystemExit('Mounted private Colab only; no Windows sample extraction')
    approval = json.loads(args.approval.read_text(encoding='utf-8'))
    if (args.archive.resolve() != Path('/content/drive/MyDrive/BODMAS_disarmed_malware_binaries.zip')
        or args.archive.stat().st_size != 72932177367
        or args.output_parent.resolve() != Path('/content/drive/MyDrive/IAM302t_COHORT100_PRIVATE_20261109')):
        raise SystemExit('Existing source/private output location differs')
    args.output_parent.mkdir(exist_ok=True)
    try: copy_selected(args.archive, args.plan.read_bytes(), approval, args.output_parent, resume=args.resume, portable_journal=True)
    except KeyboardInterrupt: raise SystemExit('Interrupted; committed rows preserved. Resume only the printed checkpoint directory.')


if __name__ == '__main__': main()
