"""Bounded static cohort audit; original PE identity never becomes content SHA.

Run only in the isolated VMware guest. Reuses audit_pe and reviewed benign,
compiler and matching helpers. SQLite commits each selected malware/archive;
the old study/checkpoints are read-only and no training is admitted here.
"""
from collections import Counter
from pathlib import Path
import argparse
import contextlib
import csv
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import zipfile


class AuditPaused(RuntimeError):
    """A resource limit pauses the batch; unprocessed samples remain pending."""


def sha(raw): return hashlib.sha256(raw).hexdigest()


def file_sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda:f.read(1024**2),b''):h.update(block)
    return h.hexdigest()


def save(path,value):
    with Path(path).open('x',encoding='utf-8') as f:json.dump(value,f,indent=2,allow_nan=False)


def table(path,rows):
    if not rows:raise ValueError('Empty output table')
    with Path(path).open('x',encoding='utf-8',newline='') as f:
        fields=list(rows[0])+sorted(set().union(*(r.keys() for r in rows))-set(rows[0]))
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)


def load(base,name):
    spec=importlib.util.spec_from_file_location('cohort100_'+Path(name).stem,base/name)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


def read_csv(raw):return list(csv.DictReader(io.StringIO(raw.decode('utf-8-sig'))))


def validate_packet(packet,plan_raw,approval,transfer,copy):
    rows=copy.validate_plan(plan_raw,approval)
    if (transfer.get('selected_records')!=len(rows) or transfer.get('copied_records',-1)+transfer.get('failed_records',-1)!=len(rows)
        or transfer.get('status') not in {'TRANSFER_READY','PARTIAL_TRANSFER_READY_ERRORS_RETAINED'}
        or file_sha(packet)!=transfer.get('packet_sha256')):
        raise ValueError('Transfer receipt/count/checksum differs')
    with zipfile.ZipFile(packet) as z:
        infos=z.infolist();index={i.filename:i for i in infos}
        if len(infos)!=len(index):raise ValueError('Duplicate packet members')
        names={'SOURCE_PLAN_PRIVATE.csv','TRANSFER_CHECKS_PRIVATE.csv','AUDIT_INPUT_PRIVATE.csv'}
        for name in names:
            if name not in index or index[name].file_size>2*1024**2:raise ValueError('Missing/oversized packet metadata')
        if z.read('SOURCE_PLAN_PRIVATE.csv')!=plan_raw:raise ValueError('Selected CSV changed')
        checks=read_csv(z.read('TRANSFER_CHECKS_PRIVATE.csv'));lookup={r['parent_sha256']:r for r in checks}
        if len(checks)!=len(rows) or set(lookup)!={r['parent_sha256'] for r in rows}:raise ValueError('Transfer identity set differs')
        payload=0
        for r in rows:
            c=lookup[r['parent_sha256']];expected='samples/'+r['parent_sha256']+'.bin'
            if c['status']=='COPIED':
                if (c['member']!=expected or not re.fullmatch('[0-9a-f]{64}',c['disarmed_sha256'])
                    or int(c['bytes'])!=int(r['file_size']) or expected not in index):raise ValueError('Copied member contract differs')
                info=index[expected]
                if info.is_dir() or info.flag_bits&1 or (info.external_attr>>16)&0o170000==0o120000 or info.file_size!=int(c['bytes']):
                    raise ValueError('Unsafe/oversized member')
                names.add(expected);payload+=info.file_size
            elif c['status']=='FAILED':
                if c['member'] or c['disarmed_sha256'] or int(c['bytes'])!=0:raise ValueError('Failed transfer misrepresented')
            else:raise ValueError('Unknown transfer status')
        if set(index)!=names or payload!=transfer.get('payload_bytes') or payload>approval['payload_bytes']:
            raise ValueError('Packet allowlist/payload differs')
        audit=read_csv(z.read('AUDIT_INPUT_PRIVATE.csv'))
        expected=[dict(parent_sha256=r['parent_sha256'],family=r['family'],zip_member=r['parent_sha256']+'.bin',
            expected_disarmed_sha256=lookup[r['parent_sha256']]['disarmed_sha256'],file_size=r['file_size']) for r in rows]
        if audit!=expected or Counter(c['status'] for c in checks)!=Counter({'COPIED':transfer['copied_records'],'FAILED':transfer['failed_records']}):
            raise ValueError('Audit input or transfer accounting differs')
    return rows,lookup


def run_tasks(db,kind,items,key,worker,after_commit=None):
    """Exactly one durable outcome per selected item; interruptions keep commits."""
    wanted=[str(key(r)) for r in items]
    if len(set(wanted))!=len(wanted):raise ValueError('Repeated checkpoint item')
    db.execute('CREATE TABLE IF NOT EXISTS outcomes(kind TEXT,id TEXT,result TEXT NOT NULL,PRIMARY KEY(kind,id))')
    db.commit()
    cached={i:json.loads(raw) for i,raw in db.execute('SELECT id,result FROM outcomes WHERE kind=?',(kind,))}
    if not set(cached).issubset(set(wanted)):raise ValueError('Unexpected checkpoint item')
    for i,item in enumerate(items,1):
        identity=str(key(item))
        if identity in cached:continue
        try: result=worker(item)
        except AuditPaused: raise
        except Exception as exc:result=dict(status='ERROR',error_type=type(exc).__name__)
        raw=json.dumps(result,allow_nan=False)
        db.execute('INSERT INTO outcomes VALUES (?,?,?)',(kind,identity,raw));db.commit();cached[identity]=result
        if after_commit:after_commit(i)
        if i%32==0 or i==len(items):print(f'COMMITTED_{kind.upper()} {i}/{len(items)}',flush=True)
    return [cached[str(key(r))] for r in items]


def observation(source,audit,header):
    """No reconstruction: original machine/subsystem remain provider metadata."""
    if not header or header.get('pe_status')!='parsed' or audit.get('pe_status')!='parsed' or audit.get('die_status')!='clean':return None
    if json.loads(audit.get('structure_warnings','[]')) or header['is_dll']:return None
    if (audit.get('disarmed_hash_check')!='match' or audit['disarmed_sha256']!=header['disarmed_sha256']
        or int(audit['actual_size'])!=int(source['file_size']) or header['family']!=source['family']):
        raise ValueError('Static content identity/size/family differs')
    if 'linker_major' in source and (int(source['linker_major']),int(source['linker_minor']))!=(header['linker_major'],header['linker_minor']):
        raise ValueError('Observed linker differs from frozen retrieval metadata')
    row=dict(header,label='1',sha256=header['disarmed_sha256'],variant='DISARMED_HEADER_OBSERVATION',
        split='pool_unassigned',source_project='BODMAS',signed=int(audit['certificate_present']),
        observed_prefix_sha256=header['observed_disarmed_prefix_sha256'],software_lineage='',
        V0_hash_verification='NOT_PERFORMED',training_admitted=0,prefix_byte_state='DISARMED_NOT_ORIGINAL_V0')
    return row


def unique_proposal(rows):
    parents=Counter(r['parent_sha256'] for r in rows);prefixes=Counter(r['observed_prefix_sha256'] for r in rows)
    # Preserve original records; exclusions apply only to the prospective cohort.
    eligible=[r for r in rows if parents[r['parent_sha256']]==1 and prefixes[r['observed_prefix_sha256']]==1]
    return eligible,dict(duplicate_parent_rows=sum(n for n in parents.values() if n>1),
                         repeated_or_cross_label_prefix_rows=sum(n for n in prefixes.values() if n>1))


def baseline(base,project,c,e,planner,protected):
    matches=[p for p in (project/'runs').glob('compiler-controls-*/safe/RESULTS_FOR_CODEX.json')
             if p.stat().st_size<128*1024 and file_sha(p)==e.EXPECTED_SUMMARY]
    if len(matches)!=1:raise ValueError('Exact completed benign97 evidence missing/ambiguous; no old audit rerun')
    e.read_metadata(matches[0],protected);private=matches[0].parent.parent/'private'
    provenance=e.read_metadata(private/'PROVENANCE_PRIVATE.json',protected)
    roots=e.verify_provenance(provenance,project,base,c.PLAN_SHA,protected)
    if len(roots)!=1:raise ValueError('Old added benign metadata ambiguous')
    added=e.read_metadata(next(iter(roots))/'ADDED_BENIGN_ROWS_PRIVATE.json',protected)
    old,_=c.read_study(base,project,planner,protected)
    rows=c.merge_verified_benign(old,added)
    compilers=e.read_metadata(private/'COMPILER_EVIDENCE_PRIVATE.json',protected)
    if len(added)!=34 or Counter(r['label'] for r in rows)!={'0':259,'1':262}:raise ValueError('Completed study differs')
    return rows,compilers


def benign_archives(base,approval):
    raw=(base/'private/BENIGN_ALLOWLIST.json').read_bytes()
    if sha(raw)!=approval['benign_allowlist_sha256']:raise ValueError('Reviewed benign list changed')
    specs=json.loads(raw);expected={s['lineage']:s for s in specs}
    acquisition=json.loads((base/'BENIGN_ACQUISITION.json').read_text());archives=acquisition['archives']
    if len(specs)!=55 or len(expected)!=55 or len(archives)!=55 or acquisition['acquisition_errors']:
        raise ValueError('Expected exact55 reviewed original benign archives')
    seen=set()
    for record in archives:
        spec=expected.get(record['software_lineage']);parts=Path(record['archive_path']).parts
        if (spec is None or record['software_lineage'] in seen or record['publisher']!='NirSoft'
            or record['program']!=spec['program'] or record['source_url']!=spec['reviewed_download']
            or '\\' in record['archive_path'] or ':' in record['archive_path']
            or parts[:2]!=('sources',spec['slug']) or len(parts)!=3 or '..' in parts
            or record['archive_sha256']!=record['published_archive_sha256'] or record['publisher_hash_verified'] is not True):
            raise ValueError('Unreviewed benign archive/lineage')
        path=base/record['archive_path']
        if path.is_symlink() or not path.resolve().is_relative_to(base/'sources') or path.stat().st_size!=record['archive_bytes'] or file_sha(path)!=record['archive_sha256']:
            raise ValueError('Original benign archive changed')
        seen.add(record['software_lineage'])
    return archives


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--packet',type=Path,required=True)
    p.add_argument('--transfer',type=Path,required=True);p.add_argument('--resume',type=Path)
    args=p.parse_args();base=Path(__file__).resolve().parent;project=Path.home()/'IAM302t'
    if sys.platform!='linux':raise SystemExit('Isolated Ubuntu VMware only')
    manifest=json.loads((base/'KIT_FILES.json').read_text())
    for n,h in manifest.items():
        path=base/n
        if path.is_symlink() or not path.resolve().is_relative_to(base) or file_sha(path)!=h:raise ValueError('Kit changed')
    isolation=load(base,'rich_linker_control.py');isolation.isolated()
    if input('Network DISCONNECTED; Shared Folders/Clipboard/Drag-and-Drop DISABLED. Type STATIC-1024-55: ').strip()!='STATIC-1024-55':
        raise RuntimeError('Isolation not confirmed')
    if shutil.disk_usage(project).free<2*1024**3:raise OSError('Require2GiB free reserve before this bounded audit')
    copy=load(base,'COPY_COMPATIBLE_BATCH.py');c=load(base,'CHECK_COMPILER_CONTROLS_VM.py')
    e=load(base,'EXPORT_COMPILER_DEFICITS_VM.py');planner=c.load(base,'PLAN_NEW256_MATCHED_VM.py')
    freeze=c.load(base,'FREEZE_MATCHED_COHORT_VM.py');intake=load(base,'AUDIT_NEW_BENIGN_VM.py')
    detector=load(base,'DIE_INTERPRET.py');approval=json.loads((base/'APPROVAL.json').read_text())
    plan_raw=(base/'private/CANDIDATES_PRIVATE.csv').read_bytes();transfer=json.loads(args.transfer.read_text())
    selected,checks=validate_packet(args.packet,plan_raw,approval,transfer,copy)
    archives=benign_archives(base,approval)
    protected={args.packet:file_sha(args.packet),args.transfer:file_sha(args.transfer)}
    study,compilers=baseline(base,project,c,e,planner,protected)
    tool=intake.native_die(project);protected[tool]=file_sha(tool)
    sys.path.insert(0,str(project));from byteplot.pe_audit import audit_pe
    import pefile
    import byteplot.pe_audit as audit_module
    binding=dict(packet_sha256=protected[args.packet],plan_sha256=sha(plan_raw),
        kit_manifest_sha256=file_sha(base/'KIT_FILES.json'),die_sha256=protected[tool],audit_code_sha256=file_sha(Path(audit_module.__file__)))
    os.umask(0o077)
    if args.resume:
        if args.resume.is_symlink():raise ValueError('Symlink resume')
        out=args.resume.resolve(strict=True)
        if out.parent!=(project/'runs').resolve() or not out.name.startswith('cohort100-static-'):raise ValueError('Resume outside new audit scope')
        if json.loads((out/'BINDING_PRIVATE.json').read_text())!=binding:raise ValueError('Checkpoint binding differs')
    else:
        out=Path(tempfile.mkdtemp(prefix='cohort100-static-',dir=project/'runs'))
        save(out/'BINDING_PRIVATE.json',binding);(out/'malware').mkdir();(out/'benign').mkdir()
    print('NEW_OUTPUT='+str(out),flush=True)
    db=sqlite3.connect(out/'static_checkpoint.sqlite');db.execute('PRAGMA synchronous=FULL')
    try:
        with zipfile.ZipFile(args.packet) as z:
            def audit_malware(r):
                if shutil.disk_usage(project).free<1024**3+2*int(r['file_size']):
                    raise AuditPaused('Free-space reserve reached; resume the printed output after making room')
                parent=r['parent_sha256'];check=checks[parent]
                task=Path(tempfile.mkdtemp(prefix=parent[:12]+'-',dir=out/'malware'));samples=task/'samples';samples.mkdir()
                source=dict(parent_sha256=parent,family=r['family'],zip_member=parent+'.bin',
                    expected_disarmed_sha256=check['disarmed_sha256'],file_size=r['file_size'])
                header=None
                if check['status']=='COPIED':
                    data=z.read(check['member'])
                    if len(data)!=int(r['file_size']) or sha(data)!=check['disarmed_sha256']:raise ValueError('Transferred content changed')
                    sample=samples/source['zip_member']
                    with sample.open('xb') as f:f.write(data)
                    sample.chmod(0o600)
                    header=dict(parent_sha256=parent,disarmed_sha256=sha(data),family=r['family'],size_bytes=len(data),
                        original_machine_from_provider=int(r['original_machine']),original_subsystem_from_provider=int(r['original_subsystem']),
                        observed_disarmed_prefix_sha256=sha(data[:65536]),V0_hash_verification='NOT_PERFORMED',training_admitted=0)
                    try:
                        with pefile.PE(data=data,fast_load=True) as pe:
                            status,entries=isolation.rich_fields(pe.parse_rich_header())
                            header.update(pe_status='parsed',observed_machine=int(pe.FILE_HEADER.Machine),
                                observed_subsystem=int(pe.OPTIONAL_HEADER.Subsystem),is_dll=bool(pe.FILE_HEADER.Characteristics&0x2000),
                                linker_major=int(pe.OPTIONAL_HEADER.MajorLinkerVersion),linker_minor=int(pe.OPTIONAL_HEADER.MinorLinkerVersion),
                                rich_status=status,rich_entries=entries)
                    except Exception as exc:header.update(pe_status='error',error_type=type(exc).__name__)
                table(task/'input.csv',[source])
                with contextlib.redirect_stdout(io.StringIO()):audit_pe(task/'input.csv',samples,task/'audit.csv',die=tool,timeout=45)
                audited=read_csv((task/'audit.csv').read_bytes())
                if len(audited)!=1 or audited[0]['parent_sha256']!=parent:raise ValueError('One-row audit contract differs')
                if check['status']=='COPIED' and file_sha(samples/source['zip_member'])!=check['disarmed_sha256']:
                    raise ValueError('Static tool modified copy')
                return dict(status='AUDITED',audit=audited[0],header=header)
            malware=run_tasks(db,'malware',selected,lambda r:r['parent_sha256'],audit_malware)
        def audit_benign(spec):
            if shutil.disk_usage(project).free<1024**3+64*1024**2:
                raise AuditPaused('Free-space reserve reached before benign archive; preserve checkpoint')
            archive=base/spec['archive_path'];protected[archive]=spec['archive_sha256']
            task=Path(tempfile.mkdtemp(prefix='archive-',dir=out/'benign'))
            (task/'candidates').mkdir();(task/'die').mkdir()
            prior=[]
            for raw, in db.execute("SELECT result FROM outcomes WHERE kind='benign'"):
                prior.extend(json.loads(raw).get('rows',[]))
            known=study+[r for r in prior if r.get('parent_sha256') and r.get('observed_prefix_sha256')]
            rows=intake.inspect_archive(archive,spec,task,known,isolation.rich_fields,tool,detector.interpret_die)
            for r in rows:
                r['training_admitted']=0
                log=task/'die'/(r.get('parent_sha256','')+'.log')
                if log.is_file():r['_die_log_private']=str(log)
            return dict(status='AUDITED',rows=rows)
        benign=run_tasks(db,'benign',archives,lambda r:r['software_lineage'],audit_benign)
    finally:db.close()
    audits=[];headers=[];fresh=[]
    for source,result in zip(selected,malware):
        audit=result.get('audit',dict(parent_sha256=source['parent_sha256'],pe_status='audit_error',die_status='unknown',
            die_tool_status='not_run',truncated='',error_type=result.get('error_type','UnknownError')))
        audits.append(audit)
        if result.get('header'):headers.append(result['header'])
        r=observation(source,audit,result.get('header'))
        if r:
            r['family_original']=r['family'];r['family']=planner.canonical_family(r['family']);planner.validate_observation(r)
            fresh.append(r)
            key=c.compiler_key(audit.get('die_stdout',''))
            if key is not None:compilers[r['parent_sha256']]=key
    all_benign=[r for result in benign for r in result.get('rows',[])]
    existing_lineages={r.get('software_lineage') for r in study if r['label']=='0'}
    added=[r for r in intake.choose_lineage_representatives(all_benign) if r['software_lineage'] not in existing_lineages]
    merged=c.merge_verified_benign(study,added)
    for r in added:
        path=Path(r['_die_log_private'])
        if not path.resolve().is_relative_to(out):raise ValueError('Unexpected new detector log')
        protected[path]=file_sha(path);key=c.compiler_key(path.read_text(encoding='utf-8'))
        if key is not None:compilers[r['parent_sha256']]=key
    merged.extend(fresh)
    proposed,dedup=unique_proposal(merged);publishers=c.publisher_groups(proposed)
    eligible=[r for r in proposed if r['label']=='1' or publishers[r['parent_sha256']]]
    pairs=planner.match(eligible,lambda r:e.profile(r,compilers),constrained=True)
    folds,readiness=c.blocked_folds(pairs,publishers,freeze)
    coverage,targets=e.deficit_tables(eligible,compilers,pairs)
    if any(not p.is_file() or file_sha(p)!=h for p,h in protected.items()):raise ValueError('Protected source changed')
    snapshot=Path(tempfile.mkdtemp(prefix='snapshot-',dir=out));private=snapshot/'private';safe=snapshot/'safe';private.mkdir();safe.mkdir()
    save(private/'ALL_MALWARE_OUTCOMES_PRIVATE.json',malware);save(private/'AUDIT_ROWS_PRIVATE.json',audits)
    table(private/'e0_audit_private.csv',audits)
    save(private/'HEADERS_PRIVATE.json',headers);save(private/'NEW_OBSERVATIONS_PRIVATE.json',fresh)
    save(private/'NEW_BENIGN_ROWS_PRIVATE.json',added);save(private/'ALL_BENIGN_OUTCOMES_PRIVATE.json',benign)
    save(private/'COMPILER_EVIDENCE_PRIVATE.json',compilers);save(private/'MATCHING_PRIVATE.json',dict(pairs=pairs,folds=folds))
    save(private/'PROVENANCE_PRIVATE.json',{str(p):h for p,h in protected.items()})
    summary=dict(status='STATIC_AUDIT_AND_METADATA_PROPOSAL_ONLY_NOT_TRAINING',selected_malware=len(selected),
        transfer_copied=transfer['copied_records'],transfer_failed=transfer['failed_records'],
        malware_PE_status=dict(Counter(r['pe_status'] for r in audits)),malware_DiE_status=dict(Counter(r['die_status'] for r in audits)),
        malware_audit_errors=sum(r['status']=='ERROR' for r in malware),malware_truncated=sum(str(r.get('truncated'))=='1' for r in audits),
        malware_static_eligible_before_global_dedup=len(fresh),benign_archives=len(archives),benign_archive_errors=sum(r['status']=='ERROR' for r in benign),
        benign_member_status=dict(Counter(r['status'] for r in all_benign)),benign_added_before_global_dedup=len(added),
        previous_pool_by_label={'0':259,'1':262},proposed_pool_by_label=dict(Counter(r['label'] for r in proposed)),
        compiler_known_by_label={label:sum(r['parent_sha256'] in compilers for r in proposed if r['label']==label) for label in ['0','1']},
        previous_primary_metadata_pairs=11,current_primary_metadata_pairs=len(pairs),
        pairs_with_disarmed_malware=sum(p['malware']['variant']!='V0' for p in pairs),metadata_fold_proposal=readiness,
        dedup_exclusions=dedup,verified_new_V0=0,training_admitted=0,teacher100_verified_V0_per_class_reached=False,
        PE_execution=False,restoration=False,packing_unpacking=False,training=False,original_inputs_unchanged=True,
        old_samples_reaudited=False,Drive_submission_documents_modified=False,
        limits=['Disarmed header observations are not V0; original hashes still require verification before any training.',
                'DiE clean is not proof of unpacked state; compiler detection is static detector evidence.',
                'NirSoft is one publisher; count alone does not establish source-controlled folds or scientific adequacy.'])
    save(safe/'RESULTS_FOR_CODEX.json',summary)
    table(safe/'COMPILER_COVERAGE_SAFE.csv',coverage)
    if targets:table(safe/'REMAINING_DEFICITS_SAFE.csv',targets)
    names=[p.name for p in safe.iterdir() if p.is_file()]
    if any(re.search(rb'[0-9a-fA-F]{64}',(safe/n).read_bytes()) for n in names):raise ValueError('Sample-like identity in aggregate')
    save(safe/'SAFE_CHECKSUMS.json',{n:file_sha(safe/n) for n in names})
    packet=snapshot/'COHORT100_STATIC_RESULTS_SAFE.zip'
    with zipfile.ZipFile(packet,'x',zipfile.ZIP_DEFLATED) as z:
        for path in safe.iterdir():z.write(path,path.name)
    usb=base.parent/packet.name
    if usb.exists():print('Existing USB SAFE packet retained; new SAFE packet='+str(packet),flush=True)
    else:
        with packet.open('rb') as src,usb.open('xb') as dst:shutil.copyfileobj(src,dst)
        if file_sha(usb)!=file_sha(packet):raise OSError('USB SAFE copy differs')
    print(json.dumps(summary,indent=2));print('Return only COHORT100_STATIC_RESULTS_SAFE.zip. Keep bytes and identity manifests inside VM.')


if __name__=='__main__':main()
