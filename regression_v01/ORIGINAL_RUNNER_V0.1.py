#!/usr/bin/env python3
"""Offline independent test harness for supplied, unmodified V5C adapter candidate.
Only imports the candidate evidence_adapter.py, never Analyzer / Bridge / Program Lang.
Run in isolated throwaway directory. No network, no source modifications.
Exit 0 only when every precommitted oracle is met.
"""
import argparse, contextlib, hashlib, importlib.util, io, json, os, pathlib, stat, tempfile, zipfile, sys, traceback

HERE=pathlib.Path(__file__).resolve().parent

def zip_blob(items, method=zipfile.ZIP_DEFLATED):
    o=io.BytesIO()
    with zipfile.ZipFile(o,'w',compression=method) as z:
        for key,payload in items: z.writestr(key,payload)
    return o.getvalue()

def run_case(cid, m, root):
    e=lambda raw: m.strict_json(raw)
    def z(items): return m.inspect_zip(zip_blob(items))
    if cid=='K01': e(b'{"e":{"ok":true},"v":2}');return 'ACCEPT'
    if cid=='K02': return e(b'{"a":1,"a":2}')
    if cid=='K03': return e(b'{"z":{"q":0,"q":1}}')
    if cid=='K04': return e(b'\xff')
    if cid=='K05': return e(b'{"x":NaN}')
    if cid=='K06': return e(b'{"x":1e309}')
    if cid=='K07': return e(b'{"x":'+b'7'*4400+b'}')
    if cid=='K08': return e(b'[1,2]')
    if cid=='K09': return e(b' '*(m.MAX_JSON+1))
    if cid=='K10': return e(b'{"z":'*22 + b'null' +b'}'*22)
    if cid=='K11': return 'ZIP_COUNT:'+str(z([('good/a.json',b'{}'),('b.txt',b'ok')])['member_count'])
    if cid=='K12': return z([('../x',b'x')])
    if cid=='K13': return z([('/tmp/x',b'x')])
    if cid=='K14': return z([('a\\b',b'x')])
    if cid=='K15': return z([('e\u0301.txt',b'1'),('é.txt',b'2')])
    if cid=='K16': return z([('a',b'1'),('a',b'2')])
    if cid=='K17':
        o=io.BytesIO()
        with zipfile.ZipFile(o,'w') as a:
            info=zipfile.ZipInfo('ln');info.create_system=3;info.external_attr=(stat.S_IFLNK|0o777)<<16
            a.writestr(info,b'target')
        return m.inspect_zip(o.getvalue())
    if cid=='K18': return m.inspect_zip(zip_blob([('a',b'hello')],zipfile.ZIP_BZIP2))
    if cid=='K19': return z([('entry_%03d'%i,b'x') for i in range(257)])
    if cid=='K20': return z([('too_big.bin',b'z'*(m.MAX_ZIP_MEMBER+1))])
    if cid=='K21':
        raw=zip_blob([('data.txt',b'HELLOWORLD')],zipfile.ZIP_STORED)
        idx=raw.index(b'HELLOWORLD');raw=raw[:idx]+b'J'+raw[idx+1:]
        return m.inspect_zip(raw)
    if cid=='K22':
        raw=z([('start.py',b'raise RuntimeError("SHOULD_NOT_EXECUTE")')]);return 'ZIP_SAFE_NO_EXEC' if raw['archive_authenticity']=='NOT_ESTABLISHED' else 'WRONG_STATUS'
    if cid in ('K23','K24','K25','K26','K27','K28','K30'):
        p=root/'input.json';p.write_bytes(b'{"a":2}')
        h=hashlib.sha256(p.read_bytes()).hexdigest()
        if cid=='K23':return 'INTEGRITY:'+m.inspect_file(p,h)['integrity']
        if cid=='K24':return 'INTEGRITY:'+m.inspect_file(p,'a'*64)['integrity']
        if cid=='K25':return 'AUTH_UNKNOWN' if (m.inspect_file(p)['integrity'],m.inspect_file(p)['origin_authenticity'])==('NO_REFERENCE','UNKNOWN') else 'WRONG_STATUS'
        if cid=='K26':return m.inspect_file(p,'A'*64)
        if cid=='K27':
            p.write_bytes(b'{"a":2,"a":3}')
            return 'ASSESSMENT:'+m.create_report([(str(p),None,None)])['final_adapter_assessment']
        if cid=='K28':return 'ASSESSMENT:'+m.create_report([(str(p),'b'*64,None)])['final_adapter_assessment']
        if cid=='K30':
            target=root/'target.json';target.write_bytes(b'{}')
            p.unlink();p.symlink_to(target)
            return m.inspect_file(p)
    if cid=='K29':
        x=m.create_report([])
        return 'GATES_SEPARATE' if x['genius_review_recommendations']['G4']=='UNRESOLVED' and x['program_lang_reference']['GATE4']=='NOT_SATISFIED' and x['eureka_validation']=='NOT_PROVEN' else 'WRONG_STATUS'
    if cid=='K31':
        p=root/'input.json';p.write_bytes(b'{}')
        out=root/'old_output.json';out.write_bytes(b'ORIGINAL')
        with contextlib.redirect_stderr(io.StringIO()):
            try: m.main([str(p),'--output',str(out)])
            except SystemExit as exc:
                return 'CLI_REFUSES_OVERWRITE' if exc.code!=0 and out.read_bytes()==b'ORIGINAL' else 'WRONG_STATUS'
        return 'WRONG_STATUS'
    if cid=='K32':
        r=z([('SHA256SUMS',b'0'*64+b'  a.txt\n'),('a.txt',b'clean')])
        return 'ZIP_AUTH_NOT_ESTABLISHED' if r['archive_authenticity']=='NOT_ESTABLISHED' else 'WRONG_STATUS'
    raise RuntimeError('Unknown case '+cid)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',default=None)
    args=parser.parse_args()
    targets=json.loads((HERE/'EXPECTED_ORACLE_V0.1.json').read_text(encoding='utf8'))
    original=HERE/'EXACT_V5C_ADAPTER_V0.2.0_CANDIDATE_ORIGINAL.zip'
    data=original.read_bytes();observed_hash=hashlib.sha256(data).hexdigest()
    if observed_hash!=targets['candidate_zip_sha256']:raise SystemExit('STOP: candidate zip hash mismatch '+observed_hash)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        if z.testzip() is not None:raise SystemExit('STOP: zip CRC mismatch')
        source=z.read('V5C_EVIDENCE_ADAPTER_V0.2.0/evidence_adapter.py')
    if hashlib.sha256(source).hexdigest()!=targets['candidate_adapter_source_sha256']:raise SystemExit('STOP: adapter bytes mismatch')
    report=[]
    with tempfile.TemporaryDirectory(prefix='kimi_v5c_independent_') as d:
        work=pathlib.Path(d);adapter_py=work/'candidate_adapter.py';adapter_py.write_bytes(source)
        spec=importlib.util.spec_from_file_location('isolated_candidate_adapter',adapter_py)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        for case in targets['cases']:
            id=case['id'];expected=case['expected'];status='PASS';detail=''
            case_dir=work/id;case_dir.mkdir()
            try: actual=str(run_case(id,module,case_dir))
            except Exception as exc:
                # An unexpected exception class is never classified as a contract rejection.
                actual='REJECT:'+str(exc) if isinstance(exc,module.EvidenceError) else 'UNHANDLED:'+type(exc).__name__+':'+str(exc)[:200]
            if actual!=expected:
                status='FAIL';detail='expected '+expected+'; got '+actual
            report.append({'id':id,'intent':case['intent'],'expected':expected,'observed':actual,'verdict':status,'detail':detail})
    counts={'PASS':sum(r['verdict']=='PASS' for r in report),'FAIL':sum(r['verdict']=='FAIL' for r in report)}
    receipt={'review_mode':'LOCAL_EXECUTION_WHERE_RUN; NOT INDEPENDENT UNLESS EXECUTED BY AN INDEPENDENT REVIEWER','candidate_zip_sha256':observed_hash,'oracle_file_sha256':hashlib.sha256((HERE/'EXPECTED_ORACLE_V0.1.json').read_bytes()).hexdigest(),'python':sys.version,'counts':counts,'cases':report,'release_evidence':'NO_RELEASE_AUTHORIZATION'}
    body=json.dumps(receipt,indent=2,ensure_ascii=False)+'\n'
    if args.output:
        dest=pathlib.Path(args.output)
        if dest.exists():raise SystemExit('STOP: output already exists')
        dest.write_text(body,encoding='utf8')
    print('KIMI_V5C_INDEPENDENT',json.dumps(counts),'candidate_sha256',observed_hash)
    for x in report:
        if x['verdict']=='FAIL': print('FAIL',x['id'],x['detail'])
    return 0 if counts['FAIL']==0 else 1

if __name__=='__main__':raise SystemExit(main())
