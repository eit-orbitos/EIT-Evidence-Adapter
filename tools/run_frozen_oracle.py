#!/usr/bin/env python3
"""Run frozen V0.1 case logic/expectations against an explicitly pinned source.

The original runner and oracle are not rewritten. Only this distinct binding
wrapper selects the source; source author self-runs are not independent review.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
FROZEN_RUNNER_SHA='c1663e182893abcdb96867e2100c8a7da2dbe1ad8d566a9bb6d05447fc9d0d6d'
FROZEN_ORACLE_SHA='59c8b98dd78fd18446adb169af60e5acfbe04687ce7685812f4d5ea1358a57df'


def h(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def no_network(event,args):
    if event.startswith('socket.'):
        raise PermissionError('network use not authorized in this test runner')

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--expected-source-sha256',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():raise SystemExit('STOP: output already exists')
    runner=ROOT/'regression_v01/ORIGINAL_RUNNER_V0.1.py'
    oracle=ROOT/'regression_v01/ORIGINAL_EXPECTED_ORACLE_V0.1.json'
    assert h(runner)==FROZEN_RUNNER_SHA,'frozen runner mismatch'
    assert h(oracle)==FROZEN_ORACLE_SHA,'frozen oracle mismatch'
    assert h(args.source)==args.expected_source_sha256,'target source mismatch'
    sys.dont_write_bytecode=True
    sys.addaudithook(no_network)
    original=load('frozen_v01_cases',runner)
    target=load('adapter_target',args.source)
    expected=json.loads(oracle.read_bytes())['cases'];rows=[]
    with tempfile.TemporaryDirectory(prefix='adapter_oracle_') as d:
        for case in expected:
            p=Path(d)/case['id'];p.mkdir()
            try:actual=str(original.run_case(case['id'],target,p))
            except target.EvidenceError as exc:actual='REJECT:'+str(exc)
            except Exception as exc:actual='UNHANDLED:'+type(exc).__name__+':'+str(exc)[:200]
            rows.append({**case,'observed':actual,'verdict':'PASS' if actual==case['expected'] else 'FAIL'})
    counts={'PASS':sum(r['verdict']=='PASS' for r in rows),'FAIL':sum(r['verdict']=='FAIL' for r in rows)}
    receipt={'scope':'frozen 32 case logic and outcomes; independently bound target','source_sha256':h(args.source),'original_runner_sha256':h(runner),'original_oracle_sha256':h(oracle),'python':sys.version,'network_control':'Python audit-hook denies socket events; not kernel sandbox','counts':counts,'cases':rows,'execution_independence':'LOCAL_PREPARER_RUN unless independently executed by recipient','release_authorization':False}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x',encoding='utf8') as f:json.dump(receipt,f,indent=2);f.write('\n')
    print(json.dumps(counts))
    for r in rows:
        if r['verdict']=='FAIL':print(r['id'],r['expected'],r['observed'])
    return bool(counts['FAIL'])
if __name__=='__main__':raise SystemExit(main())
