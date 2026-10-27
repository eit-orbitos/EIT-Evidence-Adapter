#!/usr/bin/env python3
"""Supplementary reproducible mutation checks, NOT exhaustive verification.
Only the adapter is imported. No payload is extracted or executed.
"""
import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import random
import sys
import zipfile


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--expected-source-sha256',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    raw=args.source.read_bytes();digest=hashlib.sha256(raw).hexdigest()
    if digest!=args.expected_source_sha256:raise SystemExit('STOP: source mismatch')
    if args.output.exists():raise SystemExit('STOP: existing output')
    sys.dont_write_bytecode=True
    def no_network(event,_args):
        if event.startswith('socket.'):raise PermissionError('network disabled by test audit hook')
    sys.addaudithook(no_network)
    spec=importlib.util.spec_from_file_location('stress_adapter',args.source)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    random_source=random.Random(122022)
    buf=io.BytesIO()
    with zipfile.ZipFile(buf,'w',zipfile.ZIP_DEFLATED) as z:
        z.writestr('a.json',b'{"k":"'+b'v'*3000+b'"}')
        z.writestr('d/b.txt',random_source.randbytes(2000))
    zip_base=buf.getvalue()
    json_base=b'{"a":[1,2.5e3,{"b":"c\\u00e9"}],"n":null,"t":true}'
    result={}
    for name,base,count,seed,max_flips,fn in (
        ('zip',zip_base,5000,20261026,4,m.inspect_zip),
        ('json',json_base,20000,7,3,m.strict_json)):
        rng=random.Random(seed);accepted=rejected=0;unhandled={};first=[]
        for i in range(count):
            b=bytearray(base)
            for _ in range(rng.randint(1,max_flips)):b[rng.randrange(len(b))]=rng.randrange(256)
            try:fn(bytes(b));accepted+=1
            except m.EvidenceError:rejected+=1
            except Exception as exc:
                key=type(exc).__name__;unhandled[key]=unhandled.get(key,0)+1
                if len(first)<10:first.append({'case':i,'sha256':hashlib.sha256(b).hexdigest(),'exception':key})
        result[name]={'base_sha256':hashlib.sha256(base).hexdigest(),'seed':seed,'count':count,'accepted':accepted,'controlled_rejections':rejected,'unhandled':unhandled,'first_unhandled':first}
    obj={'kind':'LOCAL_PREPARER_SUPPLEMENTARY_STRESS_NOT_INDEPENDENT','source_sha256':digest,'python':sys.version,'network_control':'socket audit guard; not kernel namespace','results':result,'scope':'absence of escaping ordinary exceptions in these deterministic samples only; acceptance counts are not correctness proof','pass':all(not v['unhandled'] for v in result.values())}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x',encoding='utf8') as f:json.dump(obj,f,indent=2);f.write('\n')
    print(json.dumps(obj,indent=2))
    return 0 if obj['pass'] else 1
if __name__=='__main__':raise SystemExit(main())
