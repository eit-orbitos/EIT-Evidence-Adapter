"""Oracle V0.2: additional predeclared expectations; no post-run rebaselining.
These are preparer-authored tests, not independent certification.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import evidence_adapter as m
REPRO = Path(__file__).parent / 'repro'


def archive(payload=b'HELLOWORLD', method=zipfile.ZIP_STORED, name='data.txt',
            *, declared=None, raw_compressed=None, flags=0, descriptor='signed',
            local_size=None, local_crc=None):
    """Small in-memory ZIP fixture. No extraction or payload execution."""
    name = name.encode('utf8') if isinstance(name, str) else name
    if raw_compressed is None:
        if method == 8:
            obj = zlib.compressobj(wbits=-15)
            comp = obj.compress(payload) + obj.flush()
        else:
            comp = payload
    else:
        comp = raw_compressed
    size = len(payload) if declared is None else declared
    crc = zlib.crc32(payload[:size])
    has_dd = bool(flags & 8)
    lsize = (0 if has_dd else size) if local_size is None else local_size
    lcrc = (0 if has_dd else crc) if local_crc is None else local_crc
    lcomp = 0 if has_dd else len(comp)
    local = struct.pack('<4s5H3I2H', b'PK\x03\x04', 20, flags, method, 0, 0,
                        lcrc, lcomp, lsize, len(name), 0) + name + comp
    if has_dd and descriptor != 'absent':
        local += (b'PK\x07\x08' if descriptor == 'signed' else b'')
        local += struct.pack('<3I', crc, len(comp), size)
    central = struct.pack('<4s6H3I5H2I', b'PK\x01\x02', 20, 20, flags, method, 0, 0,
                          crc, len(comp), size, len(name), 0, 0, 0, 0, 0, 0) + name
    end = struct.pack('<4s4H2IH', b'PK\x05\x06', 0, 0, 1, 1, len(central), len(local), 0)
    return local + central + end


def built_zip(items, method=zipfile.ZIP_DEFLATED):
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', compression=method) as z:
        for n, data in items:
            z.writestr(n, data)
    return out.getvalue()


class ReleaseRegressions(unittest.TestCase):
    def reject(self, raw, reason):
        with self.assertRaises(m.EvidenceError) as ctx:
            m.inspect_zip(raw)
        self.assertEqual(str(ctx.exception), reason)

    def test_X01_corrupt_deflate(self):
        "X01: corrupt DEFLATE rejects with UNREADABLE_ZIP."
        self.reject((REPRO/'R_error.zip').read_bytes(), 'UNREADABLE_ZIP')

    def test_X02_bad_offsets(self):
        "X02: invalid header offsets reject with UNREADABLE_ZIP."
        self.reject((REPRO/'R_ValueError.zip').read_bytes(), 'UNREADABLE_ZIP')

    def test_X03_bad_utf8_name(self):
        "X03: invalid UTF-8 member name rejects with UNREADABLE_ZIP."
        self.reject((REPRO/'R_UnicodeDecodeError_name.zip').read_bytes(), 'UNREADABLE_ZIP')

    def test_X04_stored_prefix_false_acceptance(self):
        "X04: stored size/prefix forgery rejects with ZIP_SIZE_MISMATCH."
        self.reject((REPRO/'R_truncated_declared_size.zip').read_bytes(), 'ZIP_SIZE_MISMATCH')

    def test_X05_surrogate_key(self):
        "X05: a lone surrogate key rejects with JSON_INVALID_UNICODE."
        with self.assertRaisesRegex(m.EvidenceError, '^JSON_INVALID_UNICODE$'):
            m.strict_json((REPRO/'R_surrogate_key.json').read_bytes())

    def test_X06_surrogate_value(self):
        "X06: nested lone surrogate value rejects with JSON_INVALID_UNICODE."
        with self.assertRaisesRegex(m.EvidenceError, '^JSON_INVALID_UNICODE$'):
            m.strict_json(b'{"a":["\\udfff"]}')

    def test_X07_hidden_directory_payload(self):
        "X07: directory payload rejects with INVALID_ZIP_DIRECTORY."
        self.reject((REPRO/'R_dir_with_payload.zip').read_bytes(), 'INVALID_ZIP_DIRECTORY')

    def test_X08_bad_member_does_not_lose_batch(self):
        "X08: good input survives all six hostile inputs; complete BLOCKED report."
        inputs=[(REPRO/'good.json',None,None)]+[(p,None,None) for p in sorted(REPRO.iterdir()) if p.name!='good.json']
        result=m.create_report(inputs)
        self.assertEqual(len(result['evidence_inventory']), 7)
        self.assertEqual(result['evidence_inventory'][0]['status'],'INSPECTED')
        self.assertTrue(all(x['status']=='BLOCKED' for x in result['evidence_inventory'][1:]))
        self.assertEqual(result['final_adapter_assessment'],'BLOCKED')

    def test_X09_cli_complete_report(self):
        "X09: hostile batch CLI returns 2 with a valid report and no traceback."
        with tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(io.StringIO()):
            out=Path(d)/'report.json'
            code=m.main([str(REPRO/'good.json'),str(REPRO/'R_error.zip'),str(REPRO/'R_surrogate_key.json'),'--output',str(out)])
            self.assertEqual(code,2)
            doc=json.loads(out.read_bytes())
            self.assertEqual(len(doc['evidence_inventory']),3)

    def test_X10_integer_limit_independent_of_host_setting(self):
        "X10: 4300 digits accepted and 4301/4400 rejected under host limits 0/640/4300."
        source=Path(m.__file__).resolve()
        code='''import importlib.util,sys,json
s=importlib.util.spec_from_file_location("adapter",sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
before=sys.get_int_max_str_digits();out=[]
for n in (4300,4301,4400):
 for sign in (b"",b"-"):
  try: v=m.strict_json(b'{"x":'+sign+b'7'*n+b'}');out.append("ACCEPT" if isinstance(v["x"],int) else "BAD_TYPE")
  except m.EvidenceError as e: out.append(str(e))
assert sys.get_int_max_str_digits()==before
print(json.dumps(out))'''
        for limit in ('0','640','4300'):
            result=subprocess.run([sys.executable,'-B','-X','int_max_str_digits='+limit,'-c',code,str(source)],capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(json.loads(result.stdout),['ACCEPT','ACCEPT','INVALID_JSON','INVALID_JSON','INVALID_JSON','INVALID_JSON'])

    def test_X11_global_integer_setting_unchanged(self):
        "X11: parsing never mutates process-global integer conversion limits."
        before=sys.get_int_max_str_digits()
        m.strict_json(b'{"x":'+b'7'*4300+b'}')
        with self.assertRaises(m.EvidenceError):m.strict_json(b'{"x":'+b'7'*4400+b'}')
        self.assertEqual(sys.get_int_max_str_digits(),before)

    def test_X12_deflate_prefix_false_acceptance(self):
        "X12: complete DEFLATE output longer than declared size is rejected."
        self.reject(archive(method=8,declared=5),'ZIP_SIZE_MISMATCH')

    def test_X13_deflate_truncated_stream(self):
        "X13: incomplete DEFLATE stream rejects even with a complete declared prefix."
        co=zlib.compressobj(wbits=-15);comp=co.compress(b'HELLOWORLD')+co.flush()
        self.reject(archive(method=8,raw_compressed=comp[:-1]),'UNREADABLE_ZIP')

    def test_X14_deflate_trailing_data(self):
        "X14: unused data inside declared compressed span rejects."
        co=zlib.compressobj(wbits=-15);comp=co.compress(b'HELLOWORLD')+co.flush()
        self.reject(archive(method=8,raw_compressed=comp+b'JUNK'),'UNREADABLE_ZIP')

    def test_X15_concatenated_deflate_streams(self):
        "X15: concatenated streams are not one ZIP member."
        co=zlib.compressobj(wbits=-15);comp=co.compress(b'HELLOWORLD')+co.flush()
        self.reject(archive(method=8,raw_compressed=comp+comp),'UNREADABLE_ZIP')

    def test_X16_local_size_mismatch(self):
        "X16: non-descriptor local/central size mismatch rejects."
        self.reject(archive(local_size=9),'UNREADABLE_ZIP')

    def test_X17_local_crc_mismatch(self):
        "X17: non-descriptor local/central CRC mismatch rejects."
        self.reject(archive(local_crc=1),'UNREADABLE_ZIP')

    def test_X18_local_flags_mismatch(self):
        "X18: local/central flags mismatch rejects."
        raw=bytearray(archive());struct.pack_into('<H',raw,6,0x800)
        self.reject(bytes(raw),'UNREADABLE_ZIP')

    def test_X19_signed_descriptor(self):
        "X19: valid signed data descriptor accepted and complete hash checked."
        out=m.inspect_zip(archive(method=8,flags=8))
        self.assertEqual(out['members'][0]['sha256'],hashlib.sha256(b'HELLOWORLD').hexdigest())

    def test_X20_unsigned_descriptor(self):
        "X20: valid unsigned data descriptor accepted."
        out=m.inspect_zip(archive(method=8,flags=8,descriptor='unsigned'))
        self.assertEqual(out['members'][0]['byte_length'],10)

    def test_X21_descriptor_mismatch(self):
        "X21: data descriptor CRC mismatch rejects."
        raw=bytearray(archive(method=8,flags=8));p=raw.index(b'PK\x07\x08');struct.pack_into('<I',raw,p+4,1)
        self.reject(bytes(raw),'UNREADABLE_ZIP')

    def test_X22_descriptor_missing(self):
        "X22: bit-3 without required descriptor rejects."
        self.reject(archive(method=8,flags=8,descriptor='absent'),'UNREADABLE_ZIP')

    def test_X23_duplicate_local_offset(self):
        "X23: duplicate/overlapping local offsets reject."
        raw=bytearray(built_zip([('a',b'1'),('b',b'2')]))
        first=raw.index(b'PK\x01\x02');second=raw.index(b'PK\x01\x02',first+4)
        struct.pack_into('<I',raw,second+42,0)
        self.reject(bytes(raw),'UNREADABLE_ZIP')

    def test_X24_prepended_bytes_disclosed(self):
        "X24: prepended bytes explicitly counted; never executed."
        prefix=b'UNINTERPRETED_PREFIX\n'
        out=m.inspect_zip(prefix+archive())
        self.assertEqual(out['archive_offset'],len(prefix))
        self.assertEqual(out['prepended_bytes'],len(prefix))

    def test_X25_unaccounted_member_gap(self):
        "X25: gap between last member and central directory is rejected."
        raw=archive();cd=raw.index(b'PK\x01\x02');out=bytearray(raw[:cd]+b'HIDDEN'+raw[cd:]);ep=out.index(b'PK\x05\x06')
        struct.pack_into('<I',out,ep+16,cd+6)
        self.reject(bytes(out),'UNREADABLE_ZIP')

    def test_X26_source_payload_not_executed_or_extracted(self):
        "X26: executable member cannot create sentinel and is fully inventoried."
        with tempfile.TemporaryDirectory() as d:
            mark=Path(d)/'EXECUTED'
            content=('from pathlib import Path\nPath('+repr(str(mark))+').write_text("bad")\n').encode()
            before=sorted(Path(d).iterdir());out=m.inspect_zip(built_zip([('start.py',content)]))
            self.assertFalse(mark.exists());self.assertEqual(sorted(Path(d).iterdir()),before)
            self.assertEqual(out['members'][0]['sha256'],hashlib.sha256(content).hexdigest())

    def test_X27_forged_authentication_and_gate_claims_not_promoted(self):
        "X27: self-asserted signatures, all-PASS gates and matching hash never promote trust."
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'claim.json';raw=json.dumps({'signature_valid':True,'authenticated':True,'G4':'PASS','GATE4':'SATISFIED','B4':'CLOSED','execution':'VERIFIED'}).encode();p.write_bytes(raw)
            out=m.create_report([(p,m.sha256(raw),None)])
            self.assertEqual(out['evidence_inventory'][0]['integrity'],'MATCH')
            self.assertEqual(out['evidence_inventory'][0]['origin_authenticity'],'UNKNOWN')
            self.assertEqual(out['evidence_inventory'][0]['execution_attestation'],'NO_EVIDENCE')
            self.assertEqual(out['program_lang_reference']['B4'],'NOT_CLOSED')
            self.assertEqual(out['genius_review_recommendations']['G4'],'UNRESOLVED')
            self.assertNotEqual(out['final_adapter_assessment'],'PASS')
            self.assertEqual(m.create_report([(p,'0'*64,None)])['final_adapter_assessment'],'BLOCKED')

    def test_X28_empty_directory(self):
        "X28: empty stored directory accepted, explicitly counted, no hidden payload."
        out=m.inspect_zip(built_zip([('folder/',b''),('folder/a',b'1')],zipfile.ZIP_STORED))
        self.assertEqual(out['member_count'],1);self.assertEqual(out['directory_count'],1)

    def test_X29_regular_stored(self):
        "X29: full stored payload size, digest and CRC verified."
        out=m.inspect_zip(archive());self.assertEqual(out['members'][0]['byte_length'],10)
        self.assertEqual(out['members'][0]['sha256'],m.sha256(b'HELLOWORLD'));self.assertTrue(out['members'][0]['crc_checked'])

    def test_X30_regular_deflate(self):
        "X30: full deflate payload size, digest and CRC verified."
        out=m.inspect_zip(archive(method=8));self.assertEqual(out['members'][0]['byte_length'],10)
        self.assertEqual(out['members'][0]['sha256'],m.sha256(b'HELLOWORLD'))

    def test_X31_preflight_entry_limit(self):
        "X31: central entry limit is rejected before metadata reader allocation."
        raw=built_zip([('f%03d'%i,b'x') for i in range(257)])
        with mock.patch.object(m.zipfile,'ZipFile',side_effect=AssertionError('must not open')):
            self.reject(raw,'ZIP_ENTRY_LIMIT')

    def test_X32_internal_failure_is_not_expected_rejection(self):
        "X32: unexpected per-input failure is BLOCKED INTERNAL_ERROR, later row survives."
        original=m.inspect_file
        def injected(path,*args):
            if path.name=='fault.json':raise RuntimeError('synthetic implementation fault')
            return original(path,*args)
        with tempfile.TemporaryDirectory() as d:
            good=Path(d)/'good.json';good.write_bytes(b'{}')
            with mock.patch.object(m,'inspect_file',side_effect=injected):
                out=m.create_report([(Path(d)/'fault.json',None,None),(good,None,None)])
            self.assertEqual(out['evidence_inventory'][0]['reason'],'INTERNAL_ERROR:RuntimeError')
            self.assertEqual(out['evidence_inventory'][0]['error_category'],'INTERNAL_ERROR')
            self.assertEqual(out['evidence_inventory'][1]['status'],'INSPECTED')
            self.assertEqual(out['final_adapter_assessment'],'BLOCKED')

    def test_X33_archive_comment(self):
        "X33: normal archive comment accepted without inspecting as a member."
        raw=bytearray(archive());struct.pack_into('<H',raw,len(raw)-2,7);raw+=b'comment'
        self.assertEqual(m.inspect_zip(bytes(raw))['member_count'],1)

    def test_X34_compressed_directory_is_out_of_profile(self):
        "X34: compressed empty directory is rejected under zero-compressed-byte directory policy."
        self.reject(built_zip([('folder/',b'')]),'INVALID_ZIP_DIRECTORY')

    def test_X35_zip64_is_explicitly_unsupported(self):
        "X35: forced local ZIP64 is rejected rather than silently misparsed."
        out=io.BytesIO()
        with zipfile.ZipFile(out,'w') as z:
            with z.open('small','w',force_zip64=True) as f:f.write(b'x')
        self.reject(out.getvalue(),'UNSUPPORTED_ZIP64')

    def test_X36_nul_name_not_silently_truncated(self):
        "X36: NUL in original filename rejects before ZipInfo truncation can hide it."
        self.reject(archive(name=b'a\x00b'),'UNSAFE_ZIP_MEMBER_PATH')

    def test_X37_encrypted_member(self):
        "X37: encrypted flag remains an explicit unsupported member rejection."
        self.reject(archive(flags=1),'ENCRYPTED_ZIP_MEMBER')

    def test_X38_valid_unicode_pair(self):
        "X38: legitimate supplementary Unicode scalar remains accepted."
        self.assertEqual(m.strict_json(b'{"x":"\\ud83d\\ude00"}'),{'x':'😀'})

    def test_X39_local_name_mismatch(self):
        "X39: central and local names must match exactly."
        raw=bytearray(archive());raw[30]=ord('D')
        self.reject(bytes(raw),'UNREADABLE_ZIP')

    def test_X40_limit_checked_on_bytes_actually_read(self):
        "X40: direct oversized ZIP input is rejected before directory parsing."
        self.reject(b'x'*(m.MAX_ZIP_TOTAL+2_000_001),'INPUT_BYTE_LIMIT')

    def test_X41_os_filename_unicode_cannot_break_report(self):
        "X41: unencodable POSIX filename is safely escaped in JSON report."
        if os.name!='posix':self.skipTest('POSIX filename domain')
        with tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(io.StringIO()):
            bad=os.fsdecode(b'bad_\xff.json');p=Path(d)/bad;p.write_bytes(b'{}');out=Path(d)/'report.json'
            self.assertEqual(m.main([str(p),'--output',str(out)]),0)
            self.assertEqual(len(json.loads(out.read_bytes())['evidence_inventory']),1)

    def test_X42_symlink_and_fifo_refused(self):
        "X42: symlink and FIFO inputs refused without following/blocking on them."
        if os.name!='posix':self.skipTest('POSIX inode type domain')
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'target';p.write_bytes(b'{}');link=Path(d)/'link';link.symlink_to(p)
            fifo=Path(d)/'fifo';os.mkfifo(fifo)
            for value in (link,fifo):
                with self.assertRaisesRegex(m.EvidenceError,'^INPUT_NOT_REGULAR_FILE$'):m.inspect_file(value)

    def test_X43_content_validation_scope_explicit(self):
        "X43: invalid nested JSON is byte-inventoried, never reported as JSON validated."
        out=m.inspect_zip(built_zip([('nested.json',b'{"x":1,"x":2}')]))
        self.assertEqual(out['content_validation'],'NOT_PERFORMED')
        self.assertEqual(out['member_count'],1)

    def test_X44_status_snapshot_date_and_scope(self):
        "X44: historical governance constants are dated and not live/authoritative."
        out=m.create_report([])
        self.assertEqual(out['status_constants_as_of'],'2026-10-26')
        self.assertEqual(out['status_constants_authority'],'HISTORICAL_REPORTED_SNAPSHOT_NOT_LIVE')

if __name__=='__main__':unittest.main()
