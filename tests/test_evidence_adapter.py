import io
import json
import stat
import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from evidence_adapter import (EvidenceError, strict_json, inspect_zip, inspect_file,
                              create_report, sha256, MAX_JSON)


def zip_bytes(members):
    buf=io.BytesIO()
    with ZipFile(buf,'w',compression=ZIP_DEFLATED) as z:
        for key,value in members:
            z.writestr(key,value)
    return buf.getvalue()

class ContractTests(unittest.TestCase):
    def assert_reject(self, fn, reason):
        with self.assertRaises(EvidenceError) as cm: fn()
        self.assertEqual(str(cm.exception),reason)

    def test_sha_exact(self):
        self.assertEqual(sha256(b''),'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')

    def test_json_valid(self):
        self.assertEqual(strict_json(b'{"ok":true}'), {'ok':True})

    def test_duplicate_json_root(self):
        self.assert_reject(lambda:strict_json(b'{"a":1,"a":2}'),'DUPLICATE_JSON_KEY')

    def test_duplicate_json_nested(self):
        self.assert_reject(lambda:strict_json(b'{"a":{"x":1,"x":2}}'),'DUPLICATE_JSON_KEY')

    def test_nonfinite_nan(self):
        self.assert_reject(lambda:strict_json(b'{"n":NaN}'),'NON_FINITE_JSON_CONSTANT:NaN')

    def test_nonfinite_infinity(self):
        self.assert_reject(lambda:strict_json(b'{"n":Infinity}'),'NON_FINITE_JSON_CONSTANT:Infinity')

    def test_json_exponent_overflow_is_rejected(self):
        self.assert_reject(lambda: strict_json(b'{"x":1e309}'),
                           'NON_FINITE_JSON_NUMBER')

    def test_json_integer_digit_limit_is_controlled(self):
        raw = b'{"x":' + b'7'*4400 + b'}'
        self.assert_reject(lambda: strict_json(raw), 'INVALID_JSON')

    def test_json_large_finite_float_is_still_accepted(self):
        self.assertEqual(strict_json(b'{"x":1e308}')['x'], 1e308)

    def test_invalid_utf8(self):
        self.assert_reject(lambda:strict_json(b'\xff'),'INVALID_UTF8')

    def test_nonobject_root(self):
        self.assert_reject(lambda:strict_json(b'[]'),'EXPECTED_JSON_OBJECT')

    def test_json_size(self):
        self.assert_reject(lambda:strict_json(b' '* (MAX_JSON+1)),'JSON_BYTE_LIMIT')

    def test_json_depth(self):
        data=b'{' + b'"a":{' * 22 + b'}' * 22 + b'}'
        self.assert_reject(lambda:strict_json(data),'JSON_DEPTH_LIMIT')

    def test_zip_good(self):
        info=inspect_zip(zip_bytes([('a.json',b'{}'),('folder/b.txt',b'x')]))
        self.assertEqual(info['member_count'],2)
        self.assertEqual(info['members'][0]['sha256'],sha256(b'{}'))
        self.assertEqual(info['archive_authenticity'],'NOT_ESTABLISHED')

    def test_zip_parent(self):
        self.assert_reject(lambda:inspect_zip(zip_bytes([('../evil',b'x')])),'UNSAFE_ZIP_MEMBER_PATH')

    def test_zip_absolute(self):
        self.assert_reject(lambda:inspect_zip(zip_bytes([('/etc/file',b'x')])),'UNSAFE_ZIP_MEMBER_PATH')

    def test_zip_backslash(self):
        self.assert_reject(lambda:inspect_zip(zip_bytes([('a\\evil',b'x')])),'UNSAFE_ZIP_MEMBER_PATH')

    def test_zip_nfc_duplicate(self):
        self.assert_reject(lambda:inspect_zip(zip_bytes([('e\u0301.txt',b'1'),('\u00e9.txt',b'2')])),'DUPLICATE_ZIP_MEMBER_PATH')

    def test_zip_symlink(self):
        buff=io.BytesIO()
        with ZipFile(buff,'w') as z:
            i=ZipInfo('link');i.create_system=3;i.external_attr=(stat.S_IFLNK|0o777)<<16
            z.writestr(i,b'file.txt')
        self.assert_reject(lambda:inspect_zip(buff.getvalue()),'UNSAFE_ZIP_MEMBER_TYPE')

    def test_integrity_match(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'e.json';p.write_bytes(b'{}')
            self.assertEqual(inspect_file(p, sha256(b'{}'))['integrity'],'MATCH')

    def test_integrity_mismatch(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'e.json';p.write_bytes(b'{}')
            self.assertEqual(inspect_file(p, 'a'*64)['integrity'],'MISMATCH')

    def test_no_reference_not_authenticated(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'e.json';p.write_bytes(b'{}')
            r=inspect_file(p)
            self.assertEqual((r['integrity'],r['origin_authenticity']),('NO_REFERENCE','UNKNOWN'))

    def test_mismatch_blocks_report(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'e.json';p.write_bytes(b'{}')
            r=create_report([(str(p),'b'*64,None)])
            self.assertEqual(r['final_adapter_assessment'],'BLOCKED')
            self.assertEqual(r['program_lang_reference']['B4'],'NOT_CLOSED')

    def test_malformed_blocks_report(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'e.json';p.write_bytes(b'{"a":1,"a":2}')
            r=create_report([(str(p),None,None)])
            self.assertEqual(r['final_adapter_assessment'],'BLOCKED')

    def test_no_g4_gate4_coupling(self):
        r=create_report([])
        self.assertEqual(r['genius_review_recommendations']['G4'],'UNRESOLVED')
        self.assertEqual(r['program_lang_reference']['GATE4'],'NOT_SATISFIED')
        self.assertEqual(r['eureka_validation'],'NOT_PROVEN')

if __name__=='__main__': unittest.main()
