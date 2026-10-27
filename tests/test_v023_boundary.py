"""V0.2.3 additional tests: original V0.1 and V0.2 cases are immutable.

These are preparer-authored expectations, not independent validation.
"""
import io
import contextlib
import tempfile
from pathlib import Path
import unittest
import zipfile
import evidence_adapter as m

D01 = Path(__file__).resolve().parent / 'security_v023' / 'D01_double_archive_comment.zip'


def plain_zip(data=b'hello'):
    out=io.BytesIO()
    with zipfile.ZipFile(out,'w',compression=zipfile.ZIP_STORED) as z:
        z.writestr('data.txt',data)
    return out.getvalue()


class PrependRecordRegression(unittest.TestCase):
    def reject(self,raw):
        with self.assertRaises(m.EvidenceError) as e:
            m.inspect_zip(raw)
        self.assertEqual(str(e.exception),'PREPENDED_ZIP_RECORDS')

    def test_Y01_claude_D01_double_archive_rejected(self):
        """Y01: exactly supplied Claude D01 double archive is rejected."""
        self.reject(D01.read_bytes())

    def test_Y02_local_header_signature_prefix_rejected(self):
        """Y02: a prepended local ZIP signature is fail-closed."""
        self.reject(b'STUB'+b'PK\x03\x04'+b'other'+plain_zip())

    def test_Y03_benign_prefix_retained(self):
        """Y03: previously allowed unambiguous prefix remains admitted/disclosed."""
        prefix=b'UNINTERPRETED_PREFIX\n'
        out=m.inspect_zip(prefix+plain_zip())
        self.assertEqual(out['prepended_bytes'],len(prefix))
        self.assertEqual(out['member_count'],1)

    def test_Y04_unprefixed_regular_zip_retained(self):
        """Y04: ordinary archive is still inventoried."""
        out=m.inspect_zip(plain_zip())
        self.assertEqual(out['prepended_bytes'],0)
        self.assertTrue(out['members'][0]['complete_member_stream_checked'])

    def test_Y05_mixed_batch_does_not_lose_good_input(self):
        """Y05: malicious double ZIP row is BLOCKED but good row remains INSPECTED."""
        with tempfile.TemporaryDirectory() as d:
            d=Path(d)
            good=d/'good.json';good.write_text('{"ok":true}',encoding='utf-8')
            malicious=d/'ambiguous.zip';malicious.write_bytes(D01.read_bytes())
            r=m.create_report([(good,None,None),(malicious,None,None)])
            self.assertEqual([x['status'] for x in r['evidence_inventory']],['INSPECTED','BLOCKED'])
            self.assertEqual(r['evidence_inventory'][1]['reason'],'PREPENDED_ZIP_RECORDS')
            self.assertEqual(r['final_adapter_assessment'],'BLOCKED')

    def test_Y06_excessive_cli_inputs_controlled_usage(self):
        """Y06: CLI >1000 paths returns usage exit 2, not traceback."""
        with tempfile.TemporaryDirectory() as d:
            output=Path(d)/'report.json'
            with contextlib.redirect_stderr(io.StringIO()) as err:
                with self.assertRaises(SystemExit) as e:
                    m.main(['x.json']*1001+['--output',str(output)])
            self.assertEqual(e.exception.code,2)
            self.assertFalse(output.exists())
            self.assertNotIn('Traceback',err.getvalue())

    def test_Y07_central_directory_signature_prefix_rejected(self):
        """Y07: a prepended central directory signature is rejected."""
        self.reject(b'STUB'+b'PK\x01\x02'+plain_zip())

    def test_Y08_eocd_signature_prefix_rejected(self):
        """Y08: a prepended EOCD signature is rejected."""
        self.reject(b'STUB'+b'PK\x05\x06'+plain_zip())

    def test_Y09_archive_comments_still_accepted(self):
        """Y09: trailing ordinary archive comments remain accepted."""
        out=io.BytesIO()
        with zipfile.ZipFile(out,'w') as z:
            z.writestr('x.txt',b'123')
            z.comment=b'ordinary comment'
        result=m.inspect_zip(out.getvalue())
        self.assertEqual(result['member_count'],1)

if __name__ == '__main__':
    unittest.main()
