import importlib.util
import io
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('tool3105', ROOT / '3105tool.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def zip_blob(entries):
    b = io.BytesIO()
    with zipfile.ZipFile(b, 'w', zipfile.ZIP_DEFLATED) as z:
        for name, data in entries:
            z.writestr(name, data)
    return b.getvalue()


class SecurityTests(unittest.TestCase):
    def test_zip_slip(self):
        for path in ('../evil.pak', '/abs.pak', 'C:/evil.pak', 'folder/../../evil.pak'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                m._zip_bytes_entries(zip_blob([(path, b'a')]))

    def test_duplicate_zip_name(self):
        with self.assertRaisesRegex(ValueError, 'trùng'):
            m._zip_bytes_entries(zip_blob([('a.pak', b'a'), ('a.pak', b'b')]))

    def test_nested_bundle_context(self):
        inner = zip_blob([('game.pak', b'abc')])
        files = m._zip_bytes_entries(zip_blob([('com.pubg.krmobile/inner.zip', inner)]))
        self.assertEqual(files, [('com.pubg.krmobile/game.pak', b'abc')])

    def test_nested_depth(self):
        inner = zip_blob([('game.pak', b'abc')])
        for _ in range(3):
            inner = zip_blob([('inner.zip', inner)])
        with self.assertRaisesRegex(ValueError, 'độ sâu'):
            m._zip_bytes_entries(inner)

    def test_limits(self):
        old = m.MAX_ZIP_UNCOMPRESSED
        m.MAX_ZIP_UNCOMPRESSED = 3
        try:
            with self.assertRaises(ValueError):
                m._zip_bytes_entries(zip_blob([('a.pak', b'1234')]))
        finally:
            m.MAX_ZIP_UNCOMPRESSED = old

    def test_roundtrip_5server(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src, out = td/'in.zip', td/'out.3105'
            src.write_bytes(zip_blob([('game.pak', b'pak-test-data')]))
            cmd = [sys.executable, str(ROOT/'3105tool.py'), 'build', str(src), str(out), '--preset', 'pubg-5sv', '--password', 'MANVIP']
            subprocess.run(cmd, check=True, capture_output=True)
            self.assertTrue(m.verify_file(out, 'MANVIP', quiet=True))
            meta = m.read_container(out)
            _, payload = m.unlock_container(meta, 'MANVIP')
            self.assertEqual(len(payload['project']['rules']), 5)
            self.assertEqual(meta['schemaVersion'], 9)
            self.assertEqual(len(set(r['bundleID'] for r in payload['project']['rules'])), 5)

    def test_preview_matches_build_rules(self):
        entries = [('Resources/1.64.1/Thanos/HeroSkin_1.bytes', b'123')]
        bundles = [m.BUNDLE_LQ]
        preview = m.preview_paths(entries, 'lq', bundles, False, 9)
        rules = m.build_rules_from_entries(entries, 'lq', bundles, False, 9)
        self.assertEqual([x['target'] for x in preview['rows']], [r['relativePath'] for r in rules])


if __name__ == '__main__':
    unittest.main()
