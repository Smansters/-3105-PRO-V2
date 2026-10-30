import io
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analysis_engine import analyze_file

class AnalyzerTests(unittest.TestCase):
    def check(self, data, name):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / name
            p.write_bytes(data)
            return analyze_file(p)
    def test_bad_3105(self):
        self.assertEqual(self.check(b'bad', 'fake.3105')['status'], 'FAIL')
    def test_opaque_pak(self):
        self.assertEqual(self.check(b'abc', 'x.pak')['status'], 'WARN')
    def test_valid_zip(self):
        b = io.BytesIO()
        with zipfile.ZipFile(b,'w') as z: z.writestr('a.txt','abc')
        self.assertEqual(self.check(b.getvalue(),'x.zip')['entry_count'],1)
    def test_traversal(self):
        b = io.BytesIO()
        with zipfile.ZipFile(b,'w') as z: z.writestr('../a.txt','abc')
        self.assertEqual(self.check(b.getvalue(),'x.zip')['status'],'FAIL')
