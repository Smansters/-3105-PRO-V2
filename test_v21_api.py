import io
import json
import sys
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
try:
    from app import app
except ModuleNotFoundError as exc:
    if exc.name != "flask":
        raise
    app = None

@unittest.skipIf(app is None, "Flask dependency unavailable in test environment")
class V21Tests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def send(self, url, content, filename):
        return self.client.post(url, data={'input_file': (io.BytesIO(content), filename)}, content_type='multipart/form-data')

    def test_health_home(self):
        self.assertEqual(self.client.get('/').status_code, 200)

    def test_analyze_zip(self):
        b = io.BytesIO()
        with zipfile.ZipFile(b, 'w') as z:
            z.writestr('file.txt', 'abc')
        res = self.send('/api/v2.1/analyze', b.getvalue(), 'sample.zip')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json['analysis']['entry_count'], 1)
        self.assertEqual(res.json['analysis']['format'], 'zip')

    def test_reject_fake_container(self):
        res = self.send('/api/v2.1/verify', b'not-a-container', 'bad.3105')
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json['status'], 'FAIL')

    def test_pak_is_not_claimed_verified(self):
        res = self.send('/api/v2.1/analyze', b'unknown bytes', 'sample.pak')
        self.assertEqual(res.json['analysis']['status'], 'WARN')
        self.assertEqual(res.json['analysis']['format'], 'pak-opaque')

    def test_zip_path_traversal(self):
        b = io.BytesIO()
        with zipfile.ZipFile(b, 'w') as z:
            z.writestr('../bad.txt', 'abc')
        res = self.send('/api/v2.1/analyze', b.getvalue(), 'bad.zip')
        self.assertEqual(res.json['analysis']['status'], 'FAIL')
