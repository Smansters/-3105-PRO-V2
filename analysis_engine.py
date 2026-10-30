"""Non-destructive format diagnostics for 3105 PRO Editor V2.1."""
import hashlib
import io
import json
import plistlib
import zipfile
from pathlib import Path

MAGIC = b'3105PATCH\x00'


def analyze_file(path, display_name=None):
    path = Path(path)
    raw = path.read_bytes()
    result = {'filename': display_name or path.name, 'size': len(raw),
              'sha256': hashlib.sha256(raw).hexdigest(), 'format': 'unknown',
              'warnings': [], 'errors': [], 'entries': [], 'entry_count': 0}
    if raw.startswith(MAGIC):
        result['format'] = '3105'
        try:
            obj = plistlib.loads(raw[len(MAGIC):])
            if not isinstance(obj, dict):
                raise ValueError('Container plist không phải dictionary')
            result['metadata'] = {key: obj.get(key) for key in ('schemaVersion', 'packageID', 'isPasswordProtected', 'keyAADVersion') if isinstance(obj.get(key), (str, int, bool))}
            if 'encryptedPayload' not in obj:
                result['errors'].append('Thiếu encryptedPayload')
        except Exception as exc:
            result['errors'].append('Không đọc được plist: ' + str(exc))
    elif zipfile.is_zipfile(io.BytesIO(raw)):
        result['format'] = 'ipa' if (display_name or path.name).lower().endswith('.ipa') else 'zip'
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            names = set()
            for info in z.infolist():
                if info.is_dir():
                    continue
                name = info.filename
                if name in names:
                    result['warnings'].append('Trùng tên entry: ' + name)
                names.add(name)
                if name.startswith('/') or '..' in name.replace('\\', '/').split('/'):
                    result['errors'].append('Đường dẫn entry không an toàn: ' + name)
                result['entries'].append({'name': name, 'size': info.file_size, 'compressed_size': info.compress_size})
            result['entry_count'] = len(result['entries'])
            if result['format'] == 'ipa' and not any(n.startswith('Payload/') and '.app/' in n for n in names):
                result['warnings'].append('IPA không chứa Payload/*.app/')
    else:
        suffix = (display_name or path.name).lower()
        if suffix.endswith('.pak'):
            result['format'] = 'pak-opaque'
            result['warnings'].append('PAK cần parser tương thích phiên bản để đọc nội dung; chưa xác minh cấu trúc')
        elif suffix.endswith(('.zip', '.ipa', '.3105')):
            result['errors'].append('Nội dung không khớp định dạng hoặc file hỏng')
    result['status'] = 'FAIL' if result['errors'] else ('WARN' if result['warnings'] else 'PASS')
    return result
