"""Archive boundary checks only; these do not replace the real EXE lifecycle test."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'scripts'))
from check_windows_package import clean_environment, unpack_verified


def fixture_package(path, extra=None, corrupt=False):
    files = {
        'AegisAudit.exe': b'archive fixture, not an executable',
        'WINDOWS-STANDALONE.json': json.dumps({'entrypoint': 'AegisAudit.exe',
                                              'api_credentials_included': False}).encode(),
        '.tools/ghidra/docs/typestubs/service/target/__init__.pyi': b'pass\n',
    }
    files.update(extra or {})
    manifest = {'files': [{'path': name, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                          for name, data in files.items()]}
    if corrupt:
        manifest['files'][0]['sha256'] = '0' * 64
    with zipfile.ZipFile(path, 'w') as archive:
        for name, data in files.items():
            archive.writestr('aegis/' + name, data)
        archive.writestr('aegis/PACKAGE-MANIFEST.json', json.dumps(manifest))


class WindowsPackageTests(unittest.TestCase):
    def test_vendor_target_namespace_is_not_a_developer_build_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture_package(root / 'package.zip')
            result = unpack_verified(root / 'package.zip', root / 'install')
            self.assertEqual(result['file_count'], 4)

    def test_private_files_path_escapes_and_windows_collisions_are_rejected(self):
        for extra in ({'.data/server/deepseek.token': b'fixture'}, {'../outside.txt': b'fixture'},
                      {'README.txt': b'a', 'readme.txt': b'b'}, {'.env': b'fixture'}):
            with self.subTest(paths=list(extra)), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                fixture_package(root / 'package.zip', extra)
                with self.assertRaises(ValueError):
                    unpack_verified(root / 'package.zip', root / 'install')
                self.assertFalse((root / 'outside.txt').exists())

    def test_changed_payload_does_not_pass_manifest_verification(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture_package(root / 'package.zip', corrupt=True)
            with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                unpack_verified(root / 'package.zip', root / 'install')

    def test_test_environment_cannot_borrow_developer_tools_or_credentials(self):
        with patch.dict(os.environ, {'DEEPSEEK_API_KEY': 'fixture', 'PYTHONPATH': 'Z:/developer',
                                      'AEGIS_DESKTOP_JOB': 'forged-owner'}):
            environment = clean_environment()
        self.assertNotIn('DEEPSEEK_API_KEY', environment)
        self.assertNotIn('PYTHONPATH', environment)
        self.assertNotIn('AEGIS_DESKTOP_JOB', environment)
        self.assertEqual(environment['PATH'], str(Path(os.environ['SystemRoot']) / 'System32'))


if __name__ == '__main__':
    unittest.main()
