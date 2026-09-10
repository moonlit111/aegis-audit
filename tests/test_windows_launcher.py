"""Launcher checks that do not require a frozen build or model credentials."""
from contextlib import closing
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'scripts'))
from configure_model import save_settings
from windows_secrets import PREFIX, unprotect_secret
from unittest.mock import patch
from windows_launcher import choose_port, instance_names, ProcessOwner, Windows


class LauncherTests(unittest.TestCase):
    def test_cli_updates_shared_web_settings_and_refuses_active_model_work(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with closing(sqlite3.connect(root / 'aegis.sqlite')) as connection, connection:
                connection.executescript('''
                    CREATE TABLE model_settings(id INTEGER PRIMARY KEY, data TEXT);
                    CREATE TABLE audit_runs(id TEXT PRIMARY KEY, state TEXT);
                    CREATE TABLE audit_workflows(run_id TEXT);
                    CREATE TABLE model_calls(status TEXT,run_id TEXT);
                    INSERT INTO model_settings VALUES(1,'{}');
                    INSERT INTO audit_runs VALUES('r','RUNNING');
                    INSERT INTO audit_workflows VALUES('r');
                ''')
            with self.assertRaises(ValueError):
                save_settings(root, 'new-cli-fixture', 'deepseek-v4-flash')
            with closing(sqlite3.connect(root / 'aegis.sqlite')) as connection, connection:
                self.assertEqual(connection.execute('SELECT data FROM model_settings').fetchone()[0], '{}')
                connection.execute("UPDATE audit_runs SET state='COMPLETED'")
            save_settings(root, 'new-cli-fixture', 'deepseek-v4-flash')
            with closing(sqlite3.connect(root / 'aegis.sqlite')) as connection, connection:
                saved = connection.execute('SELECT data FROM model_settings').fetchone()[0]
            self.assertNotIn('new-cli-fixture', saved)
            settings = json.loads(saved)
            self.assertEqual(unprotect_secret(settings['protected_key']), 'new-cli-fixture')
            self.assertEqual(settings['provider_kind'], 'DEEPSEEK')
            self.assertFalse((root / 'deepseek.token').exists())

    def test_busy_port_is_not_reused(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            port = listener.getsockname()[1]
            with self.assertRaises(RuntimeError):
                choose_port(port)
            self.assertEqual(listener.getsockname()[1], port)

    def test_invalid_ports_are_rejected(self):
        for port in (-1, 0, 65536):
            with self.assertRaises(ValueError):
                choose_port(port)

    def test_instance_ownership_is_scoped_to_the_installation(self):
        with tempfile.TemporaryDirectory() as temporary:
            first = instance_names(Path(temporary) / 'first')
            self.assertEqual(first, instance_names(Path(temporary) / 'first'))
            self.assertNotEqual(first, instance_names(Path(temporary) / 'second'))
            self.assertNotEqual(first[0], first[1])

    def test_model_validation_does_not_overwrite_a_saved_key(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            save_settings(root, 'test-only-not-a-provider-key', 'deepseek-v4-flash')
            for key, model in [('', 'deepseek-v4-flash'), ('contains space', 'deepseek-v4-flash'),
                               ('replacement', 'another-provider')]:
                with self.assertRaises(ValueError):
                    save_settings(root, key, model)
            stored = (root / 'deepseek.token').read_text()
            self.assertTrue(stored.startswith(PREFIX))
            self.assertNotIn('test-only-not-a-provider-key', stored)
            self.assertEqual(unprotect_secret(stored), 'test-only-not-a-provider-key')
            self.assertEqual(json.loads((root / 'model.json').read_text())['model'], 'deepseek-v4-flash')

    def test_failed_atomic_write_preserves_the_previous_credential(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            save_settings(root, 'test-only-previous-key', 'deepseek-v4-flash')
            original = (root / 'deepseek.token').read_bytes()
            replace = os.replace
            def fail_token(source, target):
                if Path(target).name == 'deepseek.token':
                    raise PermissionError('fixture failure')
                return replace(source, target)
            with patch('configure_model.os.replace', side_effect=fail_token):
                with self.assertRaises(PermissionError):
                    save_settings(root, 'test-only-replacement-key', 'deepseek-v4-flash')
            self.assertEqual((root / 'deepseek.token').read_bytes(), original)
            self.assertEqual(list(root.glob('credential-*.tmp')), [])

    def test_corrupt_protected_keys_are_not_treated_as_plaintext(self):
        for value in (PREFIX + '00', PREFIX + 'not-hex', 'aegis-dpapi-v2:00'):
            with self.subTest(value=value):
                with self.assertRaises((ValueError, OSError)):
                    unprotect_secret(value)

    @unittest.skipUnless(os.name == 'nt', 'Windows Job Object')
    def test_closing_the_owner_job_reaps_its_child(self):
        windows = Windows()
        owner = ProcessOwner(windows)
        try:
            child = owner.spawn([os.environ['COMSPEC'], '/D', '/C', 'ping -n 20 127.0.0.1 > NUL'],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
            self.assertIsNone(child.poll())
            windows.require(windows.kernel.CloseHandle(owner.handle))
            owner.handle = None
            child.wait(timeout=10)
            self.assertIsNotNone(child.returncode)
        finally:
            owner.close()


if __name__ == '__main__':
    unittest.main()
