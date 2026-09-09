"""Regression checks for project-local tool lookup on Windows."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'scripts'))
from aegis import environment, resolve_command


class ToolEnvironmentTests(unittest.TestCase):
    def test_environment_does_not_modify_parent(self):
        before = os.environ.copy()
        environment()
        self.assertEqual(dict(os.environ), before)

    def test_windows_proxy_fallback_does_not_override_an_explicit_environment(self):
        with patch.dict(os.environ, {'HTTPS_PROXY': 'http://127.0.0.1:7897'}):
            with patch('aegis.urllib.request.getproxies', return_value={'https': 'http://127.0.0.1:9000'}):
                self.assertEqual(environment()['HTTPS_PROXY'], 'http://127.0.0.1:7897')
        with patch.dict(os.environ, {}, clear=True):
            with patch('aegis.urllib.request.getproxies', return_value={'https': 'http://127.0.0.1:9000'}):
                self.assertEqual(environment()['HTTPS_PROXY'], 'http://127.0.0.1:9000')

    @unittest.skipUnless(os.name == 'nt', 'Windows CreateProcess lookup')
    def test_executable_found_only_in_child_path(self):
        with tempfile.TemporaryDirectory(prefix='aegis tool lookup ') as temporary:
            binary = Path(temporary) / 'aegis-test-command.exe'
            shutil.copy2(os.environ['COMSPEC'], binary)
            env = os.environ.copy()
            env['PATH'] = temporary
            command = resolve_command([binary.stem, '/D', '/C', 'echo tool-found'], env)
            self.assertEqual(Path(command[0]), binary)
            result = subprocess.run(command, env=env, capture_output=True, check=True)
            self.assertIn(b'tool-found', result.stdout)

    @unittest.skipUnless(os.name == 'nt', 'Windows batch launcher')
    def test_pnpm_batch_in_child_path_with_spaces(self):
        with tempfile.TemporaryDirectory(prefix='aegis pnpm lookup ') as temporary:
            launcher = Path(temporary) / 'pnpm.cmd'
            launcher.write_text('@echo off\r\necho %~1\r\n', encoding='ascii')
            env = os.environ.copy()
            env['PATH'] = temporary
            command = resolve_command(['pnpm', 'argument with spaces'], env)
            self.assertEqual(Path(command[0]), launcher)
            result = subprocess.run(command, env=env, capture_output=True, check=True)
            self.assertEqual(result.stdout.strip(), b'argument with spaces')


if __name__ == '__main__':
    unittest.main()
