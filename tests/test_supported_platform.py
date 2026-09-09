"""The support boundary is Windows x64, not the formats accepted for analysis."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'scripts'))
from aegis import ROOT, environment, require_windows
from bootstrap import host_key


class SupportedPlatformTests(unittest.TestCase):
    def test_tool_catalog_contains_only_windows_x64(self):
        versions = json.loads((ROOT / 'tools/versions.json').read_text(encoding='utf-8'))
        self.assertEqual(set(versions['platforms']), {'windows-x64'})
        self.assertEqual(versions['platforms']['windows-x64']['rust_host'], 'x86_64-pc-windows-msvc')

    def test_windows_x64_is_accepted(self):
        with patch('aegis.platform.system', return_value='Windows'):
            for arch in ('AMD64', 'x86_64'):
                with patch('aegis.platform.machine', return_value=arch):
                    require_windows()
                    self.assertEqual(host_key(), 'windows-x64')

    def test_other_hosts_fail_before_tool_setup(self):
        for system, arch in [('Darwin', 'arm64'), ('Darwin', 'x86_64'),
                             ('Linux', 'x86_64'), ('Windows', 'ARM64'), ('Windows', 'x86')]:
            with self.subTest(system=system, arch=arch):
                with patch('aegis.platform.system', return_value=system), patch('aegis.platform.machine', return_value=arch):
                    for action in (require_windows, environment, host_key):
                        with self.assertRaisesRegex(RuntimeError, 'Windows x64 only'):
                            action()


if __name__ == '__main__':
    unittest.main()
