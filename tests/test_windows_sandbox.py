"""Unit checks for the A01 Windows Sandbox evidence generator."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from xml.etree import ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'scripts'))
from check_sandbox import (
    EXPECTED_INPUT,
    EXPECTED_OUTPUT,
    prepare_attempt,
    sandbox_config,
    tree_fingerprint,
    validate_attempt,
)


class WindowsSandboxProbeTests(unittest.TestCase):
    def test_wsb_policy_disables_network_and_devices(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tools = root / 'tools'
            input_dir = root / 'input'
            output_dir = root / 'output'
            for path in (tools, input_dir, output_dir):
                path.mkdir()
            config = sandbox_config(tools, input_dir, output_dir, 4096).getroot()
            values = {
                child.tag: child.text
                for child in config
                if child.tag not in ('MappedFolders', 'LogonCommand')
            }
            self.assertEqual(values['Networking'], 'Disable')
            self.assertEqual(values['vGPU'], 'Disable')
            self.assertEqual(values['ClipboardRedirection'], 'Disable')
            self.assertEqual(values['PrinterRedirection'], 'Disable')
            self.assertEqual(values['AudioInputRedirection'], 'Disable')
            self.assertEqual(values['VideoInputRedirection'], 'Disable')
            self.assertEqual(values['ProtectedClient'], 'Enable')
            self.assertEqual(values['MemoryInMB'], '4096')

            folders = config.find('MappedFolders').findall('MappedFolder')
            policies = {}
            for folder in folders:
                host = Path(folder.find('HostFolder').text).name
                policies[host] = folder.find('ReadOnly').text
            self.assertEqual(policies, {'tools': 'true', 'input': 'true', 'output': 'false'})
            command = config.find('LogonCommand/Command').text
            self.assertIn(r'\AegisTools\probe.ps1', command)
            self.assertIn(r'-InputPath', command)
            self.assertIn(r'-OutputPath', command)

    def test_attempt_contains_only_harmless_probe_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            attempt = Path(temporary) / 'attempt-001'
            prepared = prepare_attempt(attempt, 'session-001', 4096)
            manifest = prepared['manifest']
            self.assertEqual(manifest['schema_version'], 1)
            names = {item['path'] for item in manifest['files']}
            self.assertEqual(
                names,
                {'session.json', 'canary.txt', 'probe.ps1'},
            )
            self.assertTrue((attempt / 'sandbox.wsb').is_file())
            self.assertEqual(
                set(path.name for path in (attempt / 'input').iterdir()),
                EXPECTED_INPUT,
            )
            self.assertEqual(list((attempt / 'output').iterdir()), [])
            self.assertEqual(
                set(path.name for path in (attempt / 'tools').iterdir()),
                {'probe.ps1'},
            )

    def test_validator_rejects_bad_session_network_and_write_results(self):
        with tempfile.TemporaryDirectory() as temporary:
            attempt = Path(temporary) / 'attempt-001'
            prepared = prepare_attempt(attempt, 'session-001', 4096)
            output = prepared['output']
            observation = {
                'schema_version': 1,
                'session_id': 'other-session',
                'guest': {'processor_architecture': 'x86'},
                'input_write': {'allowed': True, 'error': None},
                'output_write': {'allowed': False, 'error': 'fixture'},
                'network': {
                    'dns': {'succeeded': True, 'error': None},
                    'tcp': {'succeeded': True, 'error': None},
                    'default_route_present': True,
                },
            }
            (output / 'guest-observation.json').write_text(
                json.dumps(observation),
                encoding='utf-8',
            )
            (output / 'output-marker.txt').write_text(
                'session=other-session',
                encoding='ascii',
            )
            (output / 'session.json').write_text(
                json.dumps({
                    'schema_version': 1,
                    'run_id': 'other',
                    'attempt_id': 'attempt-001',
                    'session_id': 'session-001',
                    'status': 'COMPLETED',
                }),
                encoding='utf-8',
            )
            (output / 'unexpected.txt').write_text('fixture', encoding='ascii')
            result = validate_attempt(prepared)
            self.assertEqual(result['status'], 'FAILED')
            names = {item['name'] for item in result['checks'] if not item['passed']}
            for required in (
                'output_file_set',
                'session_id',
                'input_write_rejected',
                'output_write_allowed',
                'network_dns_disabled',
                'network_tcp_disabled',
                'network_default_route_absent',
                'guest_windows_x64',
                'output_marker',
                'receipt_run_id',
            ):
                self.assertIn(required, names)

    def test_tree_fingerprint_detects_cross_session_change(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'keep.txt').write_text('unchanged', encoding='ascii')
            before = tree_fingerprint(root)
            (root / 'residue.txt').write_text('new', encoding='ascii')
            self.assertNotEqual(tree_fingerprint(root), before)

    def test_expected_output_names_are_closed(self):
        self.assertEqual(
            EXPECTED_OUTPUT,
            {'guest-observation.json', 'output-marker.txt', 'session.json'},
        )

    def test_zig_runtime_is_pinned_and_installable(self):
        root = Path(__file__).resolve().parents[1]
        versions = json.loads(
            (root / 'tools/windows/versions.json').read_text(encoding='utf-8')
        )
        self.assertEqual(versions['zig']['version'], '0.15.2')
        self.assertEqual(len(versions['zig']['sha256']), 64)
        self.assertTrue(
            (root / 'tools/windows/sandbox/install-zig.py').is_file(),
            'the pinned Zig installer must ship with the runtime tools',
        )

    def test_llvm_fuzzer_runtime_is_pinned_and_installable(self):
        root = Path(__file__).resolve().parents[1]
        versions = json.loads(
            (root / 'tools/windows/versions.json').read_text(encoding='utf-8')
        )
        self.assertEqual(versions['llvm']['version'], '23.1.1')
        self.assertEqual(len(versions['llvm']['sha256']), 64)
        self.assertIn('clang%2Bllvm', versions['llvm']['url'])
        self.assertTrue(
            (root / 'tools/windows/sandbox/install-llvm.py').is_file(),
            'the pinned LLVM installer must ship with the runtime tools',
        )

    def test_tinyinst_runtime_is_pinned(self):
        root = Path(__file__).resolve().parents[1]
        versions = json.loads(
            (root / 'tools/windows/versions.json').read_text(encoding='utf-8')
        )
        self.assertEqual(
            versions['tinyinst']['version'],
            '9b564702c01481825e4a1629d1701cf49d3d091f',
        )
        self.assertEqual(
            versions['tinyinst']['url'],
            'https://github.com/googleprojectzero/tinyinst.git',
        )

    def test_runtime_installers_are_available(self):
        root = Path(__file__).resolve().parents[1]
        for name in ('install-zig.py', 'install-llvm.py', 'install-tinyinst.py'):
            self.assertTrue(
                (root / 'tools/windows/sandbox' / name).is_file(),
                f'the pinned runtime installer must ship with the tools: {name}',
            )


if __name__ == '__main__':
    unittest.main()
