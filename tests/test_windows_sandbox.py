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

    def test_upx_runtime_is_pinned_and_installable(self):
        root = Path(__file__).resolve().parents[1]
        versions = json.loads(
            (root / 'tools/windows/versions.json').read_text(encoding='utf-8')
        )
        self.assertEqual(versions['upx']['version'], '5.2.1')
        self.assertEqual(len(versions['upx']['sha256']), 64)
        self.assertIn('upx-5.2.1-win64.zip', versions['upx']['url'])
        self.assertTrue(
            (root / 'tools/windows/install-upx.py').is_file(),
            'the pinned UPX installer must ship with the analysis tools',
        )

    def test_product_runtime_guest_scripts_are_complete(self):
        root = Path(__file__).resolve().parents[1]
        scripts = root / 'tools/windows/sandbox'
        for name in (
            'run-pe.ps1',
            'run-python.ps1',
            'run-native-source.ps1',
            'run-windows-trials.ps1',
        ):
            self.assertTrue((scripts / name).is_file(), f'missing product runtime script: {name}')

    def test_product_runtime_guest_scripts_do_not_shutdown_guest(self):
        root = Path(__file__).resolve().parents[1]
        sandbox = root / 'tools/windows/sandbox'
        for path in sandbox.glob('*.ps1'):
            text = path.read_text(encoding='utf-8-sig')
            self.assertNotIn('shutdown.exe', text, f'{path.name} must let wsb stop own cleanup')
            self.assertNotIn('/s /t', text, f'{path.name} must not initiate guest shutdown')

    def test_runtime_observer_runs_target_as_isolated_low_privilege_user(self):
        root = Path(__file__).resolve().parents[1]
        script = (
            root / 'tools/windows/sandbox/run-windows-trials.ps1'
        ).read_text(encoding='utf-8-sig')
        self.assertIn('function Protect-WindowsRuntimeOutput', script)
        self.assertIn('SetAccessRuleProtection($true, $false)', script)
        self.assertIn('function New-WindowsRuntimeTargetIdentity', script)
        self.assertIn('RandomNumberGenerator', script)
        self.assertIn('New-LocalUser', script)
        self.assertIn('Remove-LocalUser', script)
        self.assertIn("$startInfo.UserName = $TargetUser", script)
        self.assertIn('$startInfo.Password = $TargetPassword', script)
        self.assertIn("UserId 'NT AUTHORITY\\SYSTEM'", script)
        self.assertIn('-ObserverMode', script)
        self.assertIn("if ($MyInvocation.InvocationName -ne '.')", script)

    def test_malicious_observer_tamper_fixture_targets_both_evidence_files(self):
        root = Path(__file__).resolve().parents[1]
        fixture = (
            root / 'tests/fixtures/runtime/observer_tamper.py'
        ).read_text(encoding='utf-8')
        self.assertIn('guest-observation.json', fixture)
        self.assertIn('session.json', fixture)
        self.assertIn('FORGED BY TARGET', fixture)
        self.assertIn("except OSError", fixture)

    def test_runtime_installers_are_available(self):
        root = Path(__file__).resolve().parents[1]
        for name in ('install-zig.py', 'install-llvm.py', 'install-tinyinst.py'):
            self.assertTrue(
                (root / 'tools/windows/sandbox' / name).is_file(),
                f'the pinned runtime installer must ship with the tools: {name}',
            )
        self.assertTrue(
            (root / 'tools/windows/install-upx.py').is_file(),
            'the pinned UPX installer must ship with the tools',
        )


if __name__ == '__main__':
    unittest.main()
