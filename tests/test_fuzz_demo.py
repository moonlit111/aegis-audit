import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

import build_fuzz_demo
from check_fuzz_demo import replay_succeeded


class FuzzDemoTests(unittest.TestCase):
    def test_initial_seeds_match_the_source_and_have_complete_payloads(self):
        config = build_fuzz_demo.configuration('RecordView-1.0.0-fuzz.exe')
        self.assertEqual(config['mode'], 'FUZZ')
        self.assertEqual(config['adapter'], 'WINDOWS_LIBFUZZER_PREBUILT')
        seeds = [seed.encode('utf-8') for seed in config['fuzz']['seeds']]
        source_seeds = [(build_fuzz_demo.SOURCE / name).read_bytes().rstrip(b'\r\n')
                        for name in ('hello.txt', 'demo.txt')]
        self.assertEqual(seeds, source_seeds)
        for seed in seeds:
            self.assertEqual(seed[:5], b'AEG1|')
            self.assertEqual(seed[7:8], b'|')
            self.assertEqual(int(seed[5:7]), len(seed) - 8)

    def test_truncated_boundary_cases_only_run_against_the_fixed_cli(self):
        buggy = {case[0] for case in build_fuzz_demo.cli_cases(False)}
        fixed = {case[0] for case in build_fuzz_demo.cli_cases(True)}
        self.assertEqual(fixed - buggy, {'missing-payload', 'short-payload'})
        self.assertTrue(buggy < fixed)

    def test_cli_boundary_checks_preserve_receipts_outside_the_corpus(self):
        expected = {}
        for fixed, version in ((False, '1.0.0'), (True, '1.0.1')):
            for label, _, code in build_fuzz_demo.cli_cases(fixed):
                expected[(f'RecordView-{version}.exe', label)] = code

        def invoke(command, cwd, env, timeout):
            code = expected[(Path(command[0]).name, Path(command[1]).stem)]
            return {'command': command, 'exit_code': code,
                    'stdout': 'Accepted: record\n' if code == 0 else 'Rejected:\n',
                    'stderr': ''}

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            with patch.object(build_fuzz_demo, 'run', side_effect=invoke):
                receipts = build_fuzz_demo.check_cli(output)
            self.assertEqual(len(receipts), 20)
            self.assertEqual(json.loads((output / 'checks/cli.json').read_text()), receipts)
            self.assertFalse((output / 'corpus').exists())

    def test_cli_boundary_check_rejects_an_unexpected_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(build_fuzz_demo, 'run', return_value={
                    'exit_code': 0, 'stdout': '', 'stderr': ''}):
                with self.assertRaisesRegex(RuntimeError, 'CLI boundary check failed: empty'):
                    build_fuzz_demo.check_cli(Path(directory))

    def test_buggy_replay_requires_an_asan_read_not_just_a_failed_process(self):
        for fuzz in (False, True):
            item = {'fixed': False, 'libfuzzer': fuzz}
            receipt = {'exit_code': 1, 'stdout': '', 'stderr': 'Missing runtime DLL'}
            self.assertFalse(replay_succeeded(item, receipt))
            receipt['stderr'] = 'ERROR: AddressSanitizer: heap-buffer-overflow\nWRITE of size 1'
            self.assertFalse(replay_succeeded(item, receipt))
            receipt['stderr'] = 'ERROR: AddressSanitizer: heap-buffer-overflow\nREAD of size 1'
            self.assertTrue(replay_succeeded(item, receipt))
            receipt['exit_code'] = 0
            self.assertFalse(replay_succeeded(item, receipt))

    def test_fixed_replay_checks_the_cli_and_fuzzer_exit_contracts(self):
        cli = {'fixed': True, 'libfuzzer': False}
        fuzz = {'fixed': True, 'libfuzzer': True}
        receipt = {'exit_code': 3, 'stdout': 'Rejected: invalid or incomplete record.', 'stderr': ''}
        self.assertTrue(replay_succeeded(cli, receipt))
        self.assertFalse(replay_succeeded(fuzz, receipt))
        receipt.update(exit_code=0, stdout='')
        self.assertTrue(replay_succeeded(fuzz, receipt))
        self.assertFalse(replay_succeeded(cli, receipt))
        receipt['stderr'] = 'ERROR: AddressSanitizer: heap-buffer-overflow'
        self.assertFalse(replay_succeeded(fuzz, receipt))


if __name__ == '__main__':
    unittest.main()
