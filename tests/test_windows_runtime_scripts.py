import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class WindowsRuntimeScriptTests(unittest.TestCase):
    def trial(self, code, arguments=(), stdin="", timeout=5, executable=None):
        with tempfile.TemporaryDirectory(prefix="aegis-runtime-io-") as directory:
            root = Path(directory)
            spec = {
                "program": str(executable or sys.executable),
                "arguments": ["-I", "-X", "utf8", "-c", code, *arguments],
                "stdin": stdin,
                "work": str(root),
                "timeout": timeout,
            }
            config = root / "spec.json"
            config.write_text(json.dumps(spec), encoding="utf-8")
            output = root / "observation.json"
            command = """
$ErrorActionPreference = 'Stop'
. $env:AEGIS_TEST_LIBRARY
$spec = Read-WindowsRuntimeJson $env:AEGIS_TEST_SPEC
$trial = Invoke-WindowsRuntimeTrial -FilePath $spec.program -Arguments $spec.arguments `
    -StandardInput $spec.stdin -Work $spec.work -TimeoutSeconds $spec.timeout `
    -Label 'probe' -Observer 'SANITIZER' -MarkerPath ''
Write-WindowsRuntimeJson -Path $env:AEGIS_TEST_OUTPUT -Value $trial
"""
            started = time.monotonic()
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
                env={
                    **os.environ,
                    "AEGIS_TEST_LIBRARY": str(ROOT / "tools/windows/runtime/run-windows-trials.ps1"),
                    "AEGIS_TEST_SPEC": str(config),
                    "AEGIS_TEST_OUTPUT": str(output),
                },
                capture_output=True, text=True, timeout=20, check=False,
            )
            elapsed = time.monotonic() - started
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return json.loads(output.read_text(encoding="utf-8-sig")), elapsed

    def test_argv_round_trips_quotes_spaces_backslashes_and_empty_values(self):
        arguments = ["", "plain", r"a\b c", "a b\\", 'a\\"b c', 'a"b',
                     "two\twords", "\u4e2d\u6587 \\tail\\", "\\\\server\\share name\\"]
        trial, _ = self.trial("import json, sys; print(json.dumps(sys.argv[1:]))", arguments)
        self.assertEqual(trial["exit_code"], 0)
        self.assertEqual(json.loads(trial["stdout"]), arguments)
        self.assertTrue(trial["processes_reaped"])

    def test_stdin_write_is_covered_by_the_trial_deadline(self):
        trial, elapsed = self.trial("import time; time.sleep(6)", stdin="x" * 65536, timeout=1)
        self.assertTrue(trial["timed_out"])
        self.assertEqual(trial["crash_signature"], "TIMEOUT")
        self.assertFalse(trial["observed"])
        self.assertTrue(trial["processes_reaped"])
        self.assertLess(elapsed, 5)

    def test_large_output_is_drained_with_bounded_capture(self):
        code = "import sys; sys.stdout.write('x' * 1048576); sys.stderr.write('y' * 1048576)"
        trial, _ = self.trial(code)
        self.assertEqual(trial["exit_code"], 0)
        self.assertFalse(trial["timed_out"])
        self.assertTrue(trial["truncated"])
        self.assertEqual(len(trial["stdout"].encode("utf-8")), 256 * 1024)
        self.assertEqual(len(trial["stderr"].encode("utf-8")), 256 * 1024)

    def test_unicode_capture_stays_within_the_byte_limit(self):
        trial, _ = self.trial("import sys; sys.stdout.write(chr(0x4e2d) * 100000)")
        self.assertEqual(trial["exit_code"], 0)
        self.assertTrue(trial["truncated"])
        self.assertLessEqual(len(trial["stdout"].encode("utf-8")), 256 * 1024)

    def test_stderr_keywords_are_not_crash_evidence(self):
        trial, _ = self.trial(
            "import sys; print('AddressSanitizer runtime error: Segmentation fault', file=sys.stderr); sys.exit(1)"
        )
        self.assertEqual(trial["exit_code"], 1)
        self.assertFalse(trial["observed"])
        self.assertEqual(trial["crash_signature"], "EXIT_1")

    def test_native_exception_status_does_not_require_stderr(self):
        # Synthetic NTSTATUS tests classification, not an actual memory-safety defect.
        trial, _ = self.trial("import ctypes; ctypes.windll.kernel32.ExitProcess(0xC0000005)")
        self.assertEqual(trial["stderr"], "")
        self.assertTrue(trial["observed"])
        self.assertEqual(trial["crash_signature"], "NTSTATUS_C0000005")

    def test_start_failure_returns_a_factual_observation(self):
        trial, _ = self.trial("", executable=ROOT / "missing-runtime-test-program.exe")
        self.assertIsNone(trial["exit_code"])
        self.assertTrue(trial["processes_reaped"])
        self.assertTrue(trial["exception"])
        self.assertFalse(trial["observed"])

    def test_original_pe_wrapper_preserves_its_input_arguments(self):
        with tempfile.TemporaryDirectory(prefix="aegis-runtime-script-") as directory:
            root = Path(directory)
            input_path = root / "input"
            output_path = root / "output"
            input_path.mkdir()
            output_path.mkdir()
            target = input_path / "target.exe"
            target.write_bytes(Path(os.environ["COMSPEC"]).read_bytes())
            target_hash = hashlib.sha256(target.read_bytes()).hexdigest()
            session = {
                "schema_version": 1,
                "run_id": "run-001",
                "attempt_id": "attempt-001",
                "session_id": "attempt-001-session-001",
                "target_sha256": target_hash,
                "config_sha256": "0" * 64,
            }
            config = {
                "schema_version": 1,
                "config_version": "1",
                "mode": "VERIFY",
                "adapter": "WINDOWS_ORIGINAL_PE64",
                "target_path": "target.exe",
                "target_sha256": target_hash,
                "entry": {"type": "COMMAND_LINE", "path": "target.exe",
                          "arguments": ["/D", "/C", "echo", "ENTRY_ARGUMENT"]},
                "baseline_inputs": [{"type": "STDIN", "value": ""}],
                "probe_inputs": [{"type": "STDIN", "value": ""}],
                "repeats": 2,
                "timeout_seconds": 5,
                "environment": {"observer": "SANITIZER"},
                "fuzz": None,
            }
            (input_path / "session.json").write_text(
                json.dumps(session, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            (input_path / "runtime-config.json").write_text(
                json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            result = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(ROOT / "tools/windows/runtime/run-pe.ps1"),
                    "-InputPath",
                    str(input_path),
                    "-OutputPath",
                    str(output_path),
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            receipt = json.loads((output_path / "session.json").read_text(encoding="utf-8-sig"))
            observation = json.loads(
                (output_path / "guest-observation.json").read_text(encoding="utf-8-sig")
            )
            error = output_path / "guest-error.json"
            self.assertEqual(
                receipt["status"], "COMPLETED", error.read_text() if error.exists() else ""
            )
            self.assertEqual(len(observation["trials"]), 3)
            self.assertEqual([trial["exit_code"] for trial in observation["trials"]], [0, 0, 0])
            for trial in observation["trials"]:
                self.assertEqual(trial["stdout"].strip(), "ENTRY_ARGUMENT")
                self.assertEqual(json.loads(trial["input_json"])["args"], config["entry"]["arguments"])

    def test_python_wrapper_preserves_json_args_kwargs_globals_and_input_receipts(self):
        with tempfile.TemporaryDirectory(prefix="aegis-runtime-python-") as directory:
            root = Path(directory)
            source = root / "input"
            output = root / "output"
            source.mkdir()
            output.mkdir()
            target = source / "target.py"
            target.write_text(
                "import json\nflag = None\ndef inspect(*args, **kwargs):\n"
                "    return json.dumps({'args': args, 'kwargs': kwargs, 'global': flag})\n",
                encoding="utf-8",
            )
            args = [7, 18446744073709551615, True, None,
                    [1, {"name": "data", "Name": "distinct"}], {"nested": [False]}]
            kwargs = {"setting": {"enabled": True, "value": None}}
            globals_ = {"flag": {"limit": 12, "items": [False, None], "Label": "upper", "label": "lower"}}
            target_hash = hashlib.sha256(target.read_bytes()).hexdigest()
            session = {
                "schema_version": 1, "run_id": "run-json", "attempt_id": "attempt-json",
                "session_id": "session-json", "target_sha256": target_hash, "config_sha256": "0" * 64,
            }
            inputs = [{"type": "PYTHON_CALL", "invocation_json": json.dumps({"args": args, "kwargs": kwargs, "stdin": ""})},
                      {"type": "STDIN", "value": ""}]
            config = {
                "schema_version": 1, "config_version": "1", "mode": "VERIFY",
                "adapter": "WINDOWS_PYTHON_CALL", "target_path": "target.py",
                "target_sha256": target_hash,
                "entry": {"type": "FUNCTION", "module": "target.py", "function": "inspect"},
                "baseline_inputs": inputs, "probe_inputs": inputs,
                "repeats": 2, "timeout_seconds": 5,
                "environment": {"observer": "FILE_CREATED", "marker_path": "marker.txt", "globals_json": json.dumps(globals_)},
                "fuzz": None,
            }
            (source / "session.json").write_text(json.dumps(session), encoding="utf-8")
            (source / "runtime-config.json").write_text(json.dumps(config), encoding="utf-8")
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                 "-File", str(ROOT / "tools/windows/runtime/run-python.ps1"),
                 "-InputPath", str(source), "-OutputPath", str(output),
                 "-PythonPath", str(Path(sys.executable).parent)],
                capture_output=True, text=True, timeout=30, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            receipt = json.loads((output / "session.json").read_text(encoding="utf-8-sig"))
            error = output / "guest-error.json"
            self.assertEqual(receipt["status"], "COMPLETED", error.read_text() if error.exists() else "")
            observation = json.loads((output / "guest-observation.json").read_text(encoding="utf-8-sig"))
            self.assertEqual(len(observation["trials"]), 3)
            for trial in observation["trials"]:
                self.assertEqual(trial["exit_code"], 0, trial["stderr"])
                self.assertEqual(json.loads(trial["stdout"]), {"args": args, "kwargs": kwargs, "global": globals_["flag"]})
                self.assertEqual(json.loads(trial["input_json"]), {"args": args, "kwargs": kwargs, "stdin": ""})

    def test_libfuzzer_runner_preserves_crash_artifact_and_replays_it_twice(self):
        with tempfile.TemporaryDirectory(prefix="aegis-libfuzzer-") as directory:
            root = Path(directory)
            source = root / "input"
            output = root / "output"
            source.mkdir()
            output.mkdir()

            target = source / "fuzz-target.exe"
            powershell = shutil.which("powershell.exe")
            self.assertIsNotNone(powershell)
            shutil.copy2(powershell, target)
            target_hash = hashlib.sha256(target.read_bytes()).hexdigest()

            fake_target = source / "fake-fuzz.ps1"
            fake_target.write_text(
                "Set-Content -LiteralPath (Join-Path (Get-Location) 'crash-fake') "
                "-Value 'crash' -Encoding ASCII\n"
                "exit 77\n",
                encoding="ascii",
            )

            session = {
                "schema_version": 1,
                "run_id": "run-fuzz",
                "attempt_id": "attempt-fuzz",
                "session_id": "attempt-fuzz-session-fuzz",
                "target_sha256": target_hash,
                "config_sha256": "0" * 64,
            }
            config = {
                "schema_version": 1,
                "config_version": "1.0.0",
                "mode": "FUZZ",
                "adapter": "WINDOWS_LIBFUZZER_PREBUILT",
                "target_path": "fuzz-target.exe",
                "target_sha256": target_hash,
                "entry": {
                    "type": "COMMAND_LINE",
                    "path": "fuzz-target.exe",
                    "arguments": [
                        "-NoProfile",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-File",
                        "fake-fuzz.ps1",
                    ],
                },
                "baseline_inputs": [],
                "probe_inputs": [],
                "repeats": 2,
                "timeout_seconds": 5,
                "environment": {
                    "observer": "SANITIZER",
                    "compiler": "LLVM 23.1.1",
                },
                "fuzz": {
                    "engine": "LLVM_LIBFUZZER",
                    "runs": 10,
                    "timeout_seconds": 2,
                    "budget_seconds": 10,
                    "random_seed": 71413,
                    "max_input_bytes": 32,
                    "seeds": ["seed"],
                },
            }
            (source / "session.json").write_text(json.dumps(session), encoding="utf-8")
            (source / "runtime-config.json").write_text(json.dumps(config), encoding="utf-8")

            result = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(ROOT / "tools/windows/runtime/run-libfuzzer.ps1"),
                    "-InputPath",
                    str(source),
                    "-OutputPath",
                    str(output),
                    "-LlvmPath",
                    str(ROOT / ".tools/llvm-min"),
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            receipt = json.loads((output / "session.json").read_text(encoding="utf-8-sig"))
            error = output / "guest-error.json"
            self.assertEqual(
                receipt["status"], "COMPLETED", error.read_text() if error.exists() else ""
            )
            observation = json.loads(
                (output / "guest-observation.json").read_text(encoding="utf-8-sig")
            )
            self.assertEqual(observation["mode"], "FUZZ")
            self.assertEqual(observation["fuzz"]["engine"], "LLVM_LIBFUZZER")
            self.assertTrue(observation["fuzz"]["coverage_feedback"])
            self.assertEqual(len(observation["crashes"]), 1)
            crash = observation["crashes"][0]
            self.assertTrue(crash["reproduced"])
            self.assertEqual(len(crash["replays"]), 2)
            self.assertFalse(crash["minimized"])
            self.assertTrue((output / "crash-01-input.bin").is_file())
            self.assertTrue((output / "crash-01-minimize.stdout.log").is_file())
            self.assertTrue((output / "crash-01-minimize.stderr.log").is_file())


if __name__ == "__main__":
    unittest.main()
