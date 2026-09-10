import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class WindowsRuntimeScriptTests(unittest.TestCase):
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
                "entry": {"type": "COMMAND_LINE", "path": "target.exe", "arguments": []},
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
            self.assertEqual(receipt["status"], "COMPLETED")
            self.assertEqual(len(observation["trials"]), 3)
            self.assertEqual([trial["exit_code"] for trial in observation["trials"]], [0, 0, 0])


if __name__ == "__main__":
    unittest.main()
