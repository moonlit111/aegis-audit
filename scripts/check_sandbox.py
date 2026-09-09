#!/usr/bin/env python3
"""A01: verify Windows Sandbox boundaries with harmless disposable probes."""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import secrets
import subprocess
import sys
import time
from typing import Any
from xml.etree import ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aegis import ROOT, require_windows

SCHEMA_VERSION = 1
GUEST_TOOLS = r"C:\Users\WDAGUtilityAccount\Desktop\AegisTools"
GUEST_INPUT = r"C:\Users\WDAGUtilityAccount\Desktop\AegisInput"
GUEST_OUTPUT = r"C:\Users\WDAGUtilityAccount\Desktop\AegisOutput"
EXPECTED_OUTPUT = {"guest-observation.json", "output-marker.txt", "session.json"}
EXPECTED_INPUT = {"session.json", "canary.txt"}
MAX_OUTPUT_BYTES = 1024 * 1024
TOOL_FILES = ("probe.ps1",)


class SandboxExecutionError(RuntimeError):
    pass


def utc_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_text_atomic(path: Path, value: str, encoding: str = "utf-8") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(value, encoding=encoding, newline="\n")
    os.replace(temporary, path)


def write_json_atomic(path: Path, value: Any) -> None:
    write_text_atomic(path, json.dumps(value, ensure_ascii=True, indent=2))


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def is_reparse_point(path: Path) -> bool:
    try:
        attributes = path.lstat().st_file_attributes
    except (AttributeError, OSError):
        return False
    return bool(attributes & 0x400)


def mapped_folder(host: Path, guest: str, read_only: bool) -> ET.Element:
    item = ET.Element("MappedFolder")
    ET.SubElement(item, "HostFolder").text = str(host)
    ET.SubElement(item, "SandboxFolder").text = guest
    ET.SubElement(item, "ReadOnly").text = "true" if read_only else "false"
    return item


def sandbox_config(tools: Path, input_dir: Path, output_dir: Path,
                   memory_mb: int) -> ET.ElementTree:
    config = ET.Element("Configuration")
    ET.SubElement(config, "Networking").text = "Disable"
    ET.SubElement(config, "vGPU").text = "Disable"
    ET.SubElement(config, "ClipboardRedirection").text = "Disable"
    ET.SubElement(config, "PrinterRedirection").text = "Disable"
    ET.SubElement(config, "AudioInputRedirection").text = "Disable"
    ET.SubElement(config, "VideoInputRedirection").text = "Disable"
    ET.SubElement(config, "ProtectedClient").text = "Enable"
    ET.SubElement(config, "MemoryInMB").text = str(memory_mb)
    folders = ET.SubElement(config, "MappedFolders")
    folders.append(mapped_folder(tools, GUEST_TOOLS, True))
    folders.append(mapped_folder(input_dir, GUEST_INPUT, True))
    folders.append(mapped_folder(output_dir, GUEST_OUTPUT, False))
    logon = ET.SubElement(config, "LogonCommand")
    command = ET.SubElement(logon, "Command")
    command.text = (
        rf"powershell.exe -NoProfile -ExecutionPolicy Bypass -File {GUEST_TOOLS}\probe.ps1 "
        rf"-InputPath {GUEST_INPUT} -OutputPath {GUEST_OUTPUT}"
    )
    return ET.ElementTree(config)


def prepare_attempt(attempt: Path, session_id: str, memory_mb: int) -> dict[str, Any]:
    if attempt.exists():
        if not attempt.is_dir():
            raise ValueError(f"attempt path is not a directory: {attempt}")
        if any(attempt.iterdir()):
            raise ValueError(f"attempt directory is not empty: {attempt}")
    attempt.mkdir(parents=True, exist_ok=True)
    input_dir = attempt / "input"
    output_dir = attempt / "output"
    input_dir.mkdir()
    output_dir.mkdir()

    session = {
        "schema_version": SCHEMA_VERSION,
        "run_id": "a01",
        "attempt_id": attempt.name,
        "session_id": session_id,
        "created_at": utc_timestamp(),
    }
    write_json_atomic(input_dir / "session.json", session)
    canary = secrets.token_hex(32).encode("ascii")
    (input_dir / "canary.txt").write_bytes(canary)

    source_tools = ROOT / "tools/windows/sandbox"
    tools = attempt / "tools"
    tools.mkdir()
    missing = [name for name in TOOL_FILES if not (source_tools / name).is_file()]
    if missing:
        raise FileNotFoundError(f"missing sandbox probe files: {', '.join(missing)}")
    for name in TOOL_FILES:
        shutil.copyfile(source_tools / name, tools / name)
    for path in (tools, input_dir, output_dir, attempt):
        if is_reparse_point(path):
            raise ValueError(f"reparse point is not an acceptable mapping: {path}")

    config_path = attempt / "sandbox.wsb"
    tree = sandbox_config(tools, input_dir, output_dir, memory_mb)
    ET.indent(tree, space="  ")
    tree.write(config_path, encoding="utf-8", xml_declaration=True)

    files = {
        "session.json": input_dir / "session.json",
        "canary.txt": input_dir / "canary.txt",
        "probe.ps1": tools / "probe.ps1",
        "probe.ps1": tools / "probe.ps1",
    }
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "session_id": session_id,
        "config_sha256": sha256_file(config_path),
        "files": [
            {
                "path": name,
                "sha256": sha256_file(path),
                "size": path.stat().st_size,
            }
            for name, path in files.items()
        ],
    }
    write_json_atomic(attempt / "host-manifest.json", manifest)
    return {
        "attempt": attempt,
        "session_id": session_id,
        "config": config_path,
        "input": input_dir,
        "output": output_dir,
        "manifest": manifest,
    }


def tree_fingerprint(path: Path) -> list[dict[str, Any]]:
    records = []
    for item in sorted(path.rglob("*")):
        if item.is_file():
            reparse = is_reparse_point(item)
            records.append({
                "path": item.relative_to(path).as_posix(),
                "sha256": "" if reparse else sha256_file(item),
                "size": item.stat().st_size,
                "reparse": reparse,
            })
    return records


def check(name: str, passed: bool, details: str = "") -> dict[str, Any]:
    return {"name": name, "passed": bool(passed), "details": details}


def validate_attempt(prepared: dict[str, Any]) -> dict[str, Any]:
    output = prepared["output"]
    manifest = prepared["manifest"]
    session_id = prepared["session_id"]
    checks = []

    input_files = sorted(item.name for item in prepared["input"].iterdir())
    checks.append(check(
        "input_file_set",
        set(input_files) == EXPECTED_INPUT,
        f"actual={input_files}, expected={sorted(EXPECTED_INPUT)}",
    ))

    actual_files = sorted(item.name for item in output.iterdir())
    checks.append(check(
        "output_file_set",
        set(actual_files) == EXPECTED_OUTPUT,
        f"actual={actual_files}, expected={sorted(EXPECTED_OUTPUT)}",
    ))
    for item in output.iterdir():
        if item.is_file():
            size = item.stat().st_size
            checks.append(check(
                f"output_size:{item.name}",
                size <= MAX_OUTPUT_BYTES,
                f"size={size}",
            ))
        checks.append(check(
            f"output_not_reparse:{item.name}",
            item.is_file() and not is_reparse_point(item),
            f"is_file={item.is_file()}, reparse={is_reparse_point(item)}",
        ))

    observation_path = output / "guest-observation.json"
    observation = None
    observation_safe = observation_path.is_file() and not is_reparse_point(observation_path)
    if observation_safe:
        try:
            observation = read_json(observation_path)
        except (OSError, ValueError) as error:
            checks.append(check("observation_json", False, str(error)))
    else:
        checks.append(check(
            "observation_json",
            False,
            "guest observation missing or is a reparse point",
        ))

    if observation is not None:
        checks.append(check(
            "schema_version",
            observation.get("schema_version") == SCHEMA_VERSION,
            f"actual={observation.get('schema_version')}",
        ))
        checks.append(check(
            "session_id",
            observation.get("session_id") == session_id,
            f"actual={observation.get('session_id')}",
        ))
        input_write = observation.get("input_write", {})
        output_write = observation.get("output_write", {})
        network = observation.get("network", {})
        guest = observation.get("guest", {})
        checks.append(check(
            "input_write_rejected",
            input_write.get("allowed") is False,
            json.dumps(input_write, ensure_ascii=True),
        ))
        checks.append(check(
            "output_write_allowed",
            output_write.get("allowed") is True,
            json.dumps(output_write, ensure_ascii=True),
        ))
        checks.append(check(
            "network_dns_disabled",
            network.get("dns", {}).get("succeeded") is False,
            json.dumps(network.get("dns", {}), ensure_ascii=True),
        ))
        checks.append(check(
            "network_tcp_disabled",
            network.get("tcp", {}).get("succeeded") is False,
            json.dumps(network.get("tcp", {}), ensure_ascii=True),
        ))
        checks.append(check(
            "network_default_route_absent",
            network.get("default_route_present") is False,
            json.dumps(network, ensure_ascii=True),
        ))
        checks.append(check(
            "guest_windows_x64",
            guest.get("processor_architecture") == "AMD64",
            json.dumps(guest, ensure_ascii=True),
        ))

    receipt_path = output / "session.json"
    receipt = None
    if receipt_path.is_file():
        try:
            receipt = read_json(receipt_path)
        except (OSError, ValueError) as error:
            checks.append(check("receipt_json", False, str(error)))
    else:
        checks.append(check("receipt_json", False, "sandbox receipt missing"))
    if receipt is not None:
        checks.append(check("receipt_schema_version",
                            receipt.get("schema_version") == SCHEMA_VERSION,
                            f"actual={receipt.get('schema_version')}"))
        checks.append(check("receipt_run_id", receipt.get("run_id") == "a01",
                            f"actual={receipt.get('run_id')}"))
        checks.append(check("receipt_attempt_id",
                            receipt.get("attempt_id") == prepared["attempt"].name,
                            f"actual={receipt.get('attempt_id')}"))
        checks.append(check("receipt_session_id",
                            receipt.get("session_id") == session_id,
                            f"actual={receipt.get('session_id')}"))
        checks.append(check("receipt_status", receipt.get("status") == "COMPLETED",
                            f"actual={receipt.get('status')}"))

    marker_path = output / "output-marker.txt"
    marker_safe = marker_path.is_file() and not is_reparse_point(marker_path)
    marker = (
        marker_path.read_text(encoding="ascii").strip()
        if marker_safe
        else ""
    )
    checks.append(check(
        "output_marker",
        marker == f"session={session_id}",
        f"actual={marker!r}",
    ))

    input_hashes = {
        item["path"]: item["sha256"]
        for item in manifest["files"]
        if item["path"] in EXPECTED_INPUT
    }
    for name, expected_hash in input_hashes.items():
        path = prepared["input"] / name
        path_safe = path.is_file() and not is_reparse_point(path)
        actual_hash = sha256_file(path) if path_safe else ""
        checks.append(check(
            f"input_not_reparse:{name}",
            path_safe,
            f"safe={path_safe}",
        ))
        checks.append(check(
            f"input_unchanged:{name}",
            actual_hash == expected_hash,
            f"expected={expected_hash}, actual={actual_hash}",
        ))

    return {
        "status": "PASSED" if all(item["passed"] for item in checks) else "FAILED",
        "checks": checks,
        "observation": observation,
    }


def sandbox_process_ids() -> set[int]:
    result = subprocess.run(
        ["tasklist", "/FO", "CSV", "/NH"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    )
    ids = set()
    for row in csv.reader(io.StringIO(result.stdout)):
        if row and row[0].startswith("WindowsSandbox"):
            try:
                ids.add(int(row[1]))
            except (IndexError, ValueError):
                continue
    return ids


def matching_remote_session_ids(config: Path) -> set[int]:
    powershell = (
        Path(os.environ.get("SystemRoot", r"C:\Windows"))
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    script = (
        "$config = $env:AEGIS_SANDBOX_CONFIG; "
        "Get-CimInstance Win32_Process "
        "-Filter \"Name = 'WindowsSandboxRemoteSession.exe'\" | "
        "Where-Object { $_.CommandLine -and $_.CommandLine.Contains($config) } | "
        "ForEach-Object { $_.ProcessId }"
    )
    environment = os.environ.copy()
    environment["AEGIS_SANDBOX_CONFIG"] = str(config)
    try:
        result = subprocess.run(
            [str(powershell), "-NoProfile", "-NonInteractive", "-Command", script],
            env=environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired as error:
        raise SandboxExecutionError("sandbox process query timed out") from error
    ids = set()
    for line in result.stdout.splitlines():
        value = line.strip()
        if value.isdigit():
            ids.add(int(value))
    return ids


def run_attempt(prepared: dict[str, Any], timeout_seconds: int) -> dict[str, Any]:
    require_windows()
    if platform.machine().lower() not in ("amd64", "x86_64"):
        raise RuntimeError("Windows Sandbox check requires Windows x64")
    sandbox = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsSandbox.exe"
    if not sandbox.is_file():
        raise FileNotFoundError(f"Windows Sandbox executable is missing: {sandbox}")

    attempt = prepared["attempt"]
    config = prepared["config"].resolve()
    baseline = sandbox_process_ids()
    stdout_path = attempt / "sandbox.stdout.log"
    stderr_path = attempt / "sandbox.stderr.log"
    terminated = False
    termination_output = ""
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        launcher = subprocess.Popen(
            [str(sandbox), str(prepared["config"])],
            stdout=stdout,
            stderr=stderr,
        )

        # WindowsSandbox.exe is a short-lived launcher. The actual remote
        # session process owns the disposable VM and must be awaited separately.
        try:
            launcher.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass

        deadline = time.monotonic() + timeout_seconds
        remote_ids = set()
        while time.monotonic() < deadline:
            remote_ids = matching_remote_session_ids(config)
            if remote_ids:
                break
            time.sleep(1)
        if not remote_ids:
            if launcher.poll() is None:
                launcher.wait(timeout=10)
            return {
                "launcher_return_code": launcher.returncode,
                "remote_session_started": False,
                "remote_session_closed": False,
                "terminated_after_timeout": False,
                "termination_output": "",
                "sandbox_process_baseline": sorted(baseline),
                "sandbox_processes_after": sorted(sandbox_process_ids()),
                "matching_remote_sessions_after": [],
                "exit_ok": False,
            }

        while time.monotonic() < deadline:
            time.sleep(2)
            current = matching_remote_session_ids(config)
            if not current:
                break
        else:
            current = matching_remote_session_ids(config)
            terminated = True
            for pid in sorted(current):
                kill = subprocess.run(
                    ["taskkill", "/PID", str(pid), "/T", "/F"],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    check=False,
                )
                termination_output += (kill.stdout + kill.stderr).strip() + "\n"
            time.sleep(2)

        if launcher.poll() is None:
            try:
                launcher.wait(timeout=30)
            except subprocess.TimeoutExpired:
                subprocess.run(
                    ["taskkill", "/PID", str(launcher.pid), "/T", "/F"],
                    capture_output=True,
                    check=False,
                )
                launcher.wait(timeout=10)

    remaining = matching_remote_session_ids(config)
    result = {
        "launcher_return_code": launcher.returncode,
        "remote_session_started": True,
        "terminated_after_timeout": terminated,
        "termination_output": termination_output.strip(),
        "sandbox_process_baseline": sorted(baseline),
        "sandbox_processes_after": sorted(sandbox_process_ids()),
        "matching_remote_sessions_after": sorted(remaining),
        "exit_ok": launcher.returncode == 0 and not terminated and not remaining,
        "remote_session_closed": not remaining,
    }
    return result


def summary_for_attempt(prepared: dict[str, Any], execution: dict[str, Any] | None,
                        validation: dict[str, Any] | None) -> dict[str, Any]:
    if execution is None:
        status = "NOT_RUN"
    else:
        status = (
            "PASSED"
            if execution.get("exit_ok")
            and execution.get("remote_session_closed")
            and validation is not None
            and validation["status"] == "PASSED"
            else "FAILED"
        )
    return {
        "session_id": prepared["session_id"],
        "attempt": prepared["attempt"].name,
        "config_sha256": prepared["manifest"]["config_sha256"],
        "execution": execution,
        "validation": validation,
        "status": status,
    }


def write_batch_summary(path: Path, batch_id: str, attempts: list[dict[str, Any]],
                        cross_session: dict[str, Any] | None = None,
                        error: str | None = None) -> dict[str, Any]:
    if error:
        status = "FAILED"
    elif attempts and all(item["status"] == "NOT_RUN" for item in attempts):
        status = "NOT_RUN"
    elif attempts and all(item["status"] == "PASSED" for item in attempts) and (
            cross_session is None or cross_session["status"] == "PASSED"):
        status = "PASSED"
    else:
        status = "FAILED"
    summary = {
        "schema_version": SCHEMA_VERSION,
        "batch_id": batch_id,
        "created_at": utc_timestamp(),
        "status": status,
        "attempts": attempts,
        "cross_session": cross_session,
        "error": error,
    }
    write_json_atomic(path, summary)
    return summary


def verify_output_root(path: Path) -> Path:
    root = path.resolve()
    expected_root = (ROOT / ".data" / "verification" / "windows-runtime").resolve()
    if root != expected_root and expected_root not in root.parents:
        raise ValueError(f"output must be under {expected_root}")
    return root


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / ".data" / "verification" / "windows-runtime",
    )
    parser.add_argument("--batch", help="evidence batch name; default is a UTC timestamp")
    parser.add_argument(
        "--sessions",
        type=int,
        choices=(1, 2),
        default=2,
        help="run one probe or two probes for cross-session residue checks",
    )
    parser.add_argument("--timeout", type=int, default=240,
                        help="seconds to wait for each sandbox to finish")
    parser.add_argument("--memory-mb", type=int, default=4096,
                        help="Windows Sandbox memory limit in MiB")
    parser.add_argument("--dry-run", action="store_true",
                        help="generate one attempt without launching Windows Sandbox")
    args = parser.parse_args()

    if not 30 <= args.timeout <= 900:
        parser.error("--timeout must be between 30 and 900 seconds")
    if not 2048 <= args.memory_mb <= 8192:
        parser.error("--memory-mb must be between 2048 and 8192 MiB")

    try:
        output_root = verify_output_root(args.output)
        batch_id = args.batch or time.strftime("a01-%Y%m%d-%H%M%S")
        if batch_id != Path(batch_id).name or not batch_id.replace(".", "").replace("-", "").isalnum():
            raise ValueError("batch name must be a simple file name")
        batch = output_root / batch_id
        if batch.exists():
            if not batch.is_dir():
                raise ValueError(f"batch path is not a directory: {batch}")
            if any(batch.iterdir()):
                raise ValueError(f"batch directory is not empty: {batch}")
        batch.mkdir(parents=True, exist_ok=True)
        summary_path = batch / "summary.json"
        attempts = []
        first_fingerprint = None
        session_count = 1 if args.dry_run else args.sessions

        for index in range(1, session_count + 1):
            session_id = f"{batch_id}-{index:03d}"
            attempt_path = batch / f"attempt-{index:03d}"
            prepared = prepare_attempt(attempt_path, session_id, args.memory_mb)
            execution = None
            validation = None
            if not args.dry_run:
                if index == 2:
                    first_fingerprint = tree_fingerprint(batch / "attempt-001")
                execution = run_attempt(prepared, args.timeout)
                validation = validate_attempt(prepared)
            record = summary_for_attempt(prepared, execution, validation)
            attempts.append(record)
            write_batch_summary(summary_path, batch_id, attempts)
            if record["status"] != "PASSED" and not args.dry_run:
                print(f"A01 status: FAILED at attempt {index}", file=sys.stderr)
                print(f"Evidence: {summary_path}", file=sys.stderr)
                return 2

        cross_session = None
        if args.sessions == 2 and not args.dry_run:
            current_first = tree_fingerprint(batch / "attempt-001")
            unchanged = current_first == first_fingerprint
            session_ids_differ = attempts[0]["session_id"] != attempts[1]["session_id"]
            cross_session = {
                "status": "PASSED" if unchanged and session_ids_differ else "FAILED",
                "first_attempt_unchanged": unchanged,
                "session_ids_differ": session_ids_differ,
            }

        summary = write_batch_summary(summary_path, batch_id, attempts, cross_session)
        print(f"A01 status: {summary['status']}")
        print(f"Evidence: {summary_path}")
        return 0 if summary["status"] in ("PASSED", "NOT_RUN") else 2
    except (OSError, ValueError, SandboxExecutionError) as error:
        fallback = ROOT / ".data" / "verification" / "windows-runtime" / "failed"
        fallback.mkdir(parents=True, exist_ok=True)
        summary = write_batch_summary(
            fallback / f"{time.strftime('%Y%m%d-%H%M%S')}.json",
            f"failed-{time.strftime('%Y%m%d-%H%M%S')}",
            [],
            error=str(error),
        )
        print(f"A01 status: {summary['status']}: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
