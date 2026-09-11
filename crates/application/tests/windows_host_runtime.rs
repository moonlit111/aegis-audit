use aegis_application::runtime::windows_host::{
    HostRuntimeEntrypoint, HostRuntimeFileTransfer, HostRuntimeOutputPolicy, HostRuntimeSession,
    HostRuntimeSpec, collect_output, prepare, run,
};
use aegis_application::runtime::windows_runtime::{
    WindowsRuntimeAdapter, WindowsRuntimeConfig, WindowsRuntimeEntry, WindowsRuntimeEnvironment,
    WindowsRuntimeInput, WindowsRuntimeMode,
};
use aegis_domain::sha256;
use std::{fs, path::Path, time::Duration};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn host_runtime_runs_powershell_directly() {
    let temporary = tempfile::tempdir().unwrap();
    let target = temporary.path().join("target.exe");
    let script = temporary.path().join("run-pe.ps1");
    fs::write(&target, b"target").unwrap();
    fs::write(
        &script,
        r#"
        param($InputPath, $OutputPath, $PythonPath, $ZigPath)
        Write-Output $PythonPath
$session = Get-Content -LiteralPath (Join-Path $InputPath 'session.json') -Raw | ConvertFrom-Json
[ordered]@{
    schema_version = 1
    run_id = $session.run_id
    attempt_id = $session.attempt_id
    session_id = $session.session_id
    status = 'COMPLETED'
} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $OutputPath 'session.json')
"#,
    )
    .unwrap();

    let config = WindowsRuntimeConfig {
        schema_version: 1,
        config_version: "1".into(),
        mode: WindowsRuntimeMode::Verify,
        adapter: WindowsRuntimeAdapter::OriginalPe64,
        target_path: "target.exe".into(),
        target_sha256: sha256(b"target"),
        entry: WindowsRuntimeEntry::CommandLine {
            path: "target.exe".into(),
            arguments: Vec::new(),
        },
        baseline_inputs: vec![WindowsRuntimeInput::Stdin {
            value: String::new(),
        }],
        probe_inputs: vec![WindowsRuntimeInput::Stdin {
            value: String::new(),
        }],
        repeats: 2,
        timeout_seconds: 5,
        environment: WindowsRuntimeEnvironment {
            python_version: Some("3.13.13".into()),
            observer: Some("FILE_CREATED".into()),
            marker_path: Some("marker.txt".into()),
            ..Default::default()
        },
        fuzz: None,
    };
    let prepared = prepare(&HostRuntimeSpec {
        entrypoint: HostRuntimeEntrypoint::OriginalPe,
        session: HostRuntimeSession {
            run_id: "run-001".into(),
            attempt_id: "attempt-001".into(),
            session_id: "attempt-001-session-001".into(),
            target_sha256: sha256(b"target"),
            config_sha256: config.fingerprint().unwrap(),
        },
        root: temporary.path().join("attempt"),
        tool_root: temporary.path().to_path_buf(),
        inputs: vec![HostRuntimeFileTransfer {
            source: target,
            path: "target.exe".into(),
        }],
        tools: vec![HostRuntimeFileTransfer {
            source: script,
            path: "run-pe.ps1".into(),
        }],
        runtime_config: Some(config),
    })
    .unwrap();

    let execution = run(&prepared, Duration::from_secs(10), CancellationToken::new())
        .await
        .unwrap();
    assert!(
        execution.success,
        "runtime did not succeed: exit={:?} reaped={} timed_out={} cancelled={} stderr={}",
        execution.exit_code,
        execution.processes_reaped,
        execution.timed_out,
        execution.cancelled,
        execution.stderr
    );
    assert_eq!(execution.exit_code, Some(0));
    assert!(!temporary.path().join("attempt/sandbox.wsb").exists());
    assert!(
        execution
            .stdout
            .contains(temporary.path().to_string_lossy().as_ref())
    );

    let output = collect_output(&prepared, &HostRuntimeOutputPolicy::original_pe()).unwrap();
    assert_eq!(output.receipt.status, "COMPLETED");
}

#[tokio::test]
async fn host_runtime_runs_windows_python_directly() {
    let temporary = tempfile::tempdir().unwrap();
    let target = temporary.path().join("store.py");
    fs::write(
        &target,
        r#"from pathlib import Path
def fetch(name):
    if name == "private":
        Path("marker.txt").write_text("created", encoding="ascii")
    return name
"#,
    )
    .unwrap();
    let config = WindowsRuntimeConfig {
        schema_version: 1,
        config_version: "1.0.0".into(),
        mode: WindowsRuntimeMode::Verify,
        adapter: WindowsRuntimeAdapter::PythonCall,
        target_path: "store.py".into(),
        target_sha256: sha256(&fs::read(&target).unwrap()),
        entry: WindowsRuntimeEntry::Function {
            module: "store.py".into(),
            function: "fetch".into(),
        },
        baseline_inputs: vec![WindowsRuntimeInput::Argument {
            value: "public".into(),
        }],
        probe_inputs: vec![WindowsRuntimeInput::Argument {
            value: "private".into(),
        }],
        repeats: 2,
        timeout_seconds: 5,
        environment: WindowsRuntimeEnvironment {
            python_version: Some("3.13.13".into()),
            observer: Some("FILE_CREATED".into()),
            marker_path: Some("marker.txt".into()),
            ..Default::default()
        },
        fuzz: None,
    };
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let prepared = prepare(&HostRuntimeSpec {
        entrypoint: HostRuntimeEntrypoint::WindowsPython,
        session: HostRuntimeSession {
            run_id: "run-002".into(),
            attempt_id: "attempt-002".into(),
            session_id: "attempt-002-session-002".into(),
            target_sha256: config.target_sha256.clone(),
            config_sha256: config.fingerprint().unwrap(),
        },
        root: temporary.path().join("attempt"),
        tool_root: root.join(".tools"),
        inputs: vec![HostRuntimeFileTransfer {
            source: target,
            path: "store.py".into(),
        }],
        tools: vec![
            HostRuntimeFileTransfer {
                source: root.join("tools/windows/runtime/run-python.ps1"),
                path: "run-python.ps1".into(),
            },
            HostRuntimeFileTransfer {
                source: root.join("tools/windows/runtime/run-windows-trials.ps1"),
                path: "run-windows-trials.ps1".into(),
            },
        ],
        runtime_config: Some(config),
    })
    .unwrap();
    let execution = run(&prepared, Duration::from_secs(30), CancellationToken::new())
        .await
        .unwrap();
    assert!(
        execution.success,
        "runtime did not succeed: exit={:?} reaped={} timed_out={} cancelled={} stderr={}",
        execution.exit_code,
        execution.processes_reaped,
        execution.timed_out,
        execution.cancelled,
        execution.stderr
    );
    assert_eq!(execution.exit_code, Some(0));
    let output = collect_output(&prepared, &HostRuntimeOutputPolicy::windows_python()).unwrap();
    let guest_error =
        fs::read_to_string(prepared.output.join("guest-error.json")).unwrap_or_default();
    assert_eq!(
        output.receipt.status, "COMPLETED",
        "guest error: {guest_error}"
    );
}
