use aegis_application::runtime::windows_runtime::{
    WindowsFuzzOptions, WindowsRuntimeAdapter, WindowsRuntimeConfig, WindowsRuntimeEntry,
    WindowsRuntimeEnvironment, WindowsRuntimeInput, WindowsRuntimeMode,
};
use aegis_application::runtime::windows_sandbox::{
    GUEST_LLVM, GUEST_PYTHON, GUEST_TINYINST, GUEST_ZIG, SandboxEntrypoint, SandboxFileTransfer,
    SandboxMapping, SandboxOutputPolicy, SandboxSession, SandboxSpec, collect_output, prepare,
    run_libfuzzer, run_native_source, run_original_pe, run_probe, run_tinyinst, run_windows_python,
    verify_inputs,
};
use aegis_domain::{id, sha256};
use serde_json::json;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};
use tokio_util::sync::CancellationToken;

fn session() -> SandboxSession {
    SandboxSession {
        run_id: "run-001".into(),
        attempt_id: "attempt-001".into(),
        session_id: "attempt-001-session-001".into(),
        target_sha256: sha256(b"target"),
        config_sha256: sha256(b"config"),
        memory_mb: 4096,
    }
}

fn transfer(source: &Path, path: &str) -> SandboxFileTransfer {
    SandboxFileTransfer {
        source: source.to_path_buf(),
        path: path.into(),
    }
}

fn write_receipt(root: &Path, status: &str) {
    let value = json!({
        "schema_version": 1,
        "run_id": "run-001",
        "attempt_id": "attempt-001",
        "session_id": "attempt-001-session-001",
        "status": status
    });
    fs::write(
        root.join("output/session.json"),
        serde_json::to_vec_pretty(&value).unwrap(),
    )
    .unwrap();
}

#[test]
fn sandbox_attempt_has_minimal_mappings_and_fixed_entrypoint() {
    let temporary = tempfile::tempdir().unwrap();
    let target = temporary.path().join("target.zip");
    let tool = temporary.path().join("probe.ps1");
    fs::write(&target, b"target").unwrap();
    fs::write(&tool, b"param($InputPath, $OutputPath)\n").unwrap();
    let root = temporary.path().join("attempt-001");
    let prepared = prepare(&SandboxSpec {
        entrypoint: SandboxEntrypoint::BoundaryProbe,
        session: session(),
        root: root.clone(),
        inputs: vec![transfer(&target, "target.zip")],
        tools: vec![transfer(&tool, "probe.ps1")],
        mappings: Vec::new(),
        runtime_config: None,
    })
    .unwrap();

    assert!(prepared.input.join("target.zip").is_file());
    assert!(prepared.input.join("session.json").is_file());
    assert!(prepared.tools.join("probe.ps1").is_file());
    assert_eq!(fs::read_dir(&prepared.output).unwrap().count(), 0);
    verify_inputs(&prepared).unwrap();

    let config = fs::read_to_string(&prepared.config).unwrap();
    assert!(config.contains("<Networking>Disable</Networking>"));
    assert!(config.contains("<ProtectedClient>Enable</ProtectedClient>"));
    assert!(config.contains("<MemoryInMB>4096</MemoryInMB>"));
    assert!(config.contains("<ReadOnly>true</ReadOnly>"));
    assert!(config.contains("<ReadOnly>false</ReadOnly>"));
    assert!(config.contains(r"\AegisTools\probe.ps1"));
    assert!(config.contains(r"\AegisInput"));
    assert!(config.contains(r"\AegisOutput"));
    assert!(!config.contains("docker"));
    assert!(!config.contains("cmd.exe"));

    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&prepared.manifest).unwrap()).unwrap();
    assert_eq!(manifest["session"]["session_id"], "attempt-001-session-001");
    assert_eq!(manifest["policy"]["networking"], "DISABLED");
    assert_eq!(
        manifest["input_files"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|item| item["path"] == "target.zip")
            .count(),
        1
    );
}

#[test]
fn sandbox_imports_reject_traversal_and_duplicate_paths() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("input.txt");
    fs::write(&source, b"input").unwrap();
    let root = temporary.path().join("attempt-001");
    let spec = SandboxSpec {
        entrypoint: SandboxEntrypoint::BoundaryProbe,
        session: session(),
        root,
        inputs: vec![transfer(&source, "../escape.txt")],
        tools: vec![],
        mappings: Vec::new(),
        runtime_config: None,
    };
    assert!(prepare(&spec).is_err());

    let root = temporary.path().join("attempt-002");
    let spec = SandboxSpec {
        entrypoint: SandboxEntrypoint::BoundaryProbe,
        session: SandboxSession {
            attempt_id: "attempt-002".into(),
            session_id: "attempt-002-session-001".into(),
            ..session()
        },
        root,
        inputs: vec![transfer(&source, "a.txt"), transfer(&source, "a.txt")],
        tools: vec![],
        mappings: Vec::new(),
        runtime_config: None,
    };
    assert!(prepare(&spec).is_err());
}

#[test]
fn output_receipt_binds_files_to_the_current_attempt() {
    let temporary = tempfile::tempdir().unwrap();
    let target = temporary.path().join("target.zip");
    let tool = temporary.path().join("probe.ps1");
    fs::write(&target, b"target").unwrap();
    fs::write(&tool, b"param($InputPath, $OutputPath)\n").unwrap();
    let root = temporary.path().join("attempt-001");
    let prepared = prepare(&SandboxSpec {
        entrypoint: SandboxEntrypoint::BoundaryProbe,
        session: session(),
        root: root.clone(),
        inputs: vec![transfer(&target, "target.zip")],
        tools: vec![transfer(&tool, "probe.ps1")],
        mappings: Vec::new(),
        runtime_config: None,
    })
    .unwrap();
    write_receipt(&root, "COMPLETED");
    fs::write(root.join("output/output-marker.txt"), b"session=ok").unwrap();
    fs::write(
        root.join("output/guest-observation.json"),
        br#"{"schema_version":1}"#,
    )
    .unwrap();

    let output = collect_output(&prepared, &SandboxOutputPolicy::probe()).unwrap();
    assert_eq!(output.receipt.status, "COMPLETED");
    assert_eq!(output.artifacts.len(), 3);
    assert!(output.total_bytes > 0);

    fs::write(root.join("output/unexpected.txt"), b"not allowed").unwrap();
    assert!(collect_output(&prepared, &SandboxOutputPolicy::probe()).is_err());
    fs::remove_file(root.join("output/unexpected.txt")).unwrap();

    fs::write(
        root.join("output/session.json"),
        r#"{"schema_version":1,"run_id":"other","attempt_id":"attempt-001","session_id":"attempt-001-session-001","status":"COMPLETED"}"#,
    )
    .unwrap();
    assert!(collect_output(&prepared, &SandboxOutputPolicy::probe()).is_err());
}

#[test]
fn changed_inputs_and_oversized_outputs_are_rejected() {
    let temporary = tempfile::tempdir().unwrap();
    let target = temporary.path().join("target.zip");
    let tool = temporary.path().join("probe.ps1");
    fs::write(&target, b"target").unwrap();
    fs::write(&tool, b"param($InputPath, $OutputPath)\n").unwrap();
    let root = temporary.path().join("attempt-001");
    let prepared = prepare(&SandboxSpec {
        entrypoint: SandboxEntrypoint::BoundaryProbe,
        session: session(),
        root: root.clone(),
        inputs: vec![transfer(&target, "target.zip")],
        tools: vec![transfer(&tool, "probe.ps1")],
        mappings: Vec::new(),
        runtime_config: None,
    })
    .unwrap();
    fs::write(prepared.input.join("target.zip"), b"changed").unwrap();
    assert!(verify_inputs(&prepared).is_err());

    let policy = SandboxOutputPolicy {
        max_file_bytes: 2,
        ..SandboxOutputPolicy::probe()
    };
    write_receipt(&root, "COMPLETED");
    fs::write(root.join("output/output-marker.txt"), b"123456").unwrap();
    assert!(collect_output(&prepared, &policy).is_err());
}

#[test]
fn original_pe_attempt_writes_a_bounded_runtime_contract() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let target = temporary.path().join("sample.exe");
    let target_bytes = b"benign PE fixture";
    fs::write(&target, target_bytes).unwrap();
    let config = WindowsRuntimeConfig {
        schema_version: 1,
        config_version: "1".into(),
        mode: WindowsRuntimeMode::Verify,
        adapter: WindowsRuntimeAdapter::OriginalPe64,
        target_path: "sample.exe".into(),
        target_sha256: sha256(target_bytes),
        entry: WindowsRuntimeEntry::CommandLine {
            path: "sample.exe".into(),
            arguments: vec![],
        },
        baseline_inputs: vec![WindowsRuntimeInput::Stdin { value: "A".into() }],
        probe_inputs: vec![WindowsRuntimeInput::Stdin {
            value: String::new(),
        }],
        repeats: 2,
        timeout_seconds: 5,
        fuzz: None,
        environment: Default::default(),
    };
    let fingerprint = config.fingerprint().unwrap();
    let attempt = temporary.path().join("attempt-001");
    let prepared = prepare(&SandboxSpec {
        entrypoint: SandboxEntrypoint::OriginalPe,
        session: SandboxSession {
            run_id: "run-001".into(),
            attempt_id: "attempt-001".into(),
            session_id: "attempt-001-session-001".into(),
            target_sha256: sha256(target_bytes),
            config_sha256: fingerprint,
            memory_mb: 4096,
        },
        root: attempt.clone(),
        inputs: vec![transfer(&target, "sample.exe")],
        tools: vec![transfer(
            &root.join("tools/windows/sandbox/run-pe.ps1"),
            "run-pe.ps1",
        )],
        mappings: Vec::new(),
        runtime_config: Some(config),
    })
    .unwrap();

    assert!(prepared.input.join("runtime-config.json").is_file());
    assert!(prepared.tools.join("run-pe.ps1").is_file());
    let wsb = fs::read_to_string(&prepared.config).unwrap();
    assert!(wsb.contains(r"\AegisTools\run-pe.ps1"));
    assert_eq!(prepared.entrypoint, SandboxEntrypoint::OriginalPe);
}

#[test]
fn windows_python_attempt_maps_a_read_only_runtime() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let target = temporary.path().join("target.py");
    let target_bytes = b"def main():\n    return 'python-ok'\n";
    fs::write(&target, target_bytes).unwrap();
    let python_runtime = temporary.path().join("python");
    fs::create_dir(&python_runtime).unwrap();
    fs::write(python_runtime.join("python.exe"), b"placeholder").unwrap();
    let config = WindowsRuntimeConfig {
        schema_version: 1,
        config_version: "1".into(),
        mode: WindowsRuntimeMode::Verify,
        adapter: WindowsRuntimeAdapter::PythonCall,
        target_path: "target.py".into(),
        target_sha256: sha256(target_bytes),
        entry: WindowsRuntimeEntry::Function {
            module: "target.py".into(),
            function: "main".into(),
        },
        baseline_inputs: vec![WindowsRuntimeInput::Stdin {
            value: String::new(),
        }],
        probe_inputs: vec![WindowsRuntimeInput::Stdin {
            value: String::new(),
        }],
        repeats: 2,
        timeout_seconds: 5,
        fuzz: None,
        environment: aegis_application::runtime::windows_runtime::WindowsRuntimeEnvironment {
            python_version: Some("3.13.13".into()),
            ..Default::default()
        },
    };
    let fingerprint = config.fingerprint().unwrap();
    let prepared = prepare(&SandboxSpec {
        entrypoint: SandboxEntrypoint::WindowsPython,
        session: SandboxSession {
            run_id: "run-001".into(),
            attempt_id: "attempt-001".into(),
            session_id: "attempt-001-session-001".into(),
            target_sha256: sha256(target_bytes),
            config_sha256: fingerprint,
            memory_mb: 4096,
        },
        root: temporary.path().join("attempt-001"),
        inputs: vec![transfer(&target, "target.py")],
        tools: vec![transfer(
            &root.join("tools/windows/sandbox/run-python.ps1"),
            "run-python.ps1",
        )],
        mappings: vec![SandboxMapping {
            host: python_runtime,
            guest: GUEST_PYTHON.into(),
            read_only: true,
        }],
        runtime_config: Some(config),
    })
    .unwrap();

    assert!(prepared.input.join("runtime-config.json").is_file());
    assert!(prepared.tools.join("run-python.ps1").is_file());
    let wsb = fs::read_to_string(&prepared.config).unwrap();
    assert!(wsb.contains(r"\AegisTools\run-python.ps1"));
    assert!(wsb.contains(r"\AegisPython"));
}

#[test]
fn native_source_attempt_maps_a_read_only_zig_runtime() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let target = temporary.path().join("target.c");
    let target_bytes =
        b"#include <stdio.h>\nint main(void) { printf(\"native-ok\\n\"); return 0; }\n";
    fs::write(&target, target_bytes).unwrap();
    let zig_runtime = temporary.path().join("zig");
    fs::create_dir(&zig_runtime).unwrap();
    fs::write(zig_runtime.join("zig.exe"), b"placeholder").unwrap();
    let config = WindowsRuntimeConfig {
        schema_version: 1,
        config_version: "1".into(),
        mode: WindowsRuntimeMode::Verify,
        adapter: WindowsRuntimeAdapter::NativeSource,
        target_path: "target.c".into(),
        target_sha256: sha256(target_bytes),
        entry: WindowsRuntimeEntry::CommandLine {
            path: "target.c".into(),
            arguments: vec![],
        },
        baseline_inputs: vec![WindowsRuntimeInput::Stdin {
            value: String::new(),
        }],
        probe_inputs: vec![WindowsRuntimeInput::Stdin {
            value: String::new(),
        }],
        repeats: 2,
        timeout_seconds: 5,
        fuzz: None,
        environment: WindowsRuntimeEnvironment {
            compiler: Some("zig 0.15.2".into()),
            ..Default::default()
        },
    };
    let fingerprint = config.fingerprint().unwrap();
    let prepared = prepare(&SandboxSpec {
        entrypoint: SandboxEntrypoint::WindowsNativeSource,
        session: SandboxSession {
            run_id: "run-001".into(),
            attempt_id: "attempt-001".into(),
            session_id: "attempt-001-session-001".into(),
            target_sha256: sha256(target_bytes),
            config_sha256: fingerprint,
            memory_mb: 4096,
        },
        root: temporary.path().join("attempt-001"),
        inputs: vec![transfer(&target, "target.c")],
        tools: vec![transfer(
            &root.join("tools/windows/sandbox/run-native-source.ps1"),
            "run-native-source.ps1",
        )],
        mappings: vec![SandboxMapping {
            host: zig_runtime,
            guest: GUEST_ZIG.into(),
            read_only: true,
        }],
        runtime_config: Some(config),
    })
    .unwrap();

    assert!(prepared.input.join("runtime-config.json").is_file());
    assert!(prepared.tools.join("run-native-source.ps1").is_file());
    let wsb = fs::read_to_string(&prepared.config).unwrap();
    assert!(wsb.contains(r"\AegisTools\run-native-source.ps1"));
    assert!(wsb.contains(r"\AegisZig"));
}

#[test]
fn tinyinst_attempt_maps_a_read_only_engine_runtime() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let target = temporary.path().join("target.exe");
    let target_bytes = b"benign PE fixture";
    fs::write(&target, target_bytes).unwrap();
    let engine = temporary.path().join("tinyinst");
    fs::create_dir(&engine).unwrap();
    fs::write(engine.join("litecov.exe"), b"placeholder").unwrap();
    let config = WindowsRuntimeConfig {
        schema_version: 1,
        config_version: "1".into(),
        mode: WindowsRuntimeMode::Verify,
        adapter: WindowsRuntimeAdapter::OriginalPe64,
        target_path: "target.exe".into(),
        target_sha256: sha256(target_bytes),
        entry: WindowsRuntimeEntry::CommandLine {
            path: "target.exe".into(),
            arguments: vec![],
        },
        baseline_inputs: vec![WindowsRuntimeInput::Stdin {
            value: String::new(),
        }],
        probe_inputs: vec![WindowsRuntimeInput::Stdin {
            value: String::new(),
        }],
        repeats: 2,
        timeout_seconds: 5,
        fuzz: None,
        environment: Default::default(),
    };
    let fingerprint = config.fingerprint().unwrap();
    let prepared = prepare(&SandboxSpec {
        entrypoint: SandboxEntrypoint::TinyInstPe,
        session: SandboxSession {
            run_id: "run-001".into(),
            attempt_id: "attempt-001".into(),
            session_id: "attempt-001-session-001".into(),
            target_sha256: sha256(target_bytes),
            config_sha256: fingerprint,
            memory_mb: 4096,
        },
        root: temporary.path().join("attempt-001"),
        inputs: vec![transfer(&target, "target.exe")],
        tools: vec![transfer(
            &root.join("tools/windows/sandbox/run-tinyinst.ps1"),
            "run-tinyinst.ps1",
        )],
        mappings: vec![SandboxMapping {
            host: engine,
            guest: GUEST_TINYINST.into(),
            read_only: true,
        }],
        runtime_config: Some(config),
    })
    .unwrap();

    assert!(prepared.input.join("runtime-config.json").is_file());
    assert!(prepared.tools.join("run-tinyinst.ps1").is_file());
    let wsb = fs::read_to_string(&prepared.config).unwrap();
    assert!(wsb.contains(r"\AegisTools\run-tinyinst.ps1"));
    assert!(wsb.contains(r"\AegisTinyInst"));
}

#[tokio::test]
#[ignore = "requires Windows Sandbox and a harmless disposable guest"]
async fn native_windows_sandbox_probe_lifecycle() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let target = temporary.path().join("target.txt");
    fs::write(&target, b"harmless target").unwrap();
    let tool = root.join("tools/windows/sandbox/probe.ps1");
    let unique = id();
    let attempt = temporary.path().join("attempt-001");
    let prepared = prepare(&SandboxSpec {
        entrypoint: SandboxEntrypoint::BoundaryProbe,
        session: SandboxSession {
            run_id: format!("run-{unique}"),
            attempt_id: "attempt-001".into(),
            session_id: format!("attempt-001-session-{unique}"),
            target_sha256: sha256(b"harmless target"),
            config_sha256: sha256(b"native windows sandbox probe"),
            memory_mb: 4096,
        },
        root: attempt.clone(),
        inputs: vec![transfer(&target, "target.txt")],
        tools: vec![transfer(&tool, "probe.ps1")],
        mappings: Vec::new(),
        runtime_config: None,
    })
    .unwrap();

    let execution = run_probe(
        &prepared,
        Duration::from_secs(240),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    verify_inputs(&prepared).unwrap();
    let output = collect_output(&prepared, &SandboxOutputPolicy::probe()).unwrap();
    assert!(execution.success, "{execution:?}");
    assert!(execution.remote_session_started && execution.remote_session_closed);
    assert!(!execution.timed_out && !execution.cancelled);
    assert_eq!(output.receipt.status, "COMPLETED");
    assert_eq!(output.artifacts.len(), 3);

    let observation_path = prepared.output.join("guest-observation.json");
    let observation_text = fs::read_to_string(observation_path).unwrap();
    let observation: serde_json::Value =
        serde_json::from_str(observation_text.trim_start_matches('\u{feff}')).unwrap();
    assert_eq!(observation["input_write"]["allowed"], false);
    assert_eq!(observation["output_write"]["allowed"], true);
    assert_eq!(observation["network"]["dns"]["succeeded"], false);
    assert_eq!(observation["network"]["tcp"]["succeeded"], false);
    assert_eq!(observation["network"]["default_route_present"], false);

    if let Some(evidence) = std::env::var_os("AEGIS_SANDBOX_EVIDENCE") {
        let evidence = Path::new(&evidence);
        fs::create_dir_all(evidence).unwrap();
        fs::write(
            evidence.join("summary.json"),
            serde_json::to_vec_pretty(&json!({
                "observed_at": aegis_domain::now(),
                "platform": "windows/x86_64",
                "execution": execution,
                "receipt": output.receipt,
                "artifacts": output.artifacts,
                "observation": observation,
                "formal_target": false
            }))
            .unwrap(),
        )
        .unwrap();
    }
}

#[tokio::test]
#[ignore = "requires Windows Sandbox and a harmless disposable guest"]
async fn native_windows_sandbox_probe_cancellation() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let target_bytes = b"harmless cancellation target";
    let unique = id();
    let temporary = tempfile::tempdir().unwrap();
    let target = temporary.path().join("target.txt");
    fs::write(&target, target_bytes).unwrap();
    let evidence_root = std::env::var_os("AEGIS_SANDBOX_EVIDENCE")
        .map(PathBuf::from)
        .unwrap_or_else(|| temporary.path().to_path_buf());
    fs::create_dir_all(&evidence_root).unwrap();
    let attempt = evidence_root.join(format!("attempt-{unique}"));
    let prepared = prepare(&SandboxSpec {
        entrypoint: SandboxEntrypoint::BoundaryProbe,
        session: SandboxSession {
            run_id: format!("run-{unique}"),
            attempt_id: "attempt-001".into(),
            session_id: format!("attempt-001-session-{unique}"),
            target_sha256: sha256(target_bytes),
            config_sha256: sha256(b"native sandbox cancellation"),
            memory_mb: 4096,
        },
        root: attempt.clone(),
        inputs: vec![transfer(&target, "target.txt")],
        tools: vec![transfer(
            &root.join("tools/windows/sandbox/probe.ps1"),
            "probe.ps1",
        )],
        mappings: Vec::new(),
        runtime_config: None,
    })
    .unwrap();

    let cancel = CancellationToken::new();
    let trigger = cancel.clone();
    let canceller = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        trigger.cancel();
    });
    let execution = run_probe(&prepared, Duration::from_secs(240), cancel)
        .await
        .unwrap();
    canceller.await.unwrap();
    verify_inputs(&prepared).unwrap();

    assert!(execution.cancelled, "{execution:?}");
    assert!(execution.remote_session_started, "{execution:?}");
    assert!(execution.remote_session_closed, "{execution:?}");
    assert!(!execution.success, "{execution:?}");

    if let Some(evidence) = std::env::var_os("AEGIS_SANDBOX_EVIDENCE") {
        let evidence = Path::new(&evidence);
        fs::create_dir_all(evidence).unwrap();
        fs::write(
            evidence.join("cancellation-summary.json"),
            serde_json::to_vec_pretty(&json!({
                "observed_at": aegis_domain::now(),
                "platform": "windows/x86_64",
                "execution": execution,
                "formal_target": false
            }))
            .unwrap(),
        )
        .unwrap();
    }
}

#[tokio::test]
#[ignore = "requires Windows Sandbox and a harmless disposable guest"]
async fn native_windows_sandbox_probe_timeout() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let target_bytes = b"harmless timeout target";
    let unique = id();
    let temporary = tempfile::tempdir().unwrap();
    let target = temporary.path().join("target.txt");
    fs::write(&target, target_bytes).unwrap();
    let evidence_root = std::env::var_os("AEGIS_SANDBOX_EVIDENCE")
        .map(PathBuf::from)
        .unwrap_or_else(|| temporary.path().to_path_buf());
    fs::create_dir_all(&evidence_root).unwrap();
    let attempt = evidence_root.join(format!("attempt-{unique}"));
    let prepared = prepare(&SandboxSpec {
        entrypoint: SandboxEntrypoint::BoundaryProbe,
        session: SandboxSession {
            run_id: format!("run-{unique}"),
            attempt_id: "attempt-001".into(),
            session_id: format!("attempt-001-session-{unique}"),
            target_sha256: sha256(target_bytes),
            config_sha256: sha256(b"native sandbox timeout"),
            memory_mb: 4096,
        },
        root: attempt.clone(),
        inputs: vec![transfer(&target, "target.txt")],
        tools: vec![transfer(
            &root.join("tools/windows/sandbox/probe.ps1"),
            "probe.ps1",
        )],
        mappings: Vec::new(),
        runtime_config: None,
    })
    .unwrap();

    let execution = run_probe(&prepared, Duration::from_secs(8), CancellationToken::new())
        .await
        .unwrap();
    verify_inputs(&prepared).unwrap();
    assert!(execution.timed_out, "{execution:?}");
    assert!(execution.remote_session_started, "{execution:?}");
    assert!(execution.remote_session_closed, "{execution:?}");
    assert!(!execution.success, "{execution:?}");

    if let Some(evidence) = std::env::var_os("AEGIS_SANDBOX_EVIDENCE") {
        let evidence = Path::new(&evidence);
        fs::create_dir_all(evidence).unwrap();
        fs::write(
            evidence.join("timeout-summary.json"),
            serde_json::to_vec_pretty(&json!({
                "observed_at": aegis_domain::now(),
                "platform": "windows/x86_64",
                "execution": execution,
                "formal_target": false
            }))
            .unwrap(),
        )
        .unwrap();
    }
}

#[tokio::test]
#[ignore = "requires Windows Sandbox and the benign PE32/PE64 fixtures"]
async fn native_windows_sandbox_original_pe_lifecycle() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    for (adapter, target_name) in [
        (WindowsRuntimeAdapter::OriginalPe64, "sample-pe64.exe"),
        (WindowsRuntimeAdapter::OriginalPe32, "sample-pe32.exe"),
    ] {
        let target = root.join("tests/fixtures/binary").join(target_name);
        let target_bytes = fs::read(&target).unwrap();
        let config = WindowsRuntimeConfig {
            schema_version: 1,
            config_version: "1".into(),
            mode: WindowsRuntimeMode::Verify,
            adapter,
            target_path: target_name.into(),
            target_sha256: sha256(&target_bytes),
            entry: WindowsRuntimeEntry::CommandLine {
                path: target_name.into(),
                arguments: vec![],
            },
            baseline_inputs: vec![WindowsRuntimeInput::Stdin {
                value: String::new(),
            }],
            probe_inputs: vec![WindowsRuntimeInput::Stdin {
                value: String::new(),
            }],
            repeats: 2,
            timeout_seconds: 5,
            fuzz: None,
            environment: Default::default(),
        };
        let fingerprint = config.fingerprint().unwrap();
        let unique = id();
        let temporary = tempfile::tempdir().unwrap();
        let evidence_root = std::env::var_os("AEGIS_SANDBOX_EVIDENCE")
            .map(PathBuf::from)
            .unwrap_or_else(|| temporary.path().to_path_buf());
        fs::create_dir_all(&evidence_root).unwrap();
        let attempt = evidence_root.join(format!("attempt-{unique}"));
        let prepared = prepare(&SandboxSpec {
            entrypoint: SandboxEntrypoint::OriginalPe,
            session: SandboxSession {
                run_id: format!("run-{unique}"),
                attempt_id: "attempt-001".into(),
                session_id: format!("attempt-001-session-{unique}"),
                target_sha256: sha256(&target_bytes),
                config_sha256: fingerprint,
                memory_mb: 4096,
            },
            root: attempt.clone(),
            inputs: vec![transfer(&target, target_name)],
            tools: vec![
                transfer(&root.join("tools/windows/sandbox/run-pe.ps1"), "run-pe.ps1"),
                transfer(
                    &root.join("tools/windows/sandbox/run-windows-trials.ps1"),
                    "run-windows-trials.ps1",
                ),
            ],
            mappings: Vec::new(),
            runtime_config: Some(config),
        })
        .unwrap();

        let execution = run_original_pe(
            &prepared,
            Duration::from_secs(240),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        verify_inputs(&prepared).unwrap();
        let output = collect_output(&prepared, &SandboxOutputPolicy::original_pe()).unwrap();
        assert!(execution.success, "{execution:?}");
        assert!(execution.remote_session_started && execution.remote_session_closed);
        assert_eq!(output.receipt.status, "COMPLETED");
        assert_eq!(output.artifacts.len(), 5);

        let observation_text =
            fs::read_to_string(prepared.output.join("guest-observation.json")).unwrap();
        let observation: serde_json::Value =
            serde_json::from_str(observation_text.trim_start_matches('\u{feff}')).unwrap();
        assert_eq!(observation["adapter"], adapter.as_str());
        assert_eq!(observation["target_path"], target_name);
        assert_eq!(observation["exit_code"], 42);

        if let Some(evidence) = std::env::var_os("AEGIS_SANDBOX_EVIDENCE") {
            let evidence = Path::new(&evidence);
            fs::create_dir_all(evidence).unwrap();
            fs::write(
                evidence.join(format!(
                    "original-{}-summary.json",
                    adapter.as_str().to_lowercase()
                )),
                serde_json::to_vec_pretty(&json!({
                    "observed_at": aegis_domain::now(),
                    "platform": "windows/x86_64",
                    "execution": execution,
                    "receipt": output.receipt,
                    "artifacts": output.artifacts,
                    "observation": observation,
                    "target": "benign development fixture",
                    "formal_target": false
                }))
                .unwrap(),
            )
            .unwrap();
        }
    }
}

#[tokio::test]
#[ignore = "requires Windows Sandbox and the pinned Windows Python runtime"]
async fn native_windows_sandbox_python_lifecycle() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let target_bytes = b"def main():\n    return 'python-ok'\n";
    let unique = id();
    let temporary = tempfile::tempdir().unwrap();
    let target = temporary.path().join("target.py");
    fs::write(&target, target_bytes).unwrap();
    let config = WindowsRuntimeConfig {
        schema_version: 1,
        config_version: "1".into(),
        mode: WindowsRuntimeMode::Verify,
        adapter: WindowsRuntimeAdapter::PythonCall,
        target_path: "target.py".into(),
        target_sha256: sha256(target_bytes),
        entry: WindowsRuntimeEntry::Function {
            module: "target.py".into(),
            function: "main".into(),
        },
        baseline_inputs: vec![WindowsRuntimeInput::Stdin {
            value: String::new(),
        }],
        probe_inputs: vec![WindowsRuntimeInput::Stdin {
            value: String::new(),
        }],
        repeats: 2,
        timeout_seconds: 5,
        fuzz: None,
        environment: aegis_application::runtime::windows_runtime::WindowsRuntimeEnvironment {
            python_version: Some("3.13.13".into()),
            ..Default::default()
        },
    };
    let fingerprint = config.fingerprint().unwrap();
    let evidence_root = std::env::var_os("AEGIS_SANDBOX_EVIDENCE")
        .map(PathBuf::from)
        .unwrap_or_else(|| temporary.path().to_path_buf());
    fs::create_dir_all(&evidence_root).unwrap();
    let attempt = evidence_root.join(format!("attempt-{unique}"));
    let prepared = prepare(&SandboxSpec {
        entrypoint: SandboxEntrypoint::WindowsPython,
        session: SandboxSession {
            run_id: format!("run-{unique}"),
            attempt_id: "attempt-001".into(),
            session_id: format!("attempt-001-session-{unique}"),
            target_sha256: sha256(target_bytes),
            config_sha256: fingerprint,
            memory_mb: 4096,
        },
        root: attempt.clone(),
        inputs: vec![transfer(&target, "target.py")],
        tools: vec![
            transfer(
                &root.join("tools/windows/sandbox/run-python.ps1"),
                "run-python.ps1",
            ),
            transfer(
                &root.join("tools/windows/sandbox/run-windows-trials.ps1"),
                "run-windows-trials.ps1",
            ),
        ],
        mappings: vec![SandboxMapping {
            host: root.join(".tools/windows-python"),
            guest: GUEST_PYTHON.into(),
            read_only: true,
        }],
        runtime_config: Some(config),
    })
    .unwrap();

    let execution = run_windows_python(
        &prepared,
        Duration::from_secs(240),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    verify_inputs(&prepared).unwrap();
    let output = collect_output(&prepared, &SandboxOutputPolicy::windows_python()).unwrap();
    assert!(execution.success, "{execution:?}");
    assert!(execution.remote_session_started && execution.remote_session_closed);
    assert_eq!(output.receipt.status, "COMPLETED");
    assert_eq!(output.artifacts.len(), 5);

    let observation_text =
        fs::read_to_string(prepared.output.join("guest-observation.json")).unwrap();
    let observation: serde_json::Value =
        serde_json::from_str(observation_text.trim_start_matches('\u{feff}')).unwrap();
    assert_eq!(observation["adapter"], "WINDOWS_PYTHON_CALL");
    assert_eq!(observation["function"], "main");
    assert_eq!(observation["exit_code"], 0);
    let stdout = fs::read_to_string(prepared.output.join("target.stdout.log")).unwrap();
    assert!(stdout.contains("python-ok"), "{stdout:?}");

    if let Some(evidence) = std::env::var_os("AEGIS_SANDBOX_EVIDENCE") {
        let evidence = Path::new(&evidence);
        fs::create_dir_all(evidence).unwrap();
        fs::write(
            evidence.join("windows-python-summary.json"),
            serde_json::to_vec_pretty(&json!({
                "observed_at": aegis_domain::now(),
                "platform": "windows/x86_64",
                "execution": execution,
                "receipt": output.receipt,
                "artifacts": output.artifacts,
                "observation": observation,
                "stdout": stdout,
                "target": "benign development fixture",
                "formal_target": false
            }))
            .unwrap(),
        )
        .unwrap();
    }
}

#[tokio::test]
#[ignore = "requires Windows Sandbox, the pinned Windows Python runtime, and the benign tamper fixture"]
async fn native_windows_sandbox_rejects_target_evidence_tampering() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let target = root.join("tests/fixtures/runtime/observer_tamper.py");
    let target_bytes = fs::read(&target).unwrap();
    let unique = id();
    let temporary = tempfile::tempdir().unwrap();
    let config = WindowsRuntimeConfig {
        schema_version: 1,
        config_version: "1".into(),
        mode: WindowsRuntimeMode::Verify,
        adapter: WindowsRuntimeAdapter::PythonCall,
        target_path: "observer_tamper.py".into(),
        target_sha256: sha256(&target_bytes),
        entry: WindowsRuntimeEntry::Function {
            module: "observer_tamper.py".into(),
            function: "main".into(),
        },
        baseline_inputs: vec![WindowsRuntimeInput::Stdin {
            value: String::new(),
        }],
        probe_inputs: vec![WindowsRuntimeInput::Stdin {
            value: String::new(),
        }],
        repeats: 2,
        timeout_seconds: 5,
        fuzz: None,
        environment: WindowsRuntimeEnvironment {
            python_version: Some("3.13.13".into()),
            ..Default::default()
        },
    };
    let fingerprint = config.fingerprint().unwrap();
    let session_id = format!("attempt-001-session-{unique}");
    let evidence_root = std::env::var_os("AEGIS_SANDBOX_EVIDENCE")
        .map(PathBuf::from)
        .unwrap_or_else(|| temporary.path().to_path_buf());
    fs::create_dir_all(&evidence_root).unwrap();
    let attempt = evidence_root.join(format!("attempt-{unique}"));
    let prepared = prepare(&SandboxSpec {
        entrypoint: SandboxEntrypoint::WindowsPython,
        session: SandboxSession {
            run_id: format!("run-{unique}"),
            attempt_id: "attempt-001".into(),
            session_id: session_id.clone(),
            target_sha256: sha256(&target_bytes),
            config_sha256: fingerprint,
            memory_mb: 4096,
        },
        root: attempt,
        inputs: vec![transfer(&target, "observer_tamper.py")],
        tools: vec![
            transfer(
                &root.join("tools/windows/sandbox/run-python.ps1"),
                "run-python.ps1",
            ),
            transfer(
                &root.join("tools/windows/sandbox/run-windows-trials.ps1"),
                "run-windows-trials.ps1",
            ),
        ],
        mappings: vec![SandboxMapping {
            host: root.join(".tools/windows-python"),
            guest: GUEST_PYTHON.into(),
            read_only: true,
        }],
        runtime_config: Some(config),
    })
    .unwrap();

    let execution = run_windows_python(
        &prepared,
        Duration::from_secs(240),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    verify_inputs(&prepared).unwrap();
    let output = collect_output(&prepared, &SandboxOutputPolicy::windows_python()).unwrap();
    assert!(execution.success, "{execution:?}");
    assert!(execution.remote_session_started && execution.remote_session_closed);
    assert_eq!(output.receipt.status, "COMPLETED");
    assert_eq!(output.receipt.session_id, session_id);

    let stdout = fs::read_to_string(prepared.output.join("target.stdout.log")).unwrap();
    assert!(
        stdout.contains("guest-observation.json:write-rejected"),
        "{stdout:?}"
    );
    assert!(stdout.contains("session.json:write-rejected"), "{stdout:?}");
    let observation_text =
        fs::read_to_string(prepared.output.join("guest-observation.json")).unwrap();
    let receipt_text = fs::read_to_string(prepared.output.join("session.json")).unwrap();
    assert!(!observation_text.contains("FORGED BY TARGET"));
    assert!(!receipt_text.contains("FORGED BY TARGET"));
    let observation: serde_json::Value =
        serde_json::from_str(observation_text.trim_start_matches('\u{feff}')).unwrap();
    assert_eq!(observation["session_id"], session_id);
    assert_eq!(observation["exit_code"], 0);

    if let Some(evidence) = std::env::var_os("AEGIS_SANDBOX_EVIDENCE") {
        let evidence = Path::new(&evidence);
        fs::create_dir_all(evidence).unwrap();
        fs::write(
            evidence.join("observer-tamper-summary.json"),
            serde_json::to_vec_pretty(&json!({
                "observed_at": aegis_domain::now(),
                "platform": "windows/x86_64",
                "execution": execution,
                "receipt": output.receipt,
                "artifacts": output.artifacts,
                "observation": observation,
                "stdout": stdout,
                "target": "benign observer-tamper development fixture",
                "formal_target": false
            }))
            .unwrap(),
        )
        .unwrap();
    }
}

#[tokio::test]
#[ignore = "requires Windows Sandbox and the pinned Zig runtime"]
async fn native_windows_sandbox_native_source_lifecycle() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    for (target_name, target_bytes, expected_output) in [
        (
            "target.c",
            b"#include <stdio.h>\nint main(void) { printf(\"native-c-ok\\n\"); return 0; }\n"
                .as_slice(),
            "native-c-ok",
        ),
        (
            "target.cpp",
            b"#include <cstdio>\nint main() { std::printf(\"native-cpp-ok\\n\"); return 0; }\n"
                .as_slice(),
            "native-cpp-ok",
        ),
    ] {
        let unique = id();
        let temporary = tempfile::tempdir().unwrap();
        let target = temporary.path().join(target_name);
        fs::write(&target, target_bytes).unwrap();
        let config = WindowsRuntimeConfig {
            schema_version: 1,
            config_version: "1".into(),
            mode: WindowsRuntimeMode::Verify,
            adapter: WindowsRuntimeAdapter::NativeSource,
            target_path: target_name.into(),
            target_sha256: sha256(target_bytes),
            entry: WindowsRuntimeEntry::CommandLine {
                path: target_name.into(),
                arguments: vec![],
            },
            baseline_inputs: vec![WindowsRuntimeInput::Stdin {
                value: String::new(),
            }],
            probe_inputs: vec![WindowsRuntimeInput::Stdin {
                value: String::new(),
            }],
            repeats: 2,
            timeout_seconds: 5,
            fuzz: None,
            environment: WindowsRuntimeEnvironment {
                compiler: Some("zig 0.15.2".into()),
                ..Default::default()
            },
        };
        let fingerprint = config.fingerprint().unwrap();
        let evidence_root = std::env::var_os("AEGIS_SANDBOX_EVIDENCE")
            .map(PathBuf::from)
            .unwrap_or_else(|| temporary.path().to_path_buf());
        fs::create_dir_all(&evidence_root).unwrap();
        let attempt = evidence_root.join(format!("attempt-{unique}"));
        let prepared = prepare(&SandboxSpec {
            entrypoint: SandboxEntrypoint::WindowsNativeSource,
            session: SandboxSession {
                run_id: format!("run-{unique}"),
                attempt_id: "attempt-001".into(),
                session_id: format!("attempt-001-session-{unique}"),
                target_sha256: sha256(target_bytes),
                config_sha256: fingerprint,
                memory_mb: 8192,
            },
            root: attempt.clone(),
            inputs: vec![transfer(&target, target_name)],
            tools: vec![
                transfer(
                    &root.join("tools/windows/sandbox/run-native-source.ps1"),
                    "run-native-source.ps1",
                ),
                transfer(
                    &root.join("tools/windows/sandbox/run-windows-trials.ps1"),
                    "run-windows-trials.ps1",
                ),
            ],
            mappings: vec![SandboxMapping {
                host: root.join(".tools/zig"),
                guest: GUEST_ZIG.into(),
                read_only: true,
            }],
            runtime_config: Some(config),
        })
        .unwrap();

        let execution = run_native_source(
            &prepared,
            Duration::from_secs(600),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        verify_inputs(&prepared).unwrap();
        assert!(execution.success, "{execution:?}");
        assert!(execution.remote_session_started && execution.remote_session_closed);
        let output =
            collect_output(&prepared, &SandboxOutputPolicy::windows_native_source()).unwrap();
        assert_eq!(output.receipt.status, "COMPLETED");
        assert_eq!(output.artifacts.len(), 7);

        let observation_text =
            fs::read_to_string(prepared.output.join("guest-observation.json")).unwrap();
        let observation: serde_json::Value =
            serde_json::from_str(observation_text.trim_start_matches('\u{feff}')).unwrap();
        assert_eq!(observation["adapter"], "WINDOWS_NATIVE_SOURCE");
        assert_eq!(observation["target_path"], target_name);
        assert_eq!(observation["compiler"], "zig 0.15.2");
        assert_eq!(observation["compile_exit_code"], 0);
        assert_eq!(observation["exit_code"], 0);
        let stdout = fs::read_to_string(prepared.output.join("target.stdout.log")).unwrap();
        assert!(stdout.contains(expected_output), "{stdout:?}");

        if let Some(evidence) = std::env::var_os("AEGIS_SANDBOX_EVIDENCE") {
            let evidence = Path::new(&evidence);
            fs::create_dir_all(evidence).unwrap();
            fs::write(
                evidence.join(format!(
                    "native-source-{}-summary.json",
                    Path::new(target_name)
                        .extension()
                        .unwrap()
                        .to_string_lossy()
                )),
                serde_json::to_vec_pretty(&json!({
                    "observed_at": aegis_domain::now(),
                    "platform": "windows/x86_64",
                    "execution": execution,
                    "receipt": output.receipt,
                    "artifacts": output.artifacts,
                    "observation": observation,
                    "stdout": stdout,
                    "target": "benign development fixture",
                    "formal_target": false
                }))
                .unwrap(),
            )
            .unwrap();
        }
    }
}

#[tokio::test]
#[ignore = "requires Windows Sandbox and the pinned minimal LLVM/libFuzzer runtime"]
async fn native_windows_sandbox_libfuzzer_probe() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let clang = root.join(".tools/llvm-min/bin/clang.exe");
    assert!(
        clang.is_file(),
        "install the pinned minimal LLVM runtime before running this probe"
    );
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("fuzz.c");
    let target = temporary.path().join("fuzz.exe");
    fs::write(
        &source,
        r#"extern int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size);
#include <stdio.h>
int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {
    if (size > 0 && data[0] == 88) {
        FILE *file = fopen("C:/Users/WDAGUtilityAccount/Desktop/AegisOutput/crash-input.bin", "wb");
        if (file) {
            fwrite(data, 1, size, file);
            fclose(file);
        }
        *(volatile int *)0 = 0;
    }
    return 0;
}

"#,
    )
    .unwrap();

    let compiled = Command::new(&clang)
        .args([
            "-O1",
            "-fsanitize=fuzzer",
            source.as_os_str().to_string_lossy().as_ref(),
            "-o",
            target.as_os_str().to_string_lossy().as_ref(),
        ])
        .current_dir(temporary.path())
        .output()
        .expect("compile the libFuzzer probe");
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );

    let target_bytes = fs::read(&target).unwrap();
    let config = WindowsRuntimeConfig {
        schema_version: 1,
        config_version: "1".into(),
        mode: WindowsRuntimeMode::Fuzz,
        adapter: WindowsRuntimeAdapter::LibFuzzerPrebuilt,
        target_path: "fuzz.exe".into(),
        target_sha256: sha256(&target_bytes),
        entry: WindowsRuntimeEntry::CommandLine {
            path: "fuzz.exe".into(),
            arguments: vec![],
        },
        baseline_inputs: vec![WindowsRuntimeInput::Stdin { value: "A".into() }],
        probe_inputs: vec![WindowsRuntimeInput::Stdin {
            value: String::new(),
        }],
        repeats: 2,
        timeout_seconds: 5,
        fuzz: Some(WindowsFuzzOptions {
            engine: "LLVM_LIBFUZZER".into(),
            runs: 100_000,
            timeout_seconds: 10,
            random_seed: 71_413,
            max_input_bytes: 16,
        }),
        environment: WindowsRuntimeEnvironment {
            compiler: Some("llvm 23.1.1".into()),
            ..Default::default()
        },
    };
    let fingerprint = config.fingerprint().unwrap();
    let unique = id();
    let evidence_root = std::env::var_os("AEGIS_SANDBOX_EVIDENCE")
        .map(PathBuf::from)
        .unwrap_or_else(|| temporary.path().to_path_buf());
    fs::create_dir_all(&evidence_root).unwrap();
    let attempt = evidence_root.join(format!("attempt-{unique}"));
    let prepared = prepare(&SandboxSpec {
        entrypoint: SandboxEntrypoint::LibFuzzerPrebuilt,
        session: SandboxSession {
            run_id: format!("run-{unique}"),
            attempt_id: "attempt-001".into(),
            session_id: format!("attempt-001-session-{unique}"),
            target_sha256: sha256(&target_bytes),
            config_sha256: fingerprint,
            memory_mb: 4096,
        },
        root: attempt.clone(),
        inputs: vec![transfer(&target, "fuzz.exe")],
        tools: vec![transfer(
            &root.join("tools/windows/sandbox/run-libfuzzer.ps1"),
            "run-libfuzzer.ps1",
        )],
        mappings: vec![SandboxMapping {
            host: root.join(".tools/llvm-min"),
            guest: GUEST_LLVM.into(),
            read_only: true,
        }],
        runtime_config: Some(config),
    })
    .unwrap();

    let execution = run_libfuzzer(
        &prepared,
        Duration::from_secs(240),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    verify_inputs(&prepared).unwrap();
    assert!(execution.success, "{execution:?}");
    let output = collect_output(&prepared, &SandboxOutputPolicy::lib_fuzzer_prebuilt()).unwrap();
    assert_eq!(output.receipt.status, "COMPLETED");
    assert_eq!(output.artifacts.len(), 9);
    let stdout = fs::read_to_string(prepared.output.join("fuzzer.stdout.log")).unwrap();
    let stderr = fs::read_to_string(prepared.output.join("fuzzer.stderr.log")).unwrap();
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("cov:") && combined.contains("deadly signal"),
        "{combined:?}"
    );
    let observation_text =
        fs::read_to_string(prepared.output.join("guest-observation.json")).unwrap();
    let observation: serde_json::Value =
        serde_json::from_str(observation_text.trim_start_matches('\u{feff}')).unwrap();
    assert_eq!(observation["engine"], "LLVM libFuzzer");
    assert_eq!(observation["crash_found"], true);
    assert_eq!(observation["replay_reproduced"], true);
    assert_ne!(observation["engine_exit_code"], 0);
    assert_ne!(observation["replay_exit_code"], 0);
    assert!(prepared.output.join("crash-input.bin").is_file());
    assert!(prepared.output.join("corpus.zip").is_file());

    if let Some(evidence) = std::env::var_os("AEGIS_SANDBOX_EVIDENCE") {
        let evidence = Path::new(&evidence);
        fs::create_dir_all(evidence).unwrap();
        fs::write(
            evidence.join("libfuzzer-summary.json"),
            serde_json::to_vec_pretty(&json!({
                "observed_at": aegis_domain::now(),
                "platform": "windows/x86_64",
                "execution": execution,
                "receipt": output.receipt,
                "artifacts": output.artifacts,
                "stdout": stdout,
                "stderr": stderr,
                "observation": observation,
                "crash_input": "crash-input.bin",
                "corpus_archive": "corpus.zip",
                "engine": "LLVM libFuzzer",
                "coverage_feedback": "inline-8bit-counters",
                "compile_location": "host compatibility probe",
                "crash_preservation": true,
                "replay_reproduced": true,
                "execution_location": "Windows Sandbox",
                "formal_target": false
            }))
            .unwrap(),
        )
        .unwrap();
    }
}

#[tokio::test]
#[ignore = "requires Windows Sandbox and the pinned TinyInst runtime"]
async fn native_windows_sandbox_tinyinst_pe_probe() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let target = root.join("tests/fixtures/binary/sample-pe64.exe");
    let target_bytes = fs::read(&target).unwrap();
    let config = WindowsRuntimeConfig {
        schema_version: 1,
        config_version: "1".into(),
        mode: WindowsRuntimeMode::Verify,
        adapter: WindowsRuntimeAdapter::OriginalPe64,
        target_path: "sample-pe64.exe".into(),
        target_sha256: sha256(&target_bytes),
        entry: WindowsRuntimeEntry::CommandLine {
            path: "sample-pe64.exe".into(),
            arguments: vec![],
        },
        baseline_inputs: vec![WindowsRuntimeInput::Stdin {
            value: String::new(),
        }],
        probe_inputs: vec![WindowsRuntimeInput::Stdin {
            value: String::new(),
        }],
        repeats: 2,
        timeout_seconds: 5,
        fuzz: None,
        environment: Default::default(),
    };
    let fingerprint = config.fingerprint().unwrap();
    let unique = id();
    let temporary = tempfile::tempdir().unwrap();
    let evidence_root = std::env::var_os("AEGIS_SANDBOX_EVIDENCE")
        .map(PathBuf::from)
        .unwrap_or_else(|| temporary.path().to_path_buf());
    fs::create_dir_all(&evidence_root).unwrap();
    let attempt = evidence_root.join(format!("attempt-{unique}"));
    let prepared = prepare(&SandboxSpec {
        entrypoint: SandboxEntrypoint::TinyInstPe,
        session: SandboxSession {
            run_id: format!("run-{unique}"),
            attempt_id: "attempt-001".into(),
            session_id: format!("attempt-001-session-{unique}"),
            target_sha256: sha256(&target_bytes),
            config_sha256: fingerprint,
            memory_mb: 4096,
        },
        root: attempt.clone(),
        inputs: vec![transfer(&target, "sample-pe64.exe")],
        tools: vec![transfer(
            &root.join("tools/windows/sandbox/run-tinyinst.ps1"),
            "run-tinyinst.ps1",
        )],
        mappings: vec![SandboxMapping {
            host: root.join(".tools/tinyinst"),
            guest: GUEST_TINYINST.into(),
            read_only: true,
        }],
        runtime_config: Some(config),
    })
    .unwrap();

    let execution = run_tinyinst(
        &prepared,
        Duration::from_secs(300),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    verify_inputs(&prepared).unwrap();
    assert!(execution.success, "{execution:?}");
    let output = collect_output(&prepared, &SandboxOutputPolicy::tiny_inst_pe()).unwrap();
    assert_eq!(output.receipt.status, "COMPLETED");
    assert_eq!(output.artifacts.len(), 6);
    let observation_text =
        fs::read_to_string(prepared.output.join("guest-observation.json")).unwrap();
    let observation: serde_json::Value =
        serde_json::from_str(observation_text.trim_start_matches('\u{feff}')).unwrap();
    assert_eq!(observation["engine"], "TinyInst litecov");
    assert_eq!(observation["engine_exit_code"], 0);
    assert_eq!(observation["coverage_exists"], true);
    let coverage = fs::read_to_string(prepared.output.join("coverage.txt")).unwrap();
    assert!(!coverage.trim().is_empty(), "{coverage:?}");

    if let Some(evidence) = std::env::var_os("AEGIS_SANDBOX_EVIDENCE") {
        let evidence = Path::new(&evidence);
        fs::create_dir_all(evidence).unwrap();
        fs::write(
            evidence.join("tinyinst-summary.json"),
            serde_json::to_vec_pretty(&json!({
                "observed_at": aegis_domain::now(),
                "platform": "windows/x86_64",
                "execution": execution,
                "receipt": output.receipt,
                "artifacts": output.artifacts,
                "observation": observation,
                "coverage": coverage,
                "engine": "TinyInst litecov",
                "coverage_feedback": "instrumented basic blocks and edges",
                "build_location": "host compatibility probe",
                "execution_location": "Windows Sandbox",
                "formal_target": false
            }))
            .unwrap(),
        )
        .unwrap();
    }
}
