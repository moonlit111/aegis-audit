//! Opt-in checks of the installed scanner, not model or vulnerability acceptance tests.
use aegis_application::{import, process, sast};
use aegis_domain::{FileRecord, now, sha256};
use serde_json::{Value, json};
use std::{path::Path, time::Duration};
use tokio_util::sync::CancellationToken;

fn input(root: &Path, path: &str, code: &str) -> FileRecord {
    let target = root.join(path);
    std::fs::create_dir_all(target.parent().unwrap()).unwrap();
    std::fs::write(target, code).unwrap();
    FileRecord {
        path: path.into(),
        language: import::language(path).into(),
        sha256: sha256(code.as_bytes()),
        size: code.len() as u64,
    }
}

fn retain(name: &str, data: &[u8]) {
    if let Some(root) = std::env::var_os("AEGIS_NATIVE_SAST_EVIDENCE") {
        let root = Path::new(&root);
        std::fs::create_dir_all(root).unwrap();
        std::fs::write(root.join(name), data).unwrap();
    }
}

fn assert_finished(output: &process::ProcessOutput) {
    assert_eq!(
        output.exit_code,
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.processes_reaped);
    assert!(!output.truncated && !output.cancelled && !output.timed_out);
}

#[tokio::test]
#[ignore = "requires the pinned Windows Python/Semgrep installation; run with --ignored"]
async fn native_windows_scan_coverage_and_lifecycle() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let home = std::env::var_os("AEGIS_PYTHON_HOME").expect("AEGIS_PYTHON_HOME is required");
    let scanner = sast::Semgrep::discover(Path::new(&home), &root.join("tools/runtime/rules.yml"))
        .await
        .expect("the pinned native scanner must pass discovery");
    let temporary = tempfile::Builder::new()
        .prefix("aegis native \u{5ba1}\u{8ba1} ")
        .tempdir()
        .unwrap();
    let source = temporary.path().join("source");
    let work = temporary.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    let spec_for = |source: &Path| {
        let mut spec = scanner.scan_spec(source, &work);
        let system_root = std::env::var_os("SystemRoot").expect("Windows system root is required");
        spec.env.insert(
            "PATH".into(),
            Path::new(&system_root)
                .join("System32")
                .to_string_lossy()
                .into_owned(),
        );
        spec
    };
    let prefix = "tests/\u{5ba1}\u{8ba1} input/";
    let mut files = Vec::new();
    for (name, content) in [
        (
            "accounts.py",
            include_str!("../../../tests/fixtures/audit/source/accounts.py"),
        ),
        (
            "commands.py",
            include_str!("../../../tests/fixtures/audit/source/commands.py"),
        ),
        (
            "documents.py",
            include_str!("../../../tests/fixtures/audit/source/documents.py"),
        ),
        (
            "messages.c",
            include_str!("../../../tests/fixtures/audit/source/messages.c"),
        ),
    ] {
        files.push(input(&source, &format!("{prefix}{name}"), content));
    }
    files.push(input(&source, ".semgrepignore", "*\n"));
    files.push(input(&source, ".gitignore", "*.py\n*.c\n"));
    files.push(input(
        &source,
        "semgrep.py",
        "from pathlib import Path\nPath(__file__).with_suffix('.executed').touch()\nraise RuntimeError('target module must not be imported')\n",
    ));
    let output = process::run(spec_for(&source), CancellationToken::new(), |_| {})
        .await
        .unwrap();
    retain("scan.json", &output.stdout);
    retain("scan.stderr.log", &output.stderr);
    assert_finished(&output);
    assert!(
        !source.join("semgrep.executed").exists(),
        "scanner imported target code"
    );
    let raw: Value = serde_json::from_slice(&output.stdout).unwrap();
    let coverage = sast::validate_report(&raw, &files).unwrap();
    assert_eq!(coverage["status"], "COMPLETED", "{coverage}");
    assert_eq!(coverage["scanned_file_count"], 5);
    assert_eq!(coverage["results"].as_array().unwrap().len(), 2);
    assert!(coverage["errors"].as_array().unwrap().is_empty());
    assert!(
        coverage["results"]
            .as_array()
            .unwrap()
            .iter()
            .all(|result| { result["check_id"].as_str().unwrap().starts_with("aegis.") })
    );

    let empty = temporary.path().join("no-source");
    let non_source = vec![input(&empty, "README.md", "No source files.\n")];
    let output = process::run(spec_for(&empty), CancellationToken::new(), |_| {})
        .await
        .unwrap();
    retain("no-targets.json", &output.stdout);
    retain("no-targets.stderr.log", &output.stderr);
    if output.exit_code != Some(0) {
        let mut spec = spec_for(&empty);
        spec.args.push("--debug".into());
        let diagnostic = process::run(spec, CancellationToken::new(), |_| {})
            .await
            .unwrap();
        retain("no-targets.debug.log", &diagnostic.stderr);
    }
    assert_finished(&output);
    let raw: Value = serde_json::from_slice(&output.stdout).unwrap();
    let empty_coverage = sast::validate_report(&raw, &non_source).unwrap();
    assert_eq!(empty_coverage["status"], "NO_TARGETS");

    let cancel = CancellationToken::new();
    let trigger = cancel.clone();
    let task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        trigger.cancel();
    });
    let cancelled = process::run(spec_for(&source), cancel, |_| {})
        .await
        .unwrap();
    task.await.unwrap();
    assert!(cancelled.cancelled && cancelled.processes_reaped && !cancelled.timed_out);
    let mut spec = spec_for(&source);
    spec.timeout = Duration::from_millis(1);
    let timed_out = process::run(spec, CancellationToken::new(), |_| {})
        .await
        .unwrap();
    assert!(timed_out.timed_out && timed_out.processes_reaped && !timed_out.cancelled);
    retain("summary.json", &serde_json::to_vec_pretty(&json!({
        "observed_at": now(), "platform": "windows/x86_64",
        "purpose": "real native static-tool adapter regression; not model or vulnerability acceptance",
        "version": sast::SEMGREP_VERSION, "core_sha256": scanner.core_sha256,
        "rules_sha256": sha256(&std::fs::read(&scanner.rules).unwrap()),
        "files": files, "coverage": coverage, "no_targets": empty_coverage,
        "processes_reaped": true, "cancellation_reaped": cancelled.processes_reaped,
        "timeout_reaped": timed_out.processes_reaped, "target_execution": false,
        "unicode_and_space_paths": true, "target_module_not_imported": true,
        "development_tools_removed_from_scanner_path": true,
        "ignores_do_not_silently_reduce_snapshot_coverage": true
    })).unwrap());
}
