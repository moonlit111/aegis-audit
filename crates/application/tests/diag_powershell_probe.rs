//! Diagnostic probe for the CI-only `windows_host_runtime` timeout.
//!
//! Both runtime tests time out on CI having produced zero bytes on stdout and
//! stderr, after `ResumeThread` reported the expected previous suspend count of
//! 1 — so the child is resumed correctly and then goes silent. `process.rs`'s
//! own tests, which spawn `cmd.exe` through the same job/suspend machinery,
//! pass on CI.
//!
//! This runs three commands through the identical `process::run` path to find
//! which layer stops: a `cmd.exe` control, a trivial `powershell.exe -Command`,
//! and the `powershell.exe -File <script>` shape the runtime tests use.
//!
//! It always panics at the end so libtest prints the captured output.

use aegis_application::process::{ProcessSpec, run};
use std::{collections::BTreeMap, path::PathBuf, time::Duration};
use tokio_util::sync::CancellationToken;

async fn probe(
    label: &str,
    program: PathBuf,
    args: Vec<String>,
    directory: &std::path::Path,
    lines: &mut Vec<String>,
) -> bool {
    let started = std::time::Instant::now();
    let result = run(
        ProcessSpec {
            program: program.clone(),
            args,
            directory: directory.to_path_buf(),
            env: BTreeMap::new(),
            timeout: Duration::from_secs(15),
        },
        CancellationToken::new(),
        |_| {},
    )
    .await;
    match result {
        Ok(output) => {
            let ok = output.exit_code == Some(0) && !output.timed_out;
            lines.push(format!(
                "probe {label}: ok={ok} exit={:?} timed_out={} reaped={} ran_ms={} \
                 stdout={:?} stderr={:?}",
                output.exit_code,
                output.timed_out,
                output.processes_reaped,
                started.elapsed().as_millis(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            ));
            ok
        }
        Err(error) => {
            lines.push(format!(
                "probe {label}: error={error} ran_ms={}",
                started.elapsed().as_millis()
            ));
            false
        }
    }
}

#[tokio::test]
async fn diag_powershell_probe() {
    let temporary = tempfile::tempdir().unwrap();
    let script = temporary.path().join("probe.ps1");
    std::fs::write(&script, "Write-Output probe-from-file\r\n").unwrap();
    let powershell = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
        .join(r"System32\WindowsPowerShell\v1.0\powershell.exe");

    let mut lines = Vec::new();
    let mut failures = Vec::new();

    if !powershell.is_file() {
        lines.push(format!("powershell missing at {}", powershell.display()));
    }

    if !probe(
        "1-cmd",
        PathBuf::from("cmd.exe"),
        vec!["/D".into(), "/C".into(), "echo cmd-probe".into()],
        temporary.path(),
        &mut lines,
    )
    .await
    {
        failures.push("1-cmd");
    }

    if !probe(
        "2-ps-command",
        powershell.clone(),
        vec![
            "-NoProfile".into(),
            "-Command".into(),
            "Write-Output ps-command-probe".into(),
        ],
        temporary.path(),
        &mut lines,
    )
    .await
    {
        failures.push("2-ps-command");
    }

    if !probe(
        "3-ps-file",
        powershell,
        vec![
            "-NoProfile".into(),
            "-ExecutionPolicy".into(),
            "Bypass".into(),
            "-File".into(),
            script.to_string_lossy().into_owned(),
        ],
        temporary.path(),
        &mut lines,
    )
    .await
    {
        failures.push("3-ps-file");
    }

    for line in &lines {
        eprintln!("{line}");
    }
    assert!(
        failures.is_empty(),
        "probe failures: {}",
        failures.join(", ")
    );
}
