//! Diagnostic probe for the CI-only `windows_host_runtime` timeout.
//!
//! Round one established that PowerShell cannot run at all in the environment
//! `process.rs` builds for it, on CI only:
//!
//!   probe 1-cmd:        ok=true  ran_ms=27     stdout="cmd-probe"
//!   probe 2-ps-command: ok=false ran_ms=15052  stdout="" stderr=""
//!   probe 3-ps-file:    ok=false ran_ms=15036  stdout="" stderr=""
//!
//! A trivial `-Command` fails exactly like `-File`, so this is not about the
//! invocation shape or the script. `cmd.exe` goes through the identical
//! job/suspend path in 27ms, and `process.rs`'s own cmd-based tests pass on CI.
//!
//! `process.rs` calls `env_clear()` and then re-adds only PATH, JAVA_HOME,
//! SystemRoot, WINDIR, COMSPEC, PATHEXT, LANG, LC_ALL, TEMP/TMP/TMPDIR and a
//! private USERPROFILE/APPDATA/LOCALAPPDATA. This round asks whether that
//! cleared environment is what stops PowerShell, by running the same trivial
//! command three ways: with the parent environment passed through, with an
//! extended allowlist, and with the current cleared set as the control.
//!
//! It always panics at the end so libtest prints the captured output.

use aegis_application::process::{ProcessSpec, run};
use std::{collections::BTreeMap, path::PathBuf, time::Duration};
use tokio_util::sync::CancellationToken;

/// Variables a .NET console host plausibly reads at startup that the current
/// allowlist does not pass through.
const EXTENDED: &[&str] = &[
    "PSModulePath",
    "ProgramFiles",
    "ProgramFiles(x86)",
    "ProgramData",
    "PROCESSOR_ARCHITECTURE",
    "PROCESSOR_IDENTIFIER",
    "NUMBER_OF_PROCESSORS",
    "SystemDrive",
    "HOMEDRIVE",
    "HOMEPATH",
    "USERNAME",
    "USERDOMAIN",
    "OS",
    "PUBLIC",
    "ProgramW6432",
];

fn powershell() -> PathBuf {
    std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
        .join(r"System32\WindowsPowerShell\v1.0\powershell.exe")
}

async fn probe(
    label: &str,
    program: PathBuf,
    args: Vec<String>,
    directory: &std::path::Path,
    env: BTreeMap<String, String>,
    lines: &mut Vec<String>,
) -> bool {
    let started = std::time::Instant::now();
    let result = run(
        ProcessSpec {
            program,
            args,
            directory: directory.to_path_buf(),
            env,
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
                "probe {label}: ok={ok} exit={:?} timed_out={} ran_ms={} stdout={:?} stderr={:?}",
                output.exit_code,
                output.timed_out,
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
    let directory = temporary.path().to_path_buf();
    let command = || {
        vec![
            "-NoProfile".to_owned(),
            "-Command".to_owned(),
            "Write-Output ps-command-probe".to_owned(),
        ]
    };

    let inherited: BTreeMap<String, String> = std::env::vars().collect();
    let extended: BTreeMap<String, String> = EXTENDED
        .iter()
        .filter_map(|key| {
            std::env::var(key)
                .ok()
                .map(|value| ((*key).to_owned(), value))
        })
        .collect();

    let mut lines = Vec::new();
    lines.push(format!(
        "probe env: inherited={} extended={} keys_in_extended={:?}",
        inherited.len(),
        extended.len(),
        extended.keys().collect::<Vec<_>>()
    ));
    let mut failures = Vec::new();

    if !probe(
        "1-cmd-cleared",
        PathBuf::from("cmd.exe"),
        vec!["/D".into(), "/C".into(), "echo cmd-probe".into()],
        &directory,
        BTreeMap::new(),
        &mut lines,
    )
    .await
    {
        failures.push("1-cmd-cleared");
    }

    if !probe(
        "2-ps-inherited-env",
        powershell(),
        command(),
        &directory,
        inherited,
        &mut lines,
    )
    .await
    {
        failures.push("2-ps-inherited-env");
    }

    if !probe(
        "3-ps-extended-env",
        powershell(),
        command(),
        &directory,
        extended,
        &mut lines,
    )
    .await
    {
        failures.push("3-ps-extended-env");
    }

    if !probe(
        "4-ps-cleared-env",
        powershell(),
        command(),
        &directory,
        BTreeMap::new(),
        &mut lines,
    )
    .await
    {
        failures.push("4-ps-cleared-env");
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
