//! Diagnostic probe for the CI-only `windows_host_runtime` timeout.
//!
//! Round two localised it to the environment `process.rs` builds, not the
//! private profile directories:
//!
//!   probe 1-cmd-cleared:      ok=true  ran_ms=25
//!   probe 2-ps-inherited-env: ok=true  ran_ms=257
//!   probe 3-ps-extended-env:  ok=true  ran_ms=299   (private profile kept)
//!   probe 4-ps-cleared-env:   ok=false ran_ms=15035 stdout="" stderr=""
//!
//! Probe 3 kept the redirected USERPROFILE/APPDATA/LOCALAPPDATA and only added
//! fifteen variables, and PowerShell started in 299ms — so the profile is not
//! the cause and a missing variable is. This round narrows which one, so the
//! fix can add the minimum rather than the whole set.
//!
//! Categories, each added on top of the same cleared base that process.rs
//! builds:
//!
//!   A psmodulepath   PSModulePath
//!   B program-files  ProgramFiles, ProgramFiles(x86), ProgramData,
//                    ProgramW6432, PUBLIC
//!   C processor      PROCESSOR_ARCHITECTURE, PROCESSOR_IDENTIFIER,
//!                    NUMBER_OF_PROCESSORS, OS
//!   D drives-home    SystemDrive, HOMEDRIVE, HOMEPATH
//!   E identity       USERNAME, USERDOMAIN
//!   F all            every one of the fifteen — expected to pass
//!   G none           the cleared base — expected to reproduce the hang
//!
//! It always panics at the end so libtest prints the captured output.

use aegis_application::process::{ProcessSpec, run};
use std::{collections::BTreeMap, path::PathBuf, time::Duration};
use tokio_util::sync::CancellationToken;

const PSMODULEPATH: &[&str] = &["PSModulePath"];
const PROGRAM_FILES: &[&str] = &[
    "ProgramFiles",
    "ProgramFiles(x86)",
    "ProgramData",
    "ProgramW6432",
    "PUBLIC",
];
const PROCESSOR: &[&str] = &[
    "PROCESSOR_ARCHITECTURE",
    "PROCESSOR_IDENTIFIER",
    "NUMBER_OF_PROCESSORS",
    "OS",
];
const DRIVES_HOME: &[&str] = &["SystemDrive", "HOMEDRIVE", "HOMEPATH"];
const IDENTITY: &[&str] = &["USERNAME", "USERDOMAIN"];

fn powershell() -> PathBuf {
    std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
        .join(r"System32\WindowsPowerShell\v1.0\powershell.exe")
}

fn from_parent(keys: &[&str]) -> BTreeMap<String, String> {
    keys.iter()
        .filter_map(|key| {
            std::env::var(key)
                .ok()
                .map(|value| ((*key).to_owned(), value))
        })
        .collect()
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
            timeout: Duration::from_secs(12),
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

    let mut all: Vec<&str> = Vec::new();
    for group in [
        PSMODULEPATH,
        PROGRAM_FILES,
        PROCESSOR,
        DRIVES_HOME,
        IDENTITY,
    ] {
        all.extend_from_slice(group);
    }

    let mut lines = Vec::new();
    let mut failures = Vec::new();

    let cases: Vec<(&str, BTreeMap<String, String>)> = vec![
        ("A-psmodulepath", from_parent(PSMODULEPATH)),
        ("B-program-files", from_parent(PROGRAM_FILES)),
        ("C-processor", from_parent(PROCESSOR)),
        ("D-drives-home", from_parent(DRIVES_HOME)),
        ("E-identity", from_parent(IDENTITY)),
        ("F-all", from_parent(&all)),
        ("G-none", BTreeMap::new()),
    ];

    for (label, env) in cases {
        lines.push(format!(
            "probe {label}: sending {} vars {:?}",
            env.len(),
            env.keys().collect::<Vec<_>>()
        ));
        let ok = probe(label, powershell(), command(), &directory, env, &mut lines).await;
        if !ok && label != "G-none" {
            failures.push(label);
        }
    }

    for line in &lines {
        eprintln!("{line}");
    }
    // Always panic: libtest only prints captured output for a failing test, so
    // a passing run would hide the very numbers this exists to report.
    panic!(
        "probe categories that did not start PowerShell: {}",
        if failures.is_empty() {
            "none".to_owned()
        } else {
            failures.join(", ")
        }
    );
}
