//! Native Windows static scanning. Target code is read, never executed.
use crate::process::{self, ProcessSpec};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashSet},
    path::{Path, PathBuf},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

pub const SEMGREP_VERSION: &str = "1.176.1";
// The top-level `python -m semgrep` has deliberately exited with an error since 1.38.
const SEMGREP_ENTRYPOINT: &str = "semgrep.console_scripts.entrypoint";

#[derive(Clone)]
pub struct Semgrep {
    pub python: PathBuf,
    pub rules: PathBuf,
    pub core_sha256: String,
}

fn private_environment(work: &Path) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("SEMGREP_SEND_METRICS".into(), "off".into()),
        ("SEMGREP_ENABLE_VERSION_CHECK".into(), "0".into()),
        (
            "SEMGREP_SETTINGS_FILE".into(),
            work.join("semgrep-settings.yml")
                .to_string_lossy()
                .into_owned(),
        ),
        ("PYTHONUTF8".into(), "1".into()),
    ])
}

impl Semgrep {
    pub async fn discover(home: &Path, rules: &Path) -> Option<Self> {
        let python = home.join("python.exe");
        let core = home.join("Lib/site-packages/semgrep/bin/semgrep-core.exe");
        if !python.is_file() || !rules.is_file() || !core.is_file() {
            return None;
        }
        let work = tempfile::Builder::new()
            .prefix("aegis-sast-probe-")
            .tempdir()
            .ok()?;
        let output = process::run(
            ProcessSpec {
                program: python.clone(),
                args: [
                    "-I",
                    "-X",
                    "utf8",
                    "-m",
                    SEMGREP_ENTRYPOINT,
                    "--experimental",
                    "--version",
                ]
                .map(String::from)
                .to_vec(),
                directory: work.path().into(),
                env: private_environment(work.path()),
                timeout: Duration::from_secs(20),
            },
            CancellationToken::new(),
            |_| {},
        )
        .await
        .ok()?;
        if output.exit_code != Some(0)
            || !output.processes_reaped
            || output.cancelled
            || output.timed_out
            || output.truncated
            || String::from_utf8_lossy(&output.stdout).trim() != SEMGREP_VERSION
        {
            return None;
        }
        Some(Self {
            python,
            rules: rules.into(),
            core_sha256: aegis_domain::sha256(&tokio::fs::read(core).await.ok()?),
        })
    }

    pub fn scan_spec(&self, source: &Path, work: &Path) -> ProcessSpec {
        let mut args: Vec<String> = [
            "-I",
            "-X",
            "utf8",
            "-m",
            SEMGREP_ENTRYPOINT,
            "scan",
            "--experimental",
            "--json",
            "--metrics=off",
            "--disable-version-check",
            "--no-git-ignore",
            "--no-rewrite-rule-ids",
            "--x-ignore-semgrepignore-files",
            "--project-root",
            ".",
            "--jobs",
            "2",
            "--timeout",
            "15",
            "--max-target-bytes",
            "2097152",
            "--config",
        ]
        .map(String::from)
        .to_vec();
        args.push(self.rules.to_string_lossy().into_owned());
        args.push(".".into());
        ProcessSpec {
            program: self.python.clone(),
            args,
            directory: source.into(),
            env: private_environment(work),
            timeout: Duration::from_secs(120),
        }
    }
}

pub fn validate_report(report: &Value, files: &[aegis_domain::FileRecord]) -> Result<Value> {
    ensure!(
        report["version"] == SEMGREP_VERSION,
        "Semgrep report version mismatch"
    );
    let results = report["results"]
        .as_array()
        .context("Semgrep results are missing")?;
    let errors = report["errors"]
        .as_array()
        .context("Semgrep errors are missing")?;
    let scanned = report["paths"]["scanned"]
        .as_array()
        .context("Semgrep coverage is missing")?;
    let expected: BTreeMap<_, _> = files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect();
    let relative_path = |path: &Value| -> Result<String> {
        let path = path.as_str().context("Semgrep target path is invalid")?;
        let relative = path.replace('\\', "/");
        let relative = relative.strip_prefix("./").unwrap_or(&relative);
        ensure!(
            expected.contains_key(relative),
            "Semgrep reported a path outside the target snapshot"
        );
        Ok(relative.into())
    };
    let mut scanned_paths = HashSet::new();
    for path in scanned {
        ensure!(
            scanned_paths.insert(relative_path(path)?),
            "Semgrep coverage contains duplicate target paths"
        );
    }
    for finding in results {
        let path = relative_path(&finding["path"])?;
        ensure!(
            scanned_paths.contains(&path),
            "Semgrep finding is missing its scanned-file coverage"
        );
        let file = expected[path.as_str()];
        ensure!(
            finding["start"]["line"]
                .as_u64()
                .is_some_and(|line| line > 0)
                && finding["end"]["line"].as_u64() >= finding["start"]["line"].as_u64()
                && finding["start"]["col"].as_u64().is_some_and(|col| col > 0)
                && finding["end"]["col"].as_u64().is_some_and(|col| col > 0)
                && finding["start"]["offset"].as_u64().is_some()
                && finding["end"]["offset"].as_u64() >= finding["start"]["offset"].as_u64()
                && finding["end"]["offset"]
                    .as_u64()
                    .is_some_and(|offset| offset <= file.size),
            "Semgrep finding has an invalid source range"
        );
    }
    let unscanned_source_files: Vec<_> = files
        .iter()
        .filter(|file| file.language != "data" && !scanned_paths.contains(&file.path))
        .map(|file| file.path.as_str())
        .collect();
    let state = if scanned.is_empty() {
        "NO_TARGETS"
    } else if errors.is_empty()
        && unscanned_source_files.is_empty()
        && !report["skipped_rules"]
            .as_array()
            .is_some_and(|rules| !rules.is_empty())
    {
        "COMPLETED"
    } else {
        "PARTIAL"
    };
    Ok(json!({
        "status": state, "engine": format!("Semgrep CE {SEMGREP_VERSION}"),
        "platform": "windows/x86_64", "target_execution": false,
        "findings_are_clues": true, "scanned_files": scanned,
        "scanned_file_count": scanned.len(), "snapshot_file_count": files.len(),
        "unscanned_source_files": unscanned_source_files,
        "results": results, "errors": errors,
        "skipped_rules": report["skipped_rules"],
        "skipped": report["paths"]["skipped"],
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files() -> Vec<aegis_domain::FileRecord> {
        vec![aegis_domain::FileRecord {
            path: "main.py".into(),
            sha256: "a".repeat(64),
            size: 100,
            language: "python".into(),
        }]
    }

    #[test]
    fn empty_or_incomplete_scan_is_not_a_complete_success() {
        let report =
            json!({"version":SEMGREP_VERSION,"results":[],"errors":[],"paths":{"scanned":[]}});
        assert_eq!(
            validate_report(&report, &files()).unwrap()["status"],
            "NO_TARGETS"
        );
        let report = json!({"version":SEMGREP_VERSION,"results":[],"errors":[{"type":"ParseError"}],"paths":{"scanned":["main.py"]}});
        assert_eq!(
            validate_report(&report, &files()).unwrap()["status"],
            "PARTIAL"
        );
        let report = json!({"version":SEMGREP_VERSION,"results":[],"errors":[],"paths":{"scanned":["main.py"]}});
        let mut input = files();
        input.push(aegis_domain::FileRecord {
            path: "tests/ignored.py".into(),
            ..input[0].clone()
        });
        let coverage = validate_report(&report, &input).unwrap();
        assert_eq!(coverage["status"], "PARTIAL");
        assert_eq!(
            coverage["unscanned_source_files"],
            json!(["tests/ignored.py"])
        );
    }

    #[test]
    fn scanner_cannot_introduce_foreign_paths_or_missing_coverage() {
        let mut report = json!({"version":SEMGREP_VERSION,"results":[],"errors":[],"paths":{"scanned":["../evaluation/answers.py"]}});
        assert!(validate_report(&report, &files()).is_err());
        report["paths"] = json!({});
        assert!(validate_report(&report, &files()).is_err());
        report["paths"] = json!({"scanned":["main.py"]});
        report["results"] = json!([{"path":"other.py","start":{"line":1},"end":{"line":2}}]);
        assert!(validate_report(&report, &files()).is_err());
        report["results"] = json!([]);
        report["paths"] = json!({"scanned":["main.py","./main.py"]});
        assert!(validate_report(&report, &files()).is_err());
    }

    #[test]
    fn findings_require_scanned_files_and_bounded_source_offsets() {
        let mut report = json!({"version":SEMGREP_VERSION,"errors":[],"paths":{"scanned":["main.py"]},
            "results":[{"path":"main.py","start":{"line":1,"col":1,"offset":0},"end":{"line":1,"col":11,"offset":10}}]});
        assert_eq!(
            validate_report(&report, &files()).unwrap()["status"],
            "COMPLETED"
        );
        report["results"][0]["end"]["offset"] = json!(101);
        assert!(validate_report(&report, &files()).is_err());
        report["results"][0]["end"]["offset"] = json!(10);
        report["paths"] = json!({"scanned":[]});
        assert!(validate_report(&report, &files()).is_err());
    }

    #[test]
    fn native_spec_uses_isolated_python_and_local_rules() {
        let scanner = Semgrep {
            python: "C:/Tools/python.exe".into(),
            rules: "C:/Tools/rules.yml".into(),
            core_sha256: "a".repeat(64),
        };
        let spec = scanner.scan_spec(Path::new("C:/Input"), Path::new("C:/Work"));
        assert_eq!(spec.program, scanner.python);
        assert_eq!(spec.args[0], "-I");
        assert!(spec.args.iter().any(|arg| arg == SEMGREP_ENTRYPOINT));
        assert!(spec.args.iter().any(|arg| arg == "--no-git-ignore"));
        assert_eq!(spec.env["SEMGREP_SEND_METRICS"], "off");
        assert!(!spec.env.contains_key("SEMGREP_APP_TOKEN"));
    }
}
