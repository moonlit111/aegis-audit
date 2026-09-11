use aegis_domain::{Artifact, AuditEvidence, AuditRun, ProgramUnit, Project, Snapshot};
use anyhow::{Result, bail};
use serde::Serialize;
use serde_json::{Value, json};

mod reader;

#[derive(Serialize)]
pub struct ReportDocument<'a> {
    pub schema_version: u32,
    pub generated_at: String,
    pub interim: bool,
    pub snapshot_state: String,
    pub project: &'a Project,
    pub snapshot: &'a Snapshot,
    pub run: &'a AuditRun,
    pub units: &'a [ProgramUnit],
    pub artifacts: &'a [Artifact],
    pub coverage: Value,
    pub checks: Value,
    pub audit: &'a AuditEvidence,
}

pub fn render(
    project: &Project,
    snapshot: &Snapshot,
    run: &AuditRun,
    units: &[ProgramUnit],
    artifacts: &[Artifact],
    audit: &AuditEvidence,
    format: &str,
) -> Result<(Vec<u8>, &'static str, &'static str)> {
    render_at(
        project,
        snapshot,
        run,
        units,
        artifacts,
        audit,
        format,
        &aegis_domain::now(),
    )
}

pub fn is_interim(run: &AuditRun, audit: &AuditEvidence) -> bool {
    !run.state.terminal()
        || audit.runtime.iter().any(|record| {
            matches!(
                record.status.as_str(),
                "QUEUED" | "RUNNING" | "WAITING_EXECUTOR" | "CANCELLING"
            )
        })
}

#[allow(clippy::too_many_arguments)]
pub fn render_at(
    project: &Project,
    snapshot: &Snapshot,
    run: &AuditRun,
    units: &[ProgramUnit],
    artifacts: &[Artifact],
    audit: &AuditEvidence,
    format: &str,
    snapshot_at: &str,
) -> Result<(Vec<u8>, &'static str, &'static str)> {
    let check = |name: &str| run.summary[name].as_str().unwrap_or("NOT_RUN").to_owned();
    let runtime_check = |mode: &str| {
        let records: Vec<_> = audit
            .runtime
            .iter()
            .filter(|r| r.config.mode == mode)
            .collect();
        if records.is_empty() {
            "NOT_RUN"
        } else if records.iter().any(|r| {
            ["QUEUED", "RUNNING", "WAITING_EXECUTOR", "CANCELLING"].contains(&r.status.as_str())
        }) {
            "RUNNING"
        } else if records.iter().all(|r| r.status == "CANCELLED") {
            "CANCELLED"
        } else if records.iter().any(|r| {
            r.result.is_none()
                || ![
                    "VERIFIED_COMPONENT",
                    "REPRODUCED",
                    "NOT_REPRODUCED",
                    "NO_CRASH_OBSERVED",
                    "CRASH_OBSERVED",
                ]
                .contains(&r.status.as_str())
        }) {
            "PARTIAL"
        } else {
            "COMPLETED"
        }
    };
    let reviewed = audit
        .findings
        .iter()
        .filter(|finding| {
            audit
                .reviews
                .iter()
                .any(|review| review.finding_id == finding.id && review.actor == "MODEL")
        })
        .count();
    let review_status = if reviewed > 0 {
        if reviewed == audit.findings.len() {
            "COMPLETED".into()
        } else {
            "PARTIAL".into()
        }
    } else {
        check("independent_review")
    };
    let document = ReportDocument {
        schema_version: 1,
        generated_at: snapshot_at.into(),
        interim: is_interim(run, audit),
        snapshot_state: run.state.as_str().into(),
        project,
        snapshot,
        run,
        units,
        artifacts,
        coverage: run.summary.clone(),
        checks: json!({
            "vulnerability_audit":check("vulnerability_audit"),
            "independent_review":review_status,
            "fuzzing":runtime_check("FUZZ"),
            "runtime_verification":runtime_check("VERIFY"),
            "exploitation":check("exploitation")
        }),
        audit,
    };
    match format {
        // Keep the version-1 machine-readable contract, including saved evidence and history.
        "json" => Ok((
            serde_json::to_vec_pretty(&document)?,
            "application/json",
            "json",
        )),
        "html" => Ok((
            reader::render(&document, true)?.into_bytes(),
            "text/html; charset=utf-8",
            "html",
        )),
        "markdown" => Ok((
            reader::render(&document, false)?.into_bytes(),
            "text/markdown; charset=utf-8",
            "md",
        )),
        _ => bail!("unsupported report format"),
    }
}

pub fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untrusted_html_is_escaped() {
        assert_eq!(
            escape("<script>\"x\"</script>"),
            "&lt;script&gt;&quot;x&quot;&lt;/script&gt;"
        );
    }
}
