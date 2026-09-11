//! Offline report preview from a frozen JSON export. Does not contact models or run targets.
//! cargo run -p aegis-application --example report_preview -- input.json output-dir [--pdf]
use aegis_application::{pdf, report};
use aegis_domain::{Artifact, AuditEvidence, AuditRun, ProgramUnit, Project, Snapshot};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Deserialize)]
struct SavedReport {
    project: Project,
    snapshot: Snapshot,
    run: AuditRun,
    units: Vec<ProgramUnit>,
    artifacts: Vec<Artifact>,
    audit: AuditEvidence,
    generated_at: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        args.len() == 2 || (args.len() == 3 && args[2] == "--pdf"),
        "usage: report_preview input.json output-dir [--pdf]"
    );
    let input: SavedReport = serde_json::from_slice(&std::fs::read(&args[0])?)
        .context("input must be a frozen report JSON export")?;
    let directory = PathBuf::from(&args[1]);
    std::fs::create_dir_all(&directory)?;
    for format in ["html", "markdown", "json"] {
        let (bytes, _, ext) = report::render_at(
            &input.project,
            &input.snapshot,
            &input.run,
            &input.units,
            &input.artifacts,
            &input.audit,
            format,
            &input.generated_at,
        )?;
        let path = directory.join(format!("report.{ext}"));
        std::fs::write(&path, &bytes)?;
        println!("{} ({} bytes)", path.display(), bytes.len());
        if format == "html" && args.len() == 3 {
            let pdf = pdf::render(&bytes).await?;
            let path = directory.join("report.pdf");
            std::fs::write(&path, &pdf)?;
            println!("{} ({} bytes)", path.display(), pdf.len());
        }
    }
    Ok(())
}
