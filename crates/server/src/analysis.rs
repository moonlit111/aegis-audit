//! Analysis ingestion and reuse of a completed, original-image Ghidra result.
use crate::{
    error::{AppError, Result},
    store::{Store, event, load, update_run},
};
use aegis_domain as d;
use serde_json::json;
use sqlx::{Row, SqliteConnection};
use std::collections::HashMap;

// These are the fixed analysis options in executor/jobs.rs::decompile. A derived
// image, alternate exporter, partial result or different tool version is not a hit.
fn compatible_ghidra(tool: &d::ToolExecution, executors: &[d::Executor]) -> bool {
    tool.name == "ghidra"
        && !tool.version.is_empty()
        && executors.iter().any(|e| {
            e.capabilities
                .iter()
                .any(|c| c.name == "ghidra" && c.available && c.version == tool.version)
        })
        && tool.exit_code == Some(0)
        && !tool.terminated
        && tool.details["processes_reaped"] == true
        && tool.details["timed_out"] != true
        && tool.details["cancelled"] != true
        && tool.command.len() == 16
        && [
            (2, "analysis"),
            (3, "-import"),
            (5, "-scriptPath"),
            (7, "-postScript"),
            (8, "ExportProgram.java"),
            (10, "target.bin"),
            (11, "-deleteProject"),
            (12, "-analysisTimeoutPerFile"),
            (13, "120"),
            (14, "-max-cpu"),
            (15, "2"),
        ]
        .iter()
        .all(|(i, arg)| tool.command[*i] == *arg)
}

impl Store {
    pub(crate) async fn reuse_binary_structure(
        &self,
        conn: &mut SqliteConnection,
        run: &mut d::AuditRun,
        snapshot: &d::Snapshot,
        work: &str,
        executors: &[d::Executor],
    ) -> Result<()> {
        let candidates = sqlx::query("SELECT r.id AS source_run_id,w.id AS source_work_id,r.data FROM audit_runs r JOIN work_items w ON w.run_id=r.id WHERE r.snapshot_id=? AND r.state='COMPLETED' AND json_extract(r.data,'$.scope')='STRUCTURE_ANALYSIS' AND w.kind='ANALYZE' AND w.state='COMPLETED' AND w.input_artifact_id=? ORDER BY r.created_at DESC,r.id DESC LIMIT 10")
            .bind(&snapshot.id).bind(&snapshot.normalized_artifact_id).fetch_all(&mut *conn).await?;
        if candidates.is_empty() {
            return Ok(());
        }
        let manifest: d::SnapshotManifest = serde_json::from_slice(
            &self
                .artifact_bytes(&snapshot.manifest_artifact_id, 32 * 1024 * 1024)
                .await?,
        )?;
        let input: d::Artifact = load(conn, "artifacts", &snapshot.normalized_artifact_id).await?;
        if input.sha256 != manifest.target_sha256 || input.sha256 != snapshot.target_sha256 {
            return Ok(());
        }
        for row in candidates {
            let previous: d::AuditRun = serde_json::from_str(&row.get::<String, _>("data"))?;
            let Some(source_id) = previous.summary["result_artifact_id"].as_str() else {
                continue;
            };
            let source_work: String = row.get("source_work_id");
            let owned: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM artifacts WHERE id=? AND snapshot_id=? AND work_item_id=?",
            )
            .bind(source_id)
            .bind(&snapshot.id)
            .bind(&source_work)
            .fetch_one(&mut *conn)
            .await?;
            if owned != 1 {
                continue;
            }
            // An unavailable old blob must not prevent a fresh audit from starting.
            let Ok(bytes) = self.artifact_bytes(source_id, 64 * 1024 * 1024).await else {
                continue;
            };
            let Ok(mut result) = serde_json::from_slice::<d::AnalysisResult>(&bytes) else {
                continue;
            };
            if result.validate(&manifest).is_err()
                || result.partial()
                || !result.units.iter().any(|u| !u.code.trim().is_empty())
                || result.tools.len() != 1
                || !compatible_ghidra(&result.tools[0], executors)
            {
                continue;
            }
            let tool = &mut result.tools[0];
            let log_owned: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM artifacts WHERE id=? AND snapshot_id=? AND work_item_id=?",
            )
            .bind(&tool.log_artifact_id)
            .bind(&snapshot.id)
            .bind(&source_work)
            .fetch_one(&mut *conn)
            .await?;
            if log_owned != 1 {
                continue;
            }
            let mut log: d::Artifact = load(conn, "artifacts", &tool.log_artifact_id).await?;
            if self
                .artifact_bytes(&log.id, 32 * 1024 * 1024)
                .await
                .is_err()
            {
                continue;
            }
            let provenance = json!({"source_run_id":previous.id,"source_artifact_id":source_id,
                "input_sha256":input.sha256,"tool_version":tool.version,"reused_at":d::now()});
            // Attach immutable blobs to this run with fresh artifact identities. Retain
            // original tool timestamps and explicitly identify the reused execution.
            log.id = d::id();
            Self::insert_artifact(conn, &log, Some(&snapshot.id), Some(work), None).await?;
            tool.log_artifact_id = log.id;
            tool.details["analysis_reuse"] = provenance.clone();
            result.metadata["analysis_reuse"] = provenance.clone();
            let artifact = self
                .stage_bytes(
                    &serde_json::to_vec(&result)?,
                    "reused-analysis.json",
                    "application/json",
                )
                .await?;
            Self::insert_artifact(conn, &artifact, Some(&snapshot.id), Some(work), None).await?;
            run.started_at = d::now();
            self.persist_analysis(conn, run, &manifest, &result, &artifact.id, work)
                .await?;
            run.summary["analysis_reuse"] = provenance;
            update_run(conn, run).await?;
            sqlx::query("UPDATE work_items SET state='COMPLETED',cleanup_confirmed=1,payload=json_set(payload,'$.reuse_source_run_id',?) WHERE id=?")
                .bind(&previous.id).bind(work).execute(&mut *conn).await?;
            event(
                conn,
                &run.id,
                "STRUCTURE_REUSED",
                "已复用此快照完成的反编译结果；逆向智能体将评估是否需要补充恢复",
                work,
                run.unit_count,
                run.unit_count,
            )
            .await?;
            break;
        }
        Ok(())
    }

    pub(crate) async fn persist_analysis(
        &self,
        conn: &mut SqliteConnection,
        run: &mut d::AuditRun,
        manifest: &d::SnapshotManifest,
        result: &d::AnalysisResult,
        result_id: &str,
        work: &str,
    ) -> Result<()> {
        result.validate(manifest).map_err(AppError::Invalid)?;
        let ids: HashMap<String, String> = result
            .units
            .iter()
            .map(|u| {
                (
                    u.key.clone(),
                    format!(
                        "u_{}",
                        &d::sha256(format!("{}:{}", run.id, u.key).as_bytes())[..32]
                    ),
                )
            })
            .collect();
        for unit in &result.units {
            let value = d::ProgramUnit {
                id: ids[&unit.key].clone(),
                run_id: run.id.clone(),
                snapshot_id: run.snapshot_id.clone(),
                artifact_id: result_id.into(),
                unit: unit.clone(),
            };
            sqlx::query("INSERT INTO program_units(id,run_id,snapshot_id,name,path,language,data) VALUES(?,?,?,?,?,?,?)")
                .bind(&value.id).bind(&run.id).bind(&run.snapshot_id).bind(&unit.name).bind(&unit.path).bind(&unit.language)
                .bind(serde_json::to_string(&value)?).execute(&mut *conn).await?;
        }
        for edge in &result.edges {
            let value = d::ProgramEdge {
                source_id: ids[&edge.source_key].clone(),
                target_id: ids.get(&edge.target_key).cloned().unwrap_or_default(),
                target_name: edge.target_name.clone(),
                kind: edge.kind.clone(),
                certainty: edge.certainty.clone(),
                line: edge.line,
                address: edge.address.clone(),
            };
            sqlx::query(
                "INSERT INTO program_edges(run_id,source_id,target_id,data) VALUES(?,?,?,?)",
            )
            .bind(&run.id)
            .bind(&value.source_id)
            .bind(if value.target_id.is_empty() {
                None
            } else {
                Some(&value.target_id)
            })
            .bind(serde_json::to_string(&value)?)
            .execute(&mut *conn)
            .await?;
        }
        for tool in &result.tools {
            sqlx::query("INSERT INTO tool_runs(id,work_item_id,run_id,data) VALUES(?,?,?,?)")
                .bind(d::id())
                .bind(work)
                .bind(&run.id)
                .bind(serde_json::to_string(tool)?)
                .execute(&mut *conn)
                .await?;
        }
        run.state = if result.partial() {
            d::RunState::Partial
        } else {
            d::RunState::Completed
        };
        run.finished_at = d::now();
        run.unit_count = result.units.len() as u64;
        let audit_config = run.summary.get("audit_config").cloned();
        run.summary = json!({"metadata":result.metadata,"files":result.files,"warnings":result.warnings,
            "tools":result.tools,"exclusions":manifest.exclusions,"unit_count":run.unit_count,
            "function_count":result.units.iter().filter(|u|u.metadata["kind"]=="function").count(),
            "edge_count":result.edges.len(),"unresolved_calls":result.edges.iter().filter(|e|e.target_key.is_empty()).count(),
            "result_artifact_id":result_id,"vulnerability_audit":"NOT_RUN","verification":"NOT_RUN"});
        if let Some(config) = audit_config {
            run.summary["audit_config"] = config;
        }
        if run.scope == d::AUDIT_SCOPE {
            run.summary["structure_partial"] = json!(result.partial());
            if manifest.kind == "BINARY" {
                run.summary["preparation_artifact_id"] = json!(result_id);
                if result.metadata["recovery_preparation"] == "WAITING_AGENT" {
                    run.summary
                        .as_object_mut()
                        .unwrap()
                        .remove("result_artifact_id");
                    run.summary
                        .as_object_mut()
                        .unwrap()
                        .remove("structure_partial");
                }
            }
            run.summary["vulnerability_audit"] = json!("QUEUED");
            run.state = d::RunState::Running;
            run.finished_at.clear();
            sqlx::query("UPDATE audit_workflows SET state='QUEUED' WHERE run_id=?")
                .bind(&run.id)
                .execute(&mut *conn)
                .await?;
        }
        update_run(conn, run).await
    }
}
