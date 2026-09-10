use crate::{
    error::Result,
    store::{Store, load},
};
use aegis_domain as d;
use sqlx::SqliteConnection;

pub(crate) async fn event_phase(
    conn: &mut SqliteConnection,
    run_id: &str,
    kind: &str,
    work: &str,
) -> Result<(String, u32, u32)> {
    let run: d::AuditRun = load(conn, "audit_runs", run_id).await?;
    let snapshot: d::Snapshot = load(conn, "snapshots", &run.snapshot_id).await?;
    let phases = d::phase_definitions(&run.scope, snapshot.kind == "BINARY");
    let role: Option<String> =
        sqlx::query_scalar("SELECT role FROM agent_tasks WHERE id=? AND run_id=?")
            .bind(work)
            .bind(run_id)
            .fetch_optional(&mut *conn)
            .await?;
    let work_kind: Option<String> =
        sqlx::query_scalar("SELECT kind FROM work_items WHERE id=? AND run_id=?")
            .bind(work)
            .bind(run_id)
            .fetch_optional(&mut *conn)
            .await?;
    let explicit = if let Some(role) = role {
        d::role_phase(&role).to_string()
    } else if kind == "STRUCTURE_COMPLETED" {
        "STRUCTURE".into()
    } else if kind == "AUDIT_STARTED" {
        if snapshot.kind == "BINARY" {
            "RECOVERY"
        } else {
            "PLANNING"
        }
        .into()
    } else if matches!(
        kind,
        "FINDING_REVIEWED" | "ANNOTATION_CREATED" | "ANNOTATION_UPDATED"
    ) {
        "AUDIT_REVIEW".into()
    } else {
        match work_kind.as_deref() {
            Some("ANALYZE") => "STRUCTURE",
            Some("RECOVER") => "RECOVERY",
            Some("RUNTIME") => "RUNTIME",
            _ => "",
        }
        .into()
    };
    let id = if explicit.is_empty() {
        let previous: Option<String> = sqlx::query_scalar("SELECT json_extract(data,'$.phase_id') FROM run_events WHERE run_id=? ORDER BY seq DESC LIMIT 1")
            .bind(run_id).fetch_optional(&mut *conn).await?.flatten();
        previous
            .filter(|id| !id.is_empty())
            .unwrap_or_else(|| phases[0].id.clone())
    } else {
        explicit
    };
    let index = phases.iter().position(|p| p.id == id).unwrap_or(0);
    Ok((
        phases[index].id.clone(),
        index as u32 + 1,
        phases.len() as u32,
    ))
}

impl Store {
    pub async fn run_phases(&self, run_id: &str) -> Result<Vec<d::RunPhase>> {
        let _guard = self.writes.lock().await;
        let run: d::AuditRun = self.get("audit_runs", run_id).await?;
        let snapshot: d::Snapshot = self.get("snapshots", &run.snapshot_id).await?;
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT data FROM agent_tasks WHERE run_id=? ORDER BY created_at,id",
        )
        .bind(run_id)
        .fetch_all(&self.pool)
        .await?;
        let tasks = rows
            .iter()
            .map(|row| serde_json::from_str(row))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut phases = d::workflow_phases(&run, snapshot.kind == "BINARY", &tasks);
        for phase in &mut phases {
            if ["STRUCTURE", "RECOVERY", "RUNTIME"].contains(&phase.id.as_str()) {
                let row: Option<String> = sqlx::query_scalar("SELECT data FROM run_events WHERE run_id=? AND json_extract(data,'$.kind')='TOOL_PROGRESS' AND (json_extract(data,'$.phase_id')=? OR (?=1 AND json_extract(data,'$.phase_id') IS NULL)) ORDER BY seq DESC LIMIT 1")
                    .bind(run_id).bind(&phase.id).bind(phase.order).fetch_optional(&self.pool).await?;
                if let Some(row) = row {
                    let event: d::RunEvent = serde_json::from_str(&row)?;
                    phase.current = event.current;
                    phase.total = event.total;
                    if phase.detail.is_empty() {
                        phase.detail = event.message;
                    }
                }
            }
            if phase.role == "REVIEWER" {
                if let Some(task) = tasks.iter().find(|t| {
                    t.role == "REVIEWER" && matches!(t.status.as_str(), "RUNNING" | "INTERRUPTED")
                }) {
                    let row: Option<String> =
                        sqlx::query_scalar("SELECT data FROM findings WHERE id=? AND run_id=?")
                            .bind(&task.item_key)
                            .bind(run_id)
                            .fetch_optional(&self.pool)
                            .await?;
                    if let Some(row) = row {
                        phase.unit_id = serde_json::from_str::<d::Finding>(&row)?.draft.unit_id;
                    }
                }
            }
        }
        Ok(phases)
    }
}
