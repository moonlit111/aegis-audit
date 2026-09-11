use crate::{AUDIT_SCOPE, AgentTask, AuditRun, RunState};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RunPhase {
    pub id: String,
    pub title: String,
    pub order: u32,
    pub status: String,
    pub current: u64,
    pub total: u64,
    pub detail: String,
    pub role: String,
    pub unit_id: String,
}

pub fn role_phase(role: &str) -> &'static str {
    match role {
        "REVERSE" => "RECOVERY",
        "PLANNER" => "PLANNING",
        "AUDITOR" | "REVIEWER" => "AUDIT_REVIEW",
        "VERIFIER" => "VERIFICATION_PLAN",
        "REPORTER" => "REPORT",
        _ => "",
    }
}

pub fn phase_definitions(scope: &str, binary: bool) -> Vec<RunPhase> {
    let mut entries = vec![("STRUCTURE", "程序结构解析")];
    if matches!(scope, "RUNTIME_VERIFICATION" | "DYNAMIC_TESTING") {
        entries = vec![("RUNTIME", "动态执行与进程回收")];
    } else if scope == AUDIT_SCOPE {
        if binary {
            entries = vec![("PREPARATION", "目标准备")];
            entries.push(("RECOVERY", "逆向与反编译"));
        }
        entries.extend([
            ("PLANNING", "审计策略与优先级"),
            ("AUDIT_REVIEW", "逐单元审计与复核"),
            ("VERIFICATION_PLAN", "验证方案生成"),
            ("REPORT", "结论与覆盖汇总"),
        ]);
    }
    entries
        .into_iter()
        .enumerate()
        .map(|(i, (id, title))| RunPhase {
            id: id.into(),
            title: title.into(),
            order: i as u32 + 1,
            status: "PENDING".into(),
            ..Default::default()
        })
        .collect()
}

/// Reconstruct from durable workflow facts so reload/restart does not reset progress.
/// A later role closes the interleaved audit/review loop; a budget is not a percentage.
pub fn workflow_phases(run: &AuditRun, binary: bool, tasks: &[AgentTask]) -> Vec<RunPhase> {
    let mut phases = phase_definitions(&run.scope, binary);
    let preparation = binary && run.scope == AUDIT_SCOPE;
    let structure_done = run.summary["result_artifact_id"].is_string()
        || (preparation && run.summary["preparation_artifact_id"].is_string());
    let last_started = tasks
        .iter()
        .filter_map(|t| phases.iter().position(|p| p.id == role_phase(&t.role)))
        .max();
    for (index, phase) in phases.iter_mut().enumerate() {
        let rows: Vec<_> = tasks
            .iter()
            .filter(|t| role_phase(&t.role) == phase.id)
            .collect();
        let later = last_started.is_some_and(|last| last > index);
        if index == 0 {
            phase.status = if structure_done {
                if !preparation
                    && (run.summary["structure_partial"].as_bool() == Some(true)
                        || (run.scope != AUDIT_SCOPE && run.state == RunState::Partial))
                {
                    "PARTIAL"
                } else {
                    "COMPLETED"
                }
            } else if run.state == RunState::Completed {
                "COMPLETED"
            } else if run.started_at.is_empty() {
                "WAITING"
            } else {
                "RUNNING"
            }
            .into();
            if preparation && structure_done {
                phase.detail = if run.summary["analysis_reuse"].is_object() {
                    "已复用同一快照的反编译结果，后续按需补充逆向恢复"
                } else {
                    "目标信息已准备；代码恢复与反编译在下一阶段执行"
                }
                .into();
            }
        } else if rows.is_empty() {
            if later {
                phase.status = "SKIPPED".into();
                phase.detail = "本次流程没有需要执行的子任务".into();
            }
        } else {
            phase.current = rows.iter().filter(|t| t.status == "SUCCEEDED").count() as u64;
            phase.total = rows.len() as u64;
            let running = rows
                .iter()
                .find(|t| t.status == "RUNNING")
                .or_else(|| rows.iter().find(|t| t.status == "INTERRUPTED"))
                .copied();
            if let Some(task) = running {
                phase.role = task.role.clone();
                if task.role == "AUDITOR" {
                    phase.unit_id = task.item_key.clone();
                }
                phase.detail = if task.status == "INTERRUPTED" {
                    "服务重启后等待恢复，已完成结果保留".into()
                } else {
                    format!("{} 正在执行", task.role)
                };
            }
            let complete = phase.current == phase.total;
            phase.status = if complete
                && (later || phase.id != "AUDIT_REVIEW" || run.state == RunState::Completed)
            {
                "COMPLETED"
            } else if later {
                "PARTIAL"
            } else {
                "RUNNING"
            }
            .into();
            if phase.id == "AUDIT_REVIEW" {
                phase.current = rows
                    .iter()
                    .filter(|t| t.role == "AUDITOR" && t.status == "SUCCEEDED")
                    .count() as u64;
                let eligible = run.summary["eligible_unit_count"]
                    .as_u64()
                    .unwrap_or(run.unit_count);
                phase.total = eligible.min(
                    run.summary["audit_config"]["max_units"]
                        .as_u64()
                        .unwrap_or(eligible),
                );
                if phase.detail.is_empty() {
                    phase.detail =
                        "每个单元审计后立即复核新发现；计数为本次计划内的已审计单元".into();
                }
                if run.state.terminal() && phase.current < eligible && phase.status == "COMPLETED" {
                    phase.status = "PARTIAL".into();
                    phase.detail = format!(
                        "已审计 {} / {eligible} 个可审计单元；存在覆盖缺口",
                        phase.current
                    );
                }
            }
        }
    }
    let active = phases
        .iter()
        .position(|p| matches!(p.status.as_str(), "PENDING" | "WAITING" | "RUNNING"));
    if let Some(index) = active {
        if run.state.terminal() {
            phases[index].status = match run.state {
                RunState::Cancelled => "CANCELLED",
                RunState::Completed => "COMPLETED",
                RunState::Partial | RunState::LimitReached => "PARTIAL",
                _ => "FAILED",
            }
            .into();
            phases[index].detail = run.error.clone();
            for phase in &mut phases[index + 1..] {
                if phase.status == "PENDING" {
                    phase.status = "SKIPPED".into();
                    phase.detail = "任务已结束，此阶段未执行".into();
                }
            }
        } else if run.state == RunState::Cancelling {
            phases[index].status = "CANCELLING".into();
            phases[index].detail = "等待模型调用停止及工具进程回收确认".into();
        } else if phases[index].status == "PENDING" {
            phases[index].status = "WAITING".into();
            phases[index].detail = "等待调度；已完成阶段保留".into();
        }
    }
    phases
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn run() -> AuditRun {
        serde_json::from_value(json!({"id":"r","project_id":"p","snapshot_id":"s","state":"RUNNING",
            "scope":AUDIT_SCOPE,"created_at":"","started_at":"now","finished_at":"","unit_count":3,
            "summary":{"result_artifact_id":"a","eligible_unit_count":3,"audit_config":{"max_units":2}},"error":""})).unwrap()
    }
    fn task(role: &str, status: &str) -> AgentTask {
        AgentTask {
            role: role.into(),
            status: status.into(),
            ..Default::default()
        }
    }
    #[test]
    fn interleaved_review_and_resume_stay_in_same_phase() {
        let tasks = vec![
            task("PLANNER", "SUCCEEDED"),
            task("AUDITOR", "SUCCEEDED"),
            task("REVIEWER", "RUNNING"),
        ];
        let phases = workflow_phases(&run(), false, &tasks);
        assert_eq!(
            (
                phases[2].status.as_str(),
                phases[2].role.as_str(),
                phases[2].current,
                phases[2].total
            ),
            ("RUNNING", "REVIEWER", 1, 2)
        );
        let mut resumed = tasks;
        resumed[2].status = "INTERRUPTED".into();
        assert_eq!(workflow_phases(&run(), false, &resumed)[2].current, 1);
    }
    #[test]
    fn cancellation_does_not_finish_pending_phases() {
        let mut run = run();
        run.state = RunState::Cancelling;
        let tasks = vec![task("PLANNER", "SUCCEEDED"), task("AUDITOR", "RUNNING")];
        assert_eq!(workflow_phases(&run, false, &tasks)[2].status, "CANCELLING");
        run.state = RunState::Cancelled;
        let phases = workflow_phases(&run, false, &tasks);
        assert_eq!(phases[0].status, "COMPLETED");
        assert_eq!(phases[2].status, "CANCELLED");
        assert_eq!(phases[3].status, "SKIPPED");
    }
    #[test]
    fn absent_verification_is_skipped_and_coverage_gap_is_preserved() {
        let mut run = run();
        run.state = RunState::Partial;
        let tasks = vec![
            task("PLANNER", "SUCCEEDED"),
            task("AUDITOR", "SUCCEEDED"),
            task("REPORTER", "SUCCEEDED"),
        ];
        let phases = workflow_phases(&run, false, &tasks);
        assert_eq!(phases[2].status, "PARTIAL");
        assert_eq!(phases[3].status, "SKIPPED");
        assert_eq!(phases[4].status, "COMPLETED");
        assert_eq!(phase_definitions(AUDIT_SCOPE, true).len(), 6);
        assert_eq!(phase_definitions("STRUCTURE_ANALYSIS", false).len(), 1);
        assert_eq!(phase_definitions("DYNAMIC_TESTING", true)[0].id, "RUNTIME");
    }
}
