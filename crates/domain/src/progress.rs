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
                // The plan is `eligible ∩ budget`, on one basis. `eligible_unit_count`
                // counts only units that carry code — the basis the auditor plans over —
                // while `unit_count` counts every unit, including ones a semantic audit can
                // never cover. Both `eligible_unit_count` and `audit_config` are written in
                // one transaction when the audit starts, so a run that has a budget also has
                // the eligible count. A run that never reached that stage has no plan yet,
                // and falls back to `unit_count` would advertise one that is both on a
                // different basis and visibly shrinks the moment the audit begins.
                phase.total = run.summary["eligible_unit_count"]
                    .as_u64()
                    .map(|eligible| {
                        eligible.min(
                            run.summary["audit_config"]["max_units"]
                                .as_u64()
                                .unwrap_or(eligible),
                        )
                    })
                    .unwrap_or(0);
                // Completion is relative to the plan. The detail below separately
                // reports whole-target coverage, so a completed budget cannot hide gaps.
                if run.state.terminal()
                    && phase.current < phase.total
                    && phase.status == "COMPLETED"
                {
                    phase.status = "PARTIAL".into();
                    phase.detail = format!(
                        "已审计 {} / {} 个计划单元；存在覆盖缺口",
                        phase.current, phase.total
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
    // Keep plan completion and whole-target coverage visible together, including
    // while planning, after cancellation, and when reopening a budget-limited run.
    if let Some(eligible) = run.summary["eligible_unit_count"].as_u64()
        && let Some(phase) = phases.iter_mut().find(|p| p.id == "AUDIT_REVIEW")
    {
        let budget = run.summary["audit_config"]["max_units"]
            .as_u64()
            .unwrap_or(eligible);
        phase.total = eligible.min(budget);
        phase.current = tasks
            .iter()
            .filter(|t| t.role == "AUDITOR" && t.status == "SUCCEEDED")
            .count() as u64;
        let coverage = format!(
            "已审计 {} / {eligible} 个可读单元；本轮计划 {} 个（上限 {budget}）",
            phase.current, phase.total
        );
        if !phase.detail.is_empty() {
            phase.detail.push_str("。 ");
        }
        phase.detail.push_str(&coverage);
        if eligible > phase.total {
            phase
                .detail
                .push_str(&format!("；{} 个未纳入本轮", eligible - phase.total));
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
    #[test]
    fn a_finished_plan_is_not_reported_as_a_coverage_gap() {
        // max_units (2) sits below eligible (3), so auditing both planned units completes
        // this phase. It used to be downgraded to PARTIAL because the check compared the
        // audited count against `eligible`, leaving the card reading "2 / 2 个计划单元"
        // next to a 部分完成 badge. The run itself stays partial; that gap is the run's to
        // report, not this phase's.
        let mut run = run();
        run.state = RunState::Partial;
        let tasks = vec![
            task("PLANNER", "SUCCEEDED"),
            task("AUDITOR", "SUCCEEDED"),
            task("AUDITOR", "SUCCEEDED"),
            task("REPORTER", "SUCCEEDED"),
        ];
        let phases = workflow_phases(&run, false, &tasks);
        assert_eq!((phases[2].current, phases[2].total), (2, 2));
        assert_eq!(phases[2].status, "COMPLETED");
        assert!(phases[2].detail.contains("已审计 2 / 3 个可读单元"));
        assert!(phases[2].detail.contains("本轮计划 2 个（上限 2）"));
        assert!(phases[2].detail.contains("1 个未纳入本轮"));
    }
    #[test]
    fn an_unfinished_plan_still_reports_the_coverage_gap() {
        // One of the two planned units audited: the phase keeps its warning, and the
        // detail now quotes the same denominator as the progress bar.
        let mut run = run();
        run.state = RunState::Partial;
        let tasks = vec![
            task("PLANNER", "SUCCEEDED"),
            task("AUDITOR", "SUCCEEDED"),
            task("REPORTER", "SUCCEEDED"),
        ];
        let phases = workflow_phases(&run, false, &tasks);
        assert_eq!((phases[2].current, phases[2].total), (1, 2));
        assert_eq!(phases[2].status, "PARTIAL");
        assert!(
            phases[2]
                .detail
                .contains("已审计 1 / 2 个计划单元；存在覆盖缺口")
        );
        assert!(phases[2].detail.contains("已审计 1 / 3 个可读单元"));
    }
    #[test]
    fn an_unplanned_run_shows_no_plan_instead_of_the_raw_unit_count() {
        // Before the audit stage there is no eligible count and no budget, so there is no
        // plan. `unit_count` counts every unit, code-less ones included, so quoting it as
        // the plan would put the bar on a different basis than the auditor's own `limit`
        // and shrink the moment the audit started.
        let mut run = run();
        run.summary = json!({"result_artifact_id": "a"});
        let tasks = vec![task("AUDITOR", "SUCCEEDED")];
        let phases = workflow_phases(&run, false, &tasks);
        assert_eq!(phases[2].total, 0);
        assert_eq!(
            run.unit_count, 3,
            "the raw count is present and deliberately unused"
        );
        assert_eq!(phases[2].current, 1);
    }
}
