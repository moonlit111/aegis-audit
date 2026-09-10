//! Persistent tool handoffs for the REVERSE agent. Credentials stay in the controller.
use crate::{
    error::{AppError, Result},
    store::{Store, event, load, update_run},
};
use aegis_domain as d;
use serde_json::{Value, json};
use sqlx::{Row, SqliteConnection};
use std::{collections::HashMap, time::Duration};
use tokio_util::sync::CancellationToken;

fn invalid(message: &str) -> AppError {
    AppError::Invalid(message.into())
}

impl Store {
    pub(crate) async fn recovery_context(&self, run_id: &str) -> Result<Value> {
        let run: d::AuditRun = self.get("audit_runs", run_id).await?;
        let executors = self.executors().await?;
        let tools: Vec<_> = [d::RecoveryTool::Upx, d::RecoveryTool::Floss, d::RecoveryTool::Ghidra, d::RecoveryTool::IdaD810, d::RecoveryTool::BuiltinStrings]
            .into_iter().map(|tool| json!({"tool":tool,"available":executors.iter().any(|e| e.capabilities.iter().any(|c| c.name==tool.capability() && c.available)),
                "scope":match tool { d::RecoveryTool::Upx=>"UPX only; produces a separate binary",d::RecoveryTool::Floss=>"PE x86/x64 emulated string recovery; not control-flow deobfuscation",d::RecoveryTool::Ghidra=>"PE/ELF pseudocode; attaches matching recovered-string evidence",d::RecoveryTool::IdaD810=>"Local IDA/Hex-Rays + D-810; profile instructions or control_flow; requires a verified local probe",d::RecoveryTool::BuiltinStrings=>"XOR/Base64 heuristic candidates, not proven code transformations"}})).collect();
        Ok(
            json!({"tools":tools,"recovery":run.summary["recovery"],"maximum_executed_steps":d::MAX_RECOVERY_STEPS}),
        )
    }

    pub(crate) async fn plan_recovery(&self, task: &d::AgentTask, value: Value) -> Result<Value> {
        if task.role != "REVERSE" {
            return Err(AppError::Denied("只有逆向智能体可以规划工具步骤".into()));
        }
        let plan: d::RecoveryPlan = serde_json::from_value(value)?;
        plan.validate().map_err(AppError::Invalid)?;
        let _guard = self.writes.lock().await;
        let mut tx = self.pool.begin().await?;
        let mut run = Self::active_audit(&mut tx, &task.run_id).await?;
        let snapshot: d::Snapshot = load(&mut tx, "snapshots", &run.snapshot_id).await?;
        if snapshot.kind != "BINARY" {
            return Err(invalid("逆向工具只处理二进制快照"));
        }
        if !run.summary["recovery"].is_object() {
            run.summary["recovery"] =
                json!({"schema_version":1,"plans":[],"history":[],"running_work_id":""});
        }
        let state = &mut run.summary["recovery"];
        if state["running_work_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty())
        {
            return Err(invalid("当前步骤尚在执行，请先等待结果再调整计划"));
        }
        let plans = state["plans"]
            .as_array_mut()
            .ok_or_else(|| invalid("逆向计划记录无效"))?;
        if plans.len() >= 4 {
            return Err(invalid("本轮逆向计划调整达到上限"));
        }
        let plan_id = d::id();
        plans.push(json!({"id":plan_id,"task_id":task.id,"created_at":d::now(),"plan":plan}));
        state["plan"] = serde_json::to_value(&plan)?;
        state["plan_id"] = json!(plan_id);
        state["next_step"] = json!(0);
        state["status"] = json!("PLANNED");
        update_run(&mut tx, &run).await?;
        event(
            &mut tx,
            &run.id,
            "RECOVERY_PLANNED",
            &plan.assessment,
            &task.id,
            0,
            plan.steps.len() as u64,
        )
        .await?;
        tx.commit().await?;
        self.changed.notify_waiters();
        Ok(
            json!({"plan_id":plan_id,"accepted_plan":plan,"next_action":"run_recovery_step or finish with limitations"}),
        )
    }

    pub(crate) async fn run_recovery_step(
        &self,
        task: &d::AgentTask,
        args: &Value,
        shutdown: &CancellationToken,
    ) -> Result<Value> {
        if task.role != "REVERSE" {
            return Err(AppError::Denied("只有逆向智能体可以调用恢复工具".into()));
        }
        if !args.as_object().is_some_and(|o| o.is_empty()) {
            return Err(invalid("run_recovery_step 不接受命令或路径参数"));
        }
        let available = self.executors().await?;
        let work_id;
        {
            let _guard = self.writes.lock().await;
            let mut tx = self.pool.begin().await?;
            let mut run = Self::active_audit(&mut tx, &task.run_id).await?;
            if let Some(existing) = run.summary["recovery"]["running_work_id"]
                .as_str()
                .filter(|s| !s.is_empty())
            {
                work_id = existing.to_owned();
            } else {
                let snapshot: d::Snapshot = load(&mut tx, "snapshots", &run.snapshot_id).await?;
                if snapshot.kind != "BINARY" {
                    return Err(invalid("逆向工具只处理二进制快照"));
                }
                let plan: d::RecoveryPlan =
                    serde_json::from_value(run.summary["recovery"]["plan"].clone())
                        .map_err(|_| invalid("请先调用 plan_recovery 保存有特征依据的步骤计划"))?;
                let next = run.summary["recovery"]["next_step"].as_u64().unwrap_or(0) as usize;
                let step = plan
                    .steps
                    .get(next)
                    .ok_or_else(|| invalid("当前计划没有待执行步骤"))?;
                let history = run.summary["recovery"]["history"]
                    .as_array()
                    .ok_or_else(|| invalid("逆向历史无效"))?;
                if history.len() >= d::MAX_RECOVERY_STEPS {
                    return Err(invalid("逆向工具步骤达到上限"));
                }
                let input = match step.input {
                    d::RecoveryInput::Original => Some(snapshot.normalized_artifact_id.clone()),
                    d::RecoveryInput::Unpacked => history
                        .iter()
                        .rev()
                        .find(|h| h["tool"] == "upx" && h["status"] == "PROCESSED")
                        .and_then(|h| h["output_artifact_id"].as_str())
                        .map(str::to_owned),
                };
                let ready = available.iter().any(|e| {
                    e.capabilities
                        .iter()
                        .any(|c| c.name == step.tool.capability() && c.available)
                });
                let strings_id = input
                    .as_ref()
                    .and_then(|input| {
                        history.iter().rev().find(|h| {
                            h["input_artifact_id"] == input.as_str()
                                && h["strings_artifact_id"]
                                    .as_str()
                                    .is_some_and(|s| !s.is_empty())
                        })
                    })
                    .and_then(|h| h["strings_artifact_id"].as_str())
                    .unwrap_or("")
                    .to_owned();
                run.summary["recovery"]["next_step"] = json!(next + 1);
                if !ready || input.is_none() {
                    let observation = json!({"tool":step.tool,"status":if !ready {"UNAVAILABLE"} else {"INPUT_UNAVAILABLE"},
                        "reason":if !ready {"执行器未报告该工具可用；可调整计划或保留缺口"} else {"没有成功去壳的派生产物，不能把原件冒充解包结果"},
                        "plan_id":run.summary["recovery"]["plan_id"],"step":next,"work_item_id":""});
                    run.summary["recovery"]["history"]
                        .as_array_mut()
                        .unwrap()
                        .push(observation.clone());
                    update_run(&mut tx, &run).await?;
                    event(
                        &mut tx,
                        &run.id,
                        "RECOVERY_UNAVAILABLE",
                        observation["reason"].as_str().unwrap(),
                        &task.id,
                        next as u64,
                        plan.steps.len() as u64,
                    )
                    .await?;
                    tx.commit().await?;
                    self.changed.notify_waiters();
                    return Ok(observation);
                }
                let input = input.unwrap();
                let artifact: d::Artifact = load(&mut tx, "artifacts", &input).await?;
                work_id = d::id();
                let payload = json!({"step":step,"input_sha256":artifact.sha256,"manifest_artifact_id":snapshot.manifest_artifact_id,
                    "strings_artifact_id":if [d::RecoveryTool::Ghidra,d::RecoveryTool::IdaD810].contains(&step.tool) {strings_id} else {String::new()},
                    "task_id":task.id,"plan_id":run.summary["recovery"]["plan_id"],"step_index":next});
                sqlx::query("INSERT INTO work_items(id,snapshot_id,run_id,kind,capability,state,created_at,input_artifact_id,payload) VALUES(?,?,?,'RECOVER',?,'QUEUED',?,?,?)")
                    .bind(&work_id).bind(&run.snapshot_id).bind(&run.id).bind(step.tool.capability()).bind(d::now()).bind(&input).bind(payload.to_string()).execute(&mut *tx).await?;
                run.summary["recovery"]["running_work_id"] = json!(work_id);
                run.summary["recovery"]["status"] = json!("RUNNING");
                update_run(&mut tx, &run).await?;
                event(
                    &mut tx,
                    &run.id,
                    "RECOVERY_QUEUED",
                    &format!("逆向智能体调用 {}：{}", step.tool.capability(), step.reason),
                    &work_id,
                    next as u64,
                    plan.steps.len() as u64,
                )
                .await?;
            }
            tx.commit().await?;
        }
        self.changed.notify_waiters();
        loop {
            if shutdown.is_cancelled() {
                return Err(invalid("服务停止；逆向步骤保留，重启后核对原任务结果"));
            }
            let run: d::AuditRun = self.get("audit_runs", &task.run_id).await?;
            if let Some(result) = run.summary["recovery"]["history"]
                .as_array()
                .and_then(|history| history.iter().find(|h| h["work_item_id"] == work_id))
            {
                return Ok(result.clone());
            }
            if run.state != d::RunState::Running {
                return Err(invalid("逆向步骤已取消或失败；未采纳未确认的结果"));
            }
            let seconds = run.summary["audit_config"]["timeout_seconds"]
                .as_i64()
                .unwrap_or(3600);
            if chrono::DateTime::parse_from_rfc3339(&run.started_at).is_ok_and(|started| {
                (chrono::Utc::now() - started.with_timezone(&chrono::Utc)).num_seconds() >= seconds
            }) {
                self.cancel_run(&run.id).await?;
                return Err(invalid("逆向处理达到审计时限，已请求取消工具并回收进程"));
            }
            tokio::select! { _=shutdown.cancelled()=>{}, _=self.changed.notified()=>{}, _=tokio::time::sleep(Duration::from_millis(300))=>{} }
        }
    }

    pub(crate) async fn ingest_recovery(
        &self,
        conn: &mut SqliteConnection,
        run_id: &str,
        work: &str,
        attempt: &str,
        result_id: &str,
        bytes: &[u8],
    ) -> Result<()> {
        let result: d::RecoveryResult = serde_json::from_slice(bytes)?;
        let mut run: d::AuditRun = load(conn, "audit_runs", run_id).await?;
        if run.state != d::RunState::Running || run.summary["recovery"]["running_work_id"] != work {
            return Err(invalid("逆向结果不对应当前活动步骤"));
        }
        let row = sqlx::query("SELECT payload,input_artifact_id FROM work_items WHERE id=?")
            .bind(work)
            .fetch_one(&mut *conn)
            .await?;
        let payload: Value = serde_json::from_str(&row.get::<String, _>("payload"))?;
        let step: d::RecoveryStep = serde_json::from_value(payload["step"].clone())?;
        let input: d::Artifact = load(
            conn,
            "artifacts",
            &row.get::<String, _>("input_artifact_id"),
        )
        .await?;
        if result.schema_version != 1
            || result.tool != step.tool
            || result.input_artifact_id != input.id
            || result.input_sha256 != input.sha256
            || ![
                "PROCESSED",
                "RECOVERED",
                "CANDIDATES",
                "COMPLETED",
                "NOT_FOUND",
                "UNSUPPORTED",
                "UNAVAILABLE",
                "FAILED",
            ]
            .contains(&result.status.as_str())
        {
            return Err(invalid("逆向结果的工具、输入、哈希或状态与当前任务不一致"));
        }
        for id in [
            &result.output_artifact_id,
            &result.strings_artifact_id,
            &result.readable_artifact_id,
        ] {
            if !id.is_empty() {
                Self::ensure_output(conn, id, work, attempt).await?;
            }
        }
        for tool in &result.tools {
            Self::ensure_output(conn, &tool.log_artifact_id, work, attempt).await?;
        }
        if !result.output_artifact_id.is_empty() {
            let artifact: d::Artifact = load(conn, "artifacts", &result.output_artifact_id).await?;
            if result.tool != d::RecoveryTool::Upx
                || result.status != "PROCESSED"
                || result.output_sha256 != artifact.sha256
            {
                return Err(invalid("去壳派生产物与状态或哈希不符"));
            }
            let data = self.artifact_bytes(&artifact.id, 64 * 1024 * 1024).await?;
            aegis_application::import::inspect_binary(&data)
                .map_err(|e| invalid(&e.to_string()))?;
        } else if result.status == "PROCESSED" {
            return Err(invalid("去壳完成但缺少派生产物"));
        }
        if !result.strings_artifact_id.is_empty() {
            let recovered: d::RecoveredStrings = serde_json::from_slice(
                &self
                    .artifact_bytes(&result.strings_artifact_id, 8 * 1024 * 1024)
                    .await?,
            )?;
            if recovered.schema_version != 1
                || recovered.input_sha256 != input.sha256
                || recovered.tool != step.tool
                || recovered.strings.len() > 512
                || recovered.strings.iter().any(|s| s.text.len() > 8192)
                || ![d::RecoveryTool::Floss, d::RecoveryTool::BuiltinStrings].contains(&step.tool)
            {
                return Err(invalid("字符串恢复证据不属于本次输入或超过限制"));
            }
        }
        let mut preview = vec![];
        if let Some(analysis) = &result.analysis {
            if ![d::RecoveryTool::Ghidra, d::RecoveryTool::IdaD810].contains(&result.tool)
                || result.status != "COMPLETED"
                || result.readable_artifact_id.is_empty()
            {
                return Err(invalid("反编译结果缺少合法工具状态或可读产物"));
            }
            let audited: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM agent_tasks WHERE run_id=? AND role='AUDITOR'",
            )
            .bind(run_id)
            .fetch_one(&mut *conn)
            .await?;
            if audited != 0 {
                return Err(invalid("语义审计开始后不能替换其代码证据"));
            }
            let snapshot: d::Snapshot = load(conn, "snapshots", &run.snapshot_id).await?;
            let manifest: d::SnapshotManifest = serde_json::from_slice(
                &self
                    .artifact_bytes(&snapshot.manifest_artifact_id, 32 * 1024 * 1024)
                    .await?,
            )?;
            analysis.validate(&manifest).map_err(AppError::Invalid)?;
            let ids: HashMap<_, _> = analysis
                .units
                .iter()
                .map(|u| {
                    (
                        u.key.clone(),
                        format!(
                            "u_{}",
                            &d::sha256(format!("{run_id}:{result_id}:{}", u.key).as_bytes())[..32]
                        ),
                    )
                })
                .collect();
            sqlx::query("DELETE FROM program_edges WHERE run_id=?")
                .bind(run_id)
                .execute(&mut *conn)
                .await?;
            sqlx::query("DELETE FROM program_units WHERE run_id=?")
                .bind(run_id)
                .execute(&mut *conn)
                .await?;
            for unit in &analysis.units {
                let mut unit = unit.clone();
                unit.metadata["analysis_input_artifact_id"] = json!(input.id);
                unit.metadata["analysis_input_sha256"] = json!(input.sha256);
                unit.metadata["analysis_engine"] =
                    json!(if step.tool == d::RecoveryTool::IdaD810 {
                        "IDA_HEXRAYS_D810"
                    } else {
                        "GHIDRA"
                    });
                unit.metadata["address_space"] =
                    json!(if input.id == snapshot.normalized_artifact_id {
                        "ORIGINAL_IMAGE"
                    } else {
                        "UNPACKED_IMAGE"
                    });
                unit.metadata["original_instruction_mapping"] =
                    json!(if input.id == snapshot.normalized_artifact_id {
                        "FUNCTION_LEVEL_ONLY"
                    } else {
                        "NOT_ESTABLISHED"
                    });
                let value = d::ProgramUnit {
                    id: ids[&unit.key].clone(),
                    run_id: run_id.into(),
                    snapshot_id: run.snapshot_id.clone(),
                    artifact_id: result_id.into(),
                    unit,
                };
                if preview.len() < 4 && !value.unit.code.is_empty() {
                    preview.push(json!({"name":value.unit.name,"address":value.unit.address,"code":value.unit.code.chars().take(2000).collect::<String>()}));
                }
                sqlx::query("INSERT INTO program_units(id,run_id,snapshot_id,name,path,language,data) VALUES(?,?,?,?,?,?,?)")
                    .bind(&value.id).bind(run_id).bind(&run.snapshot_id).bind(&value.unit.name).bind(&value.unit.path).bind(&value.unit.language).bind(serde_json::to_string(&value)?).execute(&mut *conn).await?;
            }
            for edge in &analysis.edges {
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
                .bind(run_id)
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
            run.unit_count = analysis.units.len() as u64;
            run.summary["metadata"] = analysis.metadata.clone();
            run.summary["files"] = serde_json::to_value(&analysis.files)?;
            run.summary["warnings"] = serde_json::to_value(&analysis.warnings)?;
            run.summary["structure_partial"] = json!(analysis.partial());
            run.summary["unit_count"] = json!(run.unit_count);
            run.summary["function_count"] = json!(analysis.units.len());
            run.summary["edge_count"] = json!(analysis.edges.len());
            run.summary["unresolved_calls"] = json!(
                analysis
                    .edges
                    .iter()
                    .filter(|e| e.target_key.is_empty())
                    .count()
            );
            run.summary["result_artifact_id"] = json!(result_id);
        }
        for tool in &result.tools {
            sqlx::query("INSERT INTO tool_runs(id,work_item_id,run_id,data) VALUES(?,?,?,?)")
                .bind(d::id())
                .bind(work)
                .bind(run_id)
                .bind(serde_json::to_string(tool)?)
                .execute(&mut *conn)
                .await?;
        }
        let record = json!({"work_item_id":work,"result_artifact_id":result_id,"plan_id":payload["plan_id"],"step":payload["step_index"],
            "tool":result.tool,"status":result.status,"input_artifact_id":input.id,"input_sha256":input.sha256,
            "output_artifact_id":result.output_artifact_id,"output_sha256":result.output_sha256,"strings_artifact_id":result.strings_artifact_id,
            "readable_artifact_id":result.readable_artifact_id,"observation":result.observation,"warnings":result.warnings,
            "pseudocode_preview":preview,"tools":result.tools});
        run.summary["recovery"]["history"]
            .as_array_mut()
            .ok_or_else(|| invalid("逆向历史无效"))?
            .push(record);
        run.summary["recovery"]["running_work_id"] = json!("");
        update_run(conn, &run).await?;
        event(
            conn,
            run_id,
            "RECOVERY_COMPLETED",
            &format!("{}：{}", step.tool.capability(), result.status),
            work,
            0,
            0,
        )
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn put(store: &Store, bytes: &[u8], lease: Option<&d::WorkLease>) -> d::Artifact {
        let artifact = store
            .stage_bytes(bytes, "fixture", "application/json")
            .await
            .unwrap();
        let mut tx = store.pool.begin().await.unwrap();
        Store::insert_artifact(
            &mut tx,
            &artifact,
            lease.map(|l| l.snapshot_id.as_str()),
            lease.map(|l| l.work_item_id.as_str()),
            lease.map(|l| l.attempt_id.as_str()),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        artifact
    }
    async fn complete(
        store: &Store,
        executor: &str,
        lease: &d::WorkLease,
        artifact: &str,
        outcome: &str,
    ) -> Result<bool> {
        store
            .complete_work(
                executor,
                &lease.work_item_id,
                &lease.attempt_id,
                &lease.lease_token,
                outcome,
                artifact,
                "",
                true,
            )
            .await
    }
    async fn prepared() -> (
        tempfile::TempDir,
        Store,
        d::Executor,
        d::AuditRun,
        d::AgentTask,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).await.unwrap();
        let (executor, _) = store
            .register_executor(
                "recovery-fixture",
                "windows",
                "x86_64",
                ["import", "upx", "ghidra"]
                    .map(|name| d::ToolCapability {
                        name: name.into(),
                        available: true,
                        ..Default::default()
                    })
                    .to_vec(),
            )
            .await
            .unwrap();
        let target = include_bytes!("../../../tests/fixtures/recovery/sample.exe");
        let upload = put(&store, target, None).await;
        let project = store
            .create_project(&d::id(), "Recovery protocol behavior")
            .await
            .unwrap();
        let snapshot = store
            .create_snapshot(
                &d::id(),
                &project.id,
                "BINARY",
                &upload.id,
                "",
                "",
                "sample.exe",
            )
            .await
            .unwrap();
        let lease = store.claim_work(&executor.id).await.unwrap().unwrap();
        let normalized = put(&store, target, Some(&lease)).await;
        let manifest = d::SnapshotManifest {
            schema_version: 1,
            kind: "BINARY".into(),
            normalized_artifact_id: normalized.id,
            target_sha256: normalized.sha256,
            files: vec![d::FileRecord {
                path: "sample.exe".into(),
                sha256: d::sha256(target),
                size: target.len() as u64,
                language: "binary".into(),
            }],
            exclusions: vec![],
            metadata: json!({}),
            resolved_revision: String::new(),
        };
        let imported = put(
            &store,
            &serde_json::to_vec(&manifest).unwrap(),
            Some(&lease),
        )
        .await;
        complete(&store, &executor.id, &lease, &imported.id, "COMPLETED")
            .await
            .unwrap();
        tokio::fs::write(
            store.root.join("deepseek.token"),
            "test-key-not-used-for-network",
        )
        .await
        .unwrap();
        let run = store
            .create_run_with_options(
                &d::id(),
                &snapshot.id,
                d::AUDIT_SCOPE,
                d::AuditConfig::default(),
            )
            .await
            .unwrap();
        let lease = store.claim_work(&executor.id).await.unwrap().unwrap();
        let analysis = d::AnalysisResult {
            files: vec![d::FileResult {
                path: "sample.exe".into(),
                language: "binary".into(),
                status: "PARTIAL".into(),
                reason: "waiting for agent".into(),
                unit_count: 0,
            }],
            metadata: json!({}),
            ..Default::default()
        };
        let artifact = put(
            &store,
            &serde_json::to_vec(&analysis).unwrap(),
            Some(&lease),
        )
        .await;
        complete(&store, &executor.id, &lease, &artifact.id, "COMPLETED")
            .await
            .unwrap();
        let task = store
            .begin_agent_task(&run.id, "REVERSE", "recovery")
            .await
            .unwrap();
        (directory, store, executor, run, task)
    }
    fn plan(tool: &str, input: &str) -> Value {
        json!({"assessment":"fixture observations","evidence":["binary snapshot"],"steps":[{"tool":tool,"input":input,"reason":"inspect supplied target"}],"limitations":[]})
    }
    async fn claim(store: &Store, executor: &str) -> d::WorkLease {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Some(lease) = store.claim_work(executor).await.unwrap() {
                    return lease;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap()
    }
    #[tokio::test]
    async fn recovery_requires_a_plan_and_cannot_substitute_missing_unpacked_input() {
        let (_temp, store, executor, run, task) = prepared().await;
        assert!(
            store
                .run_recovery_step(&task, &json!({}), &CancellationToken::new())
                .await
                .is_err()
        );
        let mut other = task.clone();
        other.role = "AUDITOR".into();
        assert!(
            store
                .plan_recovery(&other, plan("upx", "original"))
                .await
                .is_err()
        );
        store
            .plan_recovery(&task, plan("ghidra", "unpacked"))
            .await
            .unwrap();
        assert!(
            store
                .run_recovery_step(
                    &task,
                    &json!({"path":"C:/foreign"}),
                    &CancellationToken::new()
                )
                .await
                .is_err()
        );
        let result = store
            .run_recovery_step(&task, &json!({}), &CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(result["status"], "INPUT_UNAVAILABLE");
        assert!(store.claim_work(&executor.id).await.unwrap().is_none());
        let run: d::AuditRun = store.get("audit_runs", &run.id).await.unwrap();
        assert_eq!(
            run.summary["recovery"]["history"].as_array().unwrap().len(),
            1
        );
    }
    #[tokio::test]
    async fn recovery_rejects_wrong_hash_and_foreign_artifacts_then_accepts_factual_failure() {
        let (_temp, store, executor, run, task) = prepared().await;
        store
            .plan_recovery(&task, plan("upx", "original"))
            .await
            .unwrap();
        let copied = store.clone();
        let agent = tokio::spawn(async move {
            copied
                .run_recovery_step(&task, &json!({}), &CancellationToken::new())
                .await
        });
        let lease = claim(&store, &executor.id).await;
        let foreign = put(&store, b"unrelated", None).await;
        assert!(
            !store
                .artifact_allowed_for_work(&foreign.id, &lease.work_item_id, &lease.attempt_id)
                .await
                .unwrap()
        );
        let input: d::Artifact = store
            .get("artifacts", &lease.input_artifact_id)
            .await
            .unwrap();
        let mut result = d::RecoveryResult {
            schema_version: 1,
            tool: d::RecoveryTool::Upx,
            status: "UNSUPPORTED".into(),
            input_artifact_id: input.id,
            input_sha256: "0".repeat(64),
            output_artifact_id: String::new(),
            output_sha256: String::new(),
            strings_artifact_id: String::new(),
            readable_artifact_id: String::new(),
            analysis: None,
            tools: vec![],
            observation: json!({"reason":"fixture failure"}),
            warnings: vec![],
        };
        let wrong = put(&store, &serde_json::to_vec(&result).unwrap(), Some(&lease)).await;
        assert!(
            complete(&store, &executor.id, &lease, &wrong.id, "COMPLETED")
                .await
                .is_err()
        );
        result.input_sha256 = input.sha256;
        result.readable_artifact_id = foreign.id;
        let wrong = put(&store, &serde_json::to_vec(&result).unwrap(), Some(&lease)).await;
        assert!(
            complete(&store, &executor.id, &lease, &wrong.id, "COMPLETED")
                .await
                .is_err()
        );
        result.readable_artifact_id.clear();
        let valid = put(&store, &serde_json::to_vec(&result).unwrap(), Some(&lease)).await;
        complete(&store, &executor.id, &lease, &valid.id, "COMPLETED")
            .await
            .unwrap();
        assert_eq!(agent.await.unwrap().unwrap()["status"], "UNSUPPORTED");
        let run: d::AuditRun = store.get("audit_runs", &run.id).await.unwrap();
        assert_eq!(run.state, d::RunState::Running);
    }
    #[tokio::test]
    async fn recovery_cancellation_waits_for_reaping_and_closes_workflow() {
        let (_temp, store, executor, run, task) = prepared().await;
        store
            .plan_recovery(&task, plan("ghidra", "original"))
            .await
            .unwrap();
        let copied = store.clone();
        let agent = tokio::spawn(async move {
            copied
                .run_recovery_step(&task, &json!({}), &CancellationToken::new())
                .await
        });
        let lease = claim(&store, &executor.id).await;
        assert_eq!(
            store.cancel_run(&run.id).await.unwrap().state,
            d::RunState::Cancelling
        );
        assert!(agent.await.unwrap().is_err());
        store
            .finish_audit(&run.id, Some("cancelled while waiting".into()))
            .await
            .unwrap();
        let before: d::AuditRun = store.get("audit_runs", &run.id).await.unwrap();
        assert_eq!(before.state, d::RunState::Cancelling);
        complete(&store, &executor.id, &lease, "", "CANCELLED")
            .await
            .unwrap();
        let after: d::AuditRun = store.get("audit_runs", &run.id).await.unwrap();
        assert_eq!(after.state, d::RunState::Cancelled);
        assert_eq!(after.summary["recovery"]["status"], "CANCELLED");
        assert_eq!(
            after.summary["recovery"]["history"][0]["status"],
            "CANCELLED"
        );
        let workflow: String =
            sqlx::query_scalar("SELECT state FROM audit_workflows WHERE run_id=?")
                .bind(&run.id)
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_eq!(workflow, "CANCELLED");
    }
}
