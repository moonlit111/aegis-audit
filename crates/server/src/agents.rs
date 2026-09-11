//! Persistent agent workflow. The controller alone holds model credentials.
use crate::{
    error::Result,
    store::{Store, event, load, update_run},
};
use aegis_application::{
    audit::{AgentAction, Corpus, Plan, parse_action, system_prompt},
    model::{DeepSeek, ModelClient, ModelRequest, ModelResponse, ProviderFailure},
};
use aegis_domain as d;
use anyhow::{Context, bail, ensure};
use serde_json::{Value, json};
use sqlx::Row;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

impl Store {
    pub async fn recover_audits(&self) -> Result<()> {
        let _guard = self.writes.lock().await;
        let mut tx = self.pool.begin().await?;
        let calls: Vec<String> = sqlx::query_scalar(
            "SELECT data FROM model_calls WHERE run_id IS NOT NULL AND status='RUNNING'",
        )
        .fetch_all(&mut *tx)
        .await?;
        for data in calls {
            let mut call: d::ModelCall = serde_json::from_str(&data)?;
            call.status = "INTERRUPTED".into();
            call.finished_at = d::now();
            call.error = "控制服务重启，原调用结果与用量未确认；该次调用仍计入预算".into();
            sqlx::query("UPDATE model_calls SET status=?,data=? WHERE id=?")
                .bind(&call.status)
                .bind(serde_json::to_string(&call)?)
                .bind(&call.id)
                .execute(&mut *tx)
                .await?;
        }
        let tasks: Vec<String> =
            sqlx::query_scalar("SELECT data FROM agent_tasks WHERE status='RUNNING'")
                .fetch_all(&mut *tx)
                .await?;
        for data in tasks {
            let mut task: d::AgentTask = serde_json::from_str(&data)?;
            task.status = "INTERRUPTED".into();
            task.error = "控制服务重启；保留已完成子任务并恢复未完成的只读审计".into();
            sqlx::query("UPDATE agent_tasks SET status=?,data=? WHERE id=?")
                .bind(&task.status)
                .bind(serde_json::to_string(&task)?)
                .bind(&task.id)
                .execute(&mut *tx)
                .await?;
            event(
                &mut tx,
                &task.run_id,
                "AGENT_INTERRUPTED",
                &task.error,
                &task.id,
                0,
                0,
            )
            .await?;
        }
        sqlx::query("UPDATE audit_workflows SET state='QUEUED' WHERE state='RUNNING'")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
    pub fn spawn_audit_worker(&self, shutdown: CancellationToken) -> tokio::task::JoinHandle<()> {
        let store = self.clone();
        tokio::spawn(async move {
            loop {
                if shutdown.is_cancelled() {
                    break;
                }
                if let Err(error) = store.next_audit(&shutdown).await {
                    tracing::error!(error=?error,"audit worker failed");
                }
                tokio::select! {_=shutdown.cancelled()=>break,_=store.changed.notified()=>{},_=tokio::time::sleep(Duration::from_secs(1))=>{}}
            }
        })
    }
    async fn next_audit(&self, shutdown: &CancellationToken) -> Result<()> {
        let row=sqlx::query("SELECT w.run_id,w.config,w.model,w.config_hash FROM audit_workflows w JOIN audit_runs r ON r.id=w.run_id WHERE w.state='QUEUED' AND r.state IN ('RUNNING','CANCELLING') ORDER BY w.created_at,w.run_id LIMIT 1")
            .fetch_optional(&self.pool).await?;
        let Some(row) = row else {
            return Ok(());
        };
        let id: String = row.get("run_id");
        let config: d::AuditConfig = serde_json::from_str(&row.get::<String, _>("config"))?;
        let model: String = row.get("model");
        let result: anyhow::Result<()> = async {
            let settings = self.model_settings().await?;
            ensure!(
                settings.fingerprint() == row.get::<String, _>("config_hash"),
                "模型配置已变更，请使用新配置创建审计任务；原结果保留"
            );
            let client = DeepSeek::new(settings.key.context("审计模型密钥不可用")?)?;
            self.drive_audit_with_model(&id, &model, &config, &client, shutdown)
                .await
        }
        .await;
        if shutdown.is_cancelled() {
            sqlx::query(
                "UPDATE audit_workflows SET state='QUEUED' WHERE run_id=? AND state='RUNNING'",
            )
            .bind(&id)
            .execute(&self.pool)
            .await?;
            return Ok(());
        }
        self.finish_audit(&id, result.err().map(|e| e.to_string()))
            .await
    }

    // Also used with a local provider in behavior tests. Production constructs only the official transport above.
    pub async fn drive_audit_with_model(
        &self,
        id: &str,
        model: &str,
        config: &d::AuditConfig,
        client: &dyn ModelClient,
        shutdown: &CancellationToken,
    ) -> anyhow::Result<()> {
        config.validate().map_err(anyhow::Error::msg)?;
        let mut corpus = self.audit_corpus(id).await?;
        {
            let _guard = self.writes.lock().await;
            let mut tx = self.pool.begin().await?;
            let mut run = Self::active_audit(&mut tx, id).await?;
            run.summary["vulnerability_audit"] = json!("RUNNING");
            run.summary["audit_config"] = serde_json::to_value(config)?;
            run.summary["eligible_unit_count"] = json!(corpus.order.len());
            update_run(&mut tx, &run).await?;
            sqlx::query("UPDATE audit_workflows SET state='RUNNING' WHERE run_id=?")
                .bind(id)
                .execute(&mut *tx)
                .await?;
            event(
                &mut tx,
                id,
                "AUDIT_STARTED",
                "开始通用语义审计；独立复核使用新的原始代码上下文",
                "",
                0,
                corpus.order.len() as u64,
            )
            .await?;
            tx.commit().await?;
            self.changed.notify_waiters();
        }
        if corpus.target["kind"] == "BINARY" {
            let reverse = AgentContext {
                store: self,
                run_id: id,
                model,
                config,
                client,
                shutdown,
                corpus: &corpus,
            };
            let input = json!({"program":corpus.catalog(),"tool_environment":self.recovery_context(id).await?});
            reverse.execute("REVERSE", "recovery", input).await?;
            corpus = self.audit_corpus(id).await?;
            let _guard = self.writes.lock().await;
            let mut tx = self.pool.begin().await?;
            let mut run = Self::active_audit(&mut tx, id).await?;
            run.summary["eligible_unit_count"] = json!(corpus.order.len());
            update_run(&mut tx, &run).await?;
            tx.commit().await?;
        }
        ensure!(
            !corpus.order.is_empty(),
            "没有可供语义审计的代码；逆向结果和解析缺口已保留"
        );
        let context = AgentContext {
            store: self,
            run_id: id,
            model,
            config,
            client,
            shutdown,
            corpus: &corpus,
        };
        let planner = context.execute("PLANNER", "plan", corpus.catalog()).await?;
        let plan: Plan = serde_json::from_value(planner.result)?;
        let order = corpus.ordered(&plan.priorities)?;
        for id in order.iter().take(config.max_units as usize) {
            let input = json!({"focus":corpus.focus(id)?,"audit_approach":plan.approach,
                "instructions":"Audit this focus unit even if no lexical clues exist. Query relevant code when evidence is incomplete."});
            context.execute_item("AUDITOR", id, input).await?;
            // Review immediately so findings remain useful when a later unit reaches a budget.
            let evidence = self.audit_evidence(context.run_id).await?;
            for finding in evidence.findings {
                if evidence
                    .reviews
                    .iter()
                    .any(|r| r.finding_id == finding.id && r.actor == "MODEL")
                    || evidence.tasks.iter().any(|task| {
                        task.role == "REVIEWER"
                            && task.item_key == finding.id
                            && task.status == "FAILED"
                    })
                {
                    continue;
                }
                let mut ids = std::collections::HashSet::new();
                let mut originals = vec![];
                for reference in &finding.evidence {
                    if ids.insert(reference.unit_id.clone()) {
                        originals.push(
                            corpus.view(
                                &reference.unit_id,
                                Some(
                                    reference
                                        .start_line
                                        .saturating_sub(6)
                                        .max(corpus.units[&reference.unit_id].unit.start_line),
                                ),
                                Some(reference.end_line.saturating_add(15)),
                            )?,
                        );
                    }
                }
                let input = json!({"candidate":finding.draft,"original_code":originals,"review_scope":"COMPONENT",
                    "verification_status":"NOT_RUN","instructions":"Independently check this claim against the original code; the auditor conversation is not provided."});
                context.execute_item("REVIEWER", &finding.id, input).await?;
            }
        }
        // Planning uses a fresh context and cannot assign an execution verdict.
        // A saved recipe is executed by a separate, cancellable runtime task.
        let evidence = self.audit_evidence(context.run_id).await?;
        for finding in evidence
            .findings
            .iter()
            .filter(|f| f.review_status == "VALIDATED")
        {
            let input = json!({"candidate":finding.draft,"target":corpus.target,
                "original_code":corpus.view(&finding.draft.unit_id,None,None)?,
                "instructions":"Produce a bounded local regression recipe or state what configuration is missing. Execution has not occurred."});
            context.execute_item("VERIFIER", &finding.id, input).await?;
        }
        let evidence = self.audit_evidence(context.run_id).await?;
        let rows:Vec<_>=evidence.findings.iter().take(100).map(|f|json!({"id":f.id,"title":f.draft.title,"category":f.draft.category,
            "review_status":f.review_status,"verification_status":f.verification_status,"recommendation":f.draft.recommendation})).collect();
        let audited = evidence
            .tasks
            .iter()
            .filter(|task| task.role == "AUDITOR" && task.status == "SUCCEEDED")
            .count();
        let failures: Vec<_> = evidence
            .tasks
            .iter()
            .filter(|task| task.status == "FAILED")
            .map(|task| json!({"role":task.role,"item_key":task.item_key,"error":task.error}))
            .collect();
        let report = json!({"findings":rows,"findings_truncated":evidence.findings.len()>100,
            "audited_units":audited,"total_units":order.len(),"failed_tasks":failures,
            "static_review_only":true,"dynamic_execution":"NOT_RUN","structure_warnings":corpus.target["structure_warnings"]});
        context.execute("REPORTER", "report", report).await?;
        if corpus.target["kind"] == "BINARY" {
            for finding in evidence.findings.iter().filter(|finding| {
                finding.review_status == "VALIDATED" && finding.draft.category == "MEMORY_BOUNDS"
            }) {
                match self.suggest_runtime(context.run_id, &finding.id).await {
                    Ok((config, _, _)) => {
                        if let Err(error) = self
                            .create_runtime(
                                &format!("auto-fuzz-{}", finding.id),
                                context.run_id,
                                &finding.id,
                                Some(config),
                            )
                            .await
                        {
                            tracing::warn!(
                                finding_id=%finding.id,
                                error=%error,
                                "automatic fuzz reuse could not be queued"
                            );
                        }
                    }
                    Err(error) => tracing::warn!(
                        finding_id=%finding.id,
                        error=%error,
                        "automatic fuzz reuse was not applicable"
                    ),
                }
            }
        }
        Ok(())
    }
    pub async fn finish_audit(&self, id: &str, error: Option<String>) -> Result<()> {
        let evidence = self.audit_evidence(id).await?;
        let _guard = self.writes.lock().await;
        let mut tx = self.pool.begin().await?;
        let mut run: d::AuditRun = load(&mut tx, "audit_runs", id).await?;
        if run.state.terminal() {
            return Ok(());
        }
        let audited = evidence
            .tasks
            .iter()
            .filter(|t| t.role == "AUDITOR" && t.status == "SUCCEEDED")
            .count();
        let eligible = run.summary["eligible_unit_count"]
            .as_u64()
            .unwrap_or(run.unit_count) as usize;
        let reviewed = evidence
            .findings
            .iter()
            .filter(|f| {
                evidence
                    .reviews
                    .iter()
                    .any(|r| r.finding_id == f.id && r.actor == "MODEL")
            })
            .count();
        let incomplete_tasks = evidence
            .tasks
            .iter()
            .filter(|t| t.status != "SUCCEEDED")
            .count();
        let partial = error.is_some()
            || incomplete_tasks > 0
            || audited < eligible
            || audited == 0
            || run.summary["structure_partial"] == true
            || run.summary["recovery"]["status"] == "PARTIAL";
        let cancelled = run.state == d::RunState::Cancelling;
        if cancelled {
            let active: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM work_items WHERE run_id=? AND state IN ('RUNNING','EXPIRED')",
            )
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
            if active > 0 {
                return Ok(());
            } // Explicit cancellation remains pending until process reaping.
        }
        run.state = if cancelled {
            d::RunState::Cancelled
        } else if partial {
            d::RunState::Partial
        } else {
            d::RunState::Completed
        };
        run.finished_at = d::now();
        run.error = error.unwrap_or_default();
        if run.summary["recovery"].is_object()
            && ["RUNNING", "PLANNED"]
                .contains(&run.summary["recovery"]["status"].as_str().unwrap_or(""))
        {
            run.summary["recovery"]["status"] =
                json!(if cancelled { "CANCELLED" } else { "PARTIAL" });
            run.summary["recovery"]["error"] = json!(run.error);
        }
        run.summary["vulnerability_audit"] = json!(if cancelled {
            "CANCELLED"
        } else if partial {
            "PARTIAL"
        } else {
            "COMPLETED"
        });
        run.summary["independent_review"] = json!(if audited == 0 {
            "NOT_RUN"
        } else if reviewed < evidence.findings.len() {
            "PARTIAL"
        } else {
            "COMPLETED"
        });
        run.summary["fuzzing"] = json!("NOT_RUN");
        // A runtime queued during audit completion owns the exploitation state;
        // do not replace QUEUED/RUNNING/COMPLETED with NOT_RUN here.
        run.summary["audited_unit_count"] = json!(audited);
        run.summary["finding_count"] = json!(evidence.findings.len());
        run.summary["reviewed_finding_count"] = json!(reviewed);
        run.summary["incomplete_agent_tasks"] = json!(incomplete_tasks);
        run.summary["model_usage"] = json!({"calls":evidence.model_calls.len(),"measured_tokens":evidence.model_calls.iter().filter(|c|c.usage_available).map(|c|c.total_tokens).sum::<u64>(),
            "unknown_usage_calls":evidence.model_calls.iter().filter(|c|!c.usage_available).count(),"cost_cny":null});
        if audited < eligible {
            run.summary["audit_coverage_gap"] = json!(format!(
                "共 {eligible} 个可读单元，完成 {audited} 个单元的语义审计；其余未审计"
            ));
        }
        update_run(&mut tx, &run).await?;
        sqlx::query("UPDATE audit_workflows SET state=? WHERE run_id=?")
            .bind(run.state.as_str())
            .bind(id)
            .execute(&mut *tx)
            .await?;
        event(
            &mut tx,
            id,
            "RUN_COMPLETED",
            &format!(
                "漏洞审计{}：{} 条候选、{} 条已复核；动态验证未执行",
                if cancelled {
                    "已取消"
                } else if partial {
                    "部分完成"
                } else {
                    "完成"
                },
                evidence.findings.len(),
                reviewed
            ),
            "",
            audited as u64,
            eligible as u64,
        )
        .await?;
        tx.commit().await?;
        self.changed.notify_waiters();
        Ok(())
    }
    async fn stop_agent_task(
        &self,
        mut task: d::AgentTask,
        error: &str,
        interrupted: bool,
    ) -> Result<()> {
        task.status = if interrupted { "INTERRUPTED" } else { "FAILED" }.into();
        task.error = error.into();
        task.finished_at = d::now();
        let _guard = self.writes.lock().await;
        let mut tx = self.pool.begin().await?;
        sqlx::query("UPDATE agent_tasks SET status=?,data=? WHERE id=? AND status<>'SUCCEEDED'")
            .bind(&task.status)
            .bind(serde_json::to_string(&task)?)
            .bind(&task.id)
            .execute(&mut *tx)
            .await?;
        event(
            &mut tx,
            &task.run_id,
            "AGENT_STOPPED",
            error,
            &task.id,
            0,
            0,
        )
        .await?;
        tx.commit().await?;
        self.changed.notify_waiters();
        Ok(())
    }
    async fn invalid_model_call(&self, mut call: d::ModelCall, error: &str) -> Result<()> {
        call.status = "INVALID_RESPONSE".into();
        call.error = error.chars().take(2048).collect();
        let _guard = self.writes.lock().await;
        sqlx::query("UPDATE model_calls SET status=?,data=? WHERE id=?")
            .bind(&call.status)
            .bind(serde_json::to_string(&call)?)
            .bind(&call.id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct InvalidAgentResponse(String);

struct AgentContext<'a> {
    store: &'a Store,
    run_id: &'a str,
    model: &'a str,
    config: &'a d::AuditConfig,
    client: &'a dyn ModelClient,
    shutdown: &'a CancellationToken,
    corpus: &'a Corpus,
}
impl AgentContext<'_> {
    async fn execute_item(&self, role: &str, key: &str, input: Value) -> anyhow::Result<()> {
        if let Err(error) = self.execute(role, key, input).await {
            // Invalid local output leaves a failed task, not a verdict. Provider,
            // storage, cancellation and run-wide budget errors still stop the run.
            if error.downcast_ref::<InvalidAgentResponse>().is_none() {
                return Err(error);
            }
            let run: d::AuditRun = self.store.get("audit_runs", self.run_id).await?;
            ensure!(
                !self.shutdown.is_cancelled() && run.state == d::RunState::Running,
                "审计已取消或服务停止"
            );
            tracing::warn!(role, item_key=key, error=%error, "invalid agent output retained; continuing independent tasks");
        }
        Ok(())
    }

    async fn execute(&self, role: &str, key: &str, input: Value) -> anyhow::Result<d::AgentTask> {
        let task = self.store.begin_agent_task(self.run_id, role, key).await?;
        if task.status == "SUCCEEDED" {
            return Ok(task);
        }
        let result = self.conversation(task.clone(), input).await;
        if let Err(error) = &result {
            self.store
                .stop_agent_task(task, &error.to_string(), self.shutdown.is_cancelled())
                .await?;
        }
        result
    }
    async fn conversation(&self, task: d::AgentTask, input: Value) -> anyhow::Result<d::AgentTask> {
        let mut corpus = self.store.audit_corpus(self.run_id).await?;
        let input = self.corpus.references(input, true);
        let tool_budget = if task.role == "PLANNER" {
            self.config.max_tool_rounds.min(1)
        } else {
            self.config.max_tool_rounds
        };
        let mut messages = vec![
            json!({"role":"system","content":format!("{}\nThis task permits at most {} tool requests, including plan updates and execution requests. Use the supplied context first. When no tool requests remain, finish with available evidence and explicit limitations. A planner prioritizes from the catalog; it does not audit every function itself.", system_prompt(&task.role), tool_budget)}),
            json!({"role":"user","content":input.to_string()}),
        ];
        let mut repairs = 0;
        let mut provider_retried = false;
        let mut tools = 0;
        for _ in 0..tool_budget + 5 {
            let request = ModelRequest {
                model: self.model.into(),
                messages: messages.clone(),
                max_tokens: self.config.max_output_tokens,
                reasoning_effort: self.config.reasoning_effort.clone(),
                timeout_seconds: self.config.model_timeout_seconds,
            };
            let response = self.turn(&task, &request).await;
            let (response, call) = match response {
                Ok(value) => value,
                Err(error)
                    if !provider_retried
                        && error
                            .downcast_ref::<ProviderFailure>()
                            .is_some_and(|e| e.retryable) =>
                {
                    provider_retried = true;
                    tokio::select! {_=self.shutdown.cancelled()=>bail!("服务正在停止"),_=tokio::time::sleep(Duration::from_secs(2))=>{}}
                    continue;
                }
                Err(error) => return Err(error),
            };
            let action: anyhow::Result<AgentAction> = if response.finish_reason == "length" {
                Err(anyhow::anyhow!(
                    "模型输出被截断（length）；单次预算为 {} token（含思考），请提高预算或缩小任务上下文",
                    request.max_tokens
                ))
            } else if response.finish_reason != "stop" {
                Err(anyhow::anyhow!(
                    "模型输出未完整结束：{}",
                    response.finish_reason
                ))
            } else {
                parse_action(&response.content)
            };
            messages.push(json!({"role":"assistant","content":response.content}));
            let validation = match action {
                Ok(AgentAction::Tool { name, arguments }) => {
                    if tools == tool_budget {
                        tools += 1;
                        messages.push(json!({"role":"user","content":"No tool requests remain. This request was not executed. Finish now using available evidence, and list missing evidence as limitations."}));
                        continue;
                    }
                    if tools > tool_budget {
                        return Err(InvalidAgentResponse(
                            "智能体查询轮数达到上限；未完成的分析保留为缺口".into(),
                        )
                        .into());
                    }
                    tools += 1;
                    let result = if task.role == "REVERSE" {
                        match name.as_str() {
                            "plan_recovery" => self
                                .store
                                .plan_recovery(&task, arguments.clone())
                                .await
                                .map_err(anyhow::Error::from),
                            "run_recovery_step" => self
                                .store
                                .run_recovery_step(&task, &arguments, self.shutdown)
                                .await
                                .map_err(anyhow::Error::from),
                            "recovery_status"
                                if arguments.as_object().is_some_and(|a| a.is_empty()) =>
                            {
                                self.store
                                    .recovery_context(self.run_id)
                                    .await
                                    .map_err(anyhow::Error::from)
                            }
                            _ => corpus.tool(&name, &arguments),
                        }
                    } else {
                        corpus.tool(&name, &arguments)
                    };
                    let mut output = match result {
                        Ok(value) => value,
                        Err(error) => json!({"error":error.to_string()}),
                    };
                    if task.role == "REVERSE" {
                        corpus = self.store.audit_corpus(self.run_id).await?;
                        if name == "run_recovery_step" && output.is_object() {
                            output["current_units"] = corpus.catalog()["units"].clone();
                        }
                    }
                    messages.push(json!({"role":"user","content":json!({"tool":name,"arguments":arguments,"result":output,"remaining_tool_requests":tool_budget-tools,"next_action":if tools==tool_budget {"finish"}else{"tool or finish"}}).to_string()}));
                    continue;
                }
                Ok(AgentAction::Finish { result }) => {
                    let result = corpus.references(result, false);
                    match Store::validate_agent_result(&task, &result, &corpus) {
                        Ok(()) => {
                            return Ok(self
                                .store
                                .finish_agent_task(task, &call.id, result, &corpus)
                                .await?);
                        }
                        Err(error) => error.to_string(),
                    }
                }
                Err(error) => error.to_string(),
            };
            self.store.invalid_model_call(call, &validation).await?;
            if repairs == 2 {
                return Err(InvalidAgentResponse(format!(
                    "智能体响应再次未通过校验：{validation}"
                ))
                .into());
            }
            repairs += 1;
            messages.push(json!({"role":"user","content":format!("Your response failed validation: {validation}. Correct the JSON/schema or exact code citations using the supplied original code. Do not invent references. {} correction attempt(s) remain. Return only the complete JSON object, with no commentary.", 3-repairs)}));
        }
        Err(InvalidAgentResponse("智能体达到有限重试上限".into()).into())
    }
    async fn cancelled(&self) {
        loop {
            tokio::select! {_=self.shutdown.cancelled()=>return,_=tokio::time::sleep(Duration::from_millis(300))=>{}}
            match self
                .store
                .get::<d::AuditRun>("audit_runs", self.run_id)
                .await
            {
                Ok(run) if run.state == d::RunState::Running => {}
                _ => return,
            }
        }
    }
    async fn turn(
        &self,
        task: &d::AgentTask,
        request: &ModelRequest,
    ) -> anyhow::Result<(ModelResponse, d::ModelCall)> {
        ensure!(!self.shutdown.is_cancelled(), "控制服务正在停止");
        let request_artifact = self
            .store
            .stage_bytes(
                &serde_json::to_vec_pretty(
                    &json!({"prompt_version":d::PROMPT_VERSION,"role":task.role,"request":request}),
                )?,
                &format!("model-request-{}.json", d::id()),
                "application/json",
            )
            .await?;
        let mut call = d::ModelCall {
            id: d::id(),
            model: self.model.into(),
            purpose: "SECURITY_AUDIT".into(),
            status: "RUNNING".into(),
            created_at: d::now(),
            run_id: self.run_id.into(),
            task_id: task.id.clone(),
            role: task.role.clone(),
            prompt_version: d::PROMPT_VERSION.into(),
            request_artifact_id: request_artifact.id.clone(),
            ..Default::default()
        };
        let remaining;
        {
            let _guard = self.store.writes.lock().await;
            let mut tx = self.store.pool.begin().await?;
            let run = Store::active_audit(&mut tx, self.run_id).await?;
            let started = chrono::DateTime::parse_from_rfc3339(&run.started_at)
                .context("审计开始时间无效")?;
            remaining = self.config.timeout_seconds as i64
                - (chrono::Utc::now() - started.with_timezone(&chrono::Utc)).num_seconds();
            ensure!(remaining > 0, "审计时间预算耗尽");
            let count: i64 = sqlx::query_scalar("SELECT count(*) FROM model_calls WHERE run_id=?")
                .bind(self.run_id)
                .fetch_one(&mut *tx)
                .await?;
            ensure!(
                count < self.config.max_model_calls as i64,
                "审计模型调用预算耗尽"
            );
            let fingerprint: String =
                sqlx::query_scalar("SELECT config_hash FROM audit_workflows WHERE run_id=?")
                    .bind(self.run_id)
                    .fetch_one(&mut *tx)
                    .await?;
            Store::insert_artifact(
                &mut tx,
                &request_artifact,
                Some(&run.snapshot_id),
                None,
                None,
            )
            .await?;
            sqlx::query("INSERT INTO model_calls(id,status,created_at,config_hash,data,run_id,task_id) VALUES(?,?,?,?,?,?,?)")
                .bind(&call.id).bind(&call.status).bind(&call.created_at).bind(fingerprint).bind(serde_json::to_string(&call)?).bind(self.run_id).bind(&task.id).execute(&mut *tx).await?;
            event(
                &mut tx,
                self.run_id,
                "MODEL_STARTED",
                &format!(
                    "{} 调用模型 ({}/{})",
                    task.role,
                    count + 1,
                    self.config.max_model_calls
                ),
                &task.id,
                0,
                0,
            )
            .await?;
            tx.commit().await?;
            self.store.changed.notify_waiters();
        }
        let started = Instant::now();
        let response = tokio::select! {
            _=self.cancelled()=>Err(anyhow::anyhow!("审计取消或控制服务停止；本次模型用量未知")),
            _=tokio::time::sleep(Duration::from_secs(remaining as u64))=>Err(anyhow::anyhow!("审计时间预算耗尽；本次模型用量未知")),
            _=tokio::time::sleep(Duration::from_secs(request.timeout_seconds.into()))=>Err(anyhow::anyhow!("单次模型请求达到 {} 秒时限；本次模型用量未知", request.timeout_seconds)),
            result=self.client.complete(request)=>result,
        };
        call.finished_at = d::now();
        call.latency_ms = started.elapsed().as_millis() as u64;
        let raw = match &response {
            Ok(value) => {
                call.status = "SUCCEEDED".into();
                call.input_tokens = value.result.input_tokens;
                call.output_tokens = value.result.output_tokens;
                call.total_tokens = value.result.total_tokens;
                call.usage_available = value.result.usage_available;
                call.provider_request_id = value.result.provider_request_id.clone();
                call.finish_reason = value.finish_reason.clone();
                value.result.response.clone()
            }
            Err(error) => {
                call.status = if self.shutdown.is_cancelled() {
                    "INTERRUPTED"
                } else {
                    "FAILED"
                }
                .into();
                call.error = error.to_string();
                json!({"error":call.error})
            }
        };
        let artifact = self
            .store
            .stage_bytes(
                &serde_json::to_vec_pretty(&raw)?,
                &format!("model-response-{}.json", call.id),
                "application/json",
            )
            .await?;
        call.artifact_id = artifact.id.clone();
        {
            let _guard = self.store.writes.lock().await;
            let mut tx = self.store.pool.begin().await?;
            let run: d::AuditRun = load(&mut tx, "audit_runs", self.run_id).await?;
            Store::insert_artifact(&mut tx, &artifact, Some(&run.snapshot_id), None, None).await?;
            sqlx::query("UPDATE model_calls SET status=?,artifact_id=?,data=? WHERE id=? AND status='RUNNING'").bind(&call.status).bind(&artifact.id).bind(serde_json::to_string(&call)?).bind(&call.id).execute(&mut *tx).await?;
            event(
                &mut tx,
                self.run_id,
                "MODEL_FINISHED",
                &format!(
                    "{}：{}；{}",
                    task.role,
                    call.status,
                    if call.usage_available {
                        format!("{} token", call.total_tokens)
                    } else {
                        "用量未知".into()
                    }
                ),
                &task.id,
                0,
                0,
            )
            .await?;
            tx.commit().await?;
            self.store.changed.notify_waiters();
        }
        Ok((response?, call))
    }
}
