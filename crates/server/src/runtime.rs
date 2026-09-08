use crate::{
    error::{AppError, Result},
    store::{Store, duplicate, event, load, record_request, update_run},
};
use aegis_domain as d;
use serde_json::json;
use sqlx::{Row, SqliteConnection};

impl Store {
    pub async fn runtime_records(&self, source_run_id: &str) -> Result<Vec<d::RuntimeRecord>> {
        let rows = sqlx::query("SELECT v.data,r.data AS run_data FROM runtime_records v JOIN audit_runs r ON r.id=v.run_id WHERE v.source_run_id=? OR v.run_id=? ORDER BY v.created_at,v.id")
            .bind(source_run_id).bind(source_run_id).fetch_all(&self.pool).await?;
        rows.into_iter()
            .map(|row| {
                let mut record: d::RuntimeRecord =
                    serde_json::from_str(&row.get::<String, _>("data"))?;
                if record.result.is_none() {
                    let run: d::AuditRun = serde_json::from_str(&row.get::<String, _>("run_data"))?;
                    record.status = run.state.as_str().into();
                }
                Ok(record)
            })
            .collect()
    }
    pub async fn runtime_record(&self, id: &str) -> Result<d::RuntimeRecord> {
        let record: d::RuntimeRecord = self.get("runtime_records", id).await?;
        self.runtime_records(&record.run_id)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| AppError::NotFound("运行记录不存在".into()))
    }
    pub async fn create_runtime(
        &self,
        request: &str,
        source_run_id: &str,
        finding_id: &str,
        config: Option<d::RuntimeConfig>,
    ) -> Result<d::RuntimeRecord> {
        let source: d::AuditRun = self.get("audit_runs", source_run_id).await?;
        if ![d::SCOPE, d::AUDIT_SCOPE].contains(&source.scope.as_str()) {
            return Err(AppError::Invalid(
                "运行验证必须关联结构分析或漏洞审计任务".into(),
            ));
        }
        let finding = if !finding_id.is_empty() {
            let finding: d::Finding = self.get("findings", finding_id).await?;
            if finding.run_id != source_run_id {
                return Err(AppError::Invalid("发现不属于当前分析任务".into()));
            }
            Some(finding)
        } else {
            None
        };
        let config = match config {
            Some(config) => config,
            None => {
                let data: Option<String> = sqlx::query_scalar("SELECT data FROM agent_tasks WHERE run_id=? AND role='VERIFIER' AND item_key=? AND status='SUCCEEDED'")
                    .bind(source_run_id).bind(finding_id).fetch_optional(&self.pool).await?;
                let task: d::AgentTask = serde_json::from_str(&data.ok_or_else(|| {
                    AppError::Precondition("此发现尚无可执行的验证方案，请补充运行配置".into())
                })?)?;
                let plan: d::VerificationPlan = serde_json::from_value(task.result)?;
                plan.validate().map_err(AppError::Invalid)?;
                plan.config
                    .ok_or_else(|| AppError::Precondition(plan.rationale))?
            }
        };
        config.validate().map_err(AppError::Invalid)?;
        if let Some(finding) = finding
            && (config.mode != "VERIFY" || !finding.evidence.iter().any(|e| e.path == config.path))
        {
            return Err(AppError::Invalid(
                "关联发现的验证必须运行其证据文件，并包含正常输入和重复测试".into(),
            ));
        }
        let snapshot: d::Snapshot = self.get("snapshots", &source.snapshot_id).await?;
        let manifest: d::SnapshotManifest = serde_json::from_slice(
            &self
                .artifact_bytes(&snapshot.manifest_artifact_id, 32 * 1024 * 1024)
                .await?,
        )?;
        if !manifest.files.iter().any(|f| f.path == config.path) {
            return Err(AppError::Invalid("运行入口不属于当前快照".into()));
        }
        if (snapshot.kind == "BINARY") != (config.adapter == "ELF") {
            return Err(AppError::Invalid("运行适配器与目标类型不符".into()));
        }
        if config.adapter == "ELF"
            && (snapshot.metadata["format"] != "ELF"
                || snapshot.metadata["architecture"] != "x86_64")
        {
            return Err(AppError::Precondition(
                "当前动态适配器需要 ELF x86_64；PE 仍需匹配的 Windows 执行环境".into(),
            ));
        }
        let hash = d::sha256(&serde_json::to_vec(&json!([
            source_run_id,
            finding_id,
            config
        ]))?);
        let _guard = self.writes.lock().await;
        let mut tx = self.pool.begin().await?;
        if let Some(id) = duplicate(&mut tx, "CreateRuntime", request, &hash).await? {
            let mut record: d::RuntimeRecord = load(&mut tx, "runtime_records", &id).await?;
            if record.result.is_none() {
                let run: d::AuditRun = load(&mut tx, "audit_runs", &record.run_id).await?;
                record.status = run.state.as_str().into();
            }
            return Ok(record);
        }
        let available = self.executors().await?.iter().any(|e| {
            e.capabilities
                .iter()
                .any(|c| c.name == "linux-runtime" && c.available)
        });
        let run = d::AuditRun {
            id: d::id(),
            project_id: source.project_id,
            snapshot_id: source.snapshot_id.clone(),
            state: if available {
                d::RunState::Queued
            } else {
                d::RunState::WaitingExecutor
            },
            scope: config.scope().into(),
            created_at: d::now(),
            started_at: String::new(),
            finished_at: String::new(),
            unit_count: 0,
            summary: json!({"source_run_id":source_run_id,"verification":"NOT_RUN","fuzzing":"NOT_RUN","exploitation":"NOT_RUN","required_capability":"linux-runtime","target_scope":config.target_scope(),"config":config}),
            error: String::new(),
        };
        let record = d::RuntimeRecord {
            id: d::id(),
            run_id: run.id.clone(),
            source_run_id: source_run_id.into(),
            finding_id: finding_id.into(),
            status: run.state.as_str().into(),
            created_at: run.created_at.clone(),
            config: config.clone(),
            result: None,
        };
        sqlx::query("INSERT INTO audit_runs(id,project_id,snapshot_id,state,created_at,data) VALUES(?,?,?,?,?,?)")
            .bind(&run.id).bind(&run.project_id).bind(&run.snapshot_id).bind(run.state.as_str()).bind(&run.created_at).bind(serde_json::to_string(&run)?).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO runtime_records(id,run_id,source_run_id,finding_id,created_at,data) VALUES(?,?,?,?,?,?)")
            .bind(&record.id).bind(&record.run_id).bind(source_run_id).bind(if finding_id.is_empty() { None } else { Some(finding_id) })
            .bind(&record.created_at).bind(serde_json::to_string(&record)?).execute(&mut *tx).await?;
        let work = d::id();
        let payload = json!({"manifest_artifact_id":snapshot.manifest_artifact_id,"config":config,"timeout_seconds":config.deadline()});
        sqlx::query("INSERT INTO work_items(id,snapshot_id,run_id,kind,capability,state,created_at,input_artifact_id,payload) VALUES(?,?,?,'RUNTIME','linux-runtime','QUEUED',?,?,?)")
            .bind(&work).bind(&run.snapshot_id).bind(&run.id).bind(&run.created_at).bind(&snapshot.normalized_artifact_id).bind(payload.to_string()).execute(&mut *tx).await?;
        event(
            &mut tx,
            &run.id,
            "RUNTIME_CREATED",
            "已冻结目标、输入、观察方式与运行预算",
            &work,
            0,
            0,
        )
        .await?;
        event(
            &mut tx,
            source_run_id,
            "RUNTIME_CREATED",
            "已创建独立运行任务；验证结果将关联原始分析",
            &run.id,
            0,
            0,
        )
        .await?;
        record_request(&mut tx, "CreateRuntime", request, &hash, &record.id).await?;
        tx.commit().await?;
        self.changed.notify_waiters();
        Ok(record)
    }

    pub(crate) async fn ingest_runtime(
        &self,
        conn: &mut SqliteConnection,
        run_id: &str,
        work: &str,
        attempt: &str,
        result_id: &str,
        bytes: &[u8],
    ) -> Result<()> {
        let data: String = sqlx::query_scalar("SELECT data FROM runtime_records WHERE run_id=?")
            .bind(run_id)
            .fetch_one(&mut *conn)
            .await?;
        let mut record: d::RuntimeRecord = serde_json::from_str(&data)?;
        let result: d::RuntimeResult = serde_json::from_slice(bytes)
            .map_err(|e| AppError::Invalid(format!("运行结果格式无效：{e}")))?;
        let mut run: d::AuditRun = load(conn, "audit_runs", run_id).await?;
        let snapshot: d::Snapshot = load(conn, "snapshots", &run.snapshot_id).await?;
        if result.target_sha256 != snapshot.target_sha256
            || result.config_hash != record.config.fingerprint()
            || result.target_scope != record.config.target_scope()
            || result.image_id.len() != 71
            || !result.image_id.starts_with("sha256:")
            || !result.image_id[7..].bytes().all(|b| b.is_ascii_hexdigit())
            || result.tools.is_empty()
            || result.tools.iter().any(|t| {
                t.version != result.image_id
                    || t.details["processes_reaped"] != true
                    || t.details["network"] != "none"
                    || t.details["isolation"] != "DOCKER"
            })
        {
            return Err(AppError::Invalid(
                "运行结果的目标、配置、镜像或回收证据不一致".into(),
            ));
        }
        result
            .observation
            .validate(&record.config)
            .map_err(AppError::Invalid)?;
        for id in [&result.recipe_artifact_id, &result.observation_artifact_id]
            .into_iter()
            .chain(result.tools.iter().map(|t| &t.log_artifact_id))
        {
            Self::ensure_output(conn, id, work, attempt).await?;
        }
        let observation: d::RuntimeObservation = serde_json::from_slice(
            &self
                .artifact_bytes(&result.observation_artifact_id, 8 * 1024 * 1024)
                .await?,
        )?;
        if serde_json::to_value(&observation)? != serde_json::to_value(&result.observation)? {
            return Err(AppError::Invalid("原始运行观察与结果记录不一致".into()));
        }
        let recipe: serde_json::Value = serde_json::from_slice(
            &self
                .artifact_bytes(&result.recipe_artifact_id, 1024 * 1024)
                .await?,
        )?;
        if recipe["config"] != serde_json::to_value(&record.config)? {
            return Err(AppError::Invalid("测试产物与运行配置不一致".into()));
        }
        let verdict = result.observation.verdict(&record.config);
        record.status = verdict.into();
        run.state = match verdict {
            "ERROR" => d::RunState::Failed,
            "INCONCLUSIVE" => d::RunState::Partial,
            _ => d::RunState::Completed,
        };
        run.finished_at = d::now();
        run.error = result.observation.error.clone();
        run.summary["runtime_record_id"] = json!(record.id);
        run.summary["result_artifact_id"] = json!(result_id);
        run.summary["verification"] = json!(verdict);
        run.summary["fuzzing"] = json!(if record.config.mode == "FUZZ" {
            if verdict == "ERROR" {
                "ERROR"
            } else {
                "COMPLETED"
            }
        } else {
            "NOT_RUN"
        });
        run.summary["runtime"] = serde_json::to_value(&result)?;
        update_run(conn, &run).await?;
        if !record.finding_id.is_empty() {
            let mut finding: d::Finding = load(conn, "findings", &record.finding_id).await?;
            let previous: Vec<String> =
                sqlx::query_scalar("SELECT data FROM runtime_records WHERE finding_id=? AND id<>?")
                    .bind(&record.finding_id)
                    .bind(&record.id)
                    .fetch_all(&mut *conn)
                    .await?;
            let mut statuses = vec![verdict.to_owned()];
            for data in previous {
                let record: d::RuntimeRecord = serde_json::from_str(&data)?;
                if record.result.is_some() {
                    statuses.push(record.status);
                }
            }
            let positive = statuses
                .iter()
                .any(|s| ["VERIFIED_COMPONENT", "REPRODUCED"].contains(&s.as_str()));
            let negative = statuses.iter().any(|s| s == "NOT_REPRODUCED");
            finding.verification_status = if positive && negative {
                "INCONCLUSIVE"
            } else if statuses.iter().any(|s| s == "REPRODUCED") {
                "REPRODUCED"
            } else if positive {
                "VERIFIED_COMPONENT"
            } else if negative {
                "NOT_REPRODUCED"
            } else {
                verdict
            }
            .into();
            finding.revision += 1;
            sqlx::query("UPDATE findings SET verification_status=?,revision=?,data=? WHERE id=?")
                .bind(&finding.verification_status)
                .bind(finding.revision)
                .bind(serde_json::to_string(&finding)?)
                .bind(&finding.id)
                .execute(&mut *conn)
                .await?;
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
        record.result = Some(result);
        sqlx::query("UPDATE runtime_records SET data=? WHERE id=?")
            .bind(serde_json::to_string(&record)?)
            .bind(&record.id)
            .execute(&mut *conn)
            .await?;
        event(
            conn,
            run_id,
            "RUNTIME_COMPLETED",
            &format!("运行结果：{verdict}；范围 {}", record.config.target_scope()),
            work,
            0,
            0,
        )
        .await?;
        event(
            conn,
            &record.source_run_id,
            "RUNTIME_COMPLETED",
            &format!("关联运行已完成：{verdict}"),
            run_id,
            0,
            0,
        )
        .await?;
        Ok(())
    }
}
