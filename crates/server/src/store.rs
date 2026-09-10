use crate::error::{AppError, Result};
use aegis_domain as d;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sqlx::{
    Row, SqliteConnection, SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::sync::{Mutex, Notify};

pub const LEASE_SECONDS: i64 = 30;
pub const MAX_UPLOAD: u64 = 512 * 1024 * 1024;

#[derive(Clone)]
pub struct Store {
    pub pool: SqlitePool,
    pub root: PathBuf,
    pub changed: Arc<Notify>,
    pub writes: Arc<Mutex<()>>,
}

pub fn valid_text(value: &str, max: usize, label: &str) -> Result<String> {
    let text = value.trim();
    if text.is_empty() || text.chars().count() > max || text.chars().any(char::is_control) {
        return Err(AppError::Invalid(format!(
            "{label}为空、过长或包含控制字符"
        )));
    }
    Ok(text.to_owned())
}

pub(crate) async fn load<T: DeserializeOwned>(
    conn: &mut SqliteConnection,
    table: &str,
    id: &str,
) -> Result<T> {
    let query = format!("SELECT data FROM {table} WHERE id=?");
    let value: String = sqlx::query_scalar(&query).bind(id).fetch_one(conn).await?;
    Ok(serde_json::from_str(&value)?)
}
pub(crate) async fn duplicate(
    conn: &mut SqliteConnection,
    method: &str,
    request: &str,
    hash: &str,
) -> Result<Option<String>> {
    if request.len() < 16
        || request.len() > 128
        || !request
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(AppError::Invalid(
            "request_id 必须是 16—128 位字母、数字、横线或下划线".into(),
        ));
    }
    let row =
        sqlx::query("SELECT body_hash,object_id FROM requests WHERE method=? AND request_id=?")
            .bind(method)
            .bind(request)
            .fetch_optional(conn)
            .await?;
    match row {
        Some(row) if row.get::<String, _>("body_hash") != hash => Err(AppError::Conflict(
            "同一 request_id 对应不同请求内容".into(),
        )),
        Some(row) => Ok(Some(row.get("object_id"))),
        None => Ok(None),
    }
}
pub(crate) async fn record_request(
    conn: &mut SqliteConnection,
    method: &str,
    request: &str,
    hash: &str,
    id: &str,
) -> Result<()> {
    sqlx::query("INSERT INTO requests(method,request_id,body_hash,object_id) VALUES(?,?,?,?)")
        .bind(method)
        .bind(request)
        .bind(hash)
        .bind(id)
        .execute(conn)
        .await?;
    Ok(())
}
pub async fn event(
    conn: &mut SqliteConnection,
    run: &str,
    kind: &str,
    message: &str,
    work: &str,
    current: u64,
    total: u64,
) -> Result<()> {
    let seq: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(seq),0)+1 FROM run_events WHERE run_id=?")
            .bind(run)
            .fetch_one(&mut *conn)
            .await?;
    let (phase_id, phase_order, phase_count) =
        crate::progress::event_phase(conn, run, kind, work).await?;
    let data = d::RunEvent {
        run_id: run.into(),
        seq: seq as u64,
        created_at: d::now(),
        kind: kind.into(),
        message: message.chars().take(8192).collect(),
        work_item_id: work.into(),
        current,
        total,
        phase_id,
        phase_order,
        phase_count,
    };
    sqlx::query("INSERT INTO run_events(run_id,seq,data) VALUES(?,?,?)")
        .bind(run)
        .bind(seq)
        .bind(serde_json::to_string(&data)?)
        .execute(conn)
        .await?;
    Ok(())
}
pub(crate) async fn update_run(conn: &mut SqliteConnection, run: &d::AuditRun) -> Result<()> {
    sqlx::query("UPDATE audit_runs SET state=?,data=? WHERE id=?")
        .bind(run.state.as_str())
        .bind(serde_json::to_string(run)?)
        .bind(&run.id)
        .execute(conn)
        .await?;
    Ok(())
}

fn lease_timeout_seconds(kind: &str, payload: &str) -> Result<u32> {
    if kind != "RUNTIME" {
        return Ok(300);
    }
    let payload: Value = serde_json::from_str(payload)
        .map_err(|e| AppError::Invalid(format!("RUNTIME payload is invalid: {e}")))?;
    let budget = payload["timeout_seconds"]
        .as_u64()
        .ok_or_else(|| AppError::Invalid("RUNTIME payload missing timeout_seconds".into()))?;
    u32::try_from(budget.saturating_add(180))
        .map_err(|_| AppError::Invalid("RUNTIME lease timeout exceeds u32".into()))
}

impl Store {
    pub async fn open(root: &Path) -> Result<Self> {
        tokio::fs::create_dir_all(root.join("blobs")).await?;
        tokio::fs::create_dir_all(root.join("tmp")).await?;
        let options = SqliteConnectOptions::new()
            .filename(root.join("aegis.sqlite"))
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(Duration::from_secs(10));
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await?;
        sqlx::migrate!("../../migrations")
            .run(&pool)
            .await
            .map_err(|e| AppError::Internal(e.into()))?;
        Ok(Self {
            pool,
            root: root.to_owned(),
            changed: Arc::new(Notify::new()),
            writes: Arc::new(Mutex::new(())),
        })
    }
    pub async fn get<T: DeserializeOwned>(&self, table: &str, id: &str) -> Result<T> {
        let mut conn = self.pool.acquire().await?;
        load(&mut conn, table, id).await
    }
    pub async fn projects(&self) -> Result<Vec<d::Project>> {
        let rows: Vec<String> =
            sqlx::query_scalar("SELECT data FROM projects ORDER BY created_at DESC,id")
                .fetch_all(&self.pool)
                .await?;
        rows.into_iter()
            .map(|s| Ok(serde_json::from_str(&s)?))
            .collect()
    }
    pub async fn snapshots(&self, project: &str) -> Result<Vec<d::Snapshot>> {
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT data FROM snapshots WHERE project_id=? ORDER BY created_at DESC,id",
        )
        .bind(project)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|s| Ok(serde_json::from_str(&s)?))
            .collect()
    }
    pub async fn runs(&self, project: &str) -> Result<Vec<d::AuditRun>> {
        let rows:Vec<String>=sqlx::query_scalar("SELECT data FROM audit_runs WHERE (?='' OR project_id=?) ORDER BY created_at DESC,id LIMIT 500").bind(project).bind(project).fetch_all(&self.pool).await?;
        rows.into_iter()
            .map(|s| Ok(serde_json::from_str(&s)?))
            .collect()
    }
    pub async fn create_project(&self, request: &str, name: &str) -> Result<d::Project> {
        let name = valid_text(name, 120, "项目名称")?;
        let hash = d::sha256(name.as_bytes());
        let _guard = self.writes.lock().await;
        let mut tx = self.pool.begin().await?;
        if let Some(id) = duplicate(&mut tx, "CreateProject", request, &hash).await? {
            return load(&mut tx, "projects", &id).await;
        }
        let project = d::Project {
            id: d::id(),
            name,
            created_at: d::now(),
        };
        sqlx::query("INSERT INTO projects(id,name,created_at,data) VALUES(?,?,?,?)")
            .bind(&project.id)
            .bind(&project.name)
            .bind(&project.created_at)
            .bind(serde_json::to_string(&project)?)
            .execute(&mut *tx)
            .await?;
        record_request(&mut tx, "CreateProject", request, &hash, &project.id).await?;
        tx.commit().await?;
        Ok(project)
    }
    pub fn blob_path(&self, hash: &str) -> PathBuf {
        self.root.join("blobs").join(&hash[..2]).join(&hash[2..])
    }
    pub async fn stage_bytes(
        &self,
        bytes: &[u8],
        name: &str,
        media_type: &str,
    ) -> Result<d::Artifact> {
        let artifact = d::Artifact {
            id: d::id(),
            sha256: d::sha256(bytes),
            size: bytes.len() as u64,
            name: name.into(),
            media_type: media_type.into(),
        };
        let path = self.blob_path(&artifact.sha256);
        tokio::fs::create_dir_all(path.parent().expect("blob parent")).await?;
        if !path.exists() {
            let temp = tempfile::NamedTempFile::new_in(self.root.join("tmp"))?;
            tokio::fs::write(temp.path(), bytes).await?;
            tokio::fs::rename(temp.path(), path).await?;
        }
        Ok(artifact)
    }
    pub async fn insert_artifact(
        conn: &mut SqliteConnection,
        artifact: &d::Artifact,
        snapshot: Option<&str>,
        work: Option<&str>,
        attempt: Option<&str>,
    ) -> Result<()> {
        sqlx::query("INSERT INTO artifacts(id,sha256,size,name,media_type,snapshot_id,work_item_id,attempt_id,data) VALUES(?,?,?,?,?,?,?,?,?)")
            .bind(&artifact.id).bind(&artifact.sha256).bind(artifact.size as i64).bind(&artifact.name).bind(&artifact.media_type).bind(snapshot).bind(work).bind(attempt).bind(serde_json::to_string(artifact)?).execute(conn).await?;
        Ok(())
    }
    pub async fn artifact_bytes(&self, id: &str, limit: u64) -> Result<Vec<u8>> {
        let artifact: d::Artifact = self.get("artifacts", id).await?;
        if artifact.size > limit {
            return Err(AppError::Invalid("产物超过读取上限".into()));
        }
        let bytes = tokio::fs::read(self.blob_path(&artifact.sha256)).await?;
        if bytes.len() as u64 != artifact.size || d::sha256(&bytes) != artifact.sha256 {
            return Err(AppError::Precondition("产物内容与归档哈希不一致".into()));
        }
        Ok(bytes)
    }
    // This persistence boundary mirrors the explicit fields of the RPC command.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_snapshot(
        &self,
        request: &str,
        project: &str,
        kind: &str,
        artifact_id: &str,
        url: &str,
        revision: &str,
        name: &str,
    ) -> Result<d::Snapshot> {
        if !["SOURCE", "BINARY", "GIT"].contains(&kind) {
            return Err(AppError::Invalid("目标类型必须是源码、二进制或 Git".into()));
        }
        if kind == "GIT" {
            let uri: axum::http::Uri = url
                .parse()
                .map_err(|_| AppError::Invalid("Git 地址无效".into()))?;
            if uri.scheme_str() != Some("https")
                || uri.authority().is_none_or(|a| a.as_str().contains('@'))
            {
                return Err(AppError::Invalid(
                    "Git 导入只接受不含凭据的 HTTPS 地址".into(),
                ));
            }
            valid_text(revision, 200, "Git 提交、标签或分支")?;
            if revision.starts_with('-') || revision.contains(' ') {
                return Err(AppError::Invalid("Git 版本参数无效".into()));
            }
        }
        let hash = d::sha256(&serde_json::to_vec(&json!([
            project,
            kind,
            artifact_id,
            url,
            revision,
            name
        ]))?);
        let _guard = self.writes.lock().await;
        let mut tx = self.pool.begin().await?;
        if let Some(id) = duplicate(&mut tx, "CreateSnapshot", request, &hash).await? {
            return load(&mut tx, "snapshots", &id).await;
        }
        let _: d::Project = load(&mut tx, "projects", project).await?;
        let upload = if kind == "GIT" {
            d::Artifact::default()
        } else {
            let row = sqlx::query("SELECT data,snapshot_id,work_item_id FROM artifacts WHERE id=?")
                .bind(artifact_id)
                .fetch_one(&mut *tx)
                .await?;
            if row.get::<Option<String>, _>("snapshot_id").is_some()
                || row.get::<Option<String>, _>("work_item_id").is_some()
            {
                return Err(AppError::Precondition(
                    "该上传已用于其他快照；请重新上传或使用已有快照".into(),
                ));
            }
            serde_json::from_str::<d::Artifact>(&row.get::<String, _>("data"))?
        };
        let snapshot = d::Snapshot {
            id: d::id(),
            project_id: project.into(),
            kind: kind.into(),
            state: "IMPORTING".into(),
            name: if name.trim().is_empty() {
                if kind == "GIT" {
                    url.into()
                } else {
                    upload.name.clone()
                }
            } else {
                valid_text(name, 200, "快照名称")?
            },
            original_artifact_id: artifact_id.into(),
            created_at: d::now(),
            ..Default::default()
        };
        sqlx::query(
            "INSERT INTO snapshots(id,project_id,kind,state,created_at,data) VALUES(?,?,?,?,?,?)",
        )
        .bind(&snapshot.id)
        .bind(project)
        .bind(kind)
        .bind(&snapshot.state)
        .bind(&snapshot.created_at)
        .bind(serde_json::to_string(&snapshot)?)
        .execute(&mut *tx)
        .await?;
        if kind != "GIT" {
            sqlx::query("UPDATE artifacts SET snapshot_id=? WHERE id=?")
                .bind(&snapshot.id)
                .bind(artifact_id)
                .execute(&mut *tx)
                .await?;
        }
        let payload = json!({"kind":kind,"git_url":url,"git_revision":revision,"name":upload.name,"input_sha256":upload.sha256});
        sqlx::query("INSERT INTO work_items(id,snapshot_id,kind,capability,state,created_at,input_artifact_id,payload) VALUES(?,?,'IMPORT',?,'QUEUED',?,?,?)").bind(d::id()).bind(&snapshot.id).bind(if kind=="GIT"{"git"}else{"import"}).bind(d::now()).bind(artifact_id).bind(payload.to_string()).execute(&mut *tx).await?;
        record_request(&mut tx, "CreateSnapshot", request, &hash, &snapshot.id).await?;
        tx.commit().await?;
        self.changed.notify_waiters();
        Ok(snapshot)
    }
    pub async fn create_run(&self, request: &str, snapshot_id: &str) -> Result<d::AuditRun> {
        self.create_run_with_options(request, snapshot_id, d::SCOPE, d::AuditConfig::default())
            .await
    }
    pub async fn create_run_with_options(
        &self,
        request: &str,
        snapshot_id: &str,
        scope: &str,
        config: d::AuditConfig,
    ) -> Result<d::AuditRun> {
        if ![d::SCOPE, d::AUDIT_SCOPE].contains(&scope) {
            return Err(AppError::Invalid("未知的分析范围".into()));
        }
        let _guard = self.writes.lock().await;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let settings = if scope == d::AUDIT_SCOPE {
            config.validate().map_err(AppError::Invalid)?;
            let settings = self.model_settings().await?;
            if settings.key.is_none() {
                return Err(AppError::Precondition(
                    "开始漏洞审计前需要配置模型连接".into(),
                ));
            }
            Some(settings)
        } else {
            None
        };
        let hash = if let Some(settings) = &settings {
            d::sha256(&serde_json::to_vec(&json!([
                snapshot_id,
                scope,
                config,
                settings.fingerprint()
            ]))?)
        } else {
            d::sha256(snapshot_id.as_bytes())
        };
        if let Some(id) = duplicate(&mut tx, "CreateRun", request, &hash).await? {
            return load(&mut tx, "audit_runs", &id).await;
        }
        let snapshot: d::Snapshot = load(&mut tx, "snapshots", snapshot_id).await?;
        if !["READY", "PARTIAL"].contains(&snapshot.state.as_str()) {
            return Err(AppError::Precondition("快照导入尚未完成或已失败".into()));
        }
        let capability = if snapshot.kind == "BINARY" && scope == d::AUDIT_SCOPE {
            "import"
        } else if snapshot.kind == "BINARY" {
            "ghidra"
        } else {
            "tree-sitter"
        };
        let available = self.executors().await?.iter().any(|e| {
            e.capabilities
                .iter()
                .any(|c| c.name == capability && c.available)
        });
        let mut run = d::AuditRun {
            id: d::id(),
            project_id: snapshot.project_id.clone(),
            snapshot_id: snapshot_id.into(),
            state: if available {
                d::RunState::Queued
            } else {
                d::RunState::WaitingExecutor
            },
            scope: scope.into(),
            created_at: d::now(),
            started_at: String::new(),
            finished_at: String::new(),
            unit_count: 0,
            summary: json!({"vulnerability_audit":"NOT_RUN","verification":"NOT_RUN","required_capability":capability}),
            error: String::new(),
        };
        if settings.is_some() {
            run.summary["audit_config"] = serde_json::to_value(&config)?;
        }
        sqlx::query("INSERT INTO audit_runs(id,project_id,snapshot_id,state,created_at,data) VALUES(?,?,?,?,?,?)").bind(&run.id).bind(&run.project_id).bind(snapshot_id).bind(run.state.as_str()).bind(&run.created_at).bind(serde_json::to_string(&run)?).execute(&mut *tx).await?;
        if let Some(settings) = settings {
            sqlx::query("INSERT INTO audit_workflows(run_id,state,config,model,config_hash,created_at) VALUES(?,'WAITING_STRUCTURE',?,?,?,?)")
                .bind(&run.id).bind(serde_json::to_string(&config)?).bind(&settings.model).bind(settings.fingerprint()).bind(&run.created_at).execute(&mut *tx).await?;
        }
        let work = d::id();
        let payload = json!({"kind":snapshot.kind,"manifest_artifact_id":snapshot.manifest_artifact_id,"scope":scope});
        sqlx::query("INSERT INTO work_items(id,snapshot_id,run_id,kind,capability,state,created_at,input_artifact_id,payload) VALUES(?,?,?,'ANALYZE',?,'QUEUED',?,?,?)").bind(&work).bind(snapshot_id).bind(&run.id).bind(capability).bind(d::now()).bind(&snapshot.normalized_artifact_id).bind(payload.to_string()).execute(&mut *tx).await?;
        event(
            &mut tx,
            &run.id,
            "RUN_CREATED",
            if available {
                "结构分析已排队"
            } else {
                "等待具有所需工具的执行器"
            },
            &work,
            0,
            0,
        )
        .await?;
        record_request(&mut tx, "CreateRun", request, &hash, &run.id).await?;
        tx.commit().await?;
        self.changed.notify_waiters();
        Ok(run)
    }
    pub async fn events(&self, run: &str, after: u64) -> Result<Vec<d::RunEvent>> {
        let cursor =
            i64::try_from(after).map_err(|_| AppError::Invalid("事件游标超出范围".into()))?;
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT data FROM run_events WHERE run_id=? AND seq>? ORDER BY seq LIMIT 500",
        )
        .bind(run)
        .bind(cursor)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|s| Ok(serde_json::from_str(&s)?))
            .collect()
    }
    pub async fn cancel_run(&self, id: &str) -> Result<d::AuditRun> {
        let _guard = self.writes.lock().await;
        let mut tx = self.pool.begin().await?;
        let mut run: d::AuditRun = load(&mut tx, "audit_runs", id).await?;
        if run.state.terminal() {
            return Ok(run);
        }
        let active: i64 = sqlx::query_scalar(
            "SELECT (SELECT COUNT(*) FROM work_items WHERE run_id=? AND state IN ('RUNNING','EXPIRED')) + (SELECT COUNT(*) FROM agent_tasks WHERE run_id=? AND status='RUNNING')",
        )
        .bind(id)
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query("UPDATE work_items SET cancel_requested=1,state=CASE WHEN state='QUEUED' THEN 'CANCELLED' ELSE state END WHERE run_id=?").bind(id).execute(&mut *tx).await?;
        run.state = if active == 0 {
            d::RunState::Cancelled
        } else {
            d::RunState::Cancelling
        };
        if active == 0 {
            run.finished_at = d::now();
            sqlx::query("UPDATE audit_workflows SET state='CANCELLED' WHERE run_id=?")
                .bind(id)
                .execute(&mut *tx)
                .await?;
        }
        update_run(&mut tx, &run).await?;
        event(
            &mut tx,
            id,
            "CANCEL_REQUESTED",
            if active == 0 {
                "排队任务已取消"
            } else {
                "正在等待执行器确认进程回收"
            },
            "",
            0,
            0,
        )
        .await?;
        tx.commit().await?;
        self.changed.notify_waiters();
        Ok(run)
    }

    pub async fn executors(&self) -> Result<Vec<d::Executor>> {
        let rows: Vec<String> =
            sqlx::query_scalar("SELECT data FROM executors WHERE last_seen>? ORDER BY id")
                .bind(chrono::Utc::now().timestamp() - LEASE_SECONDS)
                .fetch_all(&self.pool)
                .await?;
        rows.into_iter()
            .map(|s| Ok(serde_json::from_str(&s)?))
            .collect()
    }
    pub async fn executor_for_token(&self, token: &str) -> Result<Option<String>> {
        Ok(
            sqlx::query_scalar("SELECT id FROM executors WHERE token_hash=?")
                .bind(d::sha256(token.as_bytes()))
                .fetch_optional(&self.pool)
                .await?,
        )
    }
    pub async fn register_executor(
        &self,
        name: &str,
        platform: &str,
        architecture: &str,
        capabilities: Vec<d::ToolCapability>,
    ) -> Result<(d::Executor, String)> {
        let name = valid_text(name, 120, "执行器名称")?;
        if capabilities.len() > 32 {
            return Err(AppError::Invalid("工具能力清单过长".into()));
        }
        let token = format!("{}.{}", d::id(), d::id());
        let executor = d::Executor {
            id: d::id(),
            name,
            platform: valid_text(platform, 80, "平台")?,
            architecture: valid_text(architecture, 80, "架构")?,
            last_seen: d::now(),
            capabilities,
        };
        let _guard = self.writes.lock().await;
        sqlx::query("INSERT INTO executors(id,token_hash,last_seen,data) VALUES(?,?,?,?)")
            .bind(&executor.id)
            .bind(d::sha256(token.as_bytes()))
            .bind(chrono::Utc::now().timestamp())
            .bind(serde_json::to_string(&executor)?)
            .execute(&self.pool)
            .await?;
        self.changed.notify_waiters();
        Ok((executor, token))
    }
    async fn touch_executor(conn: &mut SqliteConnection, id: &str) -> Result<d::Executor> {
        let mut executor: d::Executor = load(conn, "executors", id).await?;
        executor.last_seen = d::now();
        sqlx::query("UPDATE executors SET last_seen=?,data=? WHERE id=?")
            .bind(chrono::Utc::now().timestamp())
            .bind(serde_json::to_string(&executor)?)
            .bind(id)
            .execute(conn)
            .await?;
        Ok(executor)
    }
    pub async fn refresh_capabilities(
        &self,
        id: &str,
        capabilities: Vec<d::ToolCapability>,
    ) -> Result<()> {
        if capabilities.len() > 32
            || capabilities
                .iter()
                .any(|c| c.name.len() > 120 || c.version.len() > 256 || c.detail.len() > 8192)
        {
            return Err(AppError::Invalid("工具能力清单超过上限".into()));
        }
        let _guard = self.writes.lock().await;
        let mut tx = self.pool.begin().await?;
        let mut executor = Self::touch_executor(&mut tx, id).await?;
        executor.capabilities = capabilities;
        sqlx::query("UPDATE executors SET data=? WHERE id=?")
            .bind(serde_json::to_string(&executor)?)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        self.changed.notify_waiters();
        Ok(())
    }
    pub async fn claim_work(&self, executor_id: &str) -> Result<Option<d::WorkLease>> {
        let _guard = self.writes.lock().await;
        let mut tx = self.pool.begin().await?;
        let executor = Self::touch_executor(&mut tx, executor_id).await?;
        let active:i64=sqlx::query_scalar("SELECT COUNT(*) FROM work_items WHERE executor_id=? AND state IN ('RUNNING','EXPIRED')").bind(executor_id).fetch_one(&mut *tx).await?;
        if active > 0 {
            tx.commit().await?;
            return Ok(None);
        }
        // Keep one runtime lease at a time so host resource use stays bounded.
        // A lease that has not confirmed cleanup blocks every executor.
        let active_runtime:i64=sqlx::query_scalar(
            "SELECT COUNT(*) FROM work_items WHERE kind='RUNTIME' AND (state='RUNNING' OR (state='EXPIRED' AND cleanup_confirmed=0))",
        ).fetch_one(&mut *tx).await?;
        if active_runtime > 0 {
            tx.commit().await?;
            return Ok(None);
        }
        let rows=sqlx::query("SELECT * FROM work_items WHERE state='QUEUED' AND cancel_requested=0 ORDER BY created_at,id LIMIT 200").fetch_all(&mut *tx).await?;
        for row in rows {
            let capability: String = row.get("capability");
            if !executor
                .capabilities
                .iter()
                .any(|c| c.available && c.name == capability)
            {
                continue;
            }
            let work: String = row.get("id");
            let attempt = d::id();
            let token = format!("{}.{}", d::id(), d::id());
            let run_id: Option<String> = row.get("run_id");
            let kind: String = row.get("kind");
            let payload_text: String = row.get("payload");
            let timeout_seconds = lease_timeout_seconds(&kind, &payload_text)?;
            let payload: Value = serde_json::from_str(&payload_text)?;
            sqlx::query("UPDATE work_items SET state='RUNNING',executor_id=?,attempt_id=?,lease_hash=?,lease_expires=? WHERE id=?").bind(executor_id).bind(&attempt).bind(d::sha256(token.as_bytes())).bind(chrono::Utc::now().timestamp()+LEASE_SECONDS).bind(&work).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO work_attempts(attempt_id,work_item_id,executor_id,lease_hash,started_at) VALUES(?,?,?,?,?)").bind(&attempt).bind(&work).bind(executor_id).bind(d::sha256(token.as_bytes())).bind(d::now()).execute(&mut *tx).await?;
            if let Some(id) = &run_id {
                let mut run: d::AuditRun = load(&mut tx, "audit_runs", id).await?;
                run.state = d::RunState::Running;
                if run.started_at.is_empty() {
                    run.started_at = d::now();
                }
                update_run(&mut tx, &run).await?;
                event(
                    &mut tx,
                    id,
                    "RUN_STARTED",
                    if row.get::<String, _>("kind") == "RECOVER" {
                        "执行器开始智能体规划的逆向步骤"
                    } else {
                        "执行器开始程序结构分析"
                    },
                    &work,
                    0,
                    0,
                )
                .await?;
            }
            let lease = d::WorkLease {
                work_item_id: work,
                attempt_id: attempt,
                lease_token: token,
                kind,
                snapshot_id: row.get("snapshot_id"),
                run_id: run_id.unwrap_or_default(),
                input_artifact_id: row.get("input_artifact_id"),
                payload,
                timeout_seconds,
            };
            tx.commit().await?;
            self.changed.notify_waiters();
            return Ok(Some(lease));
        }
        tx.commit().await?;
        Ok(None)
    }
    pub async fn heartbeat(
        &self,
        executor: &str,
        work: &str,
        attempt: &str,
        token: &str,
    ) -> Result<(bool, bool)> {
        let _guard = self.writes.lock().await;
        let mut tx = self.pool.begin().await?;
        Self::touch_executor(&mut tx, executor).await?;
        if work.is_empty() {
            tx.commit().await?;
            return Ok((false, true));
        }
        let row=sqlx::query("SELECT executor_id,attempt_id,lease_hash,lease_expires,state,cancel_requested FROM work_items WHERE id=?").bind(work).fetch_optional(&mut *tx).await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Ok((true, false));
        };
        let valid = row.get::<Option<String>, _>("executor_id").as_deref() == Some(executor)
            && row.get::<String, _>("attempt_id") == attempt
            && row.get::<String, _>("lease_hash") == d::sha256(token.as_bytes())
            && row.get::<i64, _>("lease_expires") >= chrono::Utc::now().timestamp()
            && row.get::<String, _>("state") == "RUNNING";
        let cancel = row.get::<i64, _>("cancel_requested") != 0;
        if valid {
            sqlx::query("UPDATE work_items SET lease_expires=? WHERE id=?")
                .bind(chrono::Utc::now().timestamp() + LEASE_SECONDS)
                .bind(work)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok((cancel || !valid, valid))
    }
    pub async fn authorize_lease(&self, work: &str, attempt: &str, token: &str) -> Result<String> {
        let mut conn = self.pool.acquire().await?;
        Self::authorize_lease_on(&mut conn, work, attempt, token).await
    }
    pub async fn authorize_lease_on(
        conn: &mut SqliteConnection,
        work: &str,
        attempt: &str,
        token: &str,
    ) -> Result<String> {
        let row=sqlx::query("SELECT snapshot_id,attempt_id,lease_hash,lease_expires,state FROM work_items WHERE id=?").bind(work).fetch_one(conn).await?;
        if row.get::<String, _>("attempt_id") != attempt
            || row.get::<String, _>("lease_hash") != d::sha256(token.as_bytes())
            || row.get::<i64, _>("lease_expires") < chrono::Utc::now().timestamp()
            || row.get::<String, _>("state") != "RUNNING"
        {
            return Err(AppError::Denied("任务租约无效或已过期".into()));
        }
        Ok(row.get("snapshot_id"))
    }
    pub async fn artifact_allowed_for_work(
        &self,
        artifact: &str,
        work: &str,
        attempt: &str,
    ) -> Result<bool> {
        let row = sqlx::query(
            "SELECT snapshot_id,input_artifact_id,kind,payload FROM work_items WHERE id=?",
        )
        .bind(work)
        .fetch_one(&self.pool)
        .await?;
        let snapshot: d::Snapshot = self
            .get("snapshots", &row.get::<String, _>("snapshot_id"))
            .await?;
        if [
            row.get::<String, _>("input_artifact_id"),
            snapshot.original_artifact_id,
            snapshot.normalized_artifact_id,
            snapshot.manifest_artifact_id,
        ]
        .iter()
        .any(|id| !id.is_empty() && id == artifact)
        {
            return Ok(true);
        }
        if row.get::<String, _>("kind") == "RECOVER" {
            let payload: Value = serde_json::from_str(&row.get::<String, _>("payload"))?;
            if !artifact.is_empty() && payload["strings_artifact_id"] == artifact {
                return Ok(true);
            }
        }
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM artifacts WHERE id=? AND work_item_id=? AND attempt_id=?",
        )
        .bind(artifact)
        .bind(work)
        .bind(attempt)
        .fetch_one(&self.pool)
        .await?;
        Ok(count == 1)
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn progress(
        &self,
        executor: &str,
        work: &str,
        attempt: &str,
        token: &str,
        message: &str,
        current: u64,
        total: u64,
    ) -> Result<()> {
        let _guard = self.writes.lock().await;
        let mut tx = self.pool.begin().await?;
        Self::authorize_lease_on(&mut tx, work, attempt, token).await?;
        let row = sqlx::query("SELECT executor_id,run_id FROM work_items WHERE id=?")
            .bind(work)
            .fetch_one(&mut *tx)
            .await?;
        if row.get::<Option<String>, _>("executor_id").as_deref() != Some(executor) {
            return Err(AppError::Denied("执行器身份不匹配".into()));
        }
        if let Some(run) = row.get::<Option<String>, _>("run_id") {
            event(
                &mut tx,
                &run,
                "TOOL_PROGRESS",
                message,
                work,
                current,
                total,
            )
            .await?;
        }
        tx.commit().await?;
        self.changed.notify_waiters();
        Ok(())
    }
    pub(crate) async fn ensure_output(
        conn: &mut SqliteConnection,
        id: &str,
        work: &str,
        attempt: &str,
    ) -> Result<d::Artifact> {
        let row = sqlx::query(
            "SELECT data FROM artifacts WHERE id=? AND work_item_id=? AND attempt_id=?",
        )
        .bind(id)
        .bind(work)
        .bind(attempt)
        .fetch_optional(conn)
        .await?;
        let row =
            row.ok_or_else(|| AppError::Invalid("结果引用了不属于当前工具尝试的产物".into()))?;
        Ok(serde_json::from_str(&row.get::<String, _>("data"))?)
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn complete_work(
        &self,
        executor: &str,
        work: &str,
        attempt: &str,
        token: &str,
        outcome: &str,
        result_id: &str,
        error: &str,
        reaped: bool,
    ) -> Result<bool> {
        if !["COMPLETED", "FAILED", "CANCELLED", "LIMIT_REACHED"].contains(&outcome) {
            return Err(AppError::Invalid("未知的工具结束状态".into()));
        }
        let completion = d::sha256(&serde_json::to_vec(&json!([
            outcome, result_id, error, reaped
        ]))?);
        let _guard = self.writes.lock().await;
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query("SELECT * FROM work_items WHERE id=?")
            .bind(work)
            .fetch_one(&mut *tx)
            .await?;
        let history=sqlx::query("SELECT lease_hash,outcome FROM work_attempts WHERE attempt_id=? AND work_item_id=? AND executor_id=?").bind(attempt).bind(work).bind(executor).fetch_optional(&mut *tx).await?;
        if history
            .as_ref()
            .is_none_or(|r| r.get::<String, _>("lease_hash") != d::sha256(token.as_bytes()))
        {
            return Err(AppError::Denied("工具尝试身份不匹配".into()));
        }
        let current = row.get::<String, _>("attempt_id") == attempt;
        if !current {
            sqlx::query("UPDATE work_attempts SET finished_at=?,outcome='STALE',detail=? WHERE attempt_id=?").bind(d::now()).bind(json!({"outcome":outcome,"result_artifact_id":result_id,"processes_reaped":reaped}).to_string()).bind(attempt).execute(&mut *tx).await?;
            tx.commit().await?;
            return Ok(false);
        }
        let previous: String = row.get("completion_hash");
        if !previous.is_empty() {
            if previous != completion {
                return Err(AppError::Conflict("该工具尝试已提交不同的结束结果".into()));
            }
            return Ok(history
                .as_ref()
                .and_then(|r| r.get::<Option<String>, _>("outcome"))
                .as_deref()
                != Some("STALE"));
        }
        let expired = row.get::<i64, _>("lease_expires") < chrono::Utc::now().timestamp()
            || row.get::<String, _>("state") == "EXPIRED";
        let cancelled = row.get::<i64, _>("cancel_requested") != 0;
        let run_id: Option<String> = row.get("run_id");
        let snapshot_id: String = row.get("snapshot_id");
        let kind: String = row.get("kind");
        let accepted = outcome == "COMPLETED" && !expired && !cancelled && reaped;
        let effective = if !reaped {
            "FAILED"
        } else if cancelled || outcome == "CANCELLED" {
            "CANCELLED"
        } else if expired {
            "FAILED"
        } else {
            outcome
        };
        let detail = if !reaped {
            "工具进程回收未确认，执行器保持隔离状态".into()
        } else if expired {
            "工具租约过期；结果未采纳，进程回收已确认".into()
        } else {
            error.chars().take(8192).collect::<String>()
        };
        if accepted {
            Self::ensure_output(&mut tx, result_id, work, attempt).await?;
            let bytes = self.artifact_bytes(result_id, 64 * 1024 * 1024).await?;
            if kind == "IMPORT" {
                let manifest: d::SnapshotManifest = serde_json::from_slice(&bytes)
                    .map_err(|e| AppError::Invalid(format!("导入结果格式无效：{e}")))?;
                if manifest.schema_version != 1
                    || manifest.files.is_empty()
                    || manifest.files.len() > 20_000
                {
                    return Err(AppError::Invalid("导入清单版本或文件数无效".into()));
                }
                let normalized =
                    Self::ensure_output(&mut tx, &manifest.normalized_artifact_id, work, attempt)
                        .await?;
                if normalized.sha256 != manifest.target_sha256 {
                    return Err(AppError::Invalid("快照哈希与产物不一致".into()));
                }
                let mut seen = HashSet::new();
                for file in &manifest.files {
                    let clean = aegis_application::import::relative_path(&file.path)
                        .map_err(|e| AppError::Invalid(e.to_string()))?;
                    if clean != file.path
                        || !seen.insert(aegis_application::import::portable_path_key(&clean))
                        || file.sha256.len() != 64
                        || !file.sha256.bytes().all(|b| b.is_ascii_hexdigit())
                    {
                        return Err(AppError::Invalid("导入清单包含无效路径或哈希".into()));
                    }
                }
                let mut snapshot: d::Snapshot = load(&mut tx, "snapshots", &snapshot_id).await?;
                snapshot.state = "READY".into();
                snapshot.normalized_artifact_id = normalized.id;
                snapshot.manifest_artifact_id = result_id.into();
                snapshot.target_sha256 = manifest.target_sha256;
                snapshot.resolved_revision = manifest.resolved_revision;
                snapshot.file_count = manifest.files.len() as u64;
                snapshot.total_bytes = manifest.files.iter().map(|f| f.size).sum();
                snapshot.metadata = manifest.metadata;
                snapshot.metadata["exclusions"] = serde_json::to_value(&manifest.exclusions)?;
                sqlx::query("UPDATE snapshots SET state=?,data=? WHERE id=?")
                    .bind(&snapshot.state)
                    .bind(serde_json::to_string(&snapshot)?)
                    .bind(&snapshot.id)
                    .execute(&mut *tx)
                    .await?;
            } else if kind == "RECOVER" {
                self.ingest_recovery(
                    &mut tx,
                    run_id
                        .as_deref()
                        .ok_or_else(|| AppError::Invalid("逆向步骤缺少关联任务".into()))?,
                    work,
                    attempt,
                    result_id,
                    &bytes,
                )
                .await?;
            } else if kind == "RUNTIME" {
                self.ingest_runtime(
                    &mut tx,
                    run_id
                        .as_deref()
                        .ok_or_else(|| AppError::Invalid("运行任务缺少关联任务".into()))?,
                    work,
                    attempt,
                    result_id,
                    &bytes,
                )
                .await?;
            } else if let Some(run_id) = &run_id {
                let result: d::AnalysisResult = serde_json::from_slice(&bytes)
                    .map_err(|e| AppError::Invalid(format!("解析结果格式无效：{e}")))?;
                let snapshot: d::Snapshot = load(&mut tx, "snapshots", &snapshot_id).await?;
                let manifest: d::SnapshotManifest = serde_json::from_slice(
                    &self
                        .artifact_bytes(&snapshot.manifest_artifact_id, 32 * 1024 * 1024)
                        .await?,
                )?;
                result.validate(&manifest).map_err(AppError::Invalid)?;
                let ids: HashMap<String, String> = result
                    .units
                    .iter()
                    .map(|u| {
                        (
                            u.key.clone(),
                            format!(
                                "u_{}",
                                &d::sha256(format!("{run_id}:{}", u.key).as_bytes())[..32]
                            ),
                        )
                    })
                    .collect();
                for unit in &result.units {
                    let value = d::ProgramUnit {
                        id: ids[&unit.key].clone(),
                        run_id: run_id.clone(),
                        snapshot_id: snapshot_id.clone(),
                        artifact_id: result_id.into(),
                        unit: unit.clone(),
                    };
                    sqlx::query("INSERT INTO program_units(id,run_id,snapshot_id,name,path,language,data) VALUES(?,?,?,?,?,?,?)").bind(&value.id).bind(run_id).bind(&snapshot_id).bind(&unit.name).bind(&unit.path).bind(&unit.language).bind(serde_json::to_string(&value)?).execute(&mut *tx).await?;
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
                    sqlx::query("INSERT INTO program_edges(run_id,source_id,target_id,data) VALUES(?,?,?,?)").bind(run_id).bind(&value.source_id).bind(if value.target_id.is_empty(){None}else{Some(&value.target_id)}).bind(serde_json::to_string(&value)?).execute(&mut *tx).await?;
                }
                for tool in &result.tools {
                    sqlx::query(
                        "INSERT INTO tool_runs(id,work_item_id,run_id,data) VALUES(?,?,?,?)",
                    )
                    .bind(d::id())
                    .bind(work)
                    .bind(run_id)
                    .bind(serde_json::to_string(tool)?)
                    .execute(&mut *tx)
                    .await?;
                }
                let mut run: d::AuditRun = load(&mut tx, "audit_runs", run_id).await?;
                run.state = if result.partial() {
                    d::RunState::Partial
                } else {
                    d::RunState::Completed
                };
                run.finished_at = d::now();
                run.unit_count = result.units.len() as u64;
                let audit_config = run.summary.get("audit_config").cloned();
                run.summary = json!({"metadata":result.metadata,"files":result.files,"warnings":result.warnings,"tools":result.tools,"exclusions":manifest.exclusions,"unit_count":run.unit_count,"function_count":result.units.iter().filter(|u|u.metadata["kind"]=="function").count(),"edge_count":result.edges.len(),"unresolved_calls":result.edges.iter().filter(|e|e.target_key.is_empty()).count(),"result_artifact_id":result_id,"vulnerability_audit":"NOT_RUN","verification":"NOT_RUN"});
                if let Some(config) = audit_config {
                    run.summary["audit_config"] = config;
                }
                if run.scope == d::AUDIT_SCOPE {
                    run.summary["structure_partial"] = json!(result.partial());
                    run.summary["vulnerability_audit"] = json!("QUEUED");
                    run.state = d::RunState::Running;
                    run.finished_at.clear();
                    sqlx::query("UPDATE audit_workflows SET state='QUEUED' WHERE run_id=?")
                        .bind(run_id)
                        .execute(&mut *tx)
                        .await?;
                }
                update_run(&mut tx, &run).await?;
                event(
                    &mut tx,
                    run_id,
                    if run.scope == d::AUDIT_SCOPE {
                        "STRUCTURE_COMPLETED"
                    } else {
                        "RUN_COMPLETED"
                    },
                    if run.scope == d::AUDIT_SCOPE {
                        "结构解析已完成，进入智能体审计与独立复核"
                    } else if run.state == d::RunState::Partial {
                        "结构分析完成，存在覆盖缺口"
                    } else {
                        "程序结构分析完成；未执行漏洞检测或验证"
                    },
                    work,
                    run.unit_count,
                    run.unit_count,
                )
                .await?;
            }
        } else if let Some(run_id) = &run_id {
            let mut run: d::AuditRun = load(&mut tx, "audit_runs", run_id).await?;
            if !run.state.terminal() {
                run.state = match effective {
                    "CANCELLED" => d::RunState::Cancelled,
                    "LIMIT_REACHED" => d::RunState::LimitReached,
                    _ => d::RunState::Failed,
                };
                run.finished_at = d::now();
                run.error = detail.clone();
                update_run(&mut tx, &run).await?;
                event(
                    &mut tx,
                    run_id,
                    "RUN_FINISHED",
                    if effective == "CANCELLED" {
                        "工具进程已回收，任务已取消"
                    } else {
                        &detail
                    },
                    work,
                    0,
                    0,
                )
                .await?;
            }
        } else {
            let mut snapshot: d::Snapshot = load(&mut tx, "snapshots", &snapshot_id).await?;
            snapshot.state = "FAILED".into();
            snapshot.error = detail.clone();
            sqlx::query("UPDATE snapshots SET state='FAILED',data=? WHERE id=?")
                .bind(serde_json::to_string(&snapshot)?)
                .bind(&snapshot_id)
                .execute(&mut *tx)
                .await?;
        }
        if kind == "RECOVER"
            && !accepted
            && let Some(run_id) = &run_id
        {
            let mut run: d::AuditRun = load(&mut tx, "audit_runs", run_id).await?;
            if run.summary["recovery"]["running_work_id"] == work {
                let payload: Value = serde_json::from_str(&row.get::<String, _>("payload"))?;
                let record = json!({"work_item_id":work,"tool":payload["step"]["tool"],"status":effective,"reason":detail,
                    "plan_id":payload["plan_id"],"step":payload["step_index"],"input_sha256":payload["input_sha256"]});
                if let Some(history) = run.summary["recovery"]["history"].as_array_mut() {
                    history.push(record);
                }
                run.summary["recovery"]["status"] = json!(effective);
                run.summary["recovery"]["running_work_id"] = json!("");
                update_run(&mut tx, &run).await?;
            }
            sqlx::query("UPDATE audit_workflows SET state=? WHERE run_id=?")
                .bind(effective)
                .bind(run_id)
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query(
            "UPDATE work_items SET state=?,completion_hash=?,cleanup_confirmed=? WHERE id=?",
        )
        .bind(if reaped { effective } else { "EXPIRED" })
        .bind(&completion)
        .bind(reaped)
        .bind(work)
        .execute(&mut *tx)
        .await?;
        sqlx::query("UPDATE work_attempts SET finished_at=?,outcome=?,detail=? WHERE attempt_id=?")
            .bind(d::now())
            .bind(if expired { "STALE" } else { effective })
            .bind(
                json!({"result_artifact_id":result_id,"error":detail,"processes_reaped":reaped})
                    .to_string(),
            )
            .bind(attempt)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        self.changed.notify_waiters();
        Ok(!expired)
    }

    pub async fn expire_leases(&self) -> Result<()> {
        let _guard = self.writes.lock().await;
        let mut tx = self.pool.begin().await?;
        let rows=sqlx::query("SELECT id,run_id,snapshot_id FROM work_items WHERE state='RUNNING' AND lease_expires<?").bind(chrono::Utc::now().timestamp()).fetch_all(&mut *tx).await?;
        for row in &rows {
            let work: String = row.get("id");
            sqlx::query("UPDATE work_items SET state='EXPIRED' WHERE id=?")
                .bind(&work)
                .execute(&mut *tx)
                .await?;
            if let Some(id) = row.get::<Option<String>, _>("run_id") {
                let mut run: d::AuditRun = load(&mut tx, "audit_runs", &id).await?;
                if !run.state.terminal() {
                    run.error = "执行器租约已失效，旧工具进程回收尚未确认；不会自动重复执行".into();
                    if run.summary["recovery"]["running_work_id"] == work {
                        run.summary["recovery"]["status"] =
                            json!(if run.state == d::RunState::Cancelling {
                                "CANCELLING"
                            } else {
                                "FAILED"
                            });
                        run.summary["recovery"]["error"] = json!(run.error);
                    }
                    if run.state != d::RunState::Cancelling {
                        run.state = d::RunState::Failed;
                        run.finished_at = d::now();
                    }
                    update_run(&mut tx, &run).await?;
                    event(&mut tx, &id, "LEASE_EXPIRED", &run.error, &work, 0, 0).await?;
                }
            } else {
                let id: String = row.get("snapshot_id");
                let mut snapshot: d::Snapshot = load(&mut tx, "snapshots", &id).await?;
                snapshot.state = "FAILED".into();
                snapshot.error = "导入执行器失联，进程状态未确认".into();
                sqlx::query("UPDATE snapshots SET state='FAILED',data=? WHERE id=?")
                    .bind(serde_json::to_string(&snapshot)?)
                    .bind(id)
                    .execute(&mut *tx)
                    .await?;
            }
        }
        tx.commit().await?;
        if !rows.is_empty() {
            self.changed.notify_waiters();
        }
        Ok(())
    }
    pub async fn list_units(
        &self,
        run: &str,
        query: &str,
        language: &str,
        offset: u32,
        limit: u32,
    ) -> Result<(Vec<d::ProgramUnit>, u64)> {
        let limit = if limit == 0 { 50 } else { limit.min(200) };
        let pattern = format!(
            "%{}%",
            query
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_")
        );
        let filter = "run_id=? AND (?='' OR name LIKE ? ESCAPE '\\' OR path LIKE ? ESCAPE '\\') AND (?='' OR language=?)";
        let count: i64 = sqlx::query_scalar(&format!(
            "SELECT COUNT(*) FROM program_units WHERE {filter}"
        ))
        .bind(run)
        .bind(query)
        .bind(&pattern)
        .bind(&pattern)
        .bind(language)
        .bind(language)
        .fetch_one(&self.pool)
        .await?;
        let rows: Vec<String> = sqlx::query_scalar(&format!(
            "SELECT data FROM program_units WHERE {filter} ORDER BY path,name,id LIMIT ? OFFSET ?"
        ))
        .bind(run)
        .bind(query)
        .bind(&pattern)
        .bind(&pattern)
        .bind(language)
        .bind(language)
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(&self.pool)
        .await?;
        let mut units = vec![];
        for row in rows {
            let mut unit: d::ProgramUnit = serde_json::from_str(&row)?;
            unit.unit.code.clear();
            unit.unit.metadata = json!({"kind":unit.unit.metadata["kind"]});
            units.push(unit);
        }
        Ok((units, count as u64))
    }
    pub async fn edges(&self, id: &str) -> Result<Vec<d::ProgramEdge>> {
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT data FROM program_edges WHERE source_id=? OR target_id=? ORDER BY id LIMIT 200",
        )
        .bind(id)
        .bind(id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|s| Ok(serde_json::from_str(&s)?))
            .collect()
    }
    pub async fn graph(&self, id: &str) -> Result<(Vec<d::ProgramUnit>, Vec<d::ProgramEdge>)> {
        let unit: d::ProgramUnit = self.get("program_units", id).await?;
        let edges = self.edges(id).await?;
        let mut ids = HashSet::from([id.to_owned()]);
        for edge in &edges {
            ids.insert(edge.source_id.clone());
            if !edge.target_id.is_empty() {
                ids.insert(edge.target_id.clone());
            }
        }
        let mut units = vec![];
        for id in ids.into_iter().take(201) {
            let mut node: d::ProgramUnit = self.get("program_units", &id).await?;
            if node.run_id == unit.run_id {
                node.unit.code.clear();
                node.unit.metadata = Value::Null;
                units.push(node);
            }
        }
        Ok((units, edges))
    }
    pub async fn run_artifacts(&self, id: &str) -> Result<Vec<d::Artifact>> {
        let run: d::AuditRun = self.get("audit_runs", id).await?;
        let snapshot: d::Snapshot = self.get("snapshots", &run.snapshot_id).await?;
        let rows:Vec<String>=sqlx::query_scalar("SELECT DISTINCT a.data FROM artifacts a WHERE a.id IN (?,?,?) OR a.work_item_id IN (SELECT id FROM work_items WHERE run_id=? OR (snapshot_id=? AND kind='IMPORT')) OR a.id IN (SELECT artifact_id FROM report_exports WHERE run_id=?) OR a.id IN (SELECT artifact_id FROM model_calls WHERE run_id=?) OR a.id IN (SELECT json_extract(data,'$.request_artifact_id') FROM model_calls WHERE run_id=?) OR a.id IN (SELECT json_extract(data,'$.result_artifact_id') FROM agent_tasks WHERE run_id=?) ORDER BY a.name,a.id")
            .bind(&snapshot.original_artifact_id).bind(&snapshot.normalized_artifact_id).bind(&snapshot.manifest_artifact_id).bind(id).bind(&run.snapshot_id).bind(id).bind(id).bind(id).bind(id).fetch_all(&self.pool).await?;
        rows.into_iter()
            .map(|s| Ok(serde_json::from_str(&s)?))
            .collect()
    }
    pub async fn reports(
        &self,
        run_id: &str,
        offset: u32,
        limit: u32,
    ) -> Result<(Vec<d::Report>, u64)> {
        let _: d::AuditRun = self.get("audit_runs", run_id).await?;
        let total: i64 = sqlx::query_scalar("SELECT count(*) FROM report_exports WHERE run_id=?")
            .bind(run_id)
            .fetch_one(&self.pool)
            .await?;
        let rows: Vec<String> = sqlx::query_scalar("SELECT data FROM report_exports WHERE run_id=? ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?")
            .bind(run_id).bind(if limit == 0 { 50 } else { limit.min(200) }).bind(offset).fetch_all(&self.pool).await?;
        Ok((
            rows.iter()
                .map(|row| serde_json::from_str(row))
                .collect::<std::result::Result<_, _>>()?,
            total as u64,
        ))
    }
    pub async fn create_report(
        &self,
        request: &str,
        run_id: &str,
        format: &str,
    ) -> Result<d::Report> {
        if !["json", "html", "markdown", "pdf"].contains(&format) {
            return Err(AppError::Invalid(
                "报告格式须为 json、html、markdown 或 pdf".into(),
            ));
        }
        let hash = d::sha256(&serde_json::to_vec(&json!([run_id, format]))?);
        let guard = self.writes.lock().await;
        let mut tx = self.pool.begin().await?;
        if let Some(id) = duplicate(&mut tx, "CreateReport", request, &hash).await? {
            return load(&mut tx, "report_exports", &id).await;
        }
        let run: d::AuditRun = load(&mut tx, "audit_runs", run_id).await?;
        let project: d::Project = load(&mut tx, "projects", &run.project_id).await?;
        let snapshot: d::Snapshot = load(&mut tx, "snapshots", &run.snapshot_id).await?;
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT data FROM program_units WHERE run_id=? ORDER BY path,name,id",
        )
        .bind(run_id)
        .fetch_all(&mut *tx)
        .await?;
        let mut units = vec![];
        for data in rows {
            let mut unit: d::ProgramUnit = serde_json::from_str(&data)?;
            unit.unit.code.clear();
            units.push(unit);
        }
        let artifacts = self.run_artifacts(run_id).await?;
        let audit = self.audit_evidence(run_id).await?;
        let snapshot_at = d::now();
        let interim = aegis_application::report::is_interim(&run, &audit);
        // Freeze the data under the write guard, then release it before formatting or
        // launching the bounded PDF process. Exports must not block lease/cancel writes.
        tx.commit().await?;
        drop(guard);
        let (bytes, mime, extension) = aegis_application::report::render_at(
            &project,
            &snapshot,
            &run,
            &units,
            &artifacts,
            &audit,
            if format == "pdf" { "html" } else { format },
            &snapshot_at,
        )?;
        let (bytes, mime, extension) = if format == "pdf" {
            (
                aegis_application::pdf::render(&bytes).await?,
                "application/pdf",
                "pdf",
            )
        } else {
            (bytes, mime, extension)
        };
        let _guard = self.writes.lock().await;
        let mut tx = self.pool.begin().await?;
        // Concurrent retries return the first immutable export, even if the run
        // advanced while both requests were rendering.
        if let Some(id) = duplicate(&mut tx, "CreateReport", request, &hash).await? {
            return load(&mut tx, "report_exports", &id).await;
        }
        let artifact = self
            .stage_bytes(&bytes, &format!("aegis-report-{run_id}.{extension}"), mime)
            .await?;
        Self::insert_artifact(&mut tx, &artifact, Some(&snapshot.id), None, None).await?;
        let report = d::Report {
            id: d::id(),
            run_id: run_id.into(),
            format: format.into(),
            artifact_id: artifact.id,
            created_at: d::now(),
            snapshot_state: run.state.as_str().into(),
            snapshot_at,
            interim,
        };
        sqlx::query(
            "INSERT INTO report_exports(id,run_id,artifact_id,created_at,data) VALUES(?,?,?,?,?)",
        )
        .bind(&report.id)
        .bind(run_id)
        .bind(&report.artifact_id)
        .bind(&report.created_at)
        .bind(serde_json::to_string(&report)?)
        .execute(&mut *tx)
        .await?;
        record_request(&mut tx, "CreateReport", request, &hash, &report.id).await?;
        tx.commit().await?;
        Ok(report)
    }
}
