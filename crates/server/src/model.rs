use crate::{
    convert,
    error::{AppError, Result},
    model_settings::Settings,
    store::{Store, duplicate, record_request},
};
use aegis_application::model::{DEFAULT_MODEL, DeepSeek, ENDPOINT};
use aegis_domain as d;
use aegis_protocol as p;
use serde_json::json;
use std::time::Instant;

impl Store {
    pub async fn model_connection(&self) -> Result<p::ModelConnection> {
        let mut result = p::ModelConnection {
            provider: "DeepSeek 官方".into(),
            endpoint: ENDPOINT.into(),
            model: DEFAULT_MODEL.into(),
            provider_kind: "DEEPSEEK".into(),
            revision: "unavailable".into(),
            settings_locked: self.model_settings_locked().await?,
            ..Default::default()
        };
        let settings = match self.model_settings().await {
            Ok(settings) => settings,
            Err(_) => {
                result.status_message = "本地模型配置不可用，可重新填写连接设置修复".into();
                return Ok(result);
            }
        };
        result.model = settings.model.clone();
        result.endpoint = settings.endpoint.clone();
        result.provider_kind = settings.provider_kind.clone();
        result.provider = if settings.provider_kind == "DEEPSEEK" {
            "DeepSeek 官方"
        } else {
            "OpenAI 兼容接口"
        }
        .into();
        result.key_source = settings.key_source.clone();
        result.revision = settings.revision.clone();
        result.configured = settings.key.is_some();
        if result.configured {
            let last: Option<String> = sqlx::query_scalar("SELECT data FROM model_calls WHERE config_hash=? AND run_id IS NULL ORDER BY created_at DESC,id DESC LIMIT 1").bind(settings.fingerprint()).fetch_optional(&self.pool).await?;
            if let Some(last) = last {
                result.last_call = convert::model_call(serde_json::from_str(&last)?).into();
            }
        }
        Ok(result)
    }

    pub async fn start_model_probe(&self, request: &str) -> Result<d::ModelCall> {
        let guard = self.writes.lock().await;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let settings = self.model_settings().await?;
        if settings.key.is_none() {
            return Err(AppError::Precondition(
                "尚未配置模型密钥，请先保存连接设置".into(),
            ));
        }
        let fingerprint = settings.fingerprint();
        if let Some(id) = duplicate(&mut tx, "CheckModelConnection", request, &fingerprint).await? {
            let data: String = sqlx::query_scalar("SELECT data FROM model_calls WHERE id=?")
                .bind(id)
                .fetch_one(&mut *tx)
                .await?;
            return Ok(serde_json::from_str(&data)?);
        }
        let active: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM model_calls WHERE status='RUNNING' AND run_id IS NULL",
        )
        .fetch_one(&mut *tx)
        .await?;
        if active > 0 {
            return Err(AppError::Precondition("已有连接检查正在执行".into()));
        }
        let call = d::ModelCall {
            id: d::id(),
            model: settings.model.clone(),
            purpose: "CONNECTION_CHECK".into(),
            status: "RUNNING".into(),
            created_at: d::now(),
            ..Default::default()
        };
        sqlx::query(
            "INSERT INTO model_calls(id,status,created_at,config_hash,data) VALUES(?,?,?,?,?)",
        )
        .bind(&call.id)
        .bind(&call.status)
        .bind(&call.created_at)
        .bind(fingerprint.as_str())
        .bind(serde_json::to_string(&call)?)
        .execute(&mut *tx)
        .await?;
        record_request(
            &mut tx,
            "CheckModelConnection",
            request,
            &fingerprint,
            &call.id,
        )
        .await?;
        tx.commit().await?;
        drop(guard);
        let store = self.clone();
        let saved = call.clone();
        tokio::spawn(async move {
            if let Err(error) = store.finish_model_probe(saved, settings).await {
                tracing::error!(error=?error,"could not persist model connection result");
            }
        });
        Ok(call)
    }

    async fn finish_model_probe(&self, mut call: d::ModelCall, settings: Settings) -> Result<()> {
        let started = Instant::now();
        let result = match DeepSeek::configured(
            settings.key.unwrap_or_default(),
            &settings.endpoint,
            &settings.provider_kind,
        ) {
            Ok(client) => client.probe(&settings.model).await,
            Err(error) => Err(error),
        };
        call.finished_at = d::now();
        call.latency_ms = started.elapsed().as_millis() as u64;
        let response = match result {
            Ok(result) => {
                call.status = "SUCCEEDED".into();
                call.input_tokens = result.input_tokens;
                call.output_tokens = result.output_tokens;
                call.total_tokens = result.total_tokens;
                call.usage_available = result.usage_available;
                call.provider_request_id = result.provider_request_id;
                result.response
            }
            Err(error) => {
                call.status = "FAILED".into();
                call.error = error.to_string();
                json!({"error":call.error})
            }
        };
        let bytes = serde_json::to_vec_pretty(
            &json!({"schema_version":1,"purpose":"CONNECTION_CHECK","model":call.model,"response":response,"usage_source":if call.usage_available{"PROVIDER"}else{"UNAVAILABLE"},"cost_cny":null}),
        )?;
        let artifact = self
            .stage_bytes(
                &bytes,
                &format!("model-connection-{}.json", call.id),
                "application/json",
            )
            .await?;
        call.artifact_id = artifact.id.clone();
        let _guard = self.writes.lock().await;
        let mut tx = self.pool.begin().await?;
        Self::insert_artifact(&mut tx, &artifact, None, None, None).await?;
        sqlx::query("UPDATE model_calls SET status=?,artifact_id=?,data=? WHERE id=?")
            .bind(&call.status)
            .bind(&artifact.id)
            .bind(serde_json::to_string(&call)?)
            .bind(&call.id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        self.changed.notify_waiters();
        Ok(())
    }

    pub async fn recover_model_probes(&self) -> Result<()> {
        let _guard = self.writes.lock().await;
        let mut tx = self.pool.begin().await?;
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT data FROM model_calls WHERE status='RUNNING' AND run_id IS NULL",
        )
        .fetch_all(&mut *tx)
        .await?;
        for row in rows {
            let mut call: d::ModelCall = serde_json::from_str(&row)?;
            call.status = "INTERRUPTED".into();
            call.finished_at = d::now();
            call.error = "控制服务重启，原连接检查结果未确认；用量未知".into();
            sqlx::query("UPDATE model_calls SET status=?,data=? WHERE id=?")
                .bind(&call.status)
                .bind(serde_json::to_string(&call)?)
                .bind(&call.id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires the pinned private Windows Python; no model API is called"]
    async fn native_python_dpapi_credentials_are_read_by_the_rust_server() {
        use std::{path::Path, process::Stdio, time::Duration};
        use tokio::io::AsyncWriteExt;

        let directory = tempfile::Builder::new()
            .prefix("aegis credential \u{5bc6}\u{94a5} ")
            .tempdir()
            .unwrap();
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let python =
            std::env::var_os("AEGIS_PYTHON_HOME").expect("private Windows Python is required");
        let mut child = tokio::process::Command::new(Path::new(&python).join("python.exe"))
            .args(["-I", "-X", "utf8", "-c", "import sys; sys.path.insert(0, sys.argv.pop(1)); from configure_model import main; main()"])
            .arg(root.join("scripts")).arg("--stdin").arg("--data-dir").arg(directory.path())
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
            .kill_on_drop(true).spawn().unwrap();
        let fixture_key = "interop-fixture-not-a-real-provider-key";
        child
            .stdin
            .take()
            .unwrap()
            .write_all(format!("{fixture_key}\n").as_bytes())
            .await
            .unwrap();
        let output = tokio::time::timeout(Duration::from_secs(15), child.wait_with_output())
            .await
            .unwrap()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains(fixture_key));
        let stored = tokio::fs::read_to_string(directory.path().join("deepseek.token"))
            .await
            .unwrap();
        assert!(stored.starts_with(aegis_application::credentials::PREFIX));
        assert!(!stored.contains(fixture_key));
        let store = Store::open(directory.path()).await.unwrap();
        assert_eq!(
            store.model_settings().await.unwrap().key.as_deref(),
            Some(fixture_key)
        );
        let status = store.model_connection().await.unwrap();
        assert!(status.configured && status.last_call.id.is_empty());
        assert!(
            !serde_json::to_string(&status)
                .unwrap()
                .contains(fixture_key)
        );
        tokio::fs::write(directory.path().join("deepseek.token"), "aegis-dpapi-v1:00")
            .await
            .unwrap();
        assert!(!store.model_connection().await.unwrap().configured);
        assert!(store.start_model_probe(&d::id()).await.is_err());
        if let Some(path) = std::env::var_os("AEGIS_NATIVE_SAST_EVIDENCE") {
            let path = Path::new(&path);
            std::fs::create_dir_all(path).unwrap();
            std::fs::write(path.join("credentials-interop.json"), serde_json::to_vec_pretty(&json!({
                "observed_at": d::now(), "platform": "windows/x86_64", "format": "aegis-dpapi-v1",
                "python_writer_rust_reader": "PASSED", "plaintext_not_stored": true,
                "corrupt_ciphertext_rejected_before_api_call": true,
                "real_provider_credential_used": false, "model_api_called": false
            })).unwrap()).unwrap();
        }
        store.pool.close().await;
    }

    #[tokio::test]
    async fn credentials_stay_private_and_interrupted_calls_are_not_reported_as_success() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).await.unwrap();
        assert!(!store.model_connection().await.unwrap().configured);
        tokio::fs::write(
            directory.path().join("deepseek.token"),
            "fixture-key-not-a-real-credential",
        )
        .await
        .unwrap();
        let settings = store.model_settings().await.unwrap();
        let call = d::ModelCall {
            id: d::id(),
            model: DEFAULT_MODEL.into(),
            status: "RUNNING".into(),
            created_at: d::now(),
            purpose: "CONNECTION_CHECK".into(),
            ..Default::default()
        };
        let request = d::id();
        let mut tx = store.pool.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO model_calls(id,status,created_at,config_hash,data) VALUES(?,?,?,?,?)",
        )
        .bind(&call.id)
        .bind(&call.status)
        .bind(&call.created_at)
        .bind(settings.fingerprint())
        .bind(serde_json::to_string(&call).unwrap())
        .execute(&mut *tx)
        .await
        .unwrap();
        record_request(
            &mut tx,
            "CheckModelConnection",
            &request,
            &settings.fingerprint(),
            &call.id,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        store.recover_model_probes().await.unwrap();
        let status = store.model_connection().await.unwrap();
        assert!(status.configured);
        assert_eq!(status.last_call.status, "INTERRUPTED");
        assert!(!status.last_call.usage_available);
        assert!(
            !serde_json::to_string(&status)
                .unwrap()
                .contains("fixture-key-not-a-real-credential")
        );
        let duplicate = store.start_model_probe(&request).await.unwrap();
        assert_eq!(duplicate.id, call.id);
        assert_eq!(duplicate.status, "INTERRUPTED");
        tokio::fs::write(
            directory.path().join("deepseek.token"),
            "changed-fixture-credential",
        )
        .await
        .unwrap();
        assert!(
            store
                .model_connection()
                .await
                .unwrap()
                .last_call
                .id
                .is_empty()
        );
    }
}
