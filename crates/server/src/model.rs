use crate::{
    convert,
    error::{AppError, Result},
    store::{Store, duplicate, record_request, valid_text},
};
use aegis_application::model::{DEFAULT_MODEL, DeepSeek, ENDPOINT};
use aegis_domain as d;
use aegis_protocol as p;
use serde::Deserialize;
use serde_json::json;
use std::{io::ErrorKind, time::Instant};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Preferences {
    model: String,
}

struct Settings {
    model: String,
    key: Option<String>,
}
impl Settings {
    fn fingerprint(&self) -> String {
        d::sha256(format!("{}:{}", self.model, self.key.as_deref().unwrap_or_default()).as_bytes())
    }
}

impl Store {
    async fn model_settings(&self) -> Result<Settings> {
        let model = match tokio::fs::read(self.root.join("model.json")).await {
            Ok(bytes) => {
                serde_json::from_slice::<Preferences>(&bytes)
                    .map_err(|_| AppError::Precondition("model.json 配置格式无效".into()))?
                    .model
            }
            Err(error) if error.kind() == ErrorKind::NotFound => DEFAULT_MODEL.into(),
            Err(error) => return Err(error.into()),
        };
        let model = valid_text(&model, 100, "模型名称")?;
        if !model.starts_with("deepseek-") {
            return Err(AppError::Precondition(
                "模型名称应为 DeepSeek 官方模型标识".into(),
            ));
        }
        let key = match tokio::fs::read_to_string(self.root.join("deepseek.token")).await {
            Ok(value) => {
                let value = value.trim().to_owned();
                if value.is_empty() { None } else { Some(value) }
            }
            Err(error) if error.kind() == ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        Ok(Settings { model, key })
    }

    pub async fn model_connection(&self) -> Result<p::ModelConnection> {
        let mut result = p::ModelConnection {
            provider: "DeepSeek 官方".into(),
            endpoint: ENDPOINT.into(),
            model: DEFAULT_MODEL.into(),
            ..Default::default()
        };
        let settings = match self.model_settings().await {
            Ok(settings) => settings,
            Err(_) => {
                result.status_message = "本地模型配置不可用，请检查服务端配置文件".into();
                return Ok(result);
            }
        };
        result.model = settings.model.clone();
        result.configured = settings.key.is_some();
        if result.configured {
            let last: Option<String> = sqlx::query_scalar("SELECT data FROM model_calls WHERE config_hash=? ORDER BY created_at DESC,id DESC LIMIT 1").bind(settings.fingerprint()).fetch_optional(&self.pool).await?;
            if let Some(last) = last {
                result.last_call = convert::model_call(serde_json::from_str(&last)?).into();
            }
        }
        Ok(result)
    }

    pub async fn start_model_probe(&self, request: &str) -> Result<d::ModelCall> {
        let settings = self.model_settings().await?;
        if settings.key.is_none() {
            return Err(AppError::Precondition("尚未配置 DeepSeek 本地密钥".into()));
        }
        let fingerprint = settings.fingerprint();
        let guard = self.writes.lock().await;
        let mut tx = self.pool.begin().await?;
        if let Some(id) = duplicate(&mut tx, "CheckModelConnection", request, &fingerprint).await? {
            let data: String = sqlx::query_scalar("SELECT data FROM model_calls WHERE id=?")
                .bind(id)
                .fetch_one(&mut *tx)
                .await?;
            return Ok(serde_json::from_str(&data)?);
        }
        let active: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM model_calls WHERE status='RUNNING'")
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
        let result = match DeepSeek::new(settings.key.unwrap_or_default()) {
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
                &format!("deepseek-connection-{}.json", call.id),
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
        let rows: Vec<String> =
            sqlx::query_scalar("SELECT data FROM model_calls WHERE status='RUNNING'")
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
