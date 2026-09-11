//! Operator-editable model settings. A single SQLite transaction stores DPAPI
//! ciphertext and the idempotency record; secrets never become response fields.
use crate::{
    error::{AppError, Result},
    store::{Store, duplicate, record_request, valid_text},
};
use aegis_application::{
    credentials,
    model::{DEFAULT_MODEL, ENDPOINT, normalize_endpoint},
};
use aegis_domain as d;
use aegis_protocol as p;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::io::ErrorKind;

#[derive(Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
struct Preferences {
    model: String,
    endpoint: String,
    provider_kind: String,
    protected_key: Option<String>,
    revision: String,
}

#[derive(Default)]
struct Environment {
    endpoint: Option<String>,
    model: Option<String>,
    api_key: Option<String>,
    deepseek_key: Option<String>,
}
impl Environment {
    fn read() -> Self {
        Self {
            endpoint: std::env::var("AEGIS_MODEL_ENDPOINT")
                .ok()
                .filter(|s| !s.is_empty()),
            model: std::env::var("AEGIS_MODEL").ok().filter(|s| !s.is_empty()),
            api_key: std::env::var("AEGIS_MODEL_API_KEY")
                .ok()
                .filter(|s| !s.is_empty()),
            deepseek_key: std::env::var("DEEPSEEK_API_KEY")
                .ok()
                .filter(|s| !s.is_empty()),
        }
    }
    fn key_for(&self, endpoint: &str, provider: &str) -> Option<(&str, &'static str)> {
        // A generic environment key is bound to its explicitly configured endpoint.
        // Changing a URL in the UI must never silently forward another provider's key.
        if normalize_endpoint(self.endpoint.as_deref().unwrap_or(ENDPOINT))
            .ok()
            .as_deref()
            == Some(endpoint)
            && let Some(key) = &self.api_key
        {
            return Some((key, "AEGIS_MODEL_API_KEY"));
        }
        if endpoint == ENDPOINT
            && provider == "DEEPSEEK"
            && let Some(key) = &self.deepseek_key
        {
            return Some((key, "DEEPSEEK_API_KEY"));
        }
        None
    }
}

pub(crate) struct Settings {
    pub model: String,
    pub endpoint: String,
    pub provider_kind: String,
    pub key: Option<String>,
    pub key_source: String,
    pub revision: String,
}
impl Settings {
    pub fn fingerprint(&self) -> String {
        if self.provider_kind == "DEEPSEEK" && self.endpoint == ENDPOINT {
            // Preserve the identity of already queued/running official-provider jobs.
            d::sha256(
                format!("{}:{}", self.model, self.key.as_deref().unwrap_or_default()).as_bytes(),
            )
        } else {
            d::sha256(
                serde_json::to_string(&json!([
                    self.provider_kind,
                    self.endpoint,
                    self.model,
                    self.key
                ]))
                .unwrap()
                .as_bytes(),
            )
        }
    }
}

pub struct ModelSettingsInput<'a> {
    pub provider_kind: &'a str,
    pub endpoint: &'a str,
    pub model: &'a str,
    pub api_key: &'a str,
    pub key_action: &'a str,
    pub expected_revision: &'a str,
}

fn valid_key(value: &str) -> Result<Option<String>> {
    if value.len() > 16384 || value.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(AppError::Precondition("模型凭据格式无效".into()));
    }
    Ok((!value.is_empty()).then(|| value.to_owned()))
}

fn public_fields(
    preferences: &Preferences,
    environment: &Environment,
) -> Result<(String, String, String)> {
    let endpoint = normalize_endpoint(if preferences.endpoint.is_empty() {
        environment.endpoint.as_deref().unwrap_or(ENDPOINT)
    } else {
        &preferences.endpoint
    })
    .map_err(|error| AppError::Invalid(error.to_string()))?;
    let provider = if preferences.provider_kind.is_empty() {
        if endpoint == ENDPOINT {
            "DEEPSEEK"
        } else {
            "OPENAI_COMPATIBLE"
        }
    } else {
        &preferences.provider_kind
    };
    if !["DEEPSEEK", "OPENAI_COMPATIBLE"].contains(&provider)
        || (provider == "DEEPSEEK" && endpoint != ENDPOINT)
    {
        return Err(AppError::Invalid(
            "接口类型与地址不匹配；自定义地址请选择兼容模式".into(),
        ));
    }
    let model = valid_text(
        if preferences.model.is_empty() {
            environment.model.as_deref().unwrap_or(DEFAULT_MODEL)
        } else {
            &preferences.model
        },
        100,
        "模型名称",
    )?;
    if model.chars().any(|c| c.is_whitespace() || c.is_control())
        || (provider == "DEEPSEEK" && !model.starts_with("deepseek-"))
    {
        return Err(AppError::Invalid(
            "模型名称无效；官方模式须填写 deepseek- 开头的标识".into(),
        ));
    }
    Ok((model, endpoint, provider.into()))
}

impl Store {
    pub(crate) async fn model_settings(&self) -> Result<Settings> {
        let saved: Option<String> =
            sqlx::query_scalar("SELECT data FROM model_settings WHERE id=1")
                .fetch_optional(&self.pool)
                .await?;
        let web_saved = saved.is_some();
        let preferences: Preferences = if let Some(saved) = saved {
            serde_json::from_str(&saved)
                .map_err(|_| AppError::Precondition("网页模型配置格式无效".into()))?
        } else {
            match tokio::fs::read(self.root.join("model.json")).await {
                Ok(bytes) => serde_json::from_slice(&bytes)
                    .map_err(|_| AppError::Precondition("model.json 配置格式无效".into()))?,
                Err(error) if error.kind() == ErrorKind::NotFound => Preferences::default(),
                Err(error) => return Err(error.into()),
            }
        };
        let environment = Environment::read();
        let (model, endpoint, provider_kind) = public_fields(&preferences, &environment)?;
        let mut key = None;
        let mut key_source = "NONE".to_string();
        let stored = if web_saved {
            preferences.protected_key.clone()
        } else if provider_kind == "DEEPSEEK" && endpoint == ENDPOINT {
            match tokio::fs::read_to_string(self.root.join("deepseek.token")).await {
                Ok(value) => Some(value),
                Err(error) if error.kind() == ErrorKind::NotFound => None,
                Err(error) => return Err(error.into()),
            }
        } else {
            None
        };
        if let Some(stored) = stored {
            let value = credentials::decode(&stored).map_err(|_| {
                AppError::Precondition("本地模型凭据无法由当前 Windows 账户解密，请重新配置".into())
            })?;
            key = valid_key(&value)?;
            if key.is_some() {
                key_source = if web_saved { "WEB_SAVED" } else { "LOCAL_FILE" }.into();
            }
        }
        if key.is_none()
            && let Some((value, source)) = environment.key_for(&endpoint, &provider_kind)
        {
            key = valid_key(value.trim())?;
            if key.is_some() {
                key_source = source.into();
            }
        }
        Ok(Settings {
            model,
            endpoint,
            provider_kind,
            key,
            key_source,
            revision: if preferences.revision.is_empty() {
                "legacy".into()
            } else {
                preferences.revision
            },
        })
    }

    pub async fn model_settings_locked(&self) -> Result<bool> {
        let active: i64 = sqlx::query_scalar("SELECT (SELECT count(*) FROM audit_workflows w JOIN audit_runs r ON r.id=w.run_id WHERE r.state IN ('QUEUED','WAITING_EXECUTOR','RUNNING','CANCELLING')) + (SELECT count(*) FROM model_calls WHERE status='RUNNING' AND run_id IS NULL)")
            .fetch_one(&self.pool).await?;
        Ok(active > 0)
    }

    pub async fn save_model_settings(
        &self,
        request: &str,
        input: ModelSettingsInput<'_>,
    ) -> Result<p::ModelConnection> {
        if !["KEEP", "REPLACE", "CLEAR"].contains(&input.key_action)
            || (input.key_action != "REPLACE" && !input.api_key.is_empty())
        {
            return Err(AppError::Invalid("请选择保留、更换或移除保存的密钥".into()));
        }
        if input.model.trim().is_empty()
            || input.endpoint.trim().is_empty()
            || input.provider_kind.is_empty()
        {
            return Err(AppError::Invalid(
                "接口类型、基础地址和模型名称不能为空".into(),
            ));
        }
        let mut preferences = Preferences {
            model: input.model.trim().into(),
            endpoint: input.endpoint.trim().into(),
            provider_kind: input.provider_kind.into(),
            ..Default::default()
        };
        let (model, endpoint, provider_kind) =
            public_fields(&preferences, &Environment::default())?;
        preferences.model = model;
        preferences.endpoint = endpoint;
        preferences.provider_kind = provider_kind;
        let hash = d::sha256(&serde_json::to_vec(&json!([
            input.provider_kind,
            input.endpoint,
            input.model,
            input.api_key,
            input.key_action,
            input.expected_revision
        ]))?);
        let guard = self.writes.lock().await;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        if duplicate(&mut tx, "SaveModelSettings", request, &hash)
            .await?
            .is_some()
        {
            drop(tx);
            drop(guard);
            return self.model_connection().await;
        }
        let current = self.model_settings().await.ok();
        let revision = current
            .as_ref()
            .map(|settings| settings.revision.as_str())
            .unwrap_or("unavailable");
        if input.expected_revision != revision {
            return Err(AppError::Conflict(
                "模型配置已更新，请重新打开配置后保存".into(),
            ));
        }
        if self.model_settings_locked().await? {
            return Err(AppError::Precondition(
                "审计或连接检测正在使用模型配置，请在任务结束或取消完成后保存".into(),
            ));
        }
        let key = match input.key_action {
            "REPLACE" => Some(
                valid_key(input.api_key.trim())?
                    .ok_or_else(|| AppError::Invalid("更换密钥时不能为空".into()))?,
            ),
            "CLEAR" => None,
            _ => {
                let current = current.as_ref().ok_or_else(|| {
                    AppError::Precondition(
                        "原模型配置无法读取，请填写新密钥或移除已保存密钥".into(),
                    )
                })?;
                if current.key.is_some()
                    && (current.endpoint != preferences.endpoint
                        || current.provider_kind != preferences.provider_kind)
                {
                    return Err(AppError::Precondition(
                        "更换接口地址或类型时，请重新填写该接口的密钥，或选择移除保存的密钥".into(),
                    ));
                }
                if ["AEGIS_MODEL_API_KEY", "DEEPSEEK_API_KEY"]
                    .contains(&current.key_source.as_str())
                {
                    None
                } else {
                    current.key.clone()
                }
            }
        };
        preferences.protected_key = Some(match key {
            Some(key) => credentials::encode(&key)
                .map_err(|_| AppError::Precondition("Windows 凭据加密失败，未修改原配置".into()))?,
            None => String::new(),
        });
        preferences.revision = d::id();
        sqlx::query("INSERT INTO model_settings(id,data) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data")
            .bind(serde_json::to_string(&preferences)?).execute(&mut *tx).await?;
        record_request(
            &mut tx,
            "SaveModelSettings",
            request,
            &hash,
            &preferences.revision,
        )
        .await?;
        tx.commit().await?;
        drop(guard);
        self.changed.notify_waiters();
        self.model_connection().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn input<'a>(
        endpoint: &'a str,
        key: &'a str,
        action: &'a str,
        revision: &'a str,
    ) -> ModelSettingsInput<'a> {
        ModelSettingsInput {
            provider_kind: "OPENAI_COMPATIBLE",
            endpoint,
            model: "custom-model",
            api_key: key,
            key_action: action,
            expected_revision: revision,
        }
    }
    #[tokio::test]
    async fn web_settings_are_encrypted_atomic_versioned_and_locked_during_probes() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).await.unwrap();
        let request = d::id();
        let endpoint = "http://127.0.0.1:12345/v1";
        let secret = "settings-fixture-only-secret";
        let saved = store
            .save_model_settings(&request, input(endpoint, secret, "REPLACE", "legacy"))
            .await
            .unwrap();
        assert!(saved.configured);
        assert_eq!(saved.key_source, "WEB_SAVED");
        assert!(!serde_json::to_string(&saved).unwrap().contains(secret));
        let stored: String = sqlx::query_scalar("SELECT data FROM model_settings WHERE id=1")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert!(stored.contains(credentials::PREFIX));
        assert!(!stored.contains(secret));
        assert_eq!(
            store.model_settings().await.unwrap().key.as_deref(),
            Some(secret)
        );
        assert_eq!(
            store
                .save_model_settings(&request, input(endpoint, secret, "REPLACE", "legacy"))
                .await
                .unwrap()
                .revision,
            saved.revision
        );
        assert!(matches!(
            store
                .save_model_settings(&d::id(), input(endpoint, "", "KEEP", "legacy"))
                .await,
            Err(AppError::Conflict(_))
        ));
        assert!(
            store
                .save_model_settings(
                    &d::id(),
                    input("http://127.0.0.1:12346/v1", "", "KEEP", &saved.revision)
                )
                .await
                .is_err()
        );
        let call = d::ModelCall {
            id: d::id(),
            status: "RUNNING".into(),
            created_at: d::now(),
            ..Default::default()
        };
        sqlx::query(
            "INSERT INTO model_calls(id,status,created_at,config_hash,data) VALUES(?,?,?,?,?)",
        )
        .bind(&call.id)
        .bind("RUNNING")
        .bind(&call.created_at)
        .bind(store.model_settings().await.unwrap().fingerprint())
        .bind(serde_json::to_string(&call).unwrap())
        .execute(&store.pool)
        .await
        .unwrap();
        assert!(store.model_connection().await.unwrap().settings_locked);
        assert!(matches!(
            store
                .save_model_settings(
                    &d::id(),
                    input(endpoint, "replacement-fixture", "REPLACE", &saved.revision)
                )
                .await,
            Err(AppError::Precondition(_))
        ));
        assert_eq!(
            sqlx::query_scalar::<_, String>("SELECT data FROM model_settings WHERE id=1")
                .fetch_one(&store.pool)
                .await
                .unwrap(),
            stored
        );
        store.recover_model_probes().await.unwrap();
        let cleared = store
            .save_model_settings(&d::id(), input(endpoint, "", "CLEAR", &saved.revision))
            .await
            .unwrap();
        assert!(!cleared.configured);
        assert!(store.model_settings().await.unwrap().key.is_none());
        let reopened = Store::open(directory.path()).await.unwrap();
        assert_eq!(
            reopened.model_connection().await.unwrap().revision,
            cleared.revision
        );
    }

    #[test]
    fn environment_fallback_is_read_by_an_isolated_server_process() {
        let directory = tempfile::tempdir().unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "model_settings::tests::environment_child",
                "--ignored",
            ])
            .env("AEGIS_TEST_MODEL_ENV_DIR", directory.path())
            .env("AEGIS_MODEL_ENDPOINT", "http://127.0.0.1:12345/v1")
            .env("AEGIS_MODEL", "environment-model")
            .env("AEGIS_MODEL_API_KEY", "environment-fixture-key")
            .env_remove("DEEPSEEK_API_KEY")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
    #[tokio::test]
    #[ignore = "invoked by the subprocess environment test"]
    async fn environment_child() {
        let directory = std::env::var_os("AEGIS_TEST_MODEL_ENV_DIR").expect("subprocess fixture");
        let store = Store::open(std::path::Path::new(&directory)).await.unwrap();
        let connection = store.model_connection().await.unwrap();
        assert_eq!(connection.key_source, "AEGIS_MODEL_API_KEY");
        assert_eq!(connection.model, "environment-model");
        assert!(connection.configured);
        let saved = store
            .save_model_settings(
                &d::id(),
                input(
                    &connection.endpoint,
                    "explicit-fixture-key",
                    "REPLACE",
                    &connection.revision,
                ),
            )
            .await
            .unwrap();
        assert_eq!(saved.key_source, "WEB_SAVED");
        let cleared = store
            .save_model_settings(
                &d::id(),
                input(&connection.endpoint, "", "CLEAR", &saved.revision),
            )
            .await
            .unwrap();
        assert_eq!(cleared.key_source, "AEGIS_MODEL_API_KEY");
    }
    #[test]
    fn environment_keys_are_bound_to_their_endpoint_and_legacy_fingerprints_are_stable() {
        let environment = Environment {
            endpoint: Some("https://compatible.example/v1".into()),
            api_key: Some("compatible-fixture".into()),
            deepseek_key: Some("official-fixture".into()),
            ..Default::default()
        };
        assert_eq!(
            environment
                .key_for("https://compatible.example/v1", "OPENAI_COMPATIBLE")
                .unwrap()
                .1,
            "AEGIS_MODEL_API_KEY"
        );
        assert!(
            environment
                .key_for("https://unrelated.example/v1", "OPENAI_COMPATIBLE")
                .is_none()
        );
        assert_eq!(
            environment.key_for(ENDPOINT, "DEEPSEEK").unwrap().1,
            "DEEPSEEK_API_KEY"
        );
        let settings = Settings {
            model: DEFAULT_MODEL.into(),
            endpoint: ENDPOINT.into(),
            provider_kind: "DEEPSEEK".into(),
            key: Some("fixture".into()),
            key_source: String::new(),
            revision: String::new(),
        };
        assert_eq!(
            settings.fingerprint(),
            d::sha256(format!("{DEFAULT_MODEL}:fixture").as_bytes())
        );
    }
}
