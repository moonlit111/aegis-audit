//! Official and compatible chat transports. Secrets never enter saved request/response records.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{future::Future, pin::Pin, time::Duration};

pub const ENDPOINT: &str = "https://api.deepseek.com";
pub const DEFAULT_MODEL: &str = "deepseek-v4-flash";
pub struct DeepSeek {
    client: reqwest::Client,
    key: String,
    endpoint: String,
    compatible: bool,
}

pub fn normalize_endpoint(value: &str) -> Result<String> {
    ensure!(value.len() <= 2048, "模型接口地址过长");
    let url = reqwest::Url::parse(value.trim()).map_err(|_| anyhow::anyhow!("模型接口地址无效"))?;
    ensure!(
        url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "接口地址不能包含用户名、密码、查询参数或片段"
    );
    let local = url.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    ensure!(
        url.scheme() == "https" || (url.scheme() == "http" && local),
        "模型接口须使用 HTTPS；本机回环地址可使用 HTTP"
    );
    let endpoint = url.as_str().trim_end_matches('/').to_owned();
    ensure!(
        !endpoint.ends_with("/chat/completions"),
        "请填写基础地址，例如 https://example.com/v1，不含 /chat/completions"
    );
    Ok(endpoint)
}

pub struct ProbeResult {
    pub response: Value,
    pub provider_request_id: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    pub usage_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelRequest {
    pub model: String,
    pub messages: Vec<Value>,
    pub max_tokens: u32,
    pub reasoning_effort: String,
    pub timeout_seconds: u32,
}

pub struct ModelResponse {
    pub content: String,
    pub finish_reason: String,
    pub result: ProbeResult,
}

pub trait ModelClient: Send + Sync {
    fn complete<'a>(
        &'a self,
        request: &'a ModelRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ModelResponse>> + Send + 'a>>;
}

#[derive(Debug)]
pub struct ProviderFailure {
    pub status: u16,
    pub retryable: bool,
    pub detail: &'static str,
}
impl std::fmt::Display for ProviderFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "模型接口返回 HTTP {}：{}", self.status, self.detail)
    }
}
impl std::error::Error for ProviderFailure {}

impl DeepSeek {
    pub fn new(key: String) -> Result<Self> {
        Self::configured(key, ENDPOINT, "DEEPSEEK")
    }

    pub fn configured(key: String, endpoint: &str, provider_kind: &str) -> Result<Self> {
        ensure!(
            !key.is_empty()
                && key.len() <= 16384
                && !key.chars().any(|c| c.is_whitespace() || c.is_control()),
            "模型密钥未配置或格式无效"
        );
        ensure!(
            ["DEEPSEEK", "OPENAI_COMPATIBLE"].contains(&provider_kind),
            "未知模型接口类型"
        );
        let endpoint = normalize_endpoint(endpoint)?;
        ensure!(
            provider_kind != "DEEPSEEK" || endpoint == ENDPOINT,
            "DeepSeek 官方模式须使用官方地址；自定义地址请选择兼容模式"
        );
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut builder = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none());
        let url = reqwest::Url::parse(&endpoint)?;
        if url.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        }) {
            builder = builder.no_proxy();
        }
        let client = builder.build()?;
        Ok(Self {
            client,
            key,
            endpoint,
            compatible: provider_kind == "OPENAI_COMPATIBLE",
        })
    }

    pub async fn probe(&self, model: &str) -> Result<ProbeResult> {
        let mut body = json!({
            "model":model,
            "messages":[{"role":"user","content":"Connection check. Return exactly this JSON object: {\"connected\":true}"}],
            "response_format":{"type":"json_object"},
            "thinking":{"type":"disabled"},
            "max_tokens":128,
            "temperature":0,
            "stream":false
        });
        if self.compatible {
            body.as_object_mut().unwrap().remove("thinking");
            body.as_object_mut().unwrap().remove("response_format");
        }
        let result = self.send(&body, 64 * 1024, 300).await?;
        let content = result.response["choices"][0]["message"]["content"]
            .as_str()
            .context("模型服务未返回消息内容")?;
        let answer: Value = serde_json::from_str(content).context("模型结构化响应校验失败")?;
        ensure!(answer["connected"] == true, "模型连接检查结果不符合约定");
        Ok(result)
    }

    async fn send(&self, body: &Value, limit: usize, timeout_seconds: u32) -> Result<ProbeResult> {
        let mut response = self
            .client
            .post(format!("{}/chat/completions", self.endpoint))
            .timeout(Duration::from_secs(timeout_seconds.into()))
            .bearer_auth(&self.key)
            .json(body)
            .send()
            .await
            .map_err(|error| {
                anyhow::anyhow!(if error.is_timeout() {
                    "模型请求超时；用量未知"
                } else {
                    "模型网络连接失败"
                })
            })?;
        if !response.status().is_success() {
            // Provider error text can echo credentials; retain only a safe status explanation.
            let status = response.status().as_u16();
            let detail = match status {
                401 | 403 => "鉴权失败",
                402 => "账户余额不足",
                429 => "请求限流",
                500..=599 => "服务暂时不可用",
                _ => "请求被拒绝",
            };
            return Err(ProviderFailure {
                status,
                retryable: status == 429 || status >= 500,
                detail,
            }
            .into());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| anyhow::anyhow!("模型响应传输中断"))?
        {
            ensure!(bytes.len() + chunk.len() <= limit, "模型响应超过归档上限");
            bytes.extend_from_slice(&chunk);
        }
        let response: Value = serde_json::from_slice(&bytes).context("模型响应不是合法 JSON")?;
        ensure!(
            !serde_json::to_string(&response)?.contains(&self.key),
            "模型响应包含不应归档的凭据，已拒绝保存"
        );
        let usage = &response["usage"];
        Ok(ProbeResult {
            provider_request_id: response["id"].as_str().unwrap_or_default().into(),
            input_tokens: usage["prompt_tokens"].as_u64().unwrap_or(0),
            output_tokens: usage["completion_tokens"].as_u64().unwrap_or(0),
            total_tokens: usage["total_tokens"].as_u64().unwrap_or(0),
            usage_available: usage["prompt_tokens"].is_u64()
                && usage["completion_tokens"].is_u64()
                && usage["total_tokens"].is_u64(),
            response,
        })
    }
}

impl ModelClient for DeepSeek {
    fn complete<'a>(
        &'a self,
        request: &'a ModelRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ModelResponse>> + Send + 'a>> {
        Box::pin(async move {
            ensure!(request.max_tokens != u32::MAX, "模型输出 token 限制无效");
            ensure!(
                (30..=aegis_domain::MAX_MODEL_TIMEOUT_SECONDS).contains(&request.timeout_seconds),
                "模型请求时限无效"
            );
            ensure!(
                ["low", "high", "max", "disabled"].contains(&request.reasoning_effort.as_str()),
                "模型推理强度无效"
            );
            let mut body = json!({
                "model":request.model, "messages":request.messages,
                "response_format":{"type":"json_object"}, "thinking":{"type":"enabled"},
                "reasoning_effort":request.reasoning_effort, "stream":false
            });
            if request.max_tokens > 0 {
                body["max_tokens"] = json!(request.max_tokens);
            }
            if request.reasoning_effort == "disabled" {
                body["thinking"] = json!({"type":"disabled"});
                body.as_object_mut()
                    .expect("request object")
                    .remove("reasoning_effort");
                body["temperature"] = json!(0);
            }
            if self.compatible {
                for key in ["thinking", "reasoning_effort", "response_format"] {
                    body.as_object_mut().unwrap().remove(key);
                }
            }
            let result = self
                .send(&body, 4 * 1024 * 1024, request.timeout_seconds)
                .await?;
            let content = result.response["choices"][0]["message"]["content"]
                .as_str()
                .unwrap_or_default()
                .into();
            let finish_reason = result.response["choices"][0]["finish_reason"]
                .as_str()
                .unwrap_or("unknown")
                .into();
            Ok(ModelResponse {
                content,
                finish_reason,
                result,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, http::StatusCode, routing::post};

    #[test]
    fn custom_endpoints_have_an_explicit_safe_base_url_contract() {
        for url in [
            "file:///secret",
            "http://example.com/v1",
            "https://user:secret@example.com",
            "https://example.com?token=secret",
            "https://example.com/#secret",
            "https://example.com/v1/chat/completions",
        ] {
            assert!(normalize_endpoint(url).is_err(), "{url}");
        }
        assert_eq!(
            normalize_endpoint("https://example.com/v1/").unwrap(),
            "https://example.com/v1"
        );
        assert!(normalize_endpoint("http://127.0.0.1:8080/v1").is_ok());
        assert!(normalize_endpoint("http://[::1]:8080/v1").is_ok());
        assert!(DeepSeek::configured("fixture".into(), "https://example.com", "DEEPSEEK").is_err());
    }

    #[tokio::test]
    async fn compatible_payloads_omit_vendor_fields_and_never_follow_credential_redirects() {
        use axum::http::HeaderMap;
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let reached = Arc::new(AtomicUsize::new(0));
        let counter = reached.clone();
        let app = Router::new()
            .route("/v1/chat/completions", post(|headers: HeaderMap, axum::Json(body): axum::Json<Value>| async move {
                assert_eq!(headers["authorization"], "Bearer compatible-fixture-token");
                for field in ["thinking","reasoning_effort","response_format"] { assert!(body.get(field).is_none()); }
                axum::Json(json!({"choices":[{"message":{"content":"{\"connected\":true}"},"finish_reason":"stop"}],"usage":{"prompt_tokens":2,"completion_tokens":1,"total_tokens":3}}))
            }))
            .route("/redirect/chat/completions", post(move || async move {
                (StatusCode::FOUND, [(axum::http::header::LOCATION, format!("http://{address}/destination"))], "compatible-fixture-token")
            }))
            .route("/destination", post(move || { let counter = counter.clone(); async move { counter.fetch_add(1, Ordering::SeqCst); "unexpected" } }))
            .route("/echo/chat/completions", post(|| async {
                axum::Json(json!({"choices":[{"message":{"content":"compatible-fixture-token"}}]}))
            }));
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = DeepSeek::configured(
            "compatible-fixture-token".into(),
            &format!("http://{address}/v1"),
            "OPENAI_COMPATIBLE",
        )
        .unwrap();
        assert_eq!(client.probe("custom-model").await.unwrap().total_tokens, 3);
        let request = ModelRequest {
            model: "custom-model".into(),
            messages: vec![json!({"role":"user","content":"{}"})],
            max_tokens: 100,
            reasoning_effort: "high".into(),
            timeout_seconds: 30,
        };
        assert_eq!(
            client.complete(&request).await.unwrap().finish_reason,
            "stop"
        );
        for path in ["redirect", "echo"] {
            let client = DeepSeek::configured(
                "compatible-fixture-token".into(),
                &format!("http://{address}/{path}"),
                "OPENAI_COMPATIBLE",
            )
            .unwrap();
            let error = client
                .probe("custom-model")
                .await
                .err()
                .unwrap()
                .to_string();
            assert!(!error.contains("compatible-fixture-token"));
        }
        assert_eq!(reached.load(Ordering::SeqCst), 0);
        server.abort();
    }

    #[tokio::test]
    async fn unlimited_context_and_output_budget_reach_the_provider() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new().route("/chat/completions", post(|axum::Json(body): axum::Json<Value>| async move {
            assert!(body.get("max_tokens").is_none());
            assert_eq!(body["reasoning_effort"], "max");
            assert_eq!(body["thinking"]["type"], "enabled");
            assert!(body.get("timeout_seconds").is_none());
            axum::Json(json!({"id":"budget-test","choices":[{"message":{"content":"{}"},"finish_reason":"stop"}],"usage":{"prompt_tokens":20,"completion_tokens":10,"total_tokens":30}}))
        }));
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let mut client = DeepSeek::new("fixture-private-token".into()).unwrap();
        client.endpoint = format!("http://{address}");
        let mut request = ModelRequest {
            model: DEFAULT_MODEL.into(),
            messages: vec![json!({"role":"user","content":"a".repeat(300 * 1024)})],
            max_tokens: 0,
            reasoning_effort: "max".into(),
            timeout_seconds: 900,
        };
        let response = client.complete(&request).await.unwrap();
        assert_eq!(response.finish_reason, "stop");
        assert_eq!(response.result.total_tokens, 30);
        request.messages = vec![json!({"role":"user","content":"a".repeat(1536 * 1024)})];
        client.complete(&request).await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn usage_is_measured_and_provider_errors_cannot_echo_the_key() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/ok/chat/completions",post(||async { axum::Json(json!({"id":"mock-request","choices":[{"message":{"content":"{\"connected\":true}"}}],"usage":{"prompt_tokens":17,"completion_tokens":6,"total_tokens":23}})) }))
            .route("/bad/chat/completions",post(||async { (StatusCode::UNAUTHORIZED,"Invalid key: fixture-private-token") }));
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let mut client = DeepSeek::new("fixture-private-token".into()).unwrap();
        client.endpoint = format!("http://{address}/ok");
        let result = client.probe(DEFAULT_MODEL).await.unwrap();
        assert!(result.usage_available);
        assert_eq!(result.total_tokens, 23);
        assert_eq!(result.provider_request_id, "mock-request");
        client.endpoint = format!("http://{address}/bad");
        let error = client.probe(DEFAULT_MODEL).await.err().unwrap().to_string();
        assert!(error.contains("401"));
        assert!(!error.contains("fixture-private-token"));
        server.abort();
    }
}
