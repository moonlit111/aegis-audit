//! DeepSeek official transport. Secrets are never part of saved request/response records.
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
        write!(
            f,
            "DeepSeek 官方接口返回 HTTP {}：{}",
            self.status, self.detail
        )
    }
}
impl std::error::Error for ProviderFailure {}

impl DeepSeek {
    pub fn new(key: String) -> Result<Self> {
        ensure!(!key.trim().is_empty(), "DeepSeek 密钥尚未配置");
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            client,
            key,
            endpoint: ENDPOINT.into(),
        })
    }

    pub async fn probe(&self, model: &str) -> Result<ProbeResult> {
        let body = json!({
            "model":model,
            "messages":[{"role":"user","content":"Connection check. Return exactly this JSON object: {\"connected\":true}"}],
            "response_format":{"type":"json_object"},
            "thinking":{"type":"disabled"},
            "max_tokens":128,
            "temperature":0,
            "stream":false
        });
        let result = self.send(&body, 64 * 1024, 300).await?;
        let content = result.response["choices"][0]["message"]["content"]
            .as_str()
            .context("DeepSeek 未返回消息内容")?;
        let answer: Value = serde_json::from_str(content).context("DeepSeek 结构化响应校验失败")?;
        ensure!(
            answer["connected"] == true,
            "DeepSeek 连接检查结果不符合约定"
        );
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
                    "DeepSeek 请求超时；用量未知"
                } else {
                    "DeepSeek 网络连接失败"
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
            .map_err(|_| anyhow::anyhow!("DeepSeek 响应传输中断"))?
        {
            ensure!(
                bytes.len() + chunk.len() <= limit,
                "DeepSeek 响应超过归档上限"
            );
            bytes.extend_from_slice(&chunk);
        }
        let response: Value =
            serde_json::from_slice(&bytes).context("DeepSeek 响应不是合法 JSON")?;
        ensure!(
            !serde_json::to_string(&response)?.contains(&self.key),
            "DeepSeek 响应包含不应归档的凭据，已拒绝保存"
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
