//! DeepSeek official transport. Secrets are never part of saved request/response records.
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::time::Duration;

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

impl DeepSeek {
    pub fn new(key: String) -> Result<Self> {
        ensure!(!key.trim().is_empty(), "DeepSeek 密钥尚未配置");
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
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
        let mut response = self
            .client
            .post(format!("{}/chat/completions", self.endpoint))
            .bearer_auth(&self.key)
            .json(&body)
            .send()
            .await
            .map_err(|error| {
                anyhow::anyhow!(if error.is_timeout() {
                    "DeepSeek 连接检查超时"
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
            bail!("DeepSeek 官方接口返回 HTTP {status}：{detail}");
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| anyhow::anyhow!("DeepSeek 响应传输中断"))?
        {
            ensure!(
                bytes.len() + chunk.len() <= 64 * 1024,
                "连接检查响应超过 64 KiB 上限"
            );
            bytes.extend_from_slice(&chunk);
        }
        let response: Value =
            serde_json::from_slice(&bytes).context("DeepSeek 响应不是合法 JSON")?;
        ensure!(
            !serde_json::to_string(&response)?.contains(&self.key),
            "DeepSeek 响应包含不应归档的凭据，已拒绝保存"
        );
        let content = response["choices"][0]["message"]["content"]
            .as_str()
            .context("DeepSeek 未返回消息内容")?;
        let answer: Value = serde_json::from_str(content).context("DeepSeek 结构化响应校验失败")?;
        ensure!(
            answer["connected"] == true,
            "DeepSeek 连接检查结果不符合约定"
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, http::StatusCode, routing::post};

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
