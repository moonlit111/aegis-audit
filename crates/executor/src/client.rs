use aegis_domain as d;
use aegis_protocol as p;
use anyhow::{Context, Result, ensure};
use connectrpc::client::{ClientConfig, HttpClient};
use futures::StreamExt;
use std::{path::Path, sync::Arc, time::Duration};
use tokio::io::AsyncWriteExt;
use tokio_util::{io::ReaderStream, sync::CancellationToken};

#[derive(Clone)]
pub struct Control {
    pub base: String,
    pub rpc: Arc<p::ExecutorServiceClient<HttpClient>>,
    pub http: reqwest::Client,
    pub executor_id: String,
}

impl Control {
    pub fn new(base: &str, token: &str, executor_id: String) -> Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let base = base.trim_end_matches('/').to_owned();
        let transport = if base.starts_with("https://") {
            let roots = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            let tls = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            HttpClient::with_tls(Arc::new(tls))
        } else {
            HttpClient::plaintext()
        };
        let config = ClientConfig::new(format!("{base}/rpc").parse()?)
            .with_default_header("authorization", format!("Bearer {token}"))
            .with_default_timeout(Duration::from_secs(15));
        let rpc = Arc::new(p::ExecutorServiceClient::new(transport, config));
        let http = reqwest::Client::builder()
            .no_proxy()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(300))
            .build()?;
        Ok(Self {
            base,
            rpc,
            http,
            executor_id,
        })
    }
    fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        lease: &p::WorkLease,
    ) -> reqwest::RequestBuilder {
        self.http
            .request(method, format!("{}{path}", self.base))
            .header("authorization", format!("Lease {}", lease.lease_token))
            .header("x-aegis-work-id", &lease.work_item_id)
            .header("x-aegis-attempt-id", &lease.attempt_id)
    }
    pub async fn download(
        &self,
        lease: &p::WorkLease,
        id: &str,
        path: &Path,
        cancel: &CancellationToken,
    ) -> Result<()> {
        let response = self
            .request(reqwest::Method::GET, &format!("/api/artifacts/{id}"), lease)
            .send()
            .await?
            .error_for_status()?;
        let expected = response
            .headers()
            .get("x-aegis-sha256")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let mut stream = response.bytes_stream();
        let mut output = tokio::fs::File::create(path).await?;
        let mut total = 0u64;
        loop {
            let next = tokio::select! {_=cancel.cancelled()=>anyhow::bail!("job cancelled"),next=stream.next()=>next};
            let Some(chunk) = next else {
                break;
            };
            let chunk = chunk?;
            total += chunk.len() as u64;
            ensure!(total <= 512 * 1024 * 1024, "download exceeded size limit");
            output.write_all(&chunk).await?;
        }
        output.flush().await?;
        drop(output);
        if !expected.is_empty() {
            ensure!(
                d::sha256(&tokio::fs::read(path).await?) == expected,
                "artifact download hash mismatch"
            );
        }
        Ok(())
    }
    pub async fn upload_file(
        &self,
        lease: &p::WorkLease,
        path: &Path,
        name: &str,
        mime: &str,
    ) -> Result<d::Artifact> {
        let file = tokio::fs::File::open(path).await?;
        let size = file.metadata().await?.len();
        let response = self
            .request(reqwest::Method::POST, "/api/uploads", lease)
            .query(&[("name", name), ("media_type", mime)])
            .header("content-length", size)
            .body(reqwest::Body::wrap_stream(ReaderStream::new(file)))
            .send()
            .await?;
        ensure!(
            response.status().is_success(),
            "artifact upload failed: {}",
            response.status()
        );
        Ok(response.json().await?)
    }
    pub async fn upload_bytes(
        &self,
        lease: &p::WorkLease,
        name: &str,
        mime: &str,
        bytes: Vec<u8>,
    ) -> Result<d::Artifact> {
        let response = self
            .request(reqwest::Method::POST, "/api/uploads", lease)
            .query(&[("name", name), ("media_type", mime)])
            .body(bytes)
            .send()
            .await?;
        ensure!(
            response.status().is_success(),
            "artifact upload failed: {}",
            response.status()
        );
        Ok(response.json().await?)
    }
    pub async fn heartbeat(&self, lease: Option<&p::WorkLease>) -> Result<p::HeartbeatResponse> {
        let mut request = p::HeartbeatRequest {
            executor_id: self.executor_id.clone(),
            ..Default::default()
        };
        if let Some(lease) = lease {
            request.work_item_id = lease.work_item_id.clone();
            request.attempt_id = lease.attempt_id.clone();
            request.lease_token = lease.lease_token.clone();
        }
        Ok(self.rpc.heartbeat(request).await?.into_owned())
    }
    pub async fn complete(&self, request: p::CompleteWorkRequest) -> Result<bool> {
        Ok(self
            .rpc
            .complete_work(request)
            .await
            .context("report work completion")?
            .into_owned()
            .accepted)
    }
}
