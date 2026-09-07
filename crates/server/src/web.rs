use crate::{
    error::{AppError, Result},
    rpc::{Api, ExecutorIdentity},
    store::{MAX_UPLOAD, Store},
};
use aegis_domain as d;
use axum::{
    Json, Router,
    body::Body,
    extract::{ConnectInfo, Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use futures::StreamExt;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    net::{IpAddr, SocketAddr},
    path::{Path as FsPath, PathBuf},
    sync::Arc,
};
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;
use tower_http::services::{ServeDir, ServeFile};

#[derive(Clone)]
pub struct WebState {
    pub store: Store,
    pub session: String,
    pub csrf: String,
    pub bootstrap_hash: String,
    pub bind: SocketAddr,
    pub dev_origin: Option<String>,
    pub shutdown: CancellationToken,
}
#[derive(Clone)]
enum Caller {
    Operator,
    Lease {
        work: String,
        attempt: String,
        snapshot: String,
    },
}

pub async fn secret(path: &FsPath) -> Result<String> {
    if path.exists() {
        let value = tokio::fs::read_to_string(path).await?;
        let value = value.trim();
        if value.len() < 32 {
            return Err(AppError::Precondition("本地凭据文件格式无效".into()));
        }
        return Ok(value.into());
    }
    let token = format!("{}.{}", d::id(), d::id());
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    let mut file = options.open(path).await?;
    file.write_all(token.as_bytes()).await?;
    file.sync_all().await?;
    Ok(token)
}

pub async fn create_state(
    root: &FsPath,
    bind: SocketAddr,
    dev_origin: Option<String>,
    shutdown: CancellationToken,
) -> Result<WebState> {
    let store = Store::open(root).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
    }
    let session = secret(&root.join("operator-session.token")).await?;
    let bootstrap = secret(&root.join("executor-bootstrap.token")).await?;
    Ok(WebState {
        store,
        csrf: d::sha256(format!("{session}:csrf").as_bytes()),
        session,
        bootstrap_hash: d::sha256(bootstrap.as_bytes()),
        bind,
        dev_origin,
        shutdown,
    })
}

pub fn router(state: WebState, static_dir: PathBuf) -> Router {
    let api = Arc::new(Api {
        store: state.store.clone(),
        shutdown: state.shutdown.clone(),
    });
    let rpc = crate::rpc::router(api).into_axum_service();
    Router::new()
        .route("/healthz", get(health))
        .route("/api/session", get(session))
        .route("/api/uploads", post(upload))
        .route("/api/artifacts/{id}", get(download))
        .nest_service("/rpc", rpc)
        .fallback_service(
            ServeDir::new(&static_dir)
                .not_found_service(ServeFile::new(static_dir.join("index.html"))),
        )
        .layer(middleware::from_fn_with_state(state.clone(), authorize))
        .with_state(state)
}

fn failure(status: StatusCode, code: &str, message: &str) -> Response {
    (status, Json(json!({"code":code,"message":message}))).into_response()
}
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            Self::Invalid(s) => failure(StatusCode::BAD_REQUEST, "invalid_argument", &s),
            Self::NotFound(s) => failure(StatusCode::NOT_FOUND, "not_found", &s),
            Self::Conflict(s) => failure(StatusCode::CONFLICT, "already_exists", &s),
            Self::Precondition(s) => {
                failure(StatusCode::PRECONDITION_FAILED, "failed_precondition", &s)
            }
            Self::Denied(s) => failure(StatusCode::FORBIDDEN, "permission_denied", &s),
            Self::Internal(error) => {
                tracing::error!(error=?error,"HTTP request failed");
                failure(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    "内部错误；请查看服务端日志",
                )
            }
        }
    }
}
fn header_text<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}
fn host_allowed(state: &WebState, headers: &HeaderMap) -> bool {
    let Ok(authority) = header_text(headers, "host").parse::<axum::http::uri::Authority>() else {
        return false;
    };
    let name = authority.host().trim_matches(['[', ']']);
    name == "localhost"
        || name.parse::<IpAddr>().is_ok_and(|ip| {
            ip.is_loopback() || ip == state.bind.ip() || state.bind.ip().is_unspecified()
        })
}
async fn authorize(State(state): State<WebState>, mut request: Request, next: Next) -> Response {
    if !host_allowed(&state, request.headers()) {
        return failure(
            StatusCode::BAD_REQUEST,
            "invalid_argument",
            "Host 不在允许范围",
        );
    }
    let origin = header_text(request.headers(), "origin");
    let expected = format!("http://{}", header_text(request.headers(), "host"));
    if !origin.is_empty() && origin != expected && state.dev_origin.as_deref() != Some(origin) {
        return failure(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "跨来源请求被拒绝",
        );
    }
    let path = request.uri().path().to_owned();
    if path == "/healthz"
        || path == "/api/session"
        || (!path.starts_with("/api/") && !path.starts_with("/rpc/"))
    {
        return next.run(request).await;
    }
    let authorization = header_text(request.headers(), "authorization").to_owned();
    if path.starts_with("/rpc/audit.v1.ExecutorService/") {
        let Some(token) = authorization.strip_prefix("Bearer ") else {
            return failure(
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
                "需要执行器凭据",
            );
        };
        if path.ends_with("/RegisterExecutor") {
            if d::sha256(token.as_bytes()) != state.bootstrap_hash {
                return failure(
                    StatusCode::FORBIDDEN,
                    "permission_denied",
                    "执行器注册凭据无效",
                );
            }
        } else {
            match state.store.executor_for_token(token).await {
                Ok(Some(id)) => {
                    request.extensions_mut().insert(ExecutorIdentity(id));
                }
                Ok(None) => {
                    return failure(
                        StatusCode::UNAUTHORIZED,
                        "unauthenticated",
                        "执行器凭据无效",
                    );
                }
                Err(error) => return error.into_response(),
            }
        }
        return next.run(request).await;
    }
    if let Some(token) = authorization.strip_prefix("Lease ") {
        if path != "/api/uploads" && !path.starts_with("/api/artifacts/") {
            return failure(
                StatusCode::FORBIDDEN,
                "permission_denied",
                "任务凭据不能访问该接口",
            );
        }
        let work = header_text(request.headers(), "x-aegis-work-id").to_owned();
        let attempt = header_text(request.headers(), "x-aegis-attempt-id").to_owned();
        match state.store.authorize_lease(&work, &attempt, token).await {
            Ok(snapshot) => {
                request.extensions_mut().insert(Caller::Lease {
                    work,
                    attempt,
                    snapshot,
                });
            }
            Err(error) => return error.into_response(),
        }
        return next.run(request).await;
    }
    let cookie = header_text(request.headers(), "cookie");
    if !cookie
        .split(';')
        .any(|v| v.trim().strip_prefix("aegis_session=") == Some(state.session.as_str()))
    {
        return failure(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "本机会话尚未建立，请刷新页面",
        );
    }
    if request.method() != Method::GET
        && request.method() != Method::HEAD
        && header_text(request.headers(), "x-aegis-csrf") != state.csrf
    {
        return failure(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "会话校验失败，请刷新页面",
        );
    }
    request.extensions_mut().insert(Caller::Operator);
    next.run(request).await
}
async fn session(
    State(state): State<WebState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if !peer.ip().is_loopback() || header_text(&headers, "sec-fetch-site") == "cross-site" {
        return failure(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "操作员会话只允许在控制主机本地建立",
        );
    }
    let mut response =
        Json(json!({"csrf_token":state.csrf,"version":env!("CARGO_PKG_VERSION"),"scope":d::SCOPE}))
            .into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "aegis_session={}; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400",
            state.session
        ))
        .expect("generated ASCII cookie"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
async fn health(State(state): State<WebState>) -> Response {
    match sqlx::query_scalar::<_, i64>("SELECT 1")
        .fetch_one(&state.store.pool)
        .await
    {
        Ok(_) => Json(json!({"ok":true,"version":env!("CARGO_PKG_VERSION")})).into_response(),
        Err(_) => failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "数据库不可用",
        ),
    }
}
#[derive(Deserialize)]
struct UploadQuery {
    name: String,
    #[serde(default = "default_media")]
    media_type: String,
}
fn default_media() -> String {
    "application/octet-stream".into()
}
async fn upload(
    State(state): State<WebState>,
    Query(query): Query<UploadQuery>,
    request: Request,
) -> Result<Response> {
    let name = crate::store::valid_text(&query.name, 240, "产物名称")?;
    if name.contains(['/', '\\']) {
        return Err(AppError::Invalid("产物名称不能包含路径".into()));
    }
    let mime = if query.media_type.len() <= 100 && HeaderValue::from_str(&query.media_type).is_ok()
    {
        query.media_type
    } else {
        default_media()
    };
    let caller = request
        .extensions()
        .get::<Caller>()
        .cloned()
        .ok_or_else(|| AppError::Denied("缺少上传身份".into()))?;
    let lease_token = header_text(request.headers(), "authorization")
        .strip_prefix("Lease ")
        .unwrap_or("")
        .to_owned();
    let file = tempfile::NamedTempFile::new_in(state.store.root.join("tmp"))?;
    let (file, path) = file.into_parts();
    let mut output = tokio::fs::File::from_std(file);
    let mut stream = request.into_body().into_data_stream();
    let mut size = 0u64;
    let mut digest = Sha256::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| AppError::Invalid(format!("上传流中断：{e}")))?;
        size += chunk.len() as u64;
        if size > MAX_UPLOAD {
            return Ok(failure(
                StatusCode::PAYLOAD_TOO_LARGE,
                "resource_exhausted",
                "文件超过 512 MiB 上传上限",
            ));
        }
        digest.update(&chunk);
        output.write_all(&chunk).await?;
    }
    if size == 0 {
        return Err(AppError::Invalid("不能上传空文件".into()));
    }
    output.flush().await?;
    output.sync_all().await?;
    drop(output);
    let artifact = d::Artifact {
        id: d::id(),
        sha256: hex::encode(digest.finalize()),
        size,
        name,
        media_type: mime,
    };
    let destination = state.store.blob_path(&artifact.sha256);
    tokio::fs::create_dir_all(destination.parent().expect("blob parent")).await?;
    if !destination.exists() {
        tokio::fs::rename(&path, &destination).await?;
    }
    let _guard = state.store.writes.lock().await;
    let mut tx = state.store.pool.begin().await?;
    if let Caller::Lease { work, attempt, .. } = &caller {
        Store::authorize_lease_on(&mut tx, work, attempt, &lease_token).await?;
    }
    match caller {
        Caller::Operator => Store::insert_artifact(&mut tx, &artifact, None, None, None).await?,
        Caller::Lease {
            work,
            attempt,
            snapshot,
        } => {
            Store::insert_artifact(
                &mut tx,
                &artifact,
                Some(&snapshot),
                Some(&work),
                Some(&attempt),
            )
            .await?
        }
    }
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(artifact)).into_response())
}
async fn download(
    State(state): State<WebState>,
    Path(id): Path<String>,
    request: Request,
) -> Result<Response> {
    if let Some(Caller::Lease { work, attempt, .. }) = request.extensions().get::<Caller>()
        && !state
            .store
            .artifact_allowed_for_work(&id, work, attempt)
            .await?
    {
        return Err(AppError::Denied("产物不在该任务的可读范围".into()));
    }
    let artifact: d::Artifact = state.store.get("artifacts", &id).await?;
    let response = ServeFile::new(state.store.blob_path(&artifact.sha256))
        .oneshot(request)
        .await
        .expect("infallible file service");
    let mut response = response.map(Body::new);
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&artifact.media_type)
            .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
    );
    let filename: String = artifact
        .name
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-_.".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename*=UTF-8''{filename}"))
            .expect("encoded filename"),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response.headers_mut().insert(
        "x-aegis-sha256",
        HeaderValue::from_str(&artifact.sha256).expect("SHA-256 hex"),
    );
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("sandbox"),
    );
    Ok(response)
}
