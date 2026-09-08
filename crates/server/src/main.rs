use aegis_server::web;
use clap::Parser;
use std::{net::SocketAddr, path::PathBuf, time::Duration};
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(
    version,
    about = "AegisAudit control service — structure analysis edition"
)]
struct Options {
    #[arg(long, default_value = "127.0.0.1:7331")]
    bind: SocketAddr,
    #[arg(long, default_value = ".data/server")]
    data_dir: PathBuf,
    #[arg(long, default_value = "frontend/dist")]
    static_dir: PathBuf,
    #[arg(long)]
    dev_origin: Option<String>,
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aegis_server=info,tower_http=info".into()),
        )
        .init();
    let options = Options::parse();
    let shutdown = CancellationToken::new();
    let listener = tokio::net::TcpListener::bind(options.bind).await?;
    let address = listener.local_addr()?;
    let state = web::create_state(
        &options.data_dir,
        address,
        options.dev_origin,
        shutdown.clone(),
    )
    .await?;
    state.store.recover_model_probes().await?;
    state.store.recover_audits().await?;
    let audit_worker = state.store.spawn_audit_worker(shutdown.clone());
    let reaper = state.store.clone();
    let reaper_stop = shutdown.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {_=reaper_stop.cancelled()=>break,_=tokio::time::sleep(Duration::from_secs(3))=>{if let Err(error)=reaper.expire_leases().await{tracing::error!(error=?error,"lease sweep failed");}}}
        }
    });
    let app = web::router(state, options.static_dir);
    tracing::info!(%address,"AegisAudit is ready; bootstrap credential remains in the data directory");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        #[cfg(unix)]
        {
            let mut terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("signal handler");
            tokio::select! {_=tokio::signal::ctrl_c()=>{},_=terminate.recv()=>{}}
        }
        #[cfg(windows)]
        {
            let mut stop = tokio::signal::windows::ctrl_break().expect("break handler");
            tokio::select! {_=tokio::signal::ctrl_c()=>{},_=stop.recv()=>{}}
        }
        shutdown.cancel();
    })
    .await?;
    audit_worker.await?;
    Ok(())
}
