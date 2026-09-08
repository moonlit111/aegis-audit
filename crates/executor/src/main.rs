mod client;
mod jobs;
mod runtime;

use aegis_protocol as p;
use anyhow::{Context, Result, ensure};
use clap::Parser;
use client::Control;
use jobs::{JobContext, Tools};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{process::Command, sync::mpsc};
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(
    version,
    about = "AegisAudit executor — program analysis and isolated local verification"
)]
struct Options {
    #[arg(long, default_value = "http://127.0.0.1:7331")]
    server: String,
    #[arg(long, default_value = ".data/executor")]
    work_dir: PathBuf,
    #[arg(long, default_value = ".data/server/executor-bootstrap.token")]
    bootstrap_file: PathBuf,
    #[arg(long, default_value = "local-executor")]
    name: String,
    #[arg(long, env = "GHIDRA_HOME")]
    ghidra_home: Option<PathBuf>,
    #[arg(long, default_value = "tools/ghidra")]
    script_dir: PathBuf,
    #[arg(long)]
    doctor: bool,
    #[arg(long)]
    once: bool,
    #[arg(long, default_value_t = 1000)]
    poll_interval_ms: u64,
}
#[derive(Serialize, Deserialize)]
struct Identity {
    server: String,
    executor_id: String,
    token: String,
}
#[derive(Serialize, Deserialize)]
struct Active {
    lease: p::WorkLease,
    completion: Option<p::CompleteWorkRequest>,
}

fn private_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    use std::io::Write;
    let mut file = tempfile::NamedTempFile::new_in(path.parent().context("missing parent")?)?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    file.as_file().sync_all()?;
    file.persist(path)?;
    Ok(())
}
fn absolute(path: &Path) -> PathBuf {
    let path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_owned());
    #[cfg(windows)]
    {
        if let Some(text) = path.to_str().and_then(|s| s.strip_prefix(r"\\?\")) {
            return PathBuf::from(text);
        }
    }
    path
}
async fn version(program: &str, arg: &str) -> Option<String> {
    let output = tokio::time::timeout(
        Duration::from_secs(5),
        Command::new(program)
            .arg(arg)
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    if !output.status.success() {
        return None;
    }
    let bytes = if output.stdout.is_empty() {
        output.stderr
    } else {
        output.stdout
    };
    Some(
        String::from_utf8_lossy(&bytes)
            .lines()
            .take(2)
            .collect::<Vec<_>>()
            .join(" "),
    )
}
async fn capabilities(options: &Options) -> (Tools, Vec<p::ToolCapability>) {
    let git = version("git", "--version").await;
    let java = version("java", "-version").await;
    let java_ok = java.as_deref().is_some_and(|s| {
        s.split('"')
            .nth(1)
            .and_then(|n| n.split('.').next())
            .and_then(|n| n.parse::<u32>().ok())
            .is_some_and(|v| v >= 21)
    });
    let platform = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "mac_arm_64",
        ("macos", _) => "mac_x86_64",
        ("windows", _) => "win_x86_64",
        ("linux", "aarch64") => "linux_arm_64",
        _ => "linux_x86_64",
    };
    let mut ghidra = None;
    let mut ghidra_detail = "未配置 Ghidra；二进制任务将等待执行器".to_owned();
    if let Some(home) = &options.ghidra_home {
        let home = absolute(home);
        let native_name = if cfg!(windows) {
            "decompile.exe"
        } else {
            "decompile"
        };
        let native = [
            home.join(format!(
                "Ghidra/Features/Decompiler/build/os/{platform}/{native_name}"
            )),
            home.join(format!(
                "Ghidra/Features/Decompiler/os/{platform}/{native_name}"
            )),
        ]
        .into_iter()
        .find(|p| p.is_file());
        let script = options.script_dir.join("ExportProgram.java").is_file();
        let native_ok = if let Some(native) = native {
            tokio::time::timeout(
                Duration::from_secs(5),
                Command::new(native)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .kill_on_drop(true)
                    .status(),
            )
            .await
            .is_ok_and(|r| r.is_ok())
        } else {
            false
        };
        let properties =
            std::fs::read_to_string(home.join("Ghidra/application.properties")).unwrap_or_default();
        let pinned = properties
            .lines()
            .any(|line| line.trim() == "application.version=12.1.3");
        if java_ok && native_ok && script && pinned {
            ghidra_detail = "原生反编译器可启动；支持 PE x86/x64、ELF x86_64 静态分析".into();
            ghidra = Some(home);
        } else {
            ghidra_detail = format!(
                "JDK 21+：{java_ok}；平台原生组件：{native_ok}；导出脚本：{script}；版本 12.1.3：{pinned}"
            );
        }
    }
    let runtime_image = aegis_application::runtime::image_id().await;
    let tools = Tools {
        ghidra: ghidra.clone(),
        script_dir: absolute(&options.script_dir),
        git: git.is_some(),
        runtime_image: runtime_image.clone(),
    };
    let mut caps = vec![
        p::ToolCapability {
            name: "import".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            available: true,
            detail: "文件哈希、ZIP 边界检查及 PE/ELF 元数据".into(),
            ..Default::default()
        },
        p::ToolCapability {
            name: "tree-sitter".into(),
            version: "0.25.10".into(),
            available: true,
            detail: "Python / Go / C / C++；直接调用线索为推断，保留解析缺口".into(),
            ..Default::default()
        },
        p::ToolCapability {
            name: "git".into(),
            version: git.clone().unwrap_or_default(),
            available: git.is_some(),
            detail: "HTTPS 仓库指定版本导入；禁用 hooks、凭据助手和递归子模块".into(),
            ..Default::default()
        },
        p::ToolCapability {
            name: "ghidra".into(),
            version: if ghidra.is_some() { "12.1.3" } else { "" }.into(),
            available: ghidra.is_some(),
            detail: ghidra_detail,
            ..Default::default()
        },
    ];
    for name in ["linux-runtime", "semgrep", "upx", "afl++"] {
        caps.push(p::ToolCapability {
            name: name.into(),
            version: runtime_image.clone().unwrap_or_default(),
            available: runtime_image.is_some(),
            detail: if runtime_image.is_some() {
                "固定 Linux amd64 容器镜像；网络关闭、目标只读挂载，执行后确认容器回收"
            } else {
                "需要 Docker 和 aegis-runtime:0.2.0 镜像；运行 python3 scripts/manage.py runtime"
            }
            .into(),
            ..Default::default()
        });
    }
    (tools, caps)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aegis_executor=info".into()),
        )
        .init();
    let options = Options::parse();
    let (tools, caps) = capabilities(&options).await;
    if options.doctor {
        println!("{}", serde_json::to_string_pretty(&caps)?);
        return Ok(());
    }
    tokio::fs::create_dir_all(&options.work_dir).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&options.work_dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let identity_path = options.work_dir.join("identity.json");
    let active_path = options.work_dir.join("active.json");
    let identity = if identity_path.is_file() {
        let identity: Identity = serde_json::from_slice(&tokio::fs::read(&identity_path).await?)?;
        ensure!(
            identity.server == options.server,
            "工作目录已绑定另一个控制服务，请使用独立工作目录"
        );
        identity
    } else {
        let token = tokio::fs::read_to_string(&options.bootstrap_file)
            .await
            .context("read executor bootstrap credential; run the server first")?;
        let control = Control::new(&options.server, token.trim(), String::new())?;
        let response = control
            .rpc
            .register_executor(p::RegisterExecutorRequest {
                name: options.name.clone(),
                platform: std::env::consts::OS.into(),
                architecture: std::env::consts::ARCH.into(),
                capabilities: caps.clone(),
                ..Default::default()
            })
            .await?
            .into_owned();
        ensure!(
            !response.executor.id.is_empty() && !response.executor_token.is_empty(),
            "invalid executor registration response"
        );
        let identity = Identity {
            server: options.server.clone(),
            executor_id: response.executor.id.clone(),
            token: response.executor_token,
        };
        private_json(&identity_path, &identity)?;
        identity
    };
    let control = Control::new(&options.server, &identity.token, identity.executor_id)?;
    control
        .rpc
        .heartbeat(p::HeartbeatRequest {
            executor_id: control.executor_id.clone(),
            capabilities: caps,
            ..Default::default()
        })
        .await?;
    if active_path.is_file() {
        let active: Active = serde_json::from_slice(&tokio::fs::read(&active_path).await?)?;
        let completion = active.completion.filter(|c| c.processes_reaped).context(
            "旧任务没有进程回收确认，执行器拒绝领取新任务；请先核实旧工具进程或重置测试环境",
        )?;
        control.complete(completion).await?;
        tokio::fs::remove_file(&active_path).await?;
    }
    let shutdown = CancellationToken::new();
    let signal = shutdown.clone();
    tokio::spawn(async move {
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
        signal.cancel();
    });
    tracing::info!(executor_id=%control.executor_id,"executor connected");
    loop {
        if shutdown.is_cancelled() {
            break;
        }
        let response = match control
            .rpc
            .claim_work(p::ClaimWorkRequest {
                executor_id: control.executor_id.clone(),
                ..Default::default()
            })
            .await
        {
            Ok(response) => response.into_owned(),
            Err(error) => {
                tracing::warn!(error=%error,"control connection unavailable");
                tokio::select! {_=tokio::time::sleep(Duration::from_secs(2))=>{},_=shutdown.cancelled()=>break}
                continue;
            }
        };
        if response.lease.work_item_id.is_empty() {
            tokio::select! {_=tokio::time::sleep(Duration::from_millis(options.poll_interval_ms.max(100)))=>{},_=shutdown.cancelled()=>break}
            continue;
        }
        let lease = (*response.lease).clone();
        let temp = tempfile::Builder::new()
            .prefix("work-")
            .tempdir_in(&options.work_dir)?;
        private_json(
            &active_path,
            &Active {
                lease: lease.clone(),
                completion: None,
            },
        )?;
        tracing::info!(work_item_id=%lease.work_item_id,kind=%lease.kind,"work started");
        let cancel = shutdown.child_token();
        let done = CancellationToken::new();
        let reaped = Arc::new(AtomicBool::new(true));
        let heartbeat_control = control.clone();
        let heartbeat_lease = lease.clone();
        let heartbeat_cancel = cancel.clone();
        let heartbeat_done = done.clone();
        let heartbeat = tokio::spawn(async move {
            let mut last_success = Instant::now();
            loop {
                tokio::select! {_=heartbeat_done.cancelled()=>break,_=tokio::time::sleep(Duration::from_secs(2))=>{}}
                match heartbeat_control.heartbeat(Some(&heartbeat_lease)).await {
                    Ok(response) => {
                        last_success = Instant::now();
                        if response.cancel_requested || !response.lease_valid {
                            heartbeat_cancel.cancel();
                        }
                    }
                    Err(error) => {
                        tracing::warn!(error=%error,"heartbeat failed");
                        if last_success.elapsed() > Duration::from_secs(15) {
                            heartbeat_cancel.cancel();
                        }
                    }
                }
            }
        });
        let (sender, mut receiver) = mpsc::channel::<(String, u64, u64)>(128);
        let progress_control = control.clone();
        let progress_lease = lease.clone();
        let mut reporter = tokio::spawn(async move {
            while let Some((message, current, total)) = receiver.recv().await {
                let _ = progress_control
                    .rpc
                    .report_progress(p::ReportProgressRequest {
                        work_item_id: progress_lease.work_item_id.clone(),
                        attempt_id: progress_lease.attempt_id.clone(),
                        lease_token: progress_lease.lease_token.clone(),
                        message: message.chars().take(8192).collect(),
                        current,
                        total,
                        ..Default::default()
                    })
                    .await;
            }
        });
        let context = JobContext {
            control: control.clone(),
            lease: lease.clone(),
            cancel: cancel.clone(),
            tools: tools.clone(),
            progress: sender,
            reaped: reaped.clone(),
        };
        let work_path = absolute(temp.path());
        let execution = jobs::execute(context, &work_path);
        tokio::pin!(execution);
        let mut deadline_reached = false;
        let outcome = tokio::select! {result=&mut execution=>result,_=tokio::time::sleep(Duration::from_secs(lease.timeout_seconds as u64))=>{deadline_reached=true;cancel.cancel();execution.await}};
        if tokio::time::timeout(Duration::from_secs(5), &mut reporter)
            .await
            .is_err()
        {
            reporter.abort();
            let _ = reporter.await;
        }
        let (status, result, error) = if deadline_reached {
            (
                "LIMIT_REACHED",
                String::new(),
                "任务超过整体执行时限，工具进程已请求回收".into(),
            )
        } else {
            match outcome {
                Ok(id) => ("COMPLETED", id, String::new()),
                Err(error) => {
                    let text = format!("{error:#}");
                    tracing::warn!(work_item_id=%lease.work_item_id,error=%text,"work failed");
                    (
                        if text.contains("timed out") {
                            "LIMIT_REACHED"
                        } else if cancel.is_cancelled() {
                            "CANCELLED"
                        } else {
                            "FAILED"
                        },
                        String::new(),
                        text,
                    )
                }
            }
        };
        let completion = p::CompleteWorkRequest {
            work_item_id: lease.work_item_id.clone(),
            attempt_id: lease.attempt_id.clone(),
            lease_token: lease.lease_token.clone(),
            outcome: status.into(),
            result_artifact_id: result,
            error,
            processes_reaped: reaped.load(Ordering::SeqCst),
            ..Default::default()
        };
        private_json(
            &active_path,
            &Active {
                lease,
                completion: Some(completion.clone()),
            },
        )?;
        let result = control.complete(completion.clone()).await;
        done.cancel();
        let _ = heartbeat.await;
        match result {
            Ok(accepted) => {
                tracing::info!(accepted, outcome = status, "work completion recorded");
                ensure!(
                    completion.processes_reaped,
                    "工具进程回收未确认，执行器停止领取任务"
                );
                tokio::fs::remove_file(&active_path).await?;
            }
            Err(error) => return Err(error.context("结果已保存在本地；重启执行器后将幂等重报")),
        }
        if options.once {
            break;
        }
    }
    Ok(())
}
