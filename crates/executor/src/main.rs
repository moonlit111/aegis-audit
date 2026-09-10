mod client;
mod jobs;
mod runtime;

#[cfg(test)]
mod native_sast_tests;

use aegis_protocol as p;
use anyhow::{Context, Result, ensure};
use clap::Parser;
use client::Control;
use jobs::{JobContext, Tools};
use serde::{Deserialize, Serialize};
use serde_json::json;
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
    about = "AegisAudit executor — program analysis and host-local verification"
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
    #[arg(long, env = "AEGIS_PYTHON_HOME")]
    python_home: Option<PathBuf>,
    #[arg(long, default_value = "tools/runtime/rules.yml")]
    semgrep_rules: PathBuf,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    process_job: Option<aegis_application::windows_job::DesktopJob>,
}

fn recoverable_owner(active: &Active) -> Result<&aegis_application::windows_job::DesktopJob> {
    ensure!(
        ["IMPORT", "ANALYZE"].contains(&active.lease.kind.as_str()),
        "旧动态任务没有宿主机回收确认，拒绝自动恢复"
    );
    active
        .process_job
        .as_ref()
        .context("旧任务没有进程回收确认，执行器拒绝领取新任务；请先核实旧工具进程或重置测试环境")
}

async fn runtime_recovery_completion(
    active: &mut Active,
    control: &Control,
) -> Result<p::CompleteWorkRequest> {
    let recovery = json!({
        "kind": "WINDOWS_HOST_RECOVERY",
        "observed_at": aegis_domain::now(),
        "work_item_id": active.lease.work_item_id,
        "attempt_id": active.lease.attempt_id,
        "processes_reaped": true,
        "outcome": "FAILED",
        "task_reexecuted": false,
    });
    let mut result = String::new();
    if control.heartbeat(Some(&active.lease)).await?.lease_valid {
        result = control
            .upload_bytes(
                &active.lease,
                "windows-host-recovery.json",
                "application/json",
                serde_json::to_vec_pretty(&recovery)?,
            )
            .await?
            .id;
    }
    Ok(p::CompleteWorkRequest {
        work_item_id: active.lease.work_item_id.clone(),
        attempt_id: active.lease.attempt_id.clone(),
        lease_token: active.lease.lease_token.clone(),
        outcome: "FAILED".into(),
        result_artifact_id: result,
        processes_reaped: true,
        error: "执行器在 RUNTIME 期间异常退出；宿主机 Job Object 已随进程退出回收，未完成任务未计为成功，请重新运行".into(),
        ..Default::default()
    })
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
    let platform = "win_x86_64";
    let mut ghidra = None;
    let mut ghidra_detail = "未配置 Ghidra；二进制任务将等待执行器".to_owned();
    if let Some(home) = &options.ghidra_home {
        let home = absolute(home);
        let native_name = "decompile.exe";
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
    let semgrep = if let Some(home) = &options.python_home {
        aegis_application::sast::Semgrep::discover(
            &absolute(home),
            &absolute(&options.semgrep_rules),
        )
        .await
    } else {
        None
    };
    let tools = Tools {
        ghidra: ghidra.clone(),
        script_dir: absolute(&options.script_dir),
        git: git.is_some(),
        semgrep: semgrep.clone(),
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
        p::ToolCapability {
            name: "semgrep".into(),
            version: if semgrep.is_some() {
                aegis_application::sast::SEMGREP_VERSION
            } else {
                ""
            }
            .into(),
            available: semgrep.is_some(),
            detail: if semgrep.is_some() {
                "Windows 原生静态规则扫描；不执行目标代码，不需要 Docker/WSL；规则命中仅为审计线索"
            } else {
                "需要项目私有 Windows Python 与 Semgrep 1.176.1；运行 py -3 scripts/bootstrap.py"
            }
            .into(),
            ..Default::default()
        },
    ];
    let root = absolute(&options.script_dir)
        .parent()
        .and_then(Path::parent)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let python_program = root.join(".tools/windows-python/python.exe");
    let zig_program = root.join(".tools/zig/zig.exe");
    let python_version = if python_program.is_file() {
        runtime::command_text(&python_program, &["--version"])
            .await
            .ok()
    } else {
        None
    };
    let zig_version = if zig_program.is_file() {
        runtime::command_text(&zig_program, &["version"]).await.ok()
    } else {
        None
    };
    let python_runtime = python_version
        .as_deref()
        .is_some_and(|version| runtime::tool_version_matches(version, "3.13.13"));
    let zig_runtime = zig_version
        .as_deref()
        .is_some_and(|version| runtime::tool_version_matches(version, "0.15.2"));
    let windows_host = python_runtime && zig_runtime;
    caps.push(p::ToolCapability {
        name: "windows-host".into(),
        version: "1".into(),
        available: windows_host,
        detail: format!(
            "VERIFY：Windows 宿主机 x64；Job Object 负责超时和进程树回收；Python={}，Zig={}，原始 PE 支持",
            python_runtime, zig_runtime
        ),
        ..Default::default()
    });
    let upx = aegis_application::protection::adapter_by_name("upx")
        .and_then(aegis_application::protection::locate_tool);
    caps.push(p::ToolCapability {
        name: "upx".into(),
        version: if upx.is_some() { "5.2.1" } else { "" }.into(),
        available: upx.is_some(),
        detail: if upx.is_some() {
            "固定 UPX 5.2.1；仅处理允许清单内的自制/支持样本，不执行目标"
        } else {
            "运行 py -3 tools/windows/install-upx.py 安装固定 UPX 5.2.1"
        }
        .into(),
        ..Default::default()
    });
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
    let desktop_job = aegis_application::windows_job::current_desktop_job()?;
    let (tools, caps) = capabilities(&options).await;
    if options.doctor {
        println!("{}", serde_json::to_string_pretty(&caps)?);
        return Ok(());
    }
    tokio::fs::create_dir_all(&options.work_dir).await?;
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
        let mut active: Active = serde_json::from_slice(&tokio::fs::read(&active_path).await?)?;
        let completion = if let Some(completion) =
            active.completion.clone().filter(|c| c.processes_reaped)
        {
            completion
        } else if active.lease.kind == "RUNTIME" {
            runtime_recovery_completion(&mut active, &control).await?
        } else {
            let owner = recoverable_owner(&active)?;
            let mut proof = None;
            for _ in 0..50 {
                proof = aegis_application::windows_job::reaping_proof(owner)?;
                if proof.is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            let proof = proof.context("旧 Windows Job Object 仍有进程，拒绝自动恢复")?;
            let recovery = serde_json::json!({
                "kind":"WINDOWS_STATIC_WORK_RECOVERY", "observed_at": aegis_domain::now(),
                "work_item_id":active.lease.work_item_id,"attempt_id":active.lease.attempt_id,
                "proof":proof,"outcome":"FAILED","task_reexecuted":false,
                "same_windows_machine_verified":true,
            });
            private_json(
                &options
                    .work_dir
                    .join(format!("recovery-{}.json", aegis_domain::id())),
                &recovery,
            )?;
            let mut result = String::new();
            if control.heartbeat(Some(&active.lease)).await?.lease_valid {
                result = control
                    .upload_bytes(
                        &active.lease,
                        "windows-recovery.json",
                        "application/json",
                        serde_json::to_vec_pretty(&recovery)?,
                    )
                    .await?
                    .id;
            }
            let completion = p::CompleteWorkRequest {
                work_item_id: active.lease.work_item_id.clone(), attempt_id: active.lease.attempt_id.clone(),
                lease_token: active.lease.lease_token.clone(), outcome: "FAILED".into(),
                result_artifact_id: result, processes_reaped: true,
                error: "Windows 启动器异常退出；已确认原生进程组回收，未完成的任务未计为成功，请重新运行".into(),
                ..Default::default()
            };
            active.completion = Some(completion.clone());
            private_json(&active_path, &active)?;
            completion
        };
        control.complete(completion).await?;
        tokio::fs::remove_file(&active_path).await?;
    }
    let shutdown = CancellationToken::new();
    let signal = shutdown.clone();
    tokio::spawn(async move {
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
        let work_path = absolute(temp.path());
        if lease.kind == "RUNTIME" {
            // Keep host runtime records and raw logs even when the executor
            // returns an error or dies before TempDir's normal cleanup.
            let _persistent_runtime_work = temp.keep();
        }
        private_json(
            &active_path,
            &Active {
                lease: lease.clone(),
                completion: None,
                process_job: desktop_job.clone(),
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
                process_job: desktop_job.clone(),
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
