use crate::client::Control;
use aegis_application::{
    import::{self, ImportLimits},
    process::{self, ProcessSpec},
    source,
};
use aegis_domain as d;
use aegis_protocol as p;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct Tools {
    pub ghidra: Option<PathBuf>,
    pub script_dir: PathBuf,
    pub git: bool,
    pub runtime_image: Option<String>,
    pub semgrep: Option<aegis_application::sast::Semgrep>,
}
#[derive(Clone)]
pub struct JobContext {
    pub control: Control,
    pub lease: p::WorkLease,
    pub cancel: CancellationToken,
    pub tools: Tools,
    pub progress: mpsc::Sender<(String, u64, u64)>,
    pub reaped: Arc<AtomicBool>,
}

pub(crate) async fn process_tool(
    ctx: &JobContext,
    spec: ProcessSpec,
    name: &str,
    version: &str,
) -> Result<(process::ProcessOutput, d::ToolExecution)> {
    let started = d::now();
    let command = std::iter::once(spec.program.to_string_lossy().into_owned())
        .chain(spec.args.clone())
        .collect();
    ctx.reaped.store(false, Ordering::SeqCst);
    let sender = ctx.progress.clone();
    let output = process::run(spec, ctx.cancel.clone(), move |message| {
        let _ = sender.try_send((message.into(), 0, 0));
    })
    .await?;
    ctx.reaped.store(output.processes_reaped, Ordering::SeqCst);
    let mut logs = Vec::new();
    logs.extend_from_slice(b"--- stdout ---\n");
    logs.extend_from_slice(&output.stdout);
    logs.extend_from_slice(b"\n--- stderr ---\n");
    logs.extend_from_slice(&output.stderr);
    let log = if logs.len() > 32 {
        Some(
            ctx.control
                .upload_bytes(
                    &ctx.lease,
                    &format!("{name}-{}.log", d::id()),
                    "text/plain; charset=utf-8",
                    logs,
                )
                .await?,
        )
    } else {
        None
    };
    let record = d::ToolExecution {
        name: name.into(),
        version: version.into(),
        command,
        started_at: started,
        finished_at: d::now(),
        exit_code: output.exit_code,
        terminated: output.cancelled || output.timed_out,
        log_artifact_id: log.map(|a| a.id).unwrap_or_default(),
        details: json!({"log_truncated":output.truncated,"processes_reaped":output.processes_reaped,"timed_out":output.timed_out,"cancelled":output.cancelled}),
    };
    ensure!(
        output.processes_reaped,
        "tool process cleanup was not confirmed"
    );
    Ok((output, record))
}

async fn git_step(
    ctx: &JobContext,
    directory: &Path,
    args: Vec<String>,
) -> Result<d::ToolExecution> {
    let null = if cfg!(windows) { "NUL" } else { "/dev/null" };
    let mut command = vec![
        "-c".into(),
        format!("core.hooksPath={null}"),
        "-c".into(),
        "credential.helper=".into(),
        "-c".into(),
        "protocol.file.allow=never".into(),
        "-c".into(),
        "protocol.ext.allow=never".into(),
    ];
    command.extend(args);
    let mut env = BTreeMap::from([
        ("GIT_TERMINAL_PROMPT".into(), "0".into()),
        ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
        ("GIT_CONFIG_GLOBAL".into(), null.into()),
        ("GIT_LFS_SKIP_SMUDGE".into(), "1".into()),
    ]);
    for key in ["http_proxy", "https_proxy", "all_proxy", "no_proxy"] {
        if let Ok(value) = std::env::var(key).or_else(|_| std::env::var(key.to_ascii_uppercase()))
            && !value.is_empty()
        {
            validate_git_proxy(key, &value)?;
            env.insert(key.into(), value);
        }
    }
    let (out, record) = process_tool(
        ctx,
        ProcessSpec {
            program: "git".into(),
            args: command,
            directory: directory.into(),
            env,
            timeout: Duration::from_secs(120),
        },
        "git",
        "installed Git; command and output retained",
    )
    .await?;
    ensure!(
        !out.cancelled && !out.timed_out && out.exit_code == Some(0),
        "Git operation failed or was interrupted: {}",
        String::from_utf8_lossy(&out.stderr)
            .chars()
            .take(2000)
            .collect::<String>()
    );
    Ok(record)
}

fn validate_git_proxy(key: &str, value: &str) -> Result<()> {
    ensure!(
        value.len() <= 8192 && !value.contains(['\r', '\n', '\0']),
        "invalid Git proxy setting"
    );
    if key != "no_proxy" {
        let url = reqwest::Url::parse(value)
            .context("Git proxy must be an absolute HTTP/HTTPS/SOCKS URL")?;
        ensure!(
            matches!(url.scheme(), "http" | "https" | "socks5" | "socks5h"),
            "unsupported Git proxy scheme"
        );
        ensure!(
            url.host_str().is_some() && url.username().is_empty() && url.password().is_none(),
            "Git proxy credentials are not forwarded to tools; use a local proxy without credentials"
        );
    }
    Ok(())
}

pub async fn execute(ctx: JobContext, workdir: &Path) -> Result<String> {
    let payload: Value = serde_json::from_str(&ctx.lease.payload_json)?;
    match ctx.lease.kind.as_str() {
        "IMPORT" => import_target(&ctx, workdir, &payload).await,
        "ANALYZE" => analyze(&ctx, workdir, &payload).await,
        "RUNTIME" => crate::runtime::execute(&ctx, workdir, &payload).await,
        _ => anyhow::bail!("Unknown work kind"),
    }
}

async fn import_target(ctx: &JobContext, workdir: &Path, payload: &Value) -> Result<String> {
    let kind = payload["kind"].as_str().context("missing target kind")?;
    let input = workdir.join("input.bin");
    let normalized = workdir.join("snapshot.zip");
    let source_dir = workdir.join("source");
    let mut revision = String::new();
    let mut tools = vec![];
    let (files, exclusions, mut metadata, normalized_artifact) = if kind == "BINARY" {
        ctx.control
            .download(
                &ctx.lease,
                &ctx.lease.input_artifact_id,
                &input,
                &ctx.cancel,
            )
            .await?;
        let data = tokio::fs::read(&input).await?;
        let metadata = import::inspect_binary(&data)?;
        let name = payload["name"]
            .as_str()
            .filter(|n| !n.is_empty())
            .unwrap_or("target.bin");
        import::relative_path(name)?;
        let file = d::FileRecord {
            path: name.into(),
            sha256: d::sha256(&data),
            size: data.len() as u64,
            language: "binary".into(),
        };
        let artifact = ctx
            .control
            .upload_file(&ctx.lease, &input, name, "application/octet-stream")
            .await?;
        (vec![file], vec![], metadata, artifact)
    } else {
        let mut original_exclusions = vec![];
        if kind == "GIT" {
            ensure!(ctx.tools.git, "Git is not installed");
            tokio::fs::create_dir_all(&source_dir).await?;
            let url = payload["git_url"].as_str().context("missing Git URL")?;
            let rev = payload["git_revision"]
                .as_str()
                .context("missing Git revision")?;
            ensure!(
                url.starts_with("https://") && !rev.starts_with('-'),
                "invalid Git source"
            );
            tools.push(git_step(ctx, &source_dir, vec!["init".into()]).await?);
            tools.push(
                git_step(
                    ctx,
                    &source_dir,
                    vec!["remote".into(), "add".into(), "origin".into(), url.into()],
                )
                .await?,
            );
            tools.push(
                git_step(
                    ctx,
                    &source_dir,
                    vec![
                        "fetch".into(),
                        "--depth=1".into(),
                        "--no-tags".into(),
                        "origin".into(),
                        rev.into(),
                    ],
                )
                .await?,
            );
            tools.push(
                git_step(
                    ctx,
                    &source_dir,
                    vec!["checkout".into(), "--detach".into(), "FETCH_HEAD".into()],
                )
                .await?,
            );
            // FETCH_HEAD records the exact fetched commit, without an additional process.
            let fetched = tokio::fs::read_to_string(source_dir.join(".git/FETCH_HEAD")).await?;
            revision = fetched.split_whitespace().next().unwrap_or("").into();
            ensure!(
                matches!(revision.len(), 40 | 64)
                    && revision.bytes().all(|b| b.is_ascii_hexdigit()),
                "Git did not report an immutable commit"
            );
        } else {
            ctx.control
                .download(
                    &ctx.lease,
                    &ctx.lease.input_artifact_id,
                    &input,
                    &ctx.cancel,
                )
                .await?;
            let source = source_dir.clone();
            let archive = input.clone();
            let bundle = tokio::task::spawn_blocking(move || {
                import::unpack_source(&archive, &source, ImportLimits::default())
            })
            .await??;
            original_exclusions = bundle.exclusions;
        }
        ensure!(!ctx.cancel.is_cancelled(), "import cancelled");
        let source = source_dir.clone();
        let target = normalized.clone();
        let mut bundle = tokio::task::spawn_blocking(move || {
            import::pack_directory(&source, &target, ImportLimits::default())
        })
        .await??;
        original_exclusions.append(&mut bundle.exclusions);
        let artifact = ctx
            .control
            .upload_file(
                &ctx.lease,
                &normalized,
                "source-snapshot.zip",
                "application/zip",
            )
            .await?;
        (bundle.files, original_exclusions, bundle.metadata, artifact)
    };
    metadata["tools"] = serde_json::to_value(tools)?;
    let manifest = d::SnapshotManifest {
        schema_version: 1,
        kind: kind.into(),
        normalized_artifact_id: normalized_artifact.id,
        target_sha256: normalized_artifact.sha256,
        files,
        exclusions,
        metadata,
        resolved_revision: revision,
    };
    Ok(ctx
        .control
        .upload_bytes(
            &ctx.lease,
            "snapshot-manifest.json",
            "application/json",
            serde_json::to_vec_pretty(&manifest)?,
        )
        .await?
        .id)
}

async fn analyze(ctx: &JobContext, workdir: &Path, payload: &Value) -> Result<String> {
    let manifest_path = workdir.join("manifest.json");
    ctx.control
        .download(
            &ctx.lease,
            payload["manifest_artifact_id"]
                .as_str()
                .context("missing manifest")?,
            &manifest_path,
            &ctx.cancel,
        )
        .await?;
    let manifest: d::SnapshotManifest =
        serde_json::from_slice(&tokio::fs::read(manifest_path).await?)?;
    let mut result = if manifest.kind == "BINARY" {
        let ghidra = ctx.tools.ghidra.as_ref().context("Ghidra is unavailable")?;
        let input = workdir.join("target.bin");
        ctx.control
            .download(
                &ctx.lease,
                &ctx.lease.input_artifact_id,
                &input,
                &ctx.cancel,
            )
            .await?;
        // Ghidra project paths cannot contain dot-prefixed components; use a dedicated native temp directory.
        let project = tempfile::Builder::new().prefix("aegis-ghidra-").tempdir()?;
        let output = workdir.join("ghidra-result.json");
        let headless = ghidra.join(if cfg!(windows) {
            "support/analyzeHeadless.bat"
        } else {
            "support/analyzeHeadless"
        });
        let args = vec![
            project.path().to_string_lossy().into_owned(),
            "analysis".into(),
            "-import".into(),
            input.to_string_lossy().into_owned(),
            "-scriptPath".into(),
            ctx.tools.script_dir.to_string_lossy().into_owned(),
            "-postScript".into(),
            "ExportProgram.java".into(),
            output.to_string_lossy().into_owned(),
            "target.bin".into(),
            "-deleteProject".into(),
            "-analysisTimeoutPerFile".into(),
            "120".into(),
            "-max-cpu".into(),
            "2".into(),
        ];
        let (output_status, record) = process_tool(
            ctx,
            ProcessSpec {
                program: headless,
                args,
                directory: workdir.into(),
                env: BTreeMap::from([("MAXMEM".into(), "2G".into())]),
                timeout: Duration::from_secs(ctx.lease.timeout_seconds as u64),
            },
            "ghidra",
            "12.1.3",
        )
        .await?;
        ensure!(!output_status.cancelled, "Ghidra analysis cancelled");
        ensure!(!output_status.timed_out, "Ghidra analysis timed out");
        ensure!(
            output_status.exit_code == Some(0) && output.is_file(),
            "Ghidra did not produce its required result artifact; inspect the retained tool log"
        );
        let bytes = tokio::fs::read(output).await?;
        ensure!(
            bytes.len() <= 64 * 1024 * 1024,
            "Ghidra output exceeds limit"
        );
        let mut result: d::AnalysisResult = serde_json::from_slice(&bytes)?;
        let original_path = &manifest
            .files
            .first()
            .context("binary manifest has no file")?
            .path;
        for unit in &mut result.units {
            unit.path = original_path.clone();
        }
        for file in &mut result.files {
            file.path = original_path.clone();
        }
        result.metadata["input_mapping"] =
            json!({"staged_name":"target.bin","snapshot_path":original_path});
        result.tools.push(record);
        result
    } else {
        let archive = workdir.join("input.zip");
        let source_dir = workdir.join("source");
        ctx.control
            .download(
                &ctx.lease,
                &ctx.lease.input_artifact_id,
                &archive,
                &ctx.cancel,
            )
            .await?;
        let source = source_dir.clone();
        tokio::task::spawn_blocking(move || {
            import::unpack_source(&archive, &source, ImportLimits::default())
        })
        .await??;
        let files = manifest.files.clone();
        let token = ctx.cancel.clone();
        let sender = ctx.progress.clone();
        tokio::task::spawn_blocking(move || {
            source::analyze_sources(
                &source_dir,
                &files,
                &token,
                move |current, total, message| {
                    if current % 20 == 0 || current == total {
                        let _ = sender.blocking_send((
                            format!("解析 {message}"),
                            current as u64,
                            total as u64,
                        ));
                    }
                },
            )
        })
        .await??
    };
    if manifest.kind != "BINARY"
        && payload["scope"]
            .as_str()
            .is_some_and(|scope| scope != d::SCOPE)
    {
        if let Some(scanner) = &ctx.tools.semgrep {
            let work = workdir.join("semgrep");
            tokio::fs::create_dir_all(&work).await?;
            let (status, mut record) = process_tool(
                ctx,
                scanner.scan_spec(&workdir.join("source"), &work),
                "semgrep",
                aegis_application::sast::SEMGREP_VERSION,
            )
            .await?;
            record.details["platform"] = json!("windows/x86_64");
            record.details["process_supervision"] = json!("WINDOWS_JOB_OBJECT");
            record.details["target_execution"] = json!(false);
            record.details["core_sha256"] = json!(scanner.core_sha256);
            record.details["rules_sha256"] =
                json!(d::sha256(&tokio::fs::read(&scanner.rules).await?));
            result.tools.push(record);
            if status.exit_code == Some(0)
                && !status.truncated
                && !status.timed_out
                && !status.cancelled
            {
                let raw = status.stdout;
                ensure!(
                    raw.len() <= 16 * 1024 * 1024,
                    "Semgrep output exceeds quota"
                );
                let artifact = ctx
                    .control
                    .upload_bytes(&ctx.lease, "semgrep.json", "application/json", raw.clone())
                    .await?;
                let parsed = serde_json::from_slice::<Value>(&raw)
                    .map_err(anyhow::Error::from)
                    .and_then(|report| {
                        aegis_application::sast::validate_report(&report, &manifest.files)
                    });
                result.metadata["semgrep"] = match parsed {
                    Ok(mut report) => {
                        report["artifact_id"] = json!(artifact.id);
                        if report["status"] != "COMPLETED" {
                            result.warnings.push(
                                "Windows Semgrep 覆盖不完整；规则命中不代表漏洞成立，语义审计继续"
                                    .into(),
                            );
                        }
                        report
                    }
                    Err(error) => {
                        result.warnings.push(
                            "Windows Semgrep 结果未通过范围/格式校验；保留原始产物，语义审计继续"
                                .into(),
                        );
                        json!({"status":"FAILED","artifact_id":artifact.id,"reason":error.to_string()})
                    }
                };
            } else {
                result.metadata["semgrep"] =
                    json!({"status":"FAILED","exit_code":status.exit_code});
                result
                    .warnings
                    .push("Semgrep 未完成；保留原始日志，语义审计仍可继续".into());
            }
        } else {
            result.metadata["semgrep"] = json!({"status":"UNSUPPORTED","reason":"执行器未准备 Windows 原生 Semgrep 1.176.1；使用内建线索并进行独立语义审计"});
        }
    }
    ensure!(!ctx.cancel.is_cancelled(), "analysis cancelled");
    result.validate(&manifest).map_err(anyhow::Error::msg)?;
    result.metadata["target_sha256"] = json!(manifest.target_sha256);
    let bytes = serde_json::to_vec_pretty(&result)?;
    ensure!(
        bytes.len() <= 64 * 1024 * 1024,
        "analysis output exceeds limit"
    );
    Ok(ctx
        .control
        .upload_bytes(
            &ctx.lease,
            "analysis-result.json",
            "application/json",
            bytes,
        )
        .await?
        .id)
}

pub(crate) async fn container_tool(
    ctx: &JobContext,
    work: &Path,
    target: &Path,
    args: Vec<String>,
    name: &str,
    seconds: u64,
) -> Result<(process::ProcessOutput, d::ToolExecution)> {
    let image = ctx
        .tools
        .runtime_image
        .as_ref()
        .context("Linux runtime image is unavailable")?;
    let started = d::now();
    let command = args.clone();
    let sender = ctx.progress.clone();
    ctx.reaped.store(false, Ordering::SeqCst);
    let output = aegis_application::runtime::run(
        aegis_application::runtime::ContainerSpec {
            image: image.clone(),
            work: work.into(),
            target: target.into(),
            runner: ctx
                .tools
                .script_dir
                .parent()
                .context("tool root missing")?
                .join("runtime"),
            args,
            timeout: Duration::from_secs(seconds),
        },
        ctx.cancel.clone(),
        move |message| {
            let _ = sender.try_send((message.into(), 0, 0));
        },
    )
    .await?;
    ctx.reaped.store(output.processes_reaped, Ordering::SeqCst);
    let mut bytes = output.stdout.clone();
    bytes.extend_from_slice(b"\n--- stderr ---\n");
    bytes.extend_from_slice(&output.stderr);
    let artifact = ctx
        .control
        .upload_bytes(
            &ctx.lease,
            &format!("{name}-{}.log", d::id()),
            "text/plain; charset=utf-8",
            bytes,
        )
        .await?;
    let record = d::ToolExecution {
        name: name.into(),
        version: image.clone(),
        command,
        started_at: started,
        finished_at: d::now(),
        exit_code: output.exit_code,
        terminated: output.cancelled || output.timed_out,
        log_artifact_id: artifact.id,
        details: json!({"isolation":"DOCKER","platform":"linux/amd64","network":"none","processes_reaped":output.processes_reaped,"timed_out":output.timed_out,"cancelled":output.cancelled,"log_truncated":output.truncated}),
    };
    ensure!(
        output.processes_reaped,
        "Container removal was not confirmed"
    );
    Ok((output, record))
}

#[cfg(test)]
mod proxy_tests {
    use super::*;

    #[test]
    fn proxy_support_does_not_forward_embedded_credentials_or_shell_commands() {
        assert!(validate_git_proxy("https_proxy", "http://127.0.0.1:7897").is_ok());
        assert!(validate_git_proxy("all_proxy", "socks5://127.0.0.1:7897").is_ok());
        assert!(validate_git_proxy("no_proxy", "localhost,127.0.0.1").is_ok());
        for value in [
            "http://user:secret@proxy.example",
            "file:///C:/private",
            "http://proxy\ncommand",
        ] {
            assert!(validate_git_proxy("https_proxy", value).is_err());
        }
    }
}
