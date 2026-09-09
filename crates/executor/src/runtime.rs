use crate::jobs::JobContext;
use aegis_application::{
    import,
    runtime::windows_runtime::{
        WindowsRuntimeAdapter, WindowsRuntimeConfig, WindowsRuntimeEntry,
        WindowsRuntimeEnvironment, WindowsRuntimeInput, WindowsRuntimeMode,
    },
    runtime::windows_sandbox::{
        self, GUEST_INPUT, GUEST_OUTPUT, GUEST_PYTHON, GUEST_TOOLS, GUEST_ZIG, SandboxEntrypoint,
        SandboxFileTransfer, SandboxMapping, SandboxOutputPolicy, SandboxSession, SandboxSpec,
    },
};
use aegis_domain as d;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{path::Path, time::Duration};

pub async fn execute(ctx: &JobContext, work: &Path, payload: &Value) -> Result<String> {
    let config: d::RuntimeConfig = serde_json::from_value(payload["config"].clone())?;
    config.validate().map_err(anyhow::Error::msg)?;
    ensure!(
        d::is_windows_runtime_adapter(&config.adapter),
        "旧 Linux/ELF 运行配置不能在 Windows 执行器中重解释"
    );
    ensure!(config.mode == "VERIFY", "Windows 产品链当前只支持 VERIFY");
    reject_unsupported_python_inputs(&config)?;

    let manifest_path = work.join("manifest.json");
    ctx.control
        .download(
            &ctx.lease,
            payload["manifest_artifact_id"]
                .as_str()
                .context("missing target manifest")?,
            &manifest_path,
            &ctx.cancel,
        )
        .await?;
    let manifest: d::SnapshotManifest =
        serde_json::from_slice(&tokio::fs::read(&manifest_path).await?)?;
    ensure!(
        manifest.files.iter().any(|file| file.path == config.path),
        "runtime path is not in the immutable target"
    );

    let target_root = work.join("target");
    let input = work.join("input.bin");
    ctx.control
        .download(
            &ctx.lease,
            &ctx.lease.input_artifact_id,
            &input,
            &ctx.cancel,
        )
        .await?;
    ensure!(
        d::sha256(&tokio::fs::read(&input).await?) == manifest.target_sha256,
        "runtime target hash mismatch"
    );

    if manifest.kind == "BINARY" {
        ensure!(
            matches!(
                config.adapter.as_str(),
                "WINDOWS_ORIGINAL_PE32" | "WINDOWS_ORIGINAL_PE64"
            ),
            "binary execution requires a Windows original PE adapter"
        );
        tokio::fs::create_dir_all(&target_root).await?;
        let target = target_root.join(&config.path);
        if let Some(parent) = target.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::copy(&input, &target).await?;
    } else {
        ensure!(
            matches!(
                config.adapter.as_str(),
                "WINDOWS_PYTHON_CALL" | "WINDOWS_NATIVE_SOURCE"
            ),
            "source execution requires a Windows source adapter"
        );
        let source = target_root.clone();
        let archive = input.clone();
        tokio::task::spawn_blocking(move || {
            import::unpack_source(&archive, &source, import::ImportLimits::default())
        })
        .await??;
    }

    let target_path = target_root.join(&config.path);
    ensure!(target_path.is_file(), "runtime target is missing");
    let target_bytes = tokio::fs::read(&target_path).await?;
    let target_sha256 = d::sha256(&target_bytes);

    let sandbox_inputs = work.join("sandbox-input");
    tokio::fs::create_dir_all(&sandbox_inputs).await?;
    let mut transfers = Vec::new();
    if manifest.kind != "BINARY" {
        collect_source_files(&target_root, &sandbox_inputs, &mut transfers).await?;
    } else {
        transfers.push(SandboxFileTransfer {
            source: target_path.clone(),
            path: config.path.clone(),
        });
    }
    for fixture in &config.fixtures {
        let relative = aegis_application::runconfig::relative_path(&fixture.path)?;
        let destination = sandbox_inputs.join(&relative);
        if let Some(parent) = destination.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(&destination, fixture.content.as_bytes()).await?;
        transfers.push(SandboxFileTransfer {
            source: destination,
            path: fixture.path.clone(),
        });
    }

    let adapter = match config.adapter.as_str() {
        "WINDOWS_PYTHON_CALL" => WindowsRuntimeAdapter::PythonCall,
        "WINDOWS_NATIVE_SOURCE" => WindowsRuntimeAdapter::NativeSource,
        "WINDOWS_ORIGINAL_PE32" => WindowsRuntimeAdapter::OriginalPe32,
        "WINDOWS_ORIGINAL_PE64" => WindowsRuntimeAdapter::OriginalPe64,
        _ => anyhow::bail!("unsupported Windows runtime adapter"),
    };
    let entry = match adapter {
        WindowsRuntimeAdapter::PythonCall => WindowsRuntimeEntry::Function {
            module: config.path.clone(),
            function: config.function.clone(),
        },
        _ => WindowsRuntimeEntry::CommandLine {
            path: config.path.clone(),
            arguments: vec![],
        },
    };
    let windows_config = WindowsRuntimeConfig {
        schema_version: aegis_application::runtime::windows_runtime::WINDOWS_RUNTIME_SCHEMA_VERSION,
        config_version: "1.0.0".into(),
        mode: WindowsRuntimeMode::Verify,
        adapter,
        target_path: config.path.clone(),
        target_sha256: target_sha256.clone(),
        entry,
        baseline_inputs: invocation_inputs(&config.baseline)?,
        probe_inputs: invocation_inputs(&config.probe)?,
        repeats: config.repeats,
        timeout_seconds: config.timeout_seconds,
        environment: WindowsRuntimeEnvironment {
            python_version: if adapter == WindowsRuntimeAdapter::PythonCall {
                Some("3.13.13".into())
            } else {
                None
            },
            compiler: if adapter == WindowsRuntimeAdapter::NativeSource {
                Some("zig 0.15.2".into())
            } else {
                None
            },
            observer: Some(config.observer.clone()),
            marker_path: if config.marker_path.is_empty() {
                None
            } else {
                Some(config.marker_path.clone())
            },
            runtime_libraries: Default::default(),
        },
        fuzz: None,
    };
    windows_config.validate()?;
    let config_sha256 = windows_config.fingerprint()?;

    let root = ctx
        .tools
        .script_dir
        .parent()
        .and_then(Path::parent)
        .context("project root missing")?
        .to_path_buf();
    verify_pinned_runtime_versions(&root, adapter).await?;
    let entrypoint = match adapter {
        WindowsRuntimeAdapter::PythonCall => SandboxEntrypoint::WindowsPython,
        WindowsRuntimeAdapter::NativeSource => SandboxEntrypoint::WindowsNativeSource,
        WindowsRuntimeAdapter::OriginalPe32 | WindowsRuntimeAdapter::OriginalPe64 => {
            SandboxEntrypoint::OriginalPe
        }
        WindowsRuntimeAdapter::LibFuzzerPrebuilt => SandboxEntrypoint::LibFuzzerPrebuilt,
    };
    let guest_script = match entrypoint {
        SandboxEntrypoint::WindowsPython => "run-python.ps1",
        SandboxEntrypoint::WindowsNativeSource => "run-native-source.ps1",
        SandboxEntrypoint::OriginalPe => "run-pe.ps1",
        _ => anyhow::bail!("unsupported product entrypoint"),
    };
    let mappings = match adapter {
        WindowsRuntimeAdapter::PythonCall => vec![SandboxMapping {
            host: root.join(".tools/windows-python"),
            guest: GUEST_PYTHON.into(),
            read_only: true,
        }],
        WindowsRuntimeAdapter::NativeSource => vec![SandboxMapping {
            host: root.join(".tools/zig"),
            guest: GUEST_ZIG.into(),
            read_only: true,
        }],
        _ => Vec::new(),
    };
    let session_id = format!("{}-session-{}", ctx.lease.attempt_id, d::id());
    let sandbox_root = work.join("sandbox");
    let prepared = sandbox_sandbox_prepare(&SandboxSpec {
        entrypoint,
        session: SandboxSession {
            run_id: ctx.lease.work_item_id.clone(),
            attempt_id: ctx.lease.attempt_id.clone(),
            session_id,
            target_sha256: target_sha256.clone(),
            config_sha256,
            memory_mb: 4096,
        },
        root: sandbox_root,
        inputs: transfers,
        tools: vec![
            SandboxFileTransfer {
                source: root.join("tools/windows/sandbox").join(guest_script),
                path: guest_script.into(),
            },
            SandboxFileTransfer {
                source: root.join("tools/windows/sandbox/run-windows-trials.ps1"),
                path: "run-windows-trials.ps1".into(),
            },
        ],
        mappings,
        runtime_config: Some(windows_config.clone()),
    })?;
    sandbox_sandbox_verify_inputs(&prepared)?;

    let _ = ctx
        .progress
        .send((
            format!(
                "开始 Windows Sandbox VERIFY：{}；范围 {}",
                config.path,
                config.target_scope()
            ),
            0,
            0,
        ))
        .await;
    ctx.reaped.store(true, std::sync::atomic::Ordering::SeqCst);
    let timeout = Duration::from_secs(u64::from(config.deadline().saturating_add(120)));
    let execution_started_at = d::now();
    ctx.reaped.store(false, std::sync::atomic::Ordering::SeqCst);
    let execution = match entrypoint {
        SandboxEntrypoint::WindowsPython => {
            sandbox_sandbox_run_python(&prepared, timeout, ctx.cancel.clone()).await?
        }
        SandboxEntrypoint::WindowsNativeSource => {
            sandbox_sandbox_run_native(&prepared, timeout, ctx.cancel.clone()).await?
        }
        SandboxEntrypoint::OriginalPe => {
            sandbox_sandbox_run_pe(&prepared, timeout, ctx.cancel.clone()).await?
        }
        _ => anyhow::bail!("unsupported product entrypoint"),
    };
    ctx.reaped.store(
        execution.remote_session_closed,
        std::sync::atomic::Ordering::SeqCst,
    );
    ensure!(
        execution.success && execution.remote_session_closed,
        "Windows Sandbox session did not complete with a confirmed cleanup: {execution:?}"
    );
    let execution_finished_at = d::now();
    let policy = match entrypoint {
        SandboxEntrypoint::WindowsPython => SandboxOutputPolicy::windows_python(),
        SandboxEntrypoint::WindowsNativeSource => SandboxOutputPolicy::windows_native_source(),
        SandboxEntrypoint::OriginalPe => SandboxOutputPolicy::original_pe(),
        _ => anyhow::bail!("unsupported product output policy"),
    };
    let output = sandbox_sandbox_collect_output(&prepared, &policy)?;

    let guest_observation_text = tokio::fs::read(prepared.output.join("guest-observation.json"))
        .await
        .unwrap_or_default();
    let guest_observation_text = String::from_utf8_lossy(&guest_observation_text)
        .trim_start_matches('\u{feff}')
        .to_string();
    let guest_observation: Value = if guest_observation_text.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&guest_observation_text)
            .context("invalid Windows Sandbox guest observation")?
    };
    let guest_error = tokio::fs::read_to_string(prepared.output.join("guest-error.json"))
        .await
        .unwrap_or_default();
    let guest_error = guest_error
        .trim_start_matches('\u{feff}')
        .trim()
        .to_string();
    let observation_error = if output.receipt.status == "ERROR" {
        if guest_error.is_empty() {
            "Windows Sandbox guest reported an error without details".into()
        } else {
            guest_error
        }
    } else {
        String::new()
    };
    let mut trials = Vec::new();
    if let Some(records) = guest_observation["trials"].as_array() {
        for (index, record) in records.iter().enumerate() {
            let expected = if index == 0 {
                &config.baseline
            } else {
                &config.probe
            };
            let input_json = serde_json::to_string(expected)?;
            trials.push(d::RuntimeTrial {
                label: record["label"].as_str().unwrap_or_default().into(),
                input_sha256: d::sha256(input_json.as_bytes()),
                input_json,
                exit_code: record["exit_code"].as_i64().map(|code| code as i32),
                timed_out: record["timed_out"].as_bool().unwrap_or_default(),
                processes_reaped: execution.remote_session_closed,
                observed: record["observed"].as_bool().unwrap_or_default(),
                exception: record["exception"].as_str().unwrap_or_default().into(),
                stdout: record["stdout"].as_str().unwrap_or_default().into(),
                stderr: record["stderr"].as_str().unwrap_or_default().into(),
                truncated: record["truncated"].as_bool().unwrap_or_default(),
                crash_signature: record["crash_signature"]
                    .as_str()
                    .unwrap_or_default()
                    .into(),
            });
        }
    }
    let build = if entrypoint == SandboxEntrypoint::WindowsNativeSource {
        json!({
            "status": if guest_observation["compile_exit_code"] == 0 { "READY" } else { "ERROR" },
            "compiler": guest_observation["compiler"],
            "compile_exit_code": guest_observation["compile_exit_code"],
        })
    } else {
        json!({"status": if observation_error.is_empty() { "READY" } else { "ERROR" }, "environment": "Windows Sandbox x64"})
    };
    let observation = d::RuntimeObservation {
        schema_version: 1,
        mode: config.mode.clone(),
        adapter: config.adapter.clone(),
        path: config.path.clone(),
        build,
        trials,
        fuzz: json!({}),
        crashes: vec![],
        error: observation_error,
    };
    observation.validate(&config).map_err(anyhow::Error::msg)?;

    let recipe = json!({
        "schema_version": 1,
        "config": config,
        "windows_runtime_config": windows_config,
        "sandbox_manifest": serde_json::from_slice::<Value>(&tokio::fs::read(&prepared.manifest).await?)?,
    });
    let recipe = ctx
        .control
        .upload_bytes(
            &ctx.lease,
            "runtime-recipe.json",
            "application/json",
            serde_json::to_vec_pretty(&recipe)?,
        )
        .await?;
    let raw = ctx
        .control
        .upload_bytes(
            &ctx.lease,
            "runtime-observation.json",
            "application/json",
            serde_json::to_vec_pretty(&observation)?,
        )
        .await?;
    let raw_logs = upload_wsb_logs(ctx, &prepared, &execution).await?;
    let log = ctx
        .control
        .upload_bytes(
            &ctx.lease,
            &format!("windows-sandbox-{}.json", d::id()),
            "application/json",
            serde_json::to_vec_pretty(&json!({
                "execution": execution,
                "receipt": output.receipt,
                "artifacts": output.artifacts,
                "guest_observation": guest_observation,
                "raw_logs": raw_logs,
            }))?,
        )
        .await?;
    let image_id = format!(
        "sha256:{}",
        d::sha256(&serde_json::to_vec(&json!({
            "isolation": "WINDOWS_SANDBOX",
            "platform": "windows-x64",
            "network": "DISABLED",
            "schema_version": aegis_application::runtime::windows_sandbox::SANDBOX_SCHEMA_VERSION,
            "python": "3.13.13",
            "zig": "0.15.2",
        }))?)
    );
    let tool = d::ToolExecution {
        name: "windows-sandbox".into(),
        version: image_id.clone(),
        command: vec![
            "wsb.exe".into(),
            "start".into(),
            "--raw".into(),
            "--config".into(),
            prepared.config.to_string_lossy().into_owned(),
        ],
        started_at: execution_started_at,
        finished_at: execution_finished_at,
        exit_code: execution.guest_exit_code,
        terminated: execution.timed_out || execution.cancelled,
        log_artifact_id: log.id,
        details: json!({
            "isolation": "WINDOWS_SANDBOX",
            "platform": "windows/x64",
            "network": "DISABLED",
            "session_id": output.receipt.session_id,
            "wsb_session_id": execution.session_id,
            "processes_reaped": execution.remote_session_closed,
            "timed_out": execution.timed_out,
            "cancelled": execution.cancelled,
            "raw_log_artifact_ids": raw_logs
                .iter()
                .map(|entry| entry["artifact_id"].clone())
                .collect::<Vec<_>>(),
            "commands": wsb_commands(&prepared.config, guest_script, &execution),
        }),
    };
    let result = d::RuntimeResult {
        target_sha256: manifest.target_sha256.clone(),
        config_hash: config.fingerprint(),
        image_id,
        target_scope: config.target_scope().into(),
        recipe_artifact_id: recipe.id,
        observation_artifact_id: raw.id,
        observation,
        tools: vec![tool],
    };
    Ok(ctx
        .control
        .upload_bytes(
            &ctx.lease,
            "runtime-result.json",
            "application/json",
            serde_json::to_vec_pretty(&result)?,
        )
        .await?
        .id)
}

fn reject_unsupported_python_inputs(config: &d::RuntimeConfig) -> Result<()> {
    if config.adapter != "WINDOWS_PYTHON_CALL" {
        return Ok(());
    }
    ensure!(
        config.globals.is_empty(),
        "Windows Python runtime has no trusted globals channel; refusing to silently discard globals"
    );
    for (label, invocation) in [("baseline", &config.baseline), ("probe", &config.probe)] {
        ensure!(
            invocation.kwargs.is_empty(),
            "Windows Python runtime has no trusted kwargs channel; refusing to silently discard {label} kwargs"
        );
    }
    Ok(())
}

pub(crate) fn tool_version_matches(actual: &str, expected: &str) -> bool {
    actual.split_whitespace().last() == Some(expected)
}

pub(crate) async fn command_text(program: &Path, args: &[&str]) -> Result<String> {
    let output = tokio::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true)
        .output()
        .await?;
    ensure!(
        output.status.success(),
        "{} exited with {}: {}{}",
        program.display(),
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    ensure!(
        !text.is_empty(),
        "{} returned an empty version",
        program.display()
    );
    Ok(text)
}

async fn verify_pinned_runtime_versions(root: &Path, adapter: WindowsRuntimeAdapter) -> Result<()> {
    match adapter {
        WindowsRuntimeAdapter::PythonCall => {
            let program = root.join(".tools/windows-python/python.exe");
            let actual = command_text(&program, &["--version"]).await?;
            ensure!(
                tool_version_matches(&actual, "3.13.13"),
                "pinned Python 3.13.13 is required, found {actual}"
            );
        }
        WindowsRuntimeAdapter::NativeSource => {
            let program = root.join(".tools/zig/zig.exe");
            let actual = command_text(&program, &["version"]).await?;
            ensure!(
                tool_version_matches(&actual, "0.15.2"),
                "pinned Zig 0.15.2 is required, found {actual}"
            );
        }
        _ => {}
    }
    Ok(())
}

fn wsb_commands(
    config: &Path,
    guest_script: &str,
    execution: &aegis_application::runtime::windows_sandbox::SandboxExecution,
) -> Vec<Vec<String>> {
    let guest_command = format!(
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -File {GUEST_TOOLS}\\{guest_script} -InputPath {GUEST_INPUT} -OutputPath {GUEST_OUTPUT}"
    );
    let mut commands = vec![
        vec![
            "wsb.exe".into(),
            "start".into(),
            "--raw".into(),
            "--config".into(),
            config.to_string_lossy().into_owned(),
        ],
        vec![
            "wsb.exe".into(),
            "exec".into(),
            "--raw".into(),
            "--id".into(),
            execution.session_id.clone(),
            "-r".into(),
            "System".into(),
            "-c".into(),
            guest_command,
        ],
        vec!["wsb.exe".into(), "list".into(), "--raw".into()],
    ];
    if execution.stop_exit_code.is_some() {
        commands.push(vec![
            "wsb.exe".into(),
            "stop".into(),
            "--raw".into(),
            "--id".into(),
            execution.session_id.clone(),
        ]);
    }
    commands
}

async fn upload_wsb_logs(
    ctx: &JobContext,
    prepared: &aegis_application::runtime::windows_sandbox::PreparedSandbox,
    execution: &aegis_application::runtime::windows_sandbox::SandboxExecution,
) -> Result<Vec<Value>> {
    let mut paths = Vec::new();
    let mut entries = tokio::fs::read_dir(&prepared.root).await?;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name.starts_with("sandbox-") && name.ends_with(".json") {
            paths.push(path);
        }
    }
    paths.sort();
    ensure!(
        !paths.is_empty(),
        "Windows Sandbox raw WSB logs are missing"
    );
    let mut uploaded = Vec::new();
    let mut total = 0_u64;
    for path in paths {
        let bytes = tokio::fs::read(&path).await?;
        total += u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        ensure!(
            total <= 32 * 1024 * 1024,
            "Windows Sandbox raw logs exceed 32 MiB"
        );
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let sha256 = d::sha256(&bytes);
        let artifact = ctx
            .control
            .upload_bytes(
                &ctx.lease,
                &format!("windows-sandbox-{}-{name}", execution.session_id),
                "application/json",
                bytes,
            )
            .await?;
        uploaded.push(json!({
            "name": name,
            "artifact_id": artifact.id,
            "sha256": sha256,
        }));
    }
    Ok(uploaded)
}

fn invocation_inputs(invocation: &d::Invocation) -> Result<Vec<WindowsRuntimeInput>> {
    let mut inputs = Vec::new();
    for argument in &invocation.args {
        let value = argument
            .as_str()
            .context("Windows runtime arguments must be strings")?;
        inputs.push(WindowsRuntimeInput::Argument {
            value: value.to_owned(),
        });
    }
    inputs.push(WindowsRuntimeInput::Stdin {
        value: invocation.stdin.clone(),
    });
    Ok(inputs)
}

async fn collect_source_files(
    source: &Path,
    destination: &Path,
    transfers: &mut Vec<SandboxFileTransfer>,
) -> Result<()> {
    let mut stack = vec![source.to_path_buf()];
    while let Some(directory) = stack.pop() {
        let mut entries = tokio::fs::read_dir(&directory).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let relative = path
                .strip_prefix(source)
                .with_context(|| format!("path escapes source tree: {}", path.display()))?;
            let relative = relative.to_string_lossy().replace('\\', "/");
            let target = destination.join(&relative);
            if let Some(parent) = target.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            tokio::fs::copy(&path, &target).await?;
            transfers.push(SandboxFileTransfer {
                source: target,
                path: relative,
            });
        }
    }
    ensure!(
        transfers.len() <= 256,
        "Windows Sandbox source input set is too large"
    );
    Ok(())
}

fn sandbox_sandbox_prepare(
    spec: &SandboxSpec,
) -> Result<aegis_application::runtime::windows_sandbox::PreparedSandbox> {
    tokio::task::block_in_place(|| windows_sandbox::prepare(spec))
}

fn sandbox_sandbox_verify_inputs(
    prepared: &aegis_application::runtime::windows_sandbox::PreparedSandbox,
) -> Result<()> {
    tokio::task::block_in_place(|| windows_sandbox::verify_inputs(prepared))
}

fn sandbox_sandbox_collect_output(
    prepared: &aegis_application::runtime::windows_sandbox::PreparedSandbox,
    policy: &SandboxOutputPolicy,
) -> Result<aegis_application::runtime::windows_sandbox::SandboxOutput> {
    tokio::task::block_in_place(|| windows_sandbox::collect_output(prepared, policy))
}

async fn sandbox_sandbox_run_python(
    prepared: &aegis_application::runtime::windows_sandbox::PreparedSandbox,
    timeout: Duration,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<aegis_application::runtime::windows_sandbox::SandboxExecution> {
    windows_sandbox::run_windows_python(prepared, timeout, cancel).await
}

async fn sandbox_sandbox_run_native(
    prepared: &aegis_application::runtime::windows_sandbox::PreparedSandbox,
    timeout: Duration,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<aegis_application::runtime::windows_sandbox::SandboxExecution> {
    windows_sandbox::run_native_source(prepared, timeout, cancel).await
}

async fn sandbox_sandbox_run_pe(
    prepared: &aegis_application::runtime::windows_sandbox::PreparedSandbox,
    timeout: Duration,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<aegis_application::runtime::windows_sandbox::SandboxExecution> {
    windows_sandbox::run_original_pe(prepared, timeout, cancel).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_tool_versions_must_match_exactly() {
        assert!(tool_version_matches("Python 3.13.13", "3.13.13"));
        assert!(tool_version_matches("0.15.2", "0.15.2"));
        assert!(!tool_version_matches("Python 3.13.12", "3.13.13"));
        assert!(!tool_version_matches("0.15.20", "0.15.2"));
    }

    #[test]
    fn windows_python_rejects_kwargs_and_globals_instead_of_discarding_them() {
        let mut config = d::RuntimeConfig {
            adapter: "WINDOWS_PYTHON_CALL".into(),
            path: "target.py".into(),
            function: "helper".into(),
            mode: "VERIFY".into(),
            observer: "FILE_CREATED".into(),
            marker_path: "marker.txt".into(),
            ..Default::default()
        };
        config
            .globals
            .insert("canary".into(), Value::String("{{canary}}".into()));
        assert!(reject_unsupported_python_inputs(&config).is_err());
        config.globals.clear();
        config
            .baseline
            .kwargs
            .insert("name".into(), Value::String("baseline".into()));
        assert!(reject_unsupported_python_inputs(&config).is_err());
        config.baseline.kwargs.clear();
        config
            .probe
            .kwargs
            .insert("name".into(), Value::String("probe".into()));
        assert!(reject_unsupported_python_inputs(&config).is_err());
        config.probe.kwargs.clear();
        assert!(reject_unsupported_python_inputs(&config).is_ok());
    }
}
