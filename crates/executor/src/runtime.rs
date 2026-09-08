use crate::jobs::{JobContext, container_tool};
use aegis_application::{import, runtime::prepare_work};
use aegis_domain as d;
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::path::Path;

pub async fn execute(ctx: &JobContext, work: &Path, payload: &Value) -> Result<String> {
    let config: d::RuntimeConfig = serde_json::from_value(payload["config"].clone())?;
    config.validate().map_err(anyhow::Error::msg)?;
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
        serde_json::from_slice(&tokio::fs::read(manifest_path).await?)?;
    ensure!(
        manifest.files.iter().any(|f| f.path == config.path),
        "runtime path is not in the immutable target"
    );
    let target = work.join("target");
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
            config.adapter == "ELF",
            "binary execution requires the ELF adapter"
        );
        tokio::fs::create_dir_all(&target).await?;
        let path = target.join(&config.path);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::copy(&input, path).await?;
    } else {
        ensure!(
            config.adapter != "ELF",
            "source snapshots require a source adapter"
        );
        let target = target.clone();
        tokio::task::spawn_blocking(move || {
            import::unpack_source(&input, &target, import::ImportLimits::default())
        })
        .await??;
    }
    let config_dir = work.join("configuration");
    prepare_work(&config_dir)?;
    let bytes = serde_json::to_vec_pretty(&config)?;
    tokio::fs::write(config_dir.join("runtime-config.json"), &bytes).await?;
    let tool_dir = ctx
        .tools
        .script_dir
        .parent()
        .context("tool root missing")?
        .join("runtime");
    let recipe = serde_json::json!({"schema_version":1,"config":config,
        "supervisor":tokio::fs::read_to_string(tool_dir.join("runner.py")).await?,
        "python_invoker":tokio::fs::read_to_string(tool_dir.join("invoke.py")).await?});
    let recipe = ctx
        .control
        .upload_bytes(
            &ctx.lease,
            "runtime-recipe.json",
            "application/json",
            serde_json::to_vec_pretty(&recipe)?,
        )
        .await?;
    let _ = ctx
        .progress
        .send((
            format!(
                "开始 {}：{}；范围 {}",
                config.mode,
                config.path,
                config.target_scope()
            ),
            0,
            0,
        ))
        .await;
    let (output, tool) = container_tool(
        ctx,
        &config_dir,
        &target,
        vec![
            "python3".into(),
            "/runner/runner.py".into(),
            "/input/runtime-config.json".into(),
        ],
        "runtime-supervisor",
        u64::from(config.deadline().saturating_sub(30)),
    )
    .await?;
    ensure!(
        !output.cancelled && !ctx.cancel.is_cancelled(),
        "runtime cancelled"
    );
    ensure!(!output.timed_out, "runtime timed out");
    let observation = if output.exit_code == Some(0) && !output.truncated {
        serde_json::from_slice::<d::RuntimeObservation>(&output.stdout)
            .context("runtime supervisor returned invalid observations")?
    } else {
        d::RuntimeObservation {
            schema_version: 1,
            mode: config.mode.clone(),
            adapter: config.adapter.clone(),
            path: config.path.clone(),
            error: format!(
                "运行监督程序未完成：exit={:?}, truncated={}；见工具日志",
                output.exit_code, output.truncated
            ),
            ..Default::default()
        }
    };
    observation.validate(&config).map_err(anyhow::Error::msg)?;
    let raw = ctx
        .control
        .upload_bytes(
            &ctx.lease,
            "runtime-observation.json",
            "application/json",
            serde_json::to_vec_pretty(&observation)?,
        )
        .await?;
    let result = d::RuntimeResult {
        target_sha256: manifest.target_sha256,
        config_hash: config.fingerprint(),
        image_id: ctx
            .tools
            .runtime_image
            .clone()
            .context("runtime image missing")?,
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
