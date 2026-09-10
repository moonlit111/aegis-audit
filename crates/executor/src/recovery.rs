use crate::jobs::{JobContext, decompile, process_tool};
use aegis_application::{deobfuscation, protection, recovery};
use aegis_domain as d;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{path::Path, sync::atomic::Ordering};

pub(crate) async fn execute(ctx: &JobContext, work: &Path, payload: &Value) -> Result<String> {
    let step: d::RecoveryStep = serde_json::from_value(payload["step"].clone())?;
    let input = work.join("target.bin");
    ctx.control
        .download(
            &ctx.lease,
            &ctx.lease.input_artifact_id,
            &input,
            &ctx.cancel,
        )
        .await?;
    let bytes = tokio::fs::read(&input).await?;
    let hash = d::sha256(&bytes);
    ensure!(payload["input_sha256"] == hash, "逆向输入哈希不匹配");
    let mut result = d::RecoveryResult {
        schema_version: 1,
        tool: step.tool,
        status: "FAILED".into(),
        input_artifact_id: ctx.lease.input_artifact_id.clone(),
        input_sha256: hash.clone(),
        output_artifact_id: String::new(),
        output_sha256: String::new(),
        strings_artifact_id: String::new(),
        readable_artifact_id: String::new(),
        analysis: None,
        tools: vec![],
        observation: json!({}),
        warnings: vec![],
    };
    let operation: Result<()> = async { match step.tool {
        d::RecoveryTool::Upx => {
            ctx.reaped.store(false,Ordering::SeqCst);
            let outcome = protection::process(&bytes,work,Some("upx"),protection::ProcessLimits::default(),ctx.cancel.clone()).await?;
            let state = outcome["state"].as_str().unwrap_or("FAILED");
            let no_process = ["NOT_REQUIRED","UNSUPPORTED","UNAVAILABLE"].contains(&state);
            ensure!(no_process || outcome["processes_reaped"] == true,"UPX 进程回收未确认");
            ctx.reaped.store(true,Ordering::SeqCst);
            result.status = if state=="NOT_REQUIRED" {"NOT_FOUND"} else {state}.into();
            if !no_process {
                let log = ctx.control.upload_bytes(&ctx.lease,"upx-result.json","application/json",serde_json::to_vec_pretty(&outcome)?).await?;
                result.tools.push(d::ToolExecution {
                    name:"upx".into(),version:outcome["tool_version"].as_str().unwrap_or_default().into(),
                    command:vec!["upx".into(),"-d".into(),"-o".into(),"derived.bin".into(),"original.bin".into()],
                    started_at:outcome["started_at"].as_str().unwrap_or_default().into(),finished_at:outcome["finished_at"].as_str().unwrap_or_default().into(),
                    exit_code:outcome["exit_code"].as_i64().map(|v|v as i32),terminated:outcome["timed_out"]==true || outcome["cancelled"]==true,
                    log_artifact_id:log.id,details:json!({"processes_reaped":true,"target_executed":false,"input_sha256":hash}),
                });
            }
            if state=="PROCESSED" {
                let derived = work.join("protection-upx/derived.bin");
                let artifact = ctx.control.upload_file(&ctx.lease,&derived,"unpacked.bin","application/octet-stream").await?;
                result.output_artifact_id = artifact.id;
                result.output_sha256 = artifact.sha256;
            }
            result.observation = outcome;
        }
        d::RecoveryTool::Floss => {
            if !bytes.starts_with(b"MZ") {
                result.status = "UNSUPPORTED".into();
                result.warnings.push("当前固定的 FLOSS 适配器只接受 PE x86/x64".into());
            } else {
                let (output,record) = process_tool(ctx,recovery::floss_spec(&input,work)?,"floss",recovery::FLOSS_VERSION).await?;
                result.tools.push(record);
                if output.exit_code==Some(0) && !output.timed_out && !output.cancelled && !output.truncated {
                    let raw: Value = serde_json::from_slice(&output.stdout).context("FLOSS JSON 输出无效")?;
                    let strings = recovery::floss_strings(&raw,&bytes)?;
                    let raw_artifact = ctx.control.upload_bytes(&ctx.lease,"floss-raw.json","application/json",output.stdout).await?;
                    save_strings(ctx,&mut result,&strings).await?;
                    result.observation["raw_artifact_id"] = json!(raw_artifact.id);
                    result.status = if strings.strings.is_empty() {"NOT_FOUND"} else {"RECOVERED"}.into();
                } else {
                    result.observation = json!({"exit_code":output.exit_code,"timed_out":output.timed_out,"cancelled":output.cancelled,"truncated":output.truncated});
                    result.warnings.push("FLOSS 未完成有效输出，保留原始日志；可调整步骤或记录缺口".into());
                }
            }
        }
        d::RecoveryTool::BuiltinStrings => {
            let raw = deobfuscation::recover(&bytes,&work.join("strings")).await?;
            let strings = recovery::builtin_strings(&raw,&bytes)?;
            save_strings(ctx,&mut result,&strings).await?;
            result.status = if strings.strings.is_empty() {"NOT_FOUND"} else {"CANDIDATES"}.into();
        }
        d::RecoveryTool::Ghidra | d::RecoveryTool::IdaD810 => {
            let manifest_path = work.join("manifest.json");
            ctx.control.download(&ctx.lease,payload["manifest_artifact_id"].as_str().context("缺少快照清单")?,&manifest_path,&ctx.cancel).await?;
            let manifest: d::SnapshotManifest = serde_json::from_slice(&tokio::fs::read(&manifest_path).await?)?;
            let path = &manifest.files.first().context("二进制清单为空")?.path;
            let (mut analysis, raw_path) = if step.tool == d::RecoveryTool::Ghidra {
                (decompile(ctx,work,&input,path).await?,work.join("ghidra-result.json"))
            } else {
                let bridge = ctx.tools.script_dir.parent().context("工具目录无效")?.join("ida/d810_export.py");
                let adapter = aegis_application::ida_d810::D810::discover(&bridge)?;
                let request = json!({"plugin_root":adapter.plugin_root,"dependencies":adapter.dependencies,"profile":step.profile.unwrap_or(d::D810Profile::Instructions),"snapshot_path":path,"max_functions":80});
                tokio::fs::write(work.join("d810-request.json"),serde_json::to_vec_pretty(&request)?).await?;
                let (output,record) = process_tool(ctx,adapter.spec(&bridge,&input,work)?,"ida-d810",&format!("IDA {}; Hex-Rays {}",adapter.ida_version,adapter.hexrays_version)).await?;
                result.tools.push(record.clone());
                let raw_path = work.join("d810-result.json");
                for name in ["ida.log","d810-error.txt"] {
                    if work.join(name).is_file() {
                        ctx.control.upload_file(&ctx.lease,&work.join(name),name,"text/plain; charset=utf-8").await?;
                    }
                }
                ensure!(output.exit_code==Some(0) && !output.timed_out && !output.cancelled && raw_path.is_file(),"IDA / D-810 未生成有效结果，已保留批处理日志");
                let mut analysis: d::AnalysisResult = serde_json::from_slice(&tokio::fs::read(&raw_path).await?)?;
                ensure!(analysis.metadata["hexrays_initialized"]==true && analysis.metadata["d810_hooks_installed"]==true,"IDA / D-810 组件未完成初始化");
                result.observation["changed_functions"] = analysis.metadata["d810_changed_functions"].clone();
                result.observation["rule_matches"] = analysis.metadata["d810_rule_matches"].clone();
                analysis.tools.push(record);
                (analysis,raw_path)
            };
            let raw_artifact = ctx.control.upload_file(&ctx.lease,&raw_path,"original-pseudocode.json","application/json").await?;
            analysis.metadata["raw_decompile_artifact_id"] = json!(raw_artifact.id);
            analysis.metadata["analysis_input_sha256"] = json!(hash);
            analysis.metadata["target_sha256"] = json!(manifest.target_sha256);
            if let Some(strings_id) = payload["strings_artifact_id"].as_str().filter(|id|!id.is_empty()) {
                let strings_path = work.join("recovered-strings.json");
                ctx.control.download(&ctx.lease,strings_id,&strings_path,&ctx.cancel).await?;
                let strings: d::RecoveredStrings = serde_json::from_slice(&tokio::fs::read(&strings_path).await?)?;
                let annotated = recovery::annotate(&mut analysis,&strings,&hash)?;
                analysis.metadata["recovered_strings_artifact_id"] = json!(strings_id);
                result.observation["annotated_string_count"] = json!(annotated);
            }
            analysis.validate(&manifest).map_err(anyhow::Error::msg)?;
            let readable = recovery::readable_code(&analysis,&hash);
            let artifact = ctx.control.upload_bytes(&ctx.lease,"recovered-pseudocode.c","text/plain; charset=utf-8",readable.into_bytes()).await?;
            result.readable_artifact_id = artifact.id;
            result.tools = analysis.tools.clone();
            result.observation["function_count"] = json!(analysis.units.len());
            result.observation["partial"] = json!(analysis.partial());
            result.observation["raw_artifact_id"] = json!(raw_artifact.id);
            result.observation["analysis_input_sha256"] = json!(hash);
            result.warnings = analysis.warnings.clone();
            result.analysis = Some(analysis);
            result.status = "COMPLETED".into();
        }
    }
    Ok(()) }.await;
    if let Err(error) = operation {
        ensure!(
            ctx.reaped.load(Ordering::SeqCst),
            "逆向工具失败且进程回收未确认：{error}"
        );
        result.status = "FAILED".into();
        result.analysis = None;
        result.observation["error"] = json!(error.to_string());
        result.warnings.push(error.to_string());
    }
    ensure!(!ctx.cancel.is_cancelled(), "逆向步骤已取消");
    let artifact = ctx
        .control
        .upload_bytes(
            &ctx.lease,
            "recovery-result.json",
            "application/json",
            serde_json::to_vec_pretty(&result)?,
        )
        .await?;
    Ok(artifact.id)
}

async fn save_strings(
    ctx: &JobContext,
    result: &mut d::RecoveryResult,
    strings: &d::RecoveredStrings,
) -> Result<()> {
    let artifact = ctx
        .control
        .upload_bytes(
            &ctx.lease,
            "recovered-strings.json",
            "application/json",
            serde_json::to_vec_pretty(strings)?,
        )
        .await?;
    result.strings_artifact_id = artifact.id;
    let text = strings
        .strings
        .iter()
        .map(|s| {
            format!(
                "[{}] function={:?}, call={:?}\n{}\n",
                s.kind, s.function_address, s.call_address, s.text
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let readable = ctx
        .control
        .upload_bytes(
            &ctx.lease,
            "recovered-strings.txt",
            "text/plain; charset=utf-8",
            text.into_bytes(),
        )
        .await?;
    result.readable_artifact_id = readable.id;
    result.observation = json!({"recovered_string_count":strings.strings.len(),"omitted":strings.omitted,"preview":strings.strings.iter().take(16).collect::<Vec<_>>()});
    result.warnings = strings.limitations.clone();
    Ok(())
}
