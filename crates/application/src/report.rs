use aegis_domain::{Artifact, AuditEvidence, AuditRun, ProgramUnit, Project, Snapshot};
use anyhow::{Result, bail};
use serde::Serialize;
use serde_json::{Value, json};

#[derive(Serialize)]
pub struct ReportDocument<'a> {
    pub schema_version: u32,
    pub generated_at: String,
    pub interim: bool,
    pub snapshot_state: String,
    pub project: &'a Project,
    pub snapshot: &'a Snapshot,
    pub run: &'a AuditRun,
    pub units: &'a [ProgramUnit],
    pub artifacts: &'a [Artifact],
    pub coverage: Value,
    pub checks: Value,
    pub audit: &'a AuditEvidence,
}

pub fn render(
    project: &Project,
    snapshot: &Snapshot,
    run: &AuditRun,
    units: &[ProgramUnit],
    artifacts: &[Artifact],
    audit: &AuditEvidence,
    format: &str,
) -> Result<(Vec<u8>, &'static str, &'static str)> {
    render_at(
        project,
        snapshot,
        run,
        units,
        artifacts,
        audit,
        format,
        &aegis_domain::now(),
    )
}

pub fn is_interim(run: &AuditRun, audit: &AuditEvidence) -> bool {
    !run.state.terminal()
        || audit.runtime.iter().any(|record| {
            matches!(
                record.status.as_str(),
                "QUEUED" | "RUNNING" | "WAITING_EXECUTOR" | "CANCELLING"
            )
        })
}

#[allow(clippy::too_many_arguments)]
pub fn render_at(
    project: &Project,
    snapshot: &Snapshot,
    run: &AuditRun,
    units: &[ProgramUnit],
    artifacts: &[Artifact],
    audit: &AuditEvidence,
    format: &str,
    snapshot_at: &str,
) -> Result<(Vec<u8>, &'static str, &'static str)> {
    let check = |name: &str| run.summary[name].as_str().unwrap_or("NOT_RUN").to_owned();
    let runtime_check = |mode: &str| {
        let records: Vec<_> = audit
            .runtime
            .iter()
            .filter(|r| r.config.mode == mode)
            .collect();
        if records.is_empty() {
            "NOT_RUN"
        } else if records.iter().any(|r| {
            ["QUEUED", "RUNNING", "WAITING_EXECUTOR", "CANCELLING"].contains(&r.status.as_str())
        }) {
            "RUNNING"
        } else if records.iter().all(|r| r.status == "CANCELLED") {
            "CANCELLED"
        } else if records
            .iter()
            .any(|r| r.result.is_none() || ["ERROR", "INCONCLUSIVE"].contains(&r.status.as_str()))
        {
            "PARTIAL"
        } else {
            "COMPLETED"
        }
    };
    let fuzzing_status = runtime_check("FUZZ");
    let runtime_status = runtime_check("VERIFY");
    let reviewed = audit
        .findings
        .iter()
        .filter(|finding| {
            audit
                .reviews
                .iter()
                .any(|review| review.finding_id == finding.id && review.actor == "MODEL")
        })
        .count();
    let review_status = if reviewed > 0 {
        if reviewed == audit.findings.len() {
            "COMPLETED".into()
        } else {
            "PARTIAL".into()
        }
    } else {
        check("independent_review")
    };
    let checks = json!({"vulnerability_audit":check("vulnerability_audit"),"independent_review":review_status,"fuzzing":fuzzing_status,"runtime_verification":runtime_status,"exploitation":check("exploitation")});
    let note = format!(
        "{} · 数据截至 {} · 导出时任务状态 {}。漏洞审计：{}；独立复核：{}；模糊测试：{}；运行验证：{}；利用验证：{}。静态复核不代表已在目标上验证漏洞或利用影响。",
        if is_interim(run, audit) {
            "阶段报告（分析或关联验证尚未结束）"
        } else {
            "结果快照"
        },
        snapshot_at,
        run.state.as_str(),
        check("vulnerability_audit"),
        review_status,
        fuzzing_status,
        runtime_status,
        check("exploitation")
    );
    let document = ReportDocument {
        schema_version: 1,
        generated_at: snapshot_at.into(),
        interim: is_interim(run, audit),
        snapshot_state: run.state.as_str().into(),
        project,
        snapshot,
        run,
        units,
        artifacts,
        coverage: run.summary.clone(),
        checks,
        audit,
    };
    let plan = audit
        .tasks
        .iter()
        .find(|task| task.role == "PLANNER" && task.status == "SUCCEEDED")
        .and_then(|task| serde_json::from_value::<crate::audit::Plan>(task.result.clone()).ok());
    match format {
        "json" => Ok((
            serde_json::to_vec_pretty(&document)?,
            "application/json",
            "json",
        )),
        "markdown" => {
            let mut text = format!(
                "# AegisAudit 分析报告\n\n项目：{}\n\n任务：{}\n\n状态：{:?}\n\n目标 SHA-256：{}\n\n{}\n\n| 程序单元 | 文件 | 位置 / 地址 | 解析质量 |\n| --- | --- | --- | --- |\n",
                md(&project.name),
                run.id,
                run.state,
                snapshot.target_sha256,
                md(&note)
            );
            for unit in units {
                text.push_str(&format!(
                    "| {} | {} | {} | {} |\n",
                    md(&unit.unit.name),
                    md(&unit.unit.path),
                    md(&location(unit)),
                    md(&unit.unit.quality)
                ));
            }
            if let Some(plan) = &plan {
                text.push_str(&format!(
                    "\n## 审计策略与优先级\n\n{}\n\n",
                    md(&plan.approach)
                ));
                for (index, item) in plan.priorities.iter().enumerate() {
                    text.push_str(&format!(
                        "{}. {}：{}\n",
                        index + 1,
                        md(&item.unit_id),
                        md(&item.reason)
                    ));
                }
                for limitation in &plan.limitations {
                    text.push_str(&format!("\n规划限制：{}\n", md(limitation)));
                }
            }
            if run.summary["recovery"].is_object() {
                text.push_str("\n## 逆向与解混淆\n\n工具完成仅表示相应步骤结束；支持范围、失败及可读产物见以下记录。\n\n");
                text.push_str(&format!(
                    "```json\n{}\n```\n",
                    serde_json::to_string_pretty(&run.summary["recovery"])?
                        .replace("```", "\\u0060\\u0060\\u0060")
                ));
            }
            if !audit.findings.is_empty() {
                text.push_str("\n## 发现与复核\n\n");
                for finding in &audit.findings {
                    text.push_str(&format!("静态结论范围：{}\n\n", md(&finding.static_scope)));
                    text.push_str(&format!("### {}\n\n{} · {} · 复核 {} · 验证 {}\n\n输入：{}\n\n危险操作：{}\n\n防护缺口：{}\n\n前提：{}\n\n影响：{}\n\n修复：{}\n\n",
                        md(&finding.draft.title),md(&finding.draft.cwe),md(&finding.draft.severity),md(&finding.review_status),md(&finding.verification_status),
                        md(&finding.draft.input_source),md(&finding.draft.sink),md(&finding.draft.missing_guard),md(&finding.draft.preconditions),md(&finding.draft.impact),md(&finding.draft.recommendation)));
                    for reference in &finding.evidence {
                        text.push_str(&format!(
                            "- 证据：{} L{}–{} {}；产物 {}；引用：{}\n",
                            md(&reference.path),
                            reference.start_line,
                            reference.end_line,
                            md(&reference.address),
                            reference.artifact_id,
                            md(&reference.quote)
                        ));
                    }
                    for review in audit.reviews.iter().filter(|r| r.finding_id == finding.id) {
                        text.push_str(&format!(
                            "\n复核 v{}（{}，{}）：{}\n\n反证：{}\n\n待补信息：{}\n",
                            review.revision,
                            md(&review.actor),
                            md(&review.draft.verdict),
                            md(&review.draft.rationale),
                            md(&review.draft.counter_evidence),
                            md(&review.draft.missing_information)
                        ));
                    }
                }
            }
            if !audit.annotations.is_empty() {
                text.push_str("\n## 关键逻辑与人工修订\n\n");
                for a in &audit.annotations {
                    text.push_str(&format!(
                        "- {} · {} · v{}（{}）：{}\n",
                        md(&a.draft.unit_id),
                        md(&a.draft.tag),
                        a.revision,
                        md(&a.actor),
                        md(&a.draft.rationale)
                    ));
                    for reference in &a.evidence {
                        text.push_str(&format!(
                            "  - 原文：{} L{}-L{}；{}\n",
                            md(&reference.path),
                            reference.start_line,
                            reference.end_line,
                            md(&reference.quote)
                        ));
                    }
                }
            }
            if !audit.runtime.is_empty() {
                text.push_str("\n## 运行验证与动态测试\n\n每条记录固定目标、配置、镜像和输入。组件验证与插桩构建只代表所记录的范围；未复现或未发现崩溃不代表程序安全。\n\n");
                for record in &audit.runtime {
                    text.push_str(&format!(
                        "### {} · {}\n\n任务：{} · 关联发现：{}\n\n入口：{} · 范围：{}\n\n",
                        md(&record.config.mode),
                        md(&record.status),
                        record.run_id,
                        md(&record.finding_id),
                        md(&record.config.path),
                        record.config.target_scope()
                    ));
                    if let Some(result) = &record.result {
                        text.push_str(&format!("配置 SHA-256：{}\n\n镜像：{}\n\n测试产物：{}\n\n原始观察：{}\n\n```json\n{}\n```\n\n",
                            result.config_hash, result.image_id, result.recipe_artifact_id, result.observation_artifact_id,
                            serde_json::to_string_pretty(&result.observation)?.replace("```", "\\u0060\\u0060\\u0060")));
                    }
                }
            }
            if run.summary["exploitation"] == "COMPLETED" {
                text.push_str("\n## 自动利用证据\n\n");
                text.push_str(&format!(
                    "利用证据：{}；利用输入：{}。该证据证明最小输入可稳定触发观察到的内存安全异常，不外推为任意代码执行。\n\n",
                    md(run.summary["exploitation_artifact_id"].as_str().unwrap_or("")),
                    md(run.summary["exploitation_input_artifact_id"].as_str().unwrap_or(""))
                ));
            }
            text.push_str("\n## 覆盖与错误\n\n");
            text.push_str(&format!(
                "```json\n{}\n```\n\n",
                serde_json::to_string_pretty(&run.summary)?.replace("```", "\\u0060\\u0060\\u0060")
            ));
            text.push_str(&format!("任务错误：{}\n\n## 证据产物\n\n", md(&run.error)));
            for artifact in artifacts {
                text.push_str(&format!(
                    "- {}；ID：{}；SHA-256：{}\n",
                    md(&artifact.name),
                    artifact.id,
                    artifact.sha256
                ));
            }
            Ok((text.into_bytes(), "text/markdown; charset=utf-8", "md"))
        }
        "html" => {
            let mut body = format!(
                r#"<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'"><title>AegisAudit 分析报告</title><style>{}</style></head><body><h1>AegisAudit · 分析报告</h1><p>项目：{} · 状态：{:?}</p><p>任务：<code>{}</code></p><p>目标 SHA-256：<code>{}</code></p><p class="note">{}</p><table><thead><tr><th>程序单元</th><th>文件</th><th>位置 / 地址</th><th>解析质量</th></tr></thead><tbody>"#,
                REPORT_STYLE,
                escape(&project.name),
                run.state,
                escape(&run.id),
                escape(&snapshot.target_sha256),
                escape(&note)
            );
            for unit in units {
                body.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    escape(&unit.unit.name),
                    escape(&unit.unit.path),
                    escape(&location(unit)),
                    escape(&unit.unit.quality)
                ));
            }
            body.push_str("</tbody></table>");
            if let Some(plan) = &plan {
                body.push_str(&format!(
                    "<h2>审计策略与优先级</h2><p>{}</p><ol>",
                    escape(&plan.approach)
                ));
                for item in &plan.priorities {
                    body.push_str(&format!(
                        "<li><code>{}</code>：{}</li>",
                        escape(&item.unit_id),
                        escape(&item.reason)
                    ));
                }
                body.push_str("</ol>");
                for limitation in &plan.limitations {
                    body.push_str(&format!("<p>规划限制：{}</p>", escape(limitation)));
                }
            }
            body.push_str("<h2>发现、复核与关键逻辑</h2>");
            if run.summary["recovery"].is_object() {
                body.push_str(&format!("<h2>逆向与解混淆</h2><p>以下记录包含智能体计划、实际工具状态、输入输出哈希与产物引用。</p><pre>{}</pre>",escape(&serde_json::to_string_pretty(&run.summary["recovery"])?)));
            }
            for finding in &audit.findings {
                body.push_str(&format!(
                    "<p>静态结论范围：{}</p>",
                    escape(&finding.static_scope)
                ));
                body.push_str(&format!("<section><h3>{}</h3><p>{} · {} · 复核 {} · 验证 {}</p><p>严重度依据：{}</p><p>输入：{}</p><p>危险操作：{}</p><p>防护缺口：{}</p><p>前提：{}</p><p>影响：{}</p><p>修复：{}</p>",escape(&finding.draft.title),escape(&finding.draft.cwe),escape(&finding.draft.severity),escape(&finding.review_status),escape(&finding.verification_status),escape(&finding.draft.severity_reason),escape(&finding.draft.input_source),escape(&finding.draft.sink),escape(&finding.draft.missing_guard),escape(&finding.draft.preconditions),escape(&finding.draft.impact),escape(&finding.draft.recommendation)));
                for reference in &finding.evidence {
                    body.push_str(&format!(
                        "<p>{} L{}–{} {} · 产物 {}</p><pre>{}</pre>",
                        escape(&reference.path),
                        reference.start_line,
                        reference.end_line,
                        escape(&reference.address),
                        escape(&reference.artifact_id),
                        escape(&reference.quote)
                    ));
                }
                for review in audit.reviews.iter().filter(|r| r.finding_id == finding.id) {
                    body.push_str(&format!(
                        "<p>复核 v{}（{}，{}）：{}</p><p>反证：{}</p><p>待补信息：{}</p>",
                        review.revision,
                        escape(&review.actor),
                        escape(&review.draft.verdict),
                        escape(&review.draft.rationale),
                        escape(&review.draft.counter_evidence),
                        escape(&review.draft.missing_information)
                    ));
                }
                body.push_str("</section>");
            }
            for a in &audit.annotations {
                body.push_str(&format!(
                    "<p>{} · {} · v{}（{}）：{}</p>",
                    escape(&a.draft.unit_id),
                    escape(&a.draft.tag),
                    a.revision,
                    escape(&a.actor),
                    escape(&a.draft.rationale)
                ));
                for reference in &a.evidence {
                    body.push_str(&format!(
                        "<p>{} L{}-L{} · {}</p><pre>{}</pre>",
                        escape(&reference.path),
                        reference.start_line,
                        reference.end_line,
                        escape(&reference.address),
                        escape(&reference.quote)
                    ));
                }
            }
            if !audit.runtime.is_empty() {
                body.push_str("<h2>运行验证与动态测试</h2><p class=\"note\">组件验证与插桩构建只代表记录的范围；未复现或未观察到崩溃不代表程序安全。</p>");
                for record in &audit.runtime {
                    body.push_str(&format!("<section><h3>{} · {}</h3><p>任务：{} · 关联发现：{}</p><p>入口：{} · 范围：{}</p>",
                        escape(&record.config.mode), escape(&record.status), escape(&record.run_id), escape(&record.finding_id), escape(&record.config.path), record.config.target_scope()));
                    if let Some(result) = &record.result {
                        body.push_str(&format!("<p>配置 SHA-256：<code>{}</code></p><p>镜像：<code>{}</code></p><p>测试产物：{} · 原始观察：{}</p><pre>{}</pre>",
                            escape(&result.config_hash), escape(&result.image_id), escape(&result.recipe_artifact_id), escape(&result.observation_artifact_id), escape(&serde_json::to_string_pretty(&result.observation)?)));
                    }
                    body.push_str("</section>");
                }
            }
            if run.summary["exploitation"] == "COMPLETED" {
                body.push_str(&format!(
                    "<h2>自动利用证据</h2><p>利用证据：<code>{}</code>；利用输入：<code>{}</code>。该证据证明最小输入可稳定触发观察到的内存安全异常，不外推为任意代码执行。</p>",
                    escape(run.summary["exploitation_artifact_id"].as_str().unwrap_or("")),
                    escape(run.summary["exploitation_input_artifact_id"].as_str().unwrap_or(""))
                ));
            }
            body.push_str(&format!(
                "<h2>覆盖与错误</h2><pre>{}</pre><p>{}</p><h2>证据产物</h2><ul>",
                escape(&serde_json::to_string_pretty(&run.summary)?),
                escape(&run.error)
            ));
            for artifact in artifacts {
                body.push_str(&format!(
                    "<li>{}；ID：<code>{}</code>；SHA-256：<code>{}</code></li>",
                    escape(&artifact.name),
                    escape(&artifact.id),
                    escape(&artifact.sha256)
                ));
            }
            body.push_str("</ul><p>可在 AegisAudit 对应任务中查看或下载以上证据。报告中的结构分析完成状态不表示目标安全。</p></body></html>");
            Ok((body.into_bytes(), "text/html; charset=utf-8", "html"))
        }
        _ => bail!("unsupported report format"),
    }
}

const REPORT_STYLE: &str = r#"
body{max-width:1100px;margin:40px auto;padding:0 24px;font:14px/1.7 "Segoe UI","Microsoft YaHei",sans-serif;color:#0f172a;background:#fff}
h1{font-size:28px;margin-bottom:20px}h2{font-size:20px;margin-top:28px}h3{font-size:16px}
p,li{overflow-wrap:anywhere;white-space:pre-wrap}table{width:100%;border-collapse:collapse;table-layout:fixed}
th,td{text-align:left;border-bottom:1px solid #e2e8f0;padding:9px;overflow-wrap:anywhere}
th{background:#f8fafc}.note{padding:14px;background:#eff6ff;border-left:3px solid #2563eb}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f8fafc;padding:12px;font:12px/1.6 Consolas,"Microsoft YaHei",monospace}
code{overflow-wrap:anywhere;font-size:12px}
@page{size:A4;margin:16mm 14mm 18mm;@bottom-right{content:counter(page) " / " counter(pages);font:9pt sans-serif;color:#64748b}}
@media print{body{max-width:none;margin:0;padding:0;font-size:10pt}h1{font-size:21pt}h2{font-size:15pt}h3{font-size:12pt}thead{display:table-header-group}tr{break-inside:avoid}h1,h2,h3{break-after:avoid}p{orphans:3;widows:3}pre{font-size:9pt;padding:8px}th,td{padding:6px}}
"#;

pub fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
fn md(text: &str) -> String {
    let mut output = String::new();
    for character in escape(text).replace(['\n', '\r'], " ").chars() {
        if "\\`*_[]()!|".contains(character) {
            output.push('\\');
        }
        output.push(character);
    }
    output
}
fn location(unit: &ProgramUnit) -> String {
    if unit.unit.address.is_empty() {
        format!("L{}–L{}", unit.unit.start_line, unit.unit.end_line)
    } else {
        unit.unit.address.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn untrusted_html_is_escaped() {
        assert_eq!(
            escape("<script>\"x\"</script>"),
            "&lt;script&gt;&quot;x&quot;&lt;/script&gt;"
        );
    }
}
