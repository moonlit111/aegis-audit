use aegis_domain::{Artifact, AuditRun, ProgramUnit, Project, Snapshot};
use anyhow::{Result, bail};
use serde::Serialize;
use serde_json::{Value, json};

#[derive(Serialize)]
pub struct ReportDocument<'a> {
    pub schema_version: u32,
    pub generated_at: String,
    pub project: &'a Project,
    pub snapshot: &'a Snapshot,
    pub run: &'a AuditRun,
    pub units: &'a [ProgramUnit],
    pub artifacts: &'a [Artifact],
    pub coverage: Value,
    pub checks: Value,
}

pub fn render(
    project: &Project,
    snapshot: &Snapshot,
    run: &AuditRun,
    units: &[ProgramUnit],
    artifacts: &[Artifact],
    format: &str,
) -> Result<(Vec<u8>, &'static str, &'static str)> {
    let document = ReportDocument {
        schema_version: 1,
        generated_at: aegis_domain::now(),
        project,
        snapshot,
        run,
        units,
        artifacts,
        coverage: run.summary.clone(),
        checks: json!({"vulnerability_audit":"NOT_RUN","independent_review":"NOT_RUN","fuzzing":"NOT_RUN","exploitation":"NOT_RUN","note":"本报告仅包含真实程序结构分析；没有执行漏洞检测或利用验证。"}),
    };
    match format {
        "json" => Ok((
            serde_json::to_vec_pretty(&document)?,
            "application/json",
            "json",
        )),
        "markdown" => {
            let mut text = format!(
                "# AegisAudit 程序结构分析报告\n\n项目：{}\n\n任务：{}\n\n状态：{:?}\n\n目标 SHA-256：{}\n\n本报告仅包含程序结构分析。漏洞审计、独立复核、模糊测试和利用验证均未执行。\n\n| 程序单元 | 文件 | 位置 / 地址 | 解析质量 |\n| --- | --- | --- | --- |\n",
                md(&project.name),
                run.id,
                run.state,
                snapshot.target_sha256
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
                "<!doctype html><html lang=\"zh-CN\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>AegisAudit 结构分析报告</title><style>body{{max-width:1100px;margin:48px auto;padding:0 24px;font:15px/1.7 system-ui;color:#172b28}}h1{{font-size:30px}}table{{width:100%;border-collapse:collapse}}th,td{{text-align:left;border-bottom:1px solid #dce7e3;padding:10px}}.note{{padding:16px;background:#f1f6f3;border-left:3px solid #2f7462}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f5f7f6;padding:16px}}code{{overflow-wrap:anywhere}}</style><h1>AegisAudit · 程序结构分析报告</h1><p>项目：{} · 状态：{:?}</p><p>任务：<code>{}</code></p><p>目标 SHA-256：<code>{}</code></p><p class=\"note\">本报告仅包含真实程序结构分析。漏洞审计、独立复核、模糊测试和利用验证均未执行。</p><table><thead><tr><th>程序单元</th><th>文件</th><th>位置 / 地址</th><th>解析质量</th></tr></thead><tbody>",
                escape(&project.name),
                run.state,
                escape(&run.id),
                escape(&snapshot.target_sha256)
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
            body.push_str(&format!(
                "</tbody></table><h2>覆盖与错误</h2><pre>{}</pre><p>{}</p><h2>证据产物</h2><ul>",
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
            body.push_str("</ul><p>可在 AegisAudit 对应任务中查看或下载以上证据。报告中的结构分析完成状态不表示目标安全。</p></html>");
            Ok((body.into_bytes(), "text/html; charset=utf-8", "html"))
        }
        _ => bail!("unsupported report format"),
    }
}

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
