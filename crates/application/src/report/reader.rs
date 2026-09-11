//! One reader-facing document, rendered to both HTML (including PDF) and Markdown.
//! Facts are selected here once so formats cannot silently omit or strengthen evidence.
use super::{ReportDocument, escape};
use crate::audit::{Plan, ReportOutput};
use aegis_domain::{AgentTask, EvidenceRef, Finding, ProgramUnit, Review, RuntimeRecord};
use anyhow::Result;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

enum Block {
    Paragraph(String),
    Note(String),
    Fields(Vec<(String, String)>),
    Metrics(Vec<(String, String)>),
    List(Vec<String>),
    Table {
        headers: Vec<String>,
        rows: Vec<Vec<String>>,
    },
    Code {
        language: String,
        text: String,
        caption: String,
    },
}

struct Section {
    id: String,
    title: String,
    blocks: Vec<Block>,
    children: Vec<Section>,
}
impl Section {
    fn new(id: impl Into<String>, title: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            blocks: vec![],
            children: vec![],
        }
    }
    fn paragraph(&mut self, text: impl Into<String>) {
        let text = text.into();
        if !text.trim().is_empty() {
            self.blocks.push(Block::Paragraph(text));
        }
    }
    fn note(&mut self, text: impl Into<String>) {
        self.blocks.push(Block::Note(text.into()));
    }
    fn fields(&mut self, fields: Vec<(String, String)>) {
        self.blocks.push(Block::Fields(
            fields
                .into_iter()
                .filter(|(_, v)| !v.trim().is_empty())
                .collect(),
        ));
    }
    fn list(&mut self, items: Vec<String>) {
        if !items.is_empty() {
            self.blocks.push(Block::List(items));
        }
    }
    fn table(&mut self, headers: &[&str], rows: Vec<Vec<String>>) {
        if !rows.is_empty() {
            self.blocks.push(Block::Table {
                headers: headers.iter().map(|s| (*s).into()).collect(),
                rows,
            });
        }
    }
    fn code(&mut self, language: &str, text: &str, caption: &str) {
        if !text.is_empty() {
            self.blocks.push(Block::Code {
                language: language.into(),
                text: text.into(),
                caption: caption.into(),
            });
        }
    }
}

pub(super) fn render(doc: &ReportDocument<'_>, html: bool) -> Result<String> {
    let sections = build(doc)?;
    let target = if doc.snapshot.name.is_empty() {
        &doc.project.name
    } else {
        &doc.snapshot.name
    };
    let title = format!("{target} · AegisAudit 分析报告");
    let metadata = Block::Fields(vec![
        ("项目".into(), doc.project.name.clone()),
        ("分析目标".into(), target.clone()),
        ("任务".into(), doc.run.id.clone()),
        ("任务状态".into(), label(&doc.snapshot_state)),
        ("分析范围".into(), label(&doc.run.scope)),
        ("数据截至".into(), doc.generated_at.clone()),
        ("目标 SHA-256".into(), doc.snapshot.target_sha256.clone()),
    ]);
    let note = if doc.interim {
        "阶段报告：分析或关联验证尚未结束，本报告固定保存导出时的结果。"
    } else if doc.run.state != aegis_domain::RunState::Completed {
        "结果快照：任务未完整完成，结论仅适用于已完成的部分；中断原因和覆盖缺口见下文。"
    } else {
        "结果快照：本报告固定保存导出时的结果，后续复核和验证不会改写此文件。"
    };
    let footer = "静态证实不等于运行复现；组件验证只适用于所记录的组件。未执行、未复现或未观察到崩溃均不能证明目标安全。完整结构化记录可另行导出 JSON，证据产物可在对应任务中查看或下载。";
    let mut output = String::new();
    if html {
        output.push_str(&format!(
            "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\"><title>{}</title><style>{}</style></head><body><main><header class=\"cover\"><p class=\"eyebrow\">AEGISAUDIT / 分析报告</p><h1>{}</h1>",
            escape(&title), include_str!("style.css"), escape(target)
        ));
        html_block(&metadata, &mut output);
        html_block(&Block::Note(note.into()), &mut output);
        output.push_str("</header><nav aria-label=\"报告目录\"><strong>目录</strong>");
        for section in &sections {
            output.push_str(&format!(
                "<a href=\"#{}\">{}</a>",
                escape(&section.id),
                escape(&section.title)
            ));
        }
        output.push_str("</nav>");
        for section in &sections {
            html_section(section, 2, &mut output);
        }
        output.push_str(&format!(
            "<footer>{}</footer></main></body></html>",
            escape(footer)
        ));
    } else {
        output.push_str(&format!(
            "# {}\n\n",
            md_inline(&title.replace(['\r', '\n'], " "))
        ));
        md_block(&metadata, &mut output);
        md_block(&Block::Note(note.into()), &mut output);
        for section in &sections {
            md_section(section, 2, &mut output);
        }
        output.push_str(&format!("---\n\n{}\n", md_text(footer)));
    }
    Ok(output)
}

fn html_section(section: &Section, level: usize, output: &mut String) {
    output.push_str(&format!(
        "<section id=\"{}\" class=\"{}\"><h{level}>{}</h{level}>",
        escape(&section.id),
        if level == 2 { "chapter" } else { "subsection" },
        escape(&section.title)
    ));
    for block in &section.blocks {
        html_block(block, output);
    }
    for child in &section.children {
        html_section(child, (level + 1).min(6), output);
    }
    output.push_str("</section>");
}
fn html_block(block: &Block, output: &mut String) {
    match block {
        Block::Paragraph(text) => output.push_str(&format!("<p>{}</p>", escape(text))),
        Block::Note(text) => output.push_str(&format!("<p class=\"note\">{}</p>", escape(text))),
        Block::Fields(fields) | Block::Metrics(fields) => {
            let class = if matches!(block, Block::Metrics(_)) {
                "metrics"
            } else {
                "fields"
            };
            output.push_str(&format!("<dl class=\"{class}\">"));
            for (key, value) in fields {
                output.push_str(&format!(
                    "<div><dt>{}</dt><dd>{}</dd></div>",
                    escape(key),
                    escape(value)
                ));
            }
            output.push_str("</dl>");
        }
        Block::List(items) => {
            output.push_str("<ul>");
            for item in items {
                output.push_str(&format!("<li>{}</li>", escape(item)));
            }
            output.push_str("</ul>");
        }
        Block::Table { headers, rows } => {
            output.push_str("<div class=\"table-wrap\"><table><thead><tr>");
            for cell in headers {
                output.push_str(&format!("<th scope=\"col\">{}</th>", escape(cell)));
            }
            output.push_str("</tr></thead><tbody>");
            for row in rows {
                output.push_str("<tr>");
                for cell in row {
                    output.push_str(&format!("<td>{}</td>", escape(cell)));
                }
                output.push_str("</tr>");
            }
            output.push_str("</tbody></table></div>");
        }
        Block::Code {
            language,
            text,
            caption,
        } => {
            output.push_str("<figure class=\"code-evidence\">");
            if !caption.is_empty() {
                output.push_str(&format!("<figcaption>{}</figcaption>", escape(caption)));
            }
            output.push_str(&format!(
                "<pre><code class=\"language-{}\">{}</code></pre></figure>",
                escape(language),
                escape(text)
            ));
        }
    }
}
fn md_section(section: &Section, level: usize, output: &mut String) {
    output.push_str(&format!(
        "{} {}\n\n",
        "#".repeat(level),
        md_inline(&section.title.replace(['\r', '\n'], " "))
    ));
    for block in &section.blocks {
        md_block(block, output);
    }
    for child in &section.children {
        md_section(child, (level + 1).min(6), output);
    }
}
fn md_block(block: &Block, output: &mut String) {
    match block {
        Block::Paragraph(text) => output.push_str(&format!("{}\n\n", md_text(text))),
        Block::Note(text) => {
            output.push_str(&format!("> {}\n\n", md_text(text).replace('\n', "\n> ")))
        }
        Block::Fields(fields) | Block::Metrics(fields) => {
            for (key, value) in fields {
                output.push_str(&format!("**{}**：{}\n\n", md_inline(key), md_text(value)));
            }
        }
        Block::List(items) => {
            for item in items {
                output.push_str(&format!("- {}\n", md_text(item).replace('\n', "\n  ")));
            }
            output.push('\n');
        }
        Block::Table { headers, rows } => {
            let row = |cells: &[String]| {
                format!(
                    "| {} |\n",
                    cells
                        .iter()
                        .map(|s| md_inline(s).replace('\n', "<br>"))
                        .collect::<Vec<_>>()
                        .join(" | ")
                )
            };
            output.push_str(&row(headers));
            output.push_str(&format!("| {} |\n", vec!["---"; headers.len()].join(" | ")));
            for cells in rows {
                output.push_str(&row(cells));
            }
            output.push('\n');
        }
        Block::Code {
            language,
            text,
            caption,
        } => {
            if !caption.is_empty() {
                output.push_str(&format!("{}\n\n", md_text(caption)));
            }
            // A fence longer than every input run preserves the original code, even if it
            // contains Markdown fences. Never HTML-escape, flatten, or rewrite code quotes.
            let longest = text
                .split(|c| c != char::from(96))
                .map(str::len)
                .max()
                .unwrap_or(0);
            let fence = "\u{60}".repeat(3.max(longest + 1));
            output.push_str(&format!("{fence}{language}\n{text}"));
            if !text.ends_with('\n') {
                output.push('\n');
            }
            output.push_str(&format!("{fence}\n\n"));
        }
    }
}
fn md_text(text: &str) -> String {
    text.replace("\r\n", "\n")
        .replace('\r', "\n")
        .split('\n')
        .map(md_inline)
        .collect::<Vec<_>>()
        .join("  \n")
}
fn md_inline(text: &str) -> String {
    let chars: Vec<_> = text.chars().collect();
    let mut out = String::new();
    for (i, &ch) in chars.iter().enumerate() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '_' if i > 0
                && chars[i - 1].is_alphanumeric()
                && chars.get(i + 1).is_some_and(|c| c.is_alphanumeric()) =>
            {
                out.push(ch)
            }
            '\\' | '*' | '_' | '[' | ']' | '(' | ')' | '!' | '|' | '#' | '+' | '-' => {
                out.push('\\');
                out.push(ch);
            }
            c if c == char::from(96) => {
                out.push('\\');
                out.push(c);
            }
            '\r' => {}
            _ => out.push(ch),
        }
    }
    out
}

fn label(value: &str) -> String {
    let chinese = match value {
        "NOT_RUN" => "未执行",
        "QUEUED" => "排队中",
        "RUNNING" => "执行中",
        "WAITING_EXECUTOR" => "等待执行器",
        "CANCELLING" => "正在取消",
        "CANCELLED" => "已取消",
        "COMPLETED" | "SUCCEEDED" => "已完成",
        "PARTIAL" => "部分完成",
        "FAILED" | "ERROR" => "失败",
        "LIMIT_REACHED" => "达到限制",
        "VALIDATED" => "静态证实",
        "REJECTED" => "已否决",
        "INCONCLUSIVE" => "待补证",
        "UNREVIEWED" => "未复核",
        "VERIFIED_COMPONENT" => "组件验证通过",
        "REPRODUCED" => "已复现",
        "NOT_REPRODUCED" => "未复现",
        "CRASH_OBSERVED" => "观察到崩溃",
        "NO_CRASH_OBSERVED" => "未观察到崩溃",
        "CRITICAL" => "严重",
        "HIGH" => "高",
        "MEDIUM" => "中",
        "LOW" => "低",
        "UNKNOWN" => "未知",
        "MODEL" => "模型",
        "HUMAN" => "人工",
        "COMPONENT" => "组件",
        "ORIGINAL" => "原始目标",
        "INSTRUMENTED_BUILD" => "插桩构建",
        "REBUILT_TARGET" => "重建目标",
        "FUZZ" => "模糊测试",
        "VERIFY" => "运行验证",
        "SECURITY_AUDIT" => "漏洞审计",
        "STRUCTURE_ANALYSIS" => "结构分析",
        "RUNTIME_VERIFICATION" => "运行验证",
        "DYNAMIC_TESTING" => "动态测试",
        "INPUT_CONTROL" => "输入控制",
        "REACHABILITY" => "危险操作可达性",
        "DEFENSE_GAP" => "防护缺口",
        "EXTRA_PRECONDITION" => "额外攻击前提",
        "SUPPORTED" => "有证据支持",
        "REFUTED" => "被证据否定",
        "UNSUPPORTED" => "不支持",
        "NEEDS_CONFIGURATION" => "待补配置",
        _ => {
            return if value.is_empty() {
                "未记录".into()
            } else {
                value.into()
            };
        }
    };
    format!("{chinese}（{value}）")
}
fn field(key: &str, value: impl Into<String>) -> (String, String) {
    (key.into(), value.into())
}
fn text_value(value: &Value) -> String {
    value.as_str().map(str::to_owned).unwrap_or_default()
}
fn unit_name(doc: &ReportDocument<'_>, id: &str) -> String {
    doc.units
        .iter()
        .find(|u| u.id == id)
        .map(|u| format!("{} · {}", u.unit.name, u.unit.path))
        .unwrap_or_else(|| id.into())
}
fn position(unit: &ProgramUnit) -> String {
    if !unit.unit.address.is_empty() {
        unit.unit.address.clone()
    } else if unit.unit.start_line > 0 {
        format!("L{}-L{}", unit.unit.start_line, unit.unit.end_line)
    } else {
        "未记录位置".into()
    }
}
fn latest_task<'a>(doc: &'a ReportDocument<'_>, role: &str) -> Option<&'a AgentTask> {
    doc.audit
        .tasks
        .iter()
        .filter(|t| t.role == role && t.status == "SUCCEEDED")
        .max_by_key(|t| (&t.finished_at, &t.created_at, &t.id))
}
fn summary_is_current(doc: &ReportDocument<'_>, task: &AgentTask) -> bool {
    // Runtime records have no finished_at. If any is linked, an old model narrative
    // cannot establish its current result; prefer the frozen structured facts.
    !task.finished_at.is_empty()
        && doc.audit.runtime.is_empty()
        && !doc
            .audit
            .reviews
            .iter()
            .any(|r| r.created_at > task.finished_at)
        && !doc
            .audit
            .findings
            .iter()
            .any(|f| f.created_at > task.finished_at)
        && !doc
            .audit
            .annotations
            .iter()
            .any(|a| a.updated_at > task.finished_at)
        && !doc
            .audit
            .tasks
            .iter()
            .any(|t| t.role != "REPORTER" && t.finished_at > task.finished_at)
}

fn build(doc: &ReportDocument<'_>) -> Result<Vec<Section>> {
    let mut findings: Vec<_> = doc.audit.findings.iter().collect();
    let severity = |f: &&Finding| match f.draft.severity.as_str() {
        "CRITICAL" => 0,
        "HIGH" => 1,
        "MEDIUM" => 2,
        "LOW" => 3,
        _ => 4,
    };
    findings.sort_by(|a, b| {
        (a.review_status == "REJECTED")
            .cmp(&(b.review_status == "REJECTED"))
            .then_with(|| severity(a).cmp(&severity(b)))
            .then_with(|| a.created_at.cmp(&b.created_at))
            .then_with(|| a.id.cmp(&b.id))
    });
    let count = |status: &str| {
        findings
            .iter()
            .filter(|f| f.review_status == status)
            .count()
    };
    let validated = count("VALIDATED");
    let rejected = count("REJECTED");
    let inconclusive = count("INCONCLUSIVE");
    let pending = findings.len() - validated - rejected - inconclusive;
    let mut overview = Section::new("overview", "结论与风险概览");
    overview.blocks.push(Block::Metrics(vec![
        field("静态证实", validated.to_string()),
        field("待复核", pending.to_string()),
        field("待补证", inconclusive.to_string()),
        field("已否决", rejected.to_string()),
    ]));
    overview.paragraph(format!(
        "共记录 {} 条发现；{} 条尚未被否决，其中静态证实 {} 条。{}",
        findings.len(),
        findings.len() - rejected,
        validated,
        coverage_sentence(doc)
    ));
    if findings.is_empty() {
        overview.note(if doc.checks["vulnerability_audit"] == "NOT_RUN" {
            "尚未执行漏洞审计，当前没有可用于判断漏洞是否存在的审计结论。"
        } else {
            "当前保存结果中没有候选发现。请结合任务状态与覆盖缺口阅读；这不表示未审计范围或整个目标安全。"
        });
    } else {
        overview.paragraph("以下按严重程度列出未否决的发现。候选严重度不等于已确认风险；已否决候选单独保留在后文。");
        overview.table(
            &["编号 / 发现", "严重程度", "复核结论", "运行验证"],
            findings
                .iter()
                .enumerate()
                .filter(|(_, f)| f.review_status != "REJECTED")
                .map(|(i, f)| {
                    vec![
                        format!("F-{:03} · {}", i + 1, f.draft.title),
                        label(&f.draft.severity),
                        label(&f.review_status),
                        label(&f.verification_status),
                    ]
                })
                .collect(),
        );
    }
    overview.table(
        &["审计项目", "导出时状态"],
        [
            ("vulnerability_audit", "漏洞审计"),
            ("independent_review", "独立复核"),
            ("runtime_verification", "运行验证"),
            ("fuzzing", "模糊测试"),
            ("exploitation", "利用验证"),
        ]
        .iter()
        .map(|(key, name)| {
            vec![
                (*name).into(),
                label(doc.checks[*key].as_str().unwrap_or("NOT_RUN")),
            ]
        })
        .collect(),
    );
    if !doc.run.error.trim().is_empty() {
        overview.note(format!("任务中断 / 错误：{}", doc.run.error));
    }

    let mut active = Section::new("findings", "发现与复核");
    let mut dismissed = Section::new("rejected", "已否决候选与复核依据");
    dismissed
        .note("以下候选已被保存的复核结论否决，不计入未否决发现。原始主张和反证保留用于追溯。");
    for (index, finding) in findings.iter().enumerate() {
        let section = finding_section(doc, finding, index + 1);
        if finding.review_status == "REJECTED" {
            dismissed.children.push(section);
        } else {
            active.children.push(section);
        }
    }
    if active.children.is_empty() {
        active.paragraph("当前没有未否决的发现。");
    }
    let mut sections = vec![overview, active];
    if !doc.audit.runtime.is_empty() {
        let mut runtime = Section::new("runtime", "运行验证与动态测试");
        runtime
            .note("验证结论按每条记录的实际范围呈现。完成测试表示已记录观察结果，不表示目标安全。");
        for (i, record) in doc.audit.runtime.iter().enumerate() {
            runtime.children.push(runtime_section(record, i + 1)?);
        }
        sections.push(runtime);
    }
    if doc.checks["exploitation"] == "COMPLETED" {
        let mut exploitation = Section::new("exploitation", "利用验证证据");
        exploitation.paragraph("任务记录利用验证已完成。具体触发结果与影响以所列证据及其验证范围为准，不据此推定任意代码执行或部署环境已被利用。");
        exploitation.fields(vec![
            field(
                "利用证据",
                text_value(&doc.run.summary["exploitation_artifact_id"]),
            ),
            field(
                "利用输入 / 复现配方",
                text_value(&doc.run.summary["exploitation_input_artifact_id"]),
            ),
        ]);
        if doc.run.summary["exploitation_artifact_id"]
            .as_str()
            .is_none_or(str::is_empty)
        {
            exploitation.note("未记录利用证据产物，无法从本报告核对实际观察结果。");
        }
        sections.push(exploitation);
    }
    sections.push(coverage_section(doc));
    if let Some(task) = latest_task(doc, "REPORTER")
        && let Ok(report) = serde_json::from_value::<ReportOutput>(task.result.clone())
        && !report.summary.trim().is_empty()
    {
        let mut narrative = Section::new("narrative", "分析摘要与建议");
        if summary_is_current(doc, task) {
            narrative.paragraph(format!("已保存的报告摘要，生成于 {}。", task.finished_at));
            narrative.paragraph(report.summary);
            narrative.list(report.recommendations);
        } else {
            narrative.note("本次导出包含后续复核或关联运行记录，已有摘要未用于概括当前验证结果。请以本报告的发现、复核与运行验证记录为准；各发现的修复建议已列在对应条目中。");
        }
        sections.push(narrative);
    }
    if let Some(task) = latest_task(doc, "PLANNER")
        && let Ok(plan) = serde_json::from_value::<Plan>(task.result.clone())
    {
        let mut strategy = Section::new("strategy", "审计策略与优先级");
        strategy.paragraph(plan.approach);
        strategy.table(
            &["程序单元 / 文件", "优先审计原因"],
            plan.priorities
                .iter()
                .map(|item| vec![unit_name(doc, &item.unit_id), item.reason.clone()])
                .collect(),
        );
        sections.push(strategy);
    }
    if doc.run.summary["recovery"].is_object() {
        sections.push(recovery_section(&doc.run.summary["recovery"]));
    }
    if !doc.audit.annotations.is_empty() {
        let mut annotations = Section::new("annotations", "关键逻辑与人工修订");
        for (i, annotation) in doc.audit.annotations.iter().enumerate() {
            let mut item = Section::new(
                format!("annotation-{}", i + 1),
                unit_name(doc, &annotation.draft.unit_id),
            );
            item.fields(vec![
                field("标签", annotation.draft.tag.clone()),
                field("子类型", annotation.draft.subtype.clone()),
                field(
                    "来源 / 版本",
                    format!("{} · v{}", label(&annotation.actor), annotation.revision),
                ),
                field("依据", annotation.draft.rationale.clone()),
            ]);
            evidence_blocks(&mut item, &annotation.evidence, doc);
            annotations.children.push(item);
        }
        sections.push(annotations);
    }
    if !dismissed.children.is_empty() {
        sections.push(dismissed);
    }
    let mut inventory = Section::new("units", "附录 A · 程序单元清单");
    inventory.paragraph(format!(
        "共 {} 个程序单元。解析质量仅描述结构提取结果，不表示已完成漏洞审计。",
        doc.units.len()
    ));
    inventory.table(
        &["程序单元", "文件", "位置 / 地址", "解析质量"],
        doc.units
            .iter()
            .map(|u| {
                vec![
                    u.unit.name.clone(),
                    u.unit.path.clone(),
                    position(u),
                    u.unit.quality.clone(),
                ]
            })
            .collect(),
    );
    sections.push(inventory);
    sections.push(artifact_section(doc));
    Ok(sections)
}

fn audited_count(doc: &ReportDocument<'_>) -> Option<u64> {
    let tasks: Vec<_> = doc
        .audit
        .tasks
        .iter()
        .filter(|t| t.role == "AUDITOR")
        .collect();
    if tasks.is_empty() {
        return doc.run.summary["audited_unit_count"].as_u64();
    }
    let mut ids = BTreeSet::new();
    for task in tasks.iter().filter(|t| t.status == "SUCCEEDED") {
        if let Some(units) = task.result["audited_unit_ids"].as_array() {
            ids.extend(
                units
                    .iter()
                    .filter_map(Value::as_str)
                    .filter(|id| !id.is_empty()),
            );
        } else if !task.item_key.is_empty() {
            ids.insert(task.item_key.as_str());
        }
    }
    Some(ids.len() as u64)
}
fn coverage_sentence(doc: &ReportDocument<'_>) -> String {
    match (
        audited_count(doc),
        doc.run.summary["eligible_unit_count"].as_u64(),
    ) {
        (Some(a), Some(total)) if total > 0 && a <= total => format!(
            "已完成 {a}/{total} 个可审计单元的语义审计（{:.1}%）；单元完成率不等于逐行覆盖率。",
            a as f64 * 100.0 / total as f64
        ),
        (Some(a), _) => format!("已记录 {a} 个完成语义审计的单元；可审计总数未确认。"),
        _ => "未记录可核对的语义审计覆盖数量。".into(),
    }
}
fn coverage_section(doc: &ReportDocument<'_>) -> Section {
    let mut section = Section::new("coverage", "覆盖范围与限制");
    section.paragraph(coverage_sentence(doc));
    let mut gaps = Vec::new();
    let mut add = |text: String| {
        if !text.trim().is_empty() && !gaps.contains(&text) {
            gaps.push(text);
        }
    };
    add(text_value(&doc.run.summary["audit_coverage_gap"]));
    if doc.run.summary["structure_partial"] == true {
        add("结构分析仅部分完成，未解析范围不具备完整审计证据。".into());
    }
    if doc.run.summary["metadata"]["call_graph_complete"] == false {
        add("调用图不完整；未解析或动态调用不能视为不存在。".into());
    }
    if let Some(warnings) = doc.run.summary["warnings"].as_array() {
        for warning in warnings {
            add(warning.as_str().map(str::to_owned).unwrap_or_else(|| {
                [
                    text_value(&warning["path"]),
                    text_value(&warning["reason"]),
                    text_value(&warning["message"]),
                ]
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(" · ")
            }));
        }
    }
    for task in &doc.audit.tasks {
        if task.role == "REPORTER" && !summary_is_current(doc, task) {
            continue;
        }
        if let Some(limitations) = task.result["limitations"].as_array() {
            for limitation in limitations.iter().filter_map(Value::as_str) {
                add(format!(
                    "{}：{limitation}",
                    if task.role == "AUDITOR" {
                        unit_name(doc, &task.item_key)
                    } else {
                        task.role.clone()
                    }
                ));
            }
        }
        if task.status == "FAILED" || !task.error.is_empty() {
            add(format!(
                "{} · {} · {}：{}",
                task.role,
                unit_name(doc, &task.item_key),
                label(&task.status),
                task.error
            ));
        } else if !["SUCCEEDED", "CANCELLED"].contains(&task.status.as_str()) {
            add(format!(
                "{} · {}：{}",
                task.role,
                unit_name(doc, &task.item_key),
                label(&task.status)
            ));
        }
    }
    let semgrep = &doc.run.summary["metadata"]["semgrep"];
    if semgrep["status"]
        .as_str()
        .is_some_and(|s| s != "COMPLETED" && s != "SUCCEEDED")
    {
        add(format!(
            "静态扫描工具：{}。{}",
            label(semgrep["status"].as_str().unwrap_or("")),
            text_value(&semgrep["reason"])
        ));
    }
    if gaps.is_empty() {
        section.paragraph("未记录额外覆盖限制；请结合上方实际审计数量与验证状态解读。");
    }
    section.list(gaps);
    for (key, title, headers) in [
        ("files", "文件处理情况", ["文件", "处理状态", "原因"]),
        (
            "exclusions",
            "导入时排除的文件或目录",
            ["文件 / 目录", "处理状态", "原因"],
        ),
    ] {
        if let Some(items) = doc.run.summary[key].as_array() {
            let mut files = Section::new(format!("coverage-{key}"), title);
            files.table(
                &headers,
                items
                    .iter()
                    .map(|item| {
                        vec![
                            text_value(&item["path"]),
                            if key == "exclusions" {
                                "已排除".into()
                            } else {
                                label(item["status"].as_str().unwrap_or(""))
                            },
                            text_value(&item["reason"]),
                        ]
                    })
                    .collect(),
            );
            if !files.blocks.is_empty() {
                section.children.push(files);
            }
        }
    }
    section
}

fn finding_section(doc: &ReportDocument<'_>, finding: &Finding, number: usize) -> Section {
    let mut section = Section::new(
        format!("finding-{number}"),
        format!("F-{number:03} · {}", finding.draft.title),
    );
    if finding.review_status == "REJECTED" {
        section.note("已否决候选。下列严重程度、影响与修复描述属于原始主张，请结合复核反证阅读。");
    }
    section.fields(vec![
        field("发现 ID", finding.id.clone()),
        field("主位置", unit_name(doc, &finding.draft.unit_id)),
        field(
            "分类 / 严重程度",
            format!(
                "{} · {} · {}",
                finding.draft.category,
                finding.draft.cwe,
                label(&finding.draft.severity)
            ),
        ),
        field("严重度依据", finding.draft.severity_reason.clone()),
        field(
            "复核 / 运行验证",
            format!(
                "{} · {}",
                label(&finding.review_status),
                label(&finding.verification_status)
            ),
        ),
        field("静态结论范围", label(&finding.static_scope)),
        field("输入来源", finding.draft.input_source.clone()),
        field("危险操作", finding.draft.sink.clone()),
        field("防护缺口", finding.draft.missing_guard.clone()),
        field("攻击前提", finding.draft.preconditions.clone()),
        field("影响", finding.draft.impact.clone()),
        field("修复建议", finding.draft.recommendation.clone()),
    ]);
    let mut evidence = Section::new(format!("finding-{number}-evidence"), "原始代码证据");
    evidence_blocks(&mut evidence, &finding.evidence, doc);
    if evidence.blocks.is_empty() {
        evidence.paragraph("未记录可展开的原始代码证据。");
    }
    section.children.push(evidence);
    let mut reviews: Vec<_> = doc
        .audit
        .reviews
        .iter()
        .filter(|r| r.finding_id == finding.id)
        .collect();
    reviews.sort_by_key(|r| (r.revision, &r.created_at, &r.id));
    for (i, review) in reviews.iter().enumerate() {
        section.children.push(review_section(
            doc,
            review,
            &format!("finding-{number}-review-{}", i + 1),
        ));
    }
    section
}
fn reference_label(reference: &EvidenceRef) -> String {
    let mut parts = vec![if reference.path.is_empty() {
        "未记录文件".into()
    } else {
        reference.path.clone()
    }];
    if reference.start_line > 0 {
        parts.push(format!("L{}-L{}", reference.start_line, reference.end_line));
    }
    if !reference.address.is_empty() {
        parts.push(reference.address.clone());
    }
    parts.join(" · ")
}
fn evidence_blocks(section: &mut Section, references: &[EvidenceRef], doc: &ReportDocument<'_>) {
    for reference in references {
        let caption = format!(
            "{} · 产物 {}",
            reference_label(reference),
            reference.artifact_id
        );
        if reference.quote.is_empty() {
            section.paragraph(caption);
            section.paragraph("本记录未附带原文，请按上述位置查看证据产物。");
        } else {
            let language = doc
                .units
                .iter()
                .find(|u| u.id == reference.unit_id)
                .map(|u| u.unit.language.as_str())
                .unwrap_or("text");
            let language = match language {
                "python" | "c" | "cpp" | "go" | "rust" | "json" => language,
                _ => "text",
            };
            section.code(language, &reference.quote, &caption);
        }
    }
}
fn review_section(doc: &ReportDocument<'_>, review: &Review, id: &str) -> Section {
    let mut section = Section::new(
        id,
        format!(
            "复核 v{} · {} · {}",
            review.revision,
            label(&review.actor),
            label(&review.draft.verdict)
        ),
    );
    section.fields(vec![
        field("复核时间", review.created_at.clone()),
        field("结论依据", review.draft.rationale.clone()),
        field("反证", review.draft.counter_evidence.clone()),
        field("待补信息", review.draft.missing_information.clone()),
    ]);
    let mut references = review.evidence.clone();
    for assessment in &review.draft.assessments {
        section.fields(vec![field(
            &format!(
                "{} · {}",
                label(&assessment.check),
                label(&assessment.status)
            ),
            assessment.rationale.clone(),
        )]);
        let mut locations = Vec::new();
        for input in &assessment.evidence {
            let position = references.iter().position(|r| {
                r.unit_id == input.unit_id
                    && r.start_line == input.start_line
                    && r.end_line == input.end_line
            });
            let reference = if let Some(index) = position {
                &references[index]
            } else {
                let unit = doc.units.iter().find(|u| u.id == input.unit_id);
                references.push(EvidenceRef {
                    unit_id: input.unit_id.clone(),
                    artifact_id: unit.map(|u| u.artifact_id.clone()).unwrap_or_default(),
                    path: unit
                        .map(|u| u.unit.path.clone())
                        .unwrap_or_else(|| input.unit_id.clone()),
                    address: unit.map(|u| u.unit.address.clone()).unwrap_or_default(),
                    start_line: input.start_line,
                    end_line: input.end_line,
                    quote: input.quote.clone(),
                });
                references.last().expect("just inserted evidence")
            };
            locations.push(reference_label(reference));
        }
        if !locations.is_empty() {
            section.paragraph(format!("条件判定引用：{}", locations.join("；")));
        }
    }
    evidence_blocks(&mut section, &references, doc);
    section
}

fn runtime_section(record: &RuntimeRecord, number: usize) -> Result<Section> {
    let mut section = Section::new(
        format!("runtime-{number}"),
        format!(
            "V-{number:03} · {} · {}",
            label(&record.config.mode),
            label(&record.status)
        ),
    );
    section.fields(vec![
        field("验证记录", record.id.clone()),
        field("任务", record.run_id.clone()),
        field(
            "关联发现",
            if record.finding_id.is_empty() {
                "未关联单条发现".into()
            } else {
                record.finding_id.clone()
            },
        ),
        field("入口", record.config.path.clone()),
        field(
            "实际验证范围",
            label(
                record
                    .result
                    .as_ref()
                    .map(|r| r.target_scope.as_str())
                    .unwrap_or(record.config.target_scope()),
            ),
        ),
        field(
            "适配器 / 观察方式",
            format!("{} · {}", record.config.adapter, record.config.observer),
        ),
    ]);
    let Some(result) = &record.result else {
        section.note("尚无完整运行结果；以上状态只表示任务进度，不表示测试已通过。");
        return Ok(section);
    };
    section.fields(vec![
        field("目标 SHA-256", result.target_sha256.clone()),
        field("配置 SHA-256", result.config_hash.clone()),
        field("执行环境 / 镜像", result.image_id.clone()),
        field("复现配方产物", result.recipe_artifact_id.clone()),
        field("原始观察产物", result.observation_artifact_id.clone()),
    ]);
    if !result.observation.error.is_empty() {
        section.note(format!("运行错误：{}", result.observation.error));
    }
    section.table(
        &[
            "轮次",
            "观察到目标现象",
            "退出码",
            "超时 / 截断 / 进程已回收",
        ],
        result
            .observation
            .trials
            .iter()
            .enumerate()
            .map(|(i, t)| {
                vec![
                    format!(
                        "{} · {}",
                        i + 1,
                        if t.label == "baseline" {
                            "正常输入"
                        } else {
                            "探测输入"
                        }
                    ),
                    yes_no(t.observed).into(),
                    t.exit_code
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "未记录".into()),
                    format!(
                        "{} / {} / {}",
                        yes_no(t.timed_out),
                        yes_no(t.truncated),
                        yes_no(t.processes_reaped)
                    ),
                ]
            })
            .collect(),
    );
    if record.config.mode == "FUZZ" {
        section.fields(
            ["engine", "executions", "timeouts", "coverage_feedback"]
                .iter()
                .filter_map(|key| {
                    let value = &result.observation.fuzz[*key];
                    (!value.is_null()).then(|| {
                        field(
                            match *key {
                                "engine" => "模糊测试引擎",
                                "executions" => "执行次数",
                                "timeouts" => "超时次数",
                                _ => "是否使用覆盖反馈",
                            },
                            value
                                .as_str()
                                .map(str::to_owned)
                                .unwrap_or_else(|| value.to_string()),
                        )
                    })
                })
                .collect(),
        );
    }
    let mut seen_details = BTreeMap::new();
    for (i, trial) in result.observation.trials.iter().enumerate() {
        let detail_key = (
            &trial.input_json,
            &trial.input_sha256,
            &trial.exception,
            &trial.crash_signature,
            &trial.stdout,
            &trial.stderr,
        );
        if let Some(previous) = seen_details.get(&detail_key) {
            section.paragraph(format!("第 {} 轮的输入、异常和输出与第 {} 轮相同；本轮观察标记、退出码和进程状态仍逐项列在上表中。", i + 1, previous));
            continue;
        }
        seen_details.insert(detail_key, i + 1);
        let mut detail = Section::new(
            format!("runtime-{number}-trial-{}", i + 1),
            format!("第 {} 轮输入与观察", i + 1),
        );
        detail.fields(vec![
            field("输入 SHA-256", trial.input_sha256.clone()),
            field("异常", trial.exception.clone()),
            field("异常签名", trial.crash_signature.clone()),
        ]);
        for (name, text, language) in [
            ("实际输入", &trial.input_json, "json"),
            ("标准输出", &trial.stdout, "text"),
            ("标准错误", &trial.stderr, "text"),
        ] {
            log_excerpt(&mut detail, name, language, text);
        }
        section.children.push(detail);
    }
    if !result.observation.crashes.is_empty() {
        section.table(
            &["异常输入 SHA-256", "异常签名", "已复现 / 已最小化"],
            result
                .observation
                .crashes
                .iter()
                .map(|c| {
                    vec![
                        c.input_sha256.clone(),
                        c.signature.clone(),
                        format!("{} / {}", yes_no(c.reproduced), yes_no(c.minimized)),
                    ]
                })
                .collect(),
        );
        section.paragraph("完整异常输入及复测日志见原始观察产物。");
    }
    Ok(section)
}
fn yes_no(value: bool) -> &'static str {
    if value { "是" } else { "否" }
}
fn log_excerpt(section: &mut Section, name: &str, language: &str, text: &str) {
    if text.is_empty() {
        return;
    }
    if text.chars().count() <= 6000 && text.lines().count() <= 60 {
        section.code(language, text, name);
    } else {
        let excerpt: String = text
            .lines()
            .take(60)
            .collect::<Vec<_>>()
            .join("\n")
            .chars()
            .take(6000)
            .collect();
        section.code(language, &excerpt, name);
        section.note("日志较长，仅展示前 60 行 / 6000 字符以内的摘录；完整输入、输出和哈希保存在原始观察产物中。");
    }
}
fn recovery_section(recovery: &Value) -> Section {
    let mut section = Section::new("recovery", "逆向与解混淆");
    section.note(
        "工具完成仅表示相应处理步骤结束；派生产物的结论范围不能自动外推到原始程序的运行行为。",
    );
    section.fields(vec![field(
        "处理状态",
        label(recovery["status"].as_str().unwrap_or("")),
    )]);
    section.paragraph(
        recovery["conclusion"]
            .as_str()
            .or(recovery["conclusion"]["summary"].as_str())
            .unwrap_or(""),
    );
    section.paragraph(text_value(&recovery["summary"]));
    section.paragraph(text_value(&recovery["plan"]["assessment"]));
    let mut limitations = BTreeSet::new();
    for value in [
        &recovery["limitations"],
        &recovery["conclusion"]["limitations"],
        &recovery["plan"]["limitations"],
    ] {
        if let Some(items) = value.as_array() {
            limitations.extend(items.iter().filter_map(Value::as_str).map(str::to_owned));
        }
    }
    section.list(limitations.into_iter().collect());
    // Current recovery stores executed records in history; steps is the legacy shape.
    if let Some(steps) = recovery["history"]
        .as_array()
        .or(recovery["steps"].as_array())
    {
        for (i, step) in steps.iter().enumerate() {
            let mut detail = Section::new(
                format!("recovery-step-{}", i + 1),
                format!(
                    "步骤 {} · {}",
                    i + 1,
                    step["tool"]
                        .as_str()
                        .or(step["name"].as_str())
                        .unwrap_or("工具处理")
                ),
            );
            let mut fields = Vec::new();
            for (key, name) in [
                ("status", "执行状态"),
                ("reason", "原因"),
                ("conclusion", "结论"),
                ("input_sha256", "输入 SHA-256"),
                ("output_sha256", "输出 SHA-256"),
                ("input_artifact_id", "输入产物"),
                ("output_artifact_id", "输出产物"),
                ("result_artifact_id", "处理结果产物"),
                ("readable_artifact_id", "可读代码产物"),
                ("strings_artifact_id", "字符串产物"),
                ("artifact_id", "产物 ID"),
                ("log_artifact_id", "日志产物"),
                ("error", "错误"),
            ] {
                if let Some(text) = step[key].as_str() {
                    fields.push(field(
                        name,
                        if key == "status" {
                            label(text)
                        } else {
                            text.into()
                        },
                    ));
                }
            }
            detail.fields(fields);
            let observation = &step["observation"];
            if let Some(count) = observation["recovered_string_count"].as_u64() {
                detail.paragraph(format!("恢复字符串数量：{count}"));
            }
            for key in ["reason", "readability", "mapping"] {
                if let Some(text) = observation[key].as_str() {
                    detail.paragraph(text);
                }
            }
            for value in [&step["warnings"], &observation["limitations"]] {
                if let Some(items) = value.as_array() {
                    detail.list(
                        items
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned)
                            .collect(),
                    );
                }
            }
            for (name, text) in [
                (
                    "标准输出",
                    observation["stdout"]
                        .as_str()
                        .or(step["stdout_tail"].as_str()),
                ),
                (
                    "标准错误",
                    observation["stderr"]
                        .as_str()
                        .or(step["stderr_tail"].as_str()),
                ),
            ] {
                if let Some(text) = text {
                    log_excerpt(&mut detail, name, "text", text);
                }
            }
            section.children.push(detail);
        }
    }
    section
}

fn artifact_ids(value: &Value, ids: &mut BTreeSet<String>) {
    match value {
        Value::Object(fields) => {
            for (key, value) in fields {
                if (key == "artifact_id" || key.ends_with("_artifact_id"))
                    && let Some(id) = value.as_str()
                    && !id.is_empty()
                {
                    ids.insert(id.into());
                }
                artifact_ids(value, ids);
            }
        }
        Value::Array(items) => {
            for item in items {
                artifact_ids(item, ids);
            }
        }
        _ => {}
    }
}
fn artifact_section(doc: &ReportDocument<'_>) -> Section {
    let mut ids: BTreeSet<String> = [
        &doc.snapshot.original_artifact_id,
        &doc.snapshot.normalized_artifact_id,
        &doc.snapshot.manifest_artifact_id,
    ]
    .into_iter()
    .filter(|id| !id.is_empty())
    .cloned()
    .collect();
    ids.extend(doc.units.iter().map(|u| u.artifact_id.clone()));
    for references in doc
        .audit
        .findings
        .iter()
        .map(|f| &f.evidence)
        .chain(doc.audit.reviews.iter().map(|r| &r.evidence))
        .chain(doc.audit.annotations.iter().map(|a| &a.evidence))
    {
        ids.extend(references.iter().map(|r| r.artifact_id.clone()));
    }
    for record in &doc.audit.runtime {
        if let Some(result) = &record.result {
            ids.insert(result.recipe_artifact_id.clone());
            ids.insert(result.observation_artifact_id.clone());
        }
    }
    artifact_ids(&doc.run.summary, &mut ids);
    let artifacts: Vec<_> = doc
        .artifacts
        .iter()
        .filter(|a| ids.contains(&a.id))
        .collect();
    let mut section = Section::new("artifacts", "附录 B · 证据产物");
    section.paragraph(format!(
        "列出正文引用或用于目标、代码与验证结果的 {} 个核心产物。其余 {} 个任务产物可在 JSON 导出和任务产物列表中查看。产物可按 ID 定位，并用 SHA-256 核对内容。",
        artifacts.len(), doc.artifacts.len() - artifacts.len()
    ));
    section.table(
        &["产物 / ID", "SHA-256", "大小"],
        artifacts
            .iter()
            .map(|a| {
                vec![
                    format!("{}\n{}", a.name, a.id),
                    a.sha256.clone(),
                    format!("{} 字节", a.size),
                ]
            })
            .collect(),
    );
    section
}
