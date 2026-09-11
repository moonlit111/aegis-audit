//! Target-scoped, read-only agent tools. No filesystem paths or shell commands are accepted.
use aegis_domain as d;
use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};

pub struct Corpus {
    pub units: HashMap<String, d::ProgramUnit>,
    pub order: Vec<String>,
    pub edges: Vec<d::ProgramEdge>,
    pub target: Value,
    aliases: HashMap<String, String>,
    identifiers: HashMap<String, String>,
}

impl Corpus {
    pub fn new(units: Vec<d::ProgramUnit>, edges: Vec<d::ProgramEdge>, target: Value) -> Self {
        let order = units
            .iter()
            .filter(|u| !u.unit.code.trim().is_empty())
            .map(|u| u.id.clone())
            .collect();
        let aliases: HashMap<_, _> = units
            .iter()
            .enumerate()
            .map(|(i, u)| (u.id.clone(), format!("U{:04}", i + 1)))
            .collect();
        let identifiers = aliases
            .iter()
            .map(|(id, alias)| (alias.clone(), id.clone()))
            .collect();
        Self {
            units: units.into_iter().map(|u| (u.id.clone(), u)).collect(),
            order,
            edges,
            target,
            aliases,
            identifiers,
        }
    }
    fn real_id<'a>(&'a self, id: &'a str) -> &'a str {
        self.identifiers.get(id).map(String::as_str).unwrap_or(id)
    }
    fn model_id<'a>(&'a self, id: &'a str) -> &'a str {
        self.aliases.get(id).map(String::as_str).unwrap_or(id)
    }
    pub fn references(&self, value: Value, to_model: bool) -> Value {
        match value {
            Value::Array(items) => Value::Array(
                items
                    .into_iter()
                    .map(|v| self.references(v, to_model))
                    .collect(),
            ),
            Value::Object(mut fields) => {
                for (key, value) in &mut fields {
                    if ["unit_id", "source_id", "target_id"].contains(&key.as_str()) {
                        if let Some(id) = value.as_str() {
                            *value = Value::String(
                                if to_model {
                                    self.model_id(id)
                                } else {
                                    self.real_id(id)
                                }
                                .into(),
                            );
                        }
                    } else if key == "audited_unit_ids" {
                        if let Some(ids) = value.as_array_mut() {
                            for id in ids {
                                if let Some(text) = id.as_str() {
                                    *id = Value::String(
                                        if to_model {
                                            self.model_id(text)
                                        } else {
                                            self.real_id(text)
                                        }
                                        .into(),
                                    );
                                }
                            }
                        }
                    } else {
                        *value = self.references(value.take(), to_model);
                    }
                }
                Value::Object(fields)
            }
            other => other,
        }
    }
    pub fn catalog(&self) -> Value {
        json!({"target":self.target,"total_units":self.order.len(),"catalog_truncated":self.order.len()>500,
            "units":self.order.iter().take(500).map(|id| {
                let u=&self.units[id];
                json!({"unit_id":self.model_id(&u.id),"name":u.unit.name,"path":u.unit.path,"language":u.unit.language,
                    "start_line":u.unit.start_line,"end_line":u.unit.end_line,"address":u.unit.address,
                    "quality":u.unit.quality,"kind":u.unit.metadata["kind"],"clues":clues(u)})
            }).collect::<Vec<_>>()})
    }
    pub fn ordered(&self, priorities: &[Priority]) -> Result<Vec<String>> {
        let mut ids = Vec::new();
        let mut seen = HashSet::new();
        for item in priorities {
            ensure!(
                self.order.contains(&item.unit_id),
                "计划引用了不可审计的程序单元"
            );
            if seen.insert(item.unit_id.clone()) {
                ids.push(item.unit_id.clone());
            }
        }
        for id in &self.order {
            if seen.insert(id.clone()) {
                ids.push(id.clone());
            }
        }
        Ok(ids)
    }
    pub fn view(&self, id: &str, start: Option<u32>, end: Option<u32>) -> Result<Value> {
        let id = self.real_id(id);
        let u = self
            .units
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("程序单元不属于当前分析任务"))?;
        let base = if u.unit.language == "binary" {
            1
        } else {
            u.unit.start_line
        };
        let first = start.unwrap_or(base);
        let last = end.unwrap_or(first.saturating_add(159));
        ensure!(
            first >= base && last >= first && last - first <= 199,
            "单次读取范围必须在程序单元内且不超过 200 行"
        );
        let lines: Vec<_> = u.unit.code.split('\n').collect();
        ensure!(
            (first - base) < lines.len() as u32,
            "代码起始行超出程序单元"
        );
        let mut text = String::new();
        let mut returned_last = first;
        for line in first..=last.min(base + lines.len() as u32 - 1) {
            let next = format!("{line}|{}\n", lines[(line - base) as usize]);
            if text.len() + next.len() > 24000 {
                break;
            }
            text.push_str(&next);
            returned_last = line;
        }
        Ok(
            json!({"unit_id":self.model_id(&u.id),"path":u.unit.path,"name":u.unit.name,"language":u.unit.language,
            "artifact_id":u.artifact_id,"address":u.unit.address,"mapping":if u.unit.language=="binary"{"FUNCTION_LEVEL_ONLY"}else{"SOURCE_LINES"},
            "start_line":first,"end_line":returned_last,"unit_start_line":base,"unit_end_line":base+lines.len() as u32-1,
            "truncated":first > base || returned_last < base+lines.len() as u32-1,"numbered_code":text,
            "clues":clues(u)}),
        )
    }
    pub fn focus(&self, id: &str) -> Result<Value> {
        let mut view = self.view(id, None, None)?;
        let unit = &self.units[id];
        if unit.unit.language == "binary" {
            return Ok(view);
        }
        let mut children: Vec<_> = self
            .units
            .values()
            .filter(|child| {
                child.id != id
                    && child.unit.path == unit.unit.path
                    && child.unit.metadata["kind"] == "function"
                    && child.unit.start_byte >= unit.unit.start_byte
                    && child.unit.end_byte <= unit.unit.end_byte
            })
            .collect();
        children.sort_by_key(|u| u.unit.start_byte);
        if children.is_empty() {
            return Ok(view);
        }
        // Preserve module initializers and source line numbers. Function bodies are audited
        // in their own tasks; the full original remains available through read_unit/read_span.
        let mut code = String::new();
        for (offset, line) in unit.unit.code.split('\n').enumerate() {
            let number = unit.unit.start_line + offset as u32;
            if number > view["end_line"].as_u64().unwrap_or(0) as u32 {
                break;
            }
            if let Some(child) = children
                .iter()
                .find(|child| number >= child.unit.start_line && number <= child.unit.end_line)
            {
                if number == child.unit.start_line {
                    code.push_str(&format!(
                        "{number}|[function {}: {} — body assigned to its own audit task]\n",
                        self.model_id(&child.id),
                        child.unit.name
                    ));
                }
            } else {
                code.push_str(&format!("{number}|{line}\n"));
            }
        }
        view["numbered_code"] = json!(code);
        view["delegated_functions"] = json!(children.iter().map(|u| json!({"unit_id":self.model_id(&u.id),"start_line":u.unit.start_line,"end_line":u.unit.end_line})).collect::<Vec<_>>());
        view["audit_scope"] = json!(
            "Audit only code outside delegated function bodies. Definitions are placeholders, not source citations. Read related units when necessary, but do not duplicate findings at an operation assigned to another task."
        );
        Ok(view)
    }
    pub fn tool(&self, name: &str, args: &Value) -> Result<Value> {
        match name {
            "inspect_target" => Ok(self.target.clone()),
            "read_unit" => self.view(string(args, "unit_id")?, None, None),
            "read_span" => self.view(
                string(args, "unit_id")?,
                Some(number(args, "start_line")?),
                Some(number(args, "end_line")?),
            ),
            "search_code" => {
                let query = string(args, "query")?;
                ensure!(
                    !query.trim().is_empty() && query.len() <= 160,
                    "查询须为 1—160 字节的文本"
                );
                let query = query.to_lowercase();
                let mut matches = Vec::new();
                for id in &self.order {
                    let u = &self.units[id];
                    let base = if u.unit.language == "binary" {
                        1
                    } else {
                        u.unit.start_line
                    };
                    for (i, line) in u.unit.code.split('\n').enumerate() {
                        if line.to_lowercase().contains(&query) {
                            matches.push(json!({"unit_id":self.model_id(&u.id),"path":u.unit.path,"line":base+i as u32,"text":line.chars().take(300).collect::<String>()}));
                            if matches.len() == 30 {
                                return Ok(json!({"matches":matches,"truncated":true}));
                            }
                        }
                    }
                }
                Ok(json!({"matches":matches,"truncated":false}))
            }
            "query_graph" => {
                let id = self.real_id(string(args, "unit_id")?);
                ensure!(self.units.contains_key(id), "图查询不属于当前任务");
                let edges: Vec<_> = self
                    .edges
                    .iter()
                    .filter(|e| e.source_id == id || e.target_id == id)
                    .collect();
                Ok(self.references(json!({"edges":edges.iter().take(60).collect::<Vec<_>>(),"truncated":edges.len()>60,"complete":false}),true))
            }
            "scan_rules" => Ok(
                json!({"engine":"builtin-lexical-clues-v1","semantic_proof":false,
                "clues":self.order.iter().filter_map(|id| {
                    let hints=clues(&self.units[id]);
                    (!hints.is_empty()).then(||json!({"unit_id":self.model_id(id),"hints":hints}))
                }).take(100).collect::<Vec<_>>()}),
            ),
            "key_logic_candidates" => Ok(self.key_logic_candidates()),
            _ => bail!("未注册的工具；只允许当前目标的只读查询"),
        }
    }
}
/// 关键逻辑线索：标签、子类型、词法/API 特征。命中只作为候选依据，不按函数名定性。
const KEY_LOGIC_CLUES: &[(&str, &str, &str)] = &[
    ("CRYPTOGRAPHY", "PASSWORD_HASH", "bcrypt"),
    ("CRYPTOGRAPHY", "PASSWORD_HASH", "argon2"),
    ("CRYPTOGRAPHY", "PASSWORD_HASH", "pbkdf2"),
    ("CRYPTOGRAPHY", "PASSWORD_HASH", "scrypt"),
    ("CRYPTOGRAPHY", "HASH", "sha256"),
    ("CRYPTOGRAPHY", "HASH", "sha512"),
    ("CRYPTOGRAPHY", "HASH", "sha1"),
    ("CRYPTOGRAPHY", "HASH", "md5"),
    ("CRYPTOGRAPHY", "HASH", "hashlib"),
    ("CRYPTOGRAPHY", "SYMMETRIC", "aes"),
    ("CRYPTOGRAPHY", "SYMMETRIC", "chacha"),
    ("CRYPTOGRAPHY", "SYMMETRIC", "cipher"),
    ("CRYPTOGRAPHY", "SYMMETRIC", "encrypt"),
    ("CRYPTOGRAPHY", "SYMMETRIC", "decrypt"),
    ("CRYPTOGRAPHY", "ASYMMETRIC", "rsa"),
    ("CRYPTOGRAPHY", "ASYMMETRIC", "ecdsa"),
    ("CRYPTOGRAPHY", "ASYMMETRIC", "public_key"),
    ("CRYPTOGRAPHY", "ASYMMETRIC", "private_key"),
    ("CRYPTOGRAPHY", "RANDOM", "urandom"),
    ("CRYPTOGRAPHY", "RANDOM", "getrandom"),
    ("AUTHENTICATION", "PASSWORD", "check_password"),
    ("AUTHENTICATION", "PASSWORD", "verify_password"),
    ("AUTHENTICATION", "PASSWORD", "compare_digest"),
    ("AUTHENTICATION", "PASSWORD", "password =="),
    ("AUTHENTICATION", "SESSION", "session"),
    ("AUTHENTICATION", "TOKEN", "jwt"),
    ("AUTHENTICATION", "TOKEN", "bearer"),
    ("AUTHENTICATION", "TOKEN", "authorization"),
    ("REGISTRATION", "ACCOUNT", "register"),
    ("REGISTRATION", "ACCOUNT", "signup"),
    ("REGISTRATION", "ACCOUNT", "sign_up"),
    ("REGISTRATION", "ACCOUNT", "create_user"),
    ("REGISTRATION", "ACCOUNT", "create_account"),
];

impl Corpus {
    /// B03：从实际代码行与调用图给出认证/加解密/注册候选，附带可回溯证据。
    /// 候选不是结论；图不完整时标记近似。
    pub fn key_logic_candidates(&self) -> Value {
        let mut grouped: HashMap<(String, &'static str, &'static str), Vec<Value>> = HashMap::new();
        for id in &self.order {
            let unit = &self.units[id];
            for (index, line) in unit.unit.code.lines().enumerate() {
                let lower = line.to_lowercase();
                for (tag, subtype, token) in KEY_LOGIC_CLUES {
                    if lower.contains(token) {
                        let hits = grouped.entry((id.clone(), tag, subtype)).or_default();
                        if hits.len() < 3 {
                            hits.push(json!({
                                "line": unit.unit.start_line + index as u32,
                                "token": token,
                                "text": line.trim().chars().take(160).collect::<String>(),
                            }));
                        }
                        break;
                    }
                }
            }
        }
        let graph_approximate = self
            .edges
            .iter()
            .any(|edge| edge.target_id.is_empty() || edge.certainty != "TOOL_REPORTED");
        let mut candidates: Vec<(String, Value)> = grouped
            .into_iter()
            .map(|((id, tag, subtype), hits)| {
                let unit = &self.units[&id];
                let callers: Vec<Value> = self
                    .edges
                    .iter()
                    .filter(|edge| edge.target_id == id)
                    .take(8)
                    .map(|edge| {
                        json!({"unit_id": self.model_id(&edge.source_id), "certainty": edge.certainty, "line": edge.line})
                    })
                    .collect();
                let callees: Vec<Value> = self
                    .edges
                    .iter()
                    .filter(|edge| edge.source_id == id)
                    .take(8)
                    .map(|edge| {
                        let target = if edge.target_id.is_empty() {
                            edge.target_name.clone()
                        } else {
                            self.model_id(&edge.target_id).to_owned()
                        };
                        json!({"target": target, "certainty": edge.certainty, "line": edge.line})
                    })
                    .collect();
                let alias = self.model_id(&id).to_owned();
                (
                    format!("{alias}|{tag}|{subtype}"),
                    json!({
                        "unit_id": alias,
                        "unit_name": unit.unit.name,
                        "address": unit.unit.address,
                        "language": unit.unit.language,
                        "tag": tag,
                        "subtype": subtype,
                        "basis": "LEXICAL_API_CLUE_WITH_CALL_GRAPH",
                        "confidence": "CANDIDATE",
                        "evidence": hits,
                        "callers": callers,
                        "callees": callees,
                        "graph_approximate": graph_approximate,
                    }),
                )
            })
            .collect();
        candidates.sort_by(|a, b| a.0.cmp(&b.0));
        candidates.truncate(60);
        json!({
            "candidates": candidates.into_iter().map(|(_, value)| value).collect::<Vec<_>>(),
            "note": "候选基于实际代码行特征与调用图，需模型或人工复核；不按函数名定性",
            "limitations": [
                "图可能不完整：推断边与未解析调用按近似处理",
                "词法线索可能命中同义写法或无关代码，结论须有代码与调用依据",
            ],
            "target_executed": false,
        })
    }
}

fn string<'a>(args: &'a Value, key: &str) -> Result<&'a str> {
    args[key]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("工具参数 {key} 应为字符串"))
}
fn number(args: &Value, key: &str) -> Result<u32> {
    args[key]
        .as_u64()
        .and_then(|v| u32::try_from(v).ok())
        .ok_or_else(|| anyhow::anyhow!("工具参数 {key} 应为行号"))
}

pub fn clues(unit: &d::ProgramUnit) -> Vec<&'static str> {
    let code = unit.unit.code.to_lowercase();
    [
        (
            "执行或解释边界",
            &[
                "eval(",
                "exec(",
                "system(",
                "subprocess",
                "execute(",
                "template(",
            ][..],
        ),
        (
            "文件与路径边界",
            &[
                "open(",
                "path.join",
                "filepath.join",
                "send_file",
                "readfile",
                "fopen(",
            ][..],
        ),
        (
            "身份或权限边界",
            &[
                "password",
                "token",
                "session",
                "auth",
                "permission",
                "register",
            ][..],
        ),
        (
            "内存或索引操作",
            &["memcpy", "strcpy", "sprintf", "malloc", "buffer", "[index]"][..],
        ),
    ]
    .iter()
    .filter(|(_, terms)| terms.iter().any(|term| code.contains(term)))
    .map(|(label, _)| *label)
    .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Priority {
    pub unit_id: String,
    pub reason: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
// Provider-added descriptive metadata does not change scheduling. Raw responses remain archived.
pub struct Plan {
    pub approach: String,
    #[serde(default)]
    pub priorities: Vec<Priority>,
    #[serde(default)]
    pub limitations: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
// Providers may add descriptive metadata; required fields and every evidence reference remain validated.
pub struct AuditOutput {
    pub audited_unit_ids: Vec<String>,
    pub findings: Vec<d::FindingDraft>,
    pub annotations: Vec<d::AnnotationDraft>,
    pub limitations: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportOutput {
    pub summary: String,
    #[serde(default)]
    pub recommendations: Vec<String>,
    #[serde(default)]
    pub limitations: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentAction {
    Tool { name: String, arguments: Value },
    Finish { result: Value },
}

pub fn parse_action(text: &str) -> Result<AgentAction> {
    let value = first_json_value(text)?;
    if value.is_object() && value.get("action").is_none() {
        // JSON-mode providers may return a direct result. The same strict role and evidence checks apply.
        Ok(AgentAction::Finish { result: value })
    } else {
        serde_json::from_value(value).map_err(|e| anyhow::anyhow!("操作协议无效：{e}"))
    }
}

/// Providers deviate from JSON mode in both directions: some append warnings after the
/// object, others prefix it with prose that the transport cannot strip. Take the first
/// JSON value, skipping a leading non-JSON preamble when the response does not begin
/// with one. The raw response stays archived, and every role, citation and evidence
/// check still applies to the value. A response with no JSON value at all is still
/// malformed — prose that merely *states* a tool intent never becomes an action.
fn first_json_value(text: &str) -> Result<Value> {
    match serde_json::Deserializer::from_str(text)
        .into_iter::<Value>()
        .next()
    {
        Some(Ok(value)) => Ok(value),
        Some(Err(error)) => {
            scan_json(text).ok_or_else(|| anyhow::anyhow!("响应 JSON 无效：{error}"))
        }
        None => Err(anyhow::anyhow!("响应 JSON 无效：内容为空")),
    }
}

/// Retry from each `{`/`[` in turn so a prose preamble cannot hide the action object.
/// The candidate count is capped: a response whose every candidate fails is malformed,
/// not merely prefixed, and must not cost a parse attempt per brace.
fn scan_json(text: &str) -> Option<Value> {
    const MAX_CANDIDATES: usize = 32;
    let mut seen = 0usize;
    for (start, character) in text.char_indices() {
        if character != '{' && character != '[' {
            continue;
        }
        seen += 1;
        if seen > MAX_CANDIDATES {
            break;
        }
        if let Some(Ok(value)) = serde_json::Deserializer::from_str(&text[start..])
            .into_iter::<Value>()
            .next()
        {
            return Some(value);
        }
    }
    None
}

pub fn system_prompt(role: &str) -> String {
    let protocol = include_str!("prompts/protocol.txt").trim();
    if role == "REVERSE" {
        return format!("{protocol}\n{}", include_str!("prompts/reverse.txt").trim());
    }
    let common = include_str!("prompts/common.txt").trim();
    let role_prompt = match role {
        "PLANNER" => include_str!("prompts/planner.txt"),
        "AUDITOR" => include_str!("prompts/auditor.txt"),
        "REVIEWER" => include_str!("prompts/reviewer.txt"),
        "REPORTER" => include_str!("prompts/reporter.txt"),
        "VERIFIER" => include_str!("prompts/verifier.txt"),
        _ => "Unknown role; return an empty JSON object.",
    };
    format!("{protocol}\n{common}\nROLE: {role}\n{}", role_prompt.trim())
}

pub fn task_system_prompt(role: &str, tool_budget: u32) -> String {
    format!(
        "{}\nThis task permits at most {tool_budget} tool requests, including plan updates and execution requests. Use the supplied context first. When no tool requests remain, finish using available evidence and explicit limitations. Keep the final action envelope and role result schema exactly as specified.",
        system_prompt(role)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn unit(id: &str, name: &str, code: &str, language: &str, address: &str) -> d::ProgramUnit {
        d::ProgramUnit {
            id: id.into(),
            run_id: "r".into(),
            snapshot_id: "s".into(),
            artifact_id: "a".into(),
            unit: d::UnitInput {
                name: name.into(),
                path: if language == "binary" {
                    "target.bin".into()
                } else {
                    "accounts.py".into()
                },
                language: language.into(),
                start_line: 1,
                code: code.into(),
                address: address.into(),
                ..Default::default()
            },
        }
    }

    fn edge(source: &str, target: &str, name: &str, certainty: &str) -> d::ProgramEdge {
        d::ProgramEdge {
            source_id: source.into(),
            target_id: target.into(),
            target_name: name.into(),
            kind: "CALL".into(),
            certainty: certainty.into(),
            line: 2,
            address: String::new(),
        }
    }

    #[test]
    fn a_tail_excerpt_remains_partial_even_when_it_reaches_the_last_line() {
        let mut source = unit("u1", "load", "guard(name)\nload(name)", "python", "");
        source.unit.start_line = 40;
        let corpus = Corpus::new(vec![source], vec![], json!({}));
        let tail = corpus.view("u1", Some(41), Some(41)).unwrap();
        assert_eq!(tail["unit_start_line"], 40);
        assert_eq!(tail["unit_end_line"], 41);
        assert_eq!(tail["truncated"], true);
        let full = corpus.view("u1", None, None).unwrap();
        assert_eq!(full["truncated"], false);
        assert!(
            full["numbered_code"]
                .as_str()
                .unwrap()
                .contains("40|guard(name)")
        );
    }

    #[test]
    fn parse_action_ignores_provider_warnings_after_json() {
        let text = concat!(
            r#"{"action":"tool","name":"inspect_target","arguments":{}}"#,
            "\n\n<system_warning>Provider metadata</system_warning>"
        );
        match parse_action(text).unwrap() {
            AgentAction::Tool { name, arguments } => {
                assert_eq!(name, "inspect_target");
                assert_eq!(arguments, json!({}));
            }
            AgentAction::Finish { .. } => panic!("expected a tool action"),
        }
    }

    #[test]
    fn parse_action_ignores_prose_before_json() {
        // Observed from an OpenAI-compatible provider that accepts response_format
        // json_object and prefixes the action with its own narration anyway.
        let text = concat!(
            "Ghidra 首趟已完成：6 个函数全部恢复，继续按计划执行 FLOSS。",
            r#"{"action":"tool","name":"run_recovery_step","arguments":{}}"#
        );
        match parse_action(text).unwrap() {
            AgentAction::Tool { name, arguments } => {
                assert_eq!(name, "run_recovery_step");
                assert_eq!(arguments, json!({}));
            }
            AgentAction::Finish { .. } => panic!("expected a tool action"),
        }
    }

    #[test]
    fn parse_action_rejects_prose_that_only_states_a_tool_intent() {
        // The preamble tolerance must not turn stated intent into an executed action.
        let error = parse_action("现在调用 inspect_target，然后继续审计。").unwrap_err();
        assert!(
            error.to_string().contains("响应 JSON 无效"),
            "unexpected error: {error}"
        );
        let error = parse_action("").unwrap_err();
        assert!(
            error.to_string().contains("响应 JSON 无效"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn key_logic_candidates_cite_code_lines_and_call_graph() {
        let units = vec![
            unit(
                "u1",
                "login",
                "def login(password):\n    return bcrypt.checkpw(password, stored)",
                "python",
                "",
            ),
            unit(
                "u2",
                "handle_login",
                "def handle_login(request):\n    return login(request.password)",
                "python",
                "",
            ),
            unit(
                "u3",
                "register_user",
                "def register_user(name):\n    return create_user(name)",
                "python",
                "",
            ),
            unit(
                "u4",
                "verify",
                "int verify(char *in, char *stored) { return compare_digest(in, stored); }",
                "binary",
                "0x140001000",
            ),
        ];
        let edges = vec![
            edge("u2", "u1", "login", "TOOL_REPORTED"),
            edge("u2", "", "unknown_dispatch", "UNKNOWN"),
        ];
        let corpus = Corpus::new(units, edges, json!({}));
        let report = corpus.key_logic_candidates();
        let candidates = report["candidates"].as_array().unwrap();

        let crypto = candidates
            .iter()
            .find(|c| c["tag"] == "CRYPTOGRAPHY" && c["subtype"] == "PASSWORD_HASH")
            .expect("password-hash candidate");
        assert_eq!(crypto["unit_id"], "U0001");
        assert_eq!(crypto["evidence"][0]["line"], 2);
        assert!(
            crypto["evidence"][0]["text"]
                .as_str()
                .unwrap()
                .contains("bcrypt")
        );
        assert_eq!(crypto["callers"][0]["unit_id"], "U0002");

        let auth = candidates
            .iter()
            .find(|c| c["tag"] == "AUTHENTICATION" && c["subtype"] == "PASSWORD")
            .expect("password-check candidate");
        assert_eq!(auth["address"], "0x140001000");
        assert_eq!(auth["language"], "binary");
        assert_eq!(auth["graph_approximate"], true);

        assert!(
            candidates
                .iter()
                .any(|c| c["tag"] == "REGISTRATION" && c["subtype"] == "ACCOUNT")
        );
        assert_eq!(report["target_executed"], false);
    }
}
