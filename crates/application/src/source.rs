use crate::import::relative_path;
use aegis_domain::{
    AnalysisResult, EdgeInput, FileRecord, FileResult, ToolExecution, UnitInput, now, sha256,
};
use anyhow::{Context, Result, ensure};
use serde_json::json;
use std::{collections::HashMap, fs, path::Path};
use tokio_util::sync::CancellationToken;
use tree_sitter::{Node, Parser};

const MAX_SOURCE_BYTES: u64 = 2 * 1024 * 1024;

fn is_function(kind: &str) -> bool {
    matches!(
        kind,
        "function_definition" | "function_declaration" | "method_declaration"
    )
}

fn function_name<'a>(node: Node<'a>, source: &'a str) -> String {
    if let Some(name) = node.child_by_field_name("name") {
        return name
            .utf8_text(source.as_bytes())
            .unwrap_or("<unnamed>")
            .to_owned();
    }
    let mut current = node.child_by_field_name("declarator");
    for _ in 0..24 {
        let Some(n) = current else {
            break;
        };
        if matches!(
            n.kind(),
            "identifier"
                | "field_identifier"
                | "qualified_identifier"
                | "scoped_identifier"
                | "destructor_name"
                | "operator_name"
        ) {
            return n
                .utf8_text(source.as_bytes())
                .unwrap_or("<unnamed>")
                .to_owned();
        }
        current = n
            .child_by_field_name("declarator")
            .or_else(|| n.child_by_field_name("name"));
    }
    format!("<function@{}>", node.start_position().row + 1)
}

fn function_nodes(root: Node<'_>) -> Vec<Node<'_>> {
    let mut stack = vec![root];
    let mut found = vec![];
    while let Some(node) = stack.pop() {
        if is_function(node.kind()) {
            found.push(node);
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    found.sort_by_key(|n| n.start_byte());
    found
}

fn details(
    node: Node<'_>,
    source: &str,
    key: &str,
    path: &str,
) -> (serde_json::Value, Vec<EdgeInput>) {
    let mut stack = vec![node];
    let mut calls = vec![];
    let mut branches = vec![];
    while let Some(n) = stack.pop() {
        if n.id() != node.id() && is_function(n.kind()) {
            continue;
        }
        if matches!(n.kind(), "call" | "call_expression")
            && let Some(callee) = n.child_by_field_name("function")
        {
            let target = callee
                .utf8_text(source.as_bytes())
                .unwrap_or("<unknown>")
                .chars()
                .take(256)
                .collect::<String>();
            calls.push(EdgeInput {
                source_key: key.into(),
                target_name: target,
                kind: "CALL".into(),
                certainty: "UNKNOWN".into(),
                line: n.start_position().row as u32 + 1,
                ..Default::default()
            });
        }
        if matches!(
            n.kind(),
            "if_statement"
                | "while_statement"
                | "for_statement"
                | "switch_statement"
                | "match_statement"
                | "for_in_statement"
        ) {
            let text = n
                .child_by_field_name("condition")
                .and_then(|c| c.utf8_text(source.as_bytes()).ok())
                .unwrap_or("");
            branches.push(json!({"kind":n.kind(),"line":n.start_position().row+1,"condition":text.chars().take(400).collect::<String>()}));
        }
        let mut cursor = n.walk();
        stack.extend(n.named_children(&mut cursor));
    }
    (
        json!({"kind":"function","source_path":path,"start_column":node.start_position().column,"end_column":node.end_position().column,"branches":branches,"control_flow_quality":"SYNTAX_ONLY","call_resolution":"BEST_EFFORT"}),
        calls,
    )
}

pub fn analyze_sources(
    directory: &Path,
    files: &[FileRecord],
    cancel: &CancellationToken,
    mut progress: impl FnMut(usize, usize, &str),
) -> Result<AnalysisResult> {
    let started_at = now();
    let mut result = AnalysisResult::default();
    for (index, file) in files.iter().enumerate() {
        ensure!(!cancel.is_cancelled(), "analysis cancelled");
        progress(index, files.len(), &file.path);
        if file.language == "data" {
            result.files.push(FileResult {
                path: file.path.clone(),
                language: file.language.clone(),
                status: "NOT_SOURCE".into(),
                reason: "资源或说明文件，未作为源码解析".into(),
                unit_count: 0,
            });
            continue;
        }
        let failure = if file.language == "unsupported" {
            Some("首轮尚未支持该源码语言")
        } else if file.size > MAX_SOURCE_BYTES {
            Some("源码超过单文件解析上限 2 MiB")
        } else {
            None
        };
        if let Some(reason) = failure {
            result.files.push(FileResult {
                path: file.path.clone(),
                language: file.language.clone(),
                status: "UNSUPPORTED".into(),
                reason: reason.into(),
                unit_count: 0,
            });
            continue;
        }
        let bytes = fs::read(directory.join(relative_path(&file.path)?))
            .with_context(|| format!("read {}", file.path))?;
        ensure!(
            sha256(&bytes) == file.sha256,
            "snapshot hash mismatch: {}",
            file.path
        );
        let source = match std::str::from_utf8(&bytes) {
            Ok(source) => source,
            Err(_) => {
                result.files.push(FileResult {
                    path: file.path.clone(),
                    language: file.language.clone(),
                    status: "FAILED".into(),
                    reason: "源码不是有效 UTF-8；未进行有损转换".into(),
                    unit_count: 0,
                });
                continue;
            }
        };
        let lang = match file.language.as_str() {
            "python" => tree_sitter_python::LANGUAGE.into(),
            "go" => tree_sitter_go::LANGUAGE.into(),
            "c" => tree_sitter_c::LANGUAGE.into(),
            "cpp" => tree_sitter_cpp::LANGUAGE.into(),
            other => anyhow::bail!("unexpected language {other}"),
        };
        let mut parser = Parser::new();
        parser.set_language(&lang)?;
        #[allow(deprecated)]
        parser.set_timeout_micros(1_000_000);
        let Some(tree) = parser.parse(source, None) else {
            result.files.push(FileResult {
                path: file.path.clone(),
                language: file.language.clone(),
                status: "FAILED".into(),
                reason: "语法解析超时".into(),
                unit_count: 0,
            });
            continue;
        };
        let root = tree.root_node();
        let functions = function_nodes(root);
        let count = functions.len() as u64;
        result.units.push(UnitInput {
            key: format!("{}::module", file.path), name: file.path.clone(), path: file.path.clone(), language: file.language.clone(),
            start_line: 1, end_line: source.lines().count().max(1) as u32, start_byte: 0, end_byte: bytes.len() as u64,
            code: source.to_owned(), quality: if root.has_error() { "PARTIAL" } else { "PARSED" }.into(),
            metadata: json!({"kind":"module","has_parse_errors":root.has_error(),"function_count":count}), ..Default::default()
        });
        for function in functions {
            let name = function_name(function, source);
            let key = format!("{}::{}:{}", file.path, function.start_byte(), name);
            let (metadata, edges) = details(function, source, &key, &file.path);
            let code = function.utf8_text(source.as_bytes())?.to_owned();
            result.units.push(UnitInput {
                key,
                name,
                path: file.path.clone(),
                language: file.language.clone(),
                start_line: function.start_position().row as u32 + 1,
                end_line: function.start_position().row as u32 + code.lines().count().max(1) as u32,
                start_byte: function.start_byte() as u64,
                end_byte: function.end_byte() as u64,
                code,
                quality: if function.has_error() {
                    "PARTIAL"
                } else {
                    "PARSED"
                }
                .into(),
                metadata,
                ..Default::default()
            });
            result.edges.extend(edges);
        }
        result.files.push(FileResult {
            path: file.path.clone(),
            language: file.language.clone(),
            status: if root.has_error() {
                "PARTIAL"
            } else {
                "PARSED"
            }
            .into(),
            reason: if root.has_error() {
                "语法树存在错误或缺失节点"
            } else {
                ""
            }
            .into(),
            unit_count: count + 1,
        });
        ensure!(result.units.len() <= 50_000, "program unit limit reached");
    }
    let mut names: HashMap<(String, String), Vec<String>> = HashMap::new();
    let paths: HashMap<String, String> = result
        .units
        .iter()
        .map(|u| (u.key.clone(), u.path.clone()))
        .collect();
    for unit in &result.units {
        if unit.metadata["kind"] == "function" {
            names
                .entry((unit.path.clone(), unit.name.clone()))
                .or_default()
                .push(unit.key.clone());
        }
    }
    for edge in &mut result.edges {
        let path = paths.get(&edge.source_key).cloned().unwrap_or_default();
        if let Some(keys) = names.get(&(path, edge.target_name.clone()))
            && keys.len() == 1
        {
            edge.target_key = keys[0].clone();
            edge.certainty = "INFERRED".into();
        }
    }
    let code_files = result
        .files
        .iter()
        .filter(|f| f.status != "NOT_SOURCE")
        .count();
    if code_files == 0 {
        result
            .warnings
            .push("快照中没有可分析的源码；未执行漏洞检测".into());
    }
    result.metadata = json!({"analysis_scope":"STRUCTURE_ANALYSIS","code_file_count":code_files,"function_count":result.units.iter().filter(|u|u.metadata["kind"] == "function").count(),"module_count":result.units.iter().filter(|u|u.metadata["kind"] == "module").count(),"call_graph_complete":false,"vulnerability_audit":"NOT_RUN","verification":"NOT_RUN"});
    result.tools.push(ToolExecution { name: "tree-sitter".into(), version: "0.25 (grammars pinned in Cargo.lock)".into(), command: vec![], started_at, finished_at: now(), exit_code: None, terminated: false, log_artifact_id: String::new(), details: json!({"execution":"IN_PROCESS","max_source_bytes":MAX_SOURCE_BYTES,"per_file_timeout_ms":1000}) });
    progress(files.len(), files.len(), "源码结构解析完成");
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_four_languages_with_exact_source_ranges_and_honest_calls() {
        let dir = tempfile::tempdir().unwrap();
        let samples = [
            (
                "处理.py",
                "python",
                "def helper(x):\n    return x\n\ndef main():\n    return helper('中文')\n",
            ),
            (
                "main.go",
                "go",
                "package main\nfunc helper(x int) int { return x }\nfunc main() { helper(1) }\n",
            ),
            (
                "main.c",
                "c",
                "int helper(int x) { return x; }\nint main(void) { return helper(1); }\n",
            ),
            (
                "main.cpp",
                "cpp",
                "int helper(int x) { return x; }\nint main() { return helper(1); }\n",
            ),
        ];
        let mut files = vec![];
        for (name, lang, text) in samples {
            fs::write(dir.path().join(name), text).unwrap();
            files.push(FileRecord {
                path: name.into(),
                language: lang.into(),
                sha256: sha256(text.as_bytes()),
                size: text.len() as u64,
            });
        }
        let result =
            analyze_sources(dir.path(), &files, &CancellationToken::new(), |_, _, _| {}).unwrap();
        assert_eq!(
            result
                .units
                .iter()
                .filter(|u| u.metadata["kind"] == "function")
                .count(),
            8
        );
        assert_eq!(
            result
                .edges
                .iter()
                .filter(|e| e.certainty == "INFERRED")
                .count(),
            4
        );
        for unit in &result.units {
            let original = fs::read_to_string(dir.path().join(&unit.path)).unwrap();
            assert_eq!(
                &original[unit.start_byte as usize..unit.end_byte as usize],
                unit.code
            );
        }
    }
    #[test]
    fn malformed_source_is_partial_not_an_empty_success() {
        let dir = tempfile::tempdir().unwrap();
        let text = "def broken(:\n  pass\n";
        fs::write(dir.path().join("broken.py"), text).unwrap();
        let files = [FileRecord {
            path: "broken.py".into(),
            language: "python".into(),
            sha256: sha256(text.as_bytes()),
            size: text.len() as u64,
        }];
        let result =
            analyze_sources(dir.path(), &files, &CancellationToken::new(), |_, _, _| {}).unwrap();
        assert_eq!(result.files[0].status, "PARTIAL");
        assert!(result.partial());
    }
}
