//! Native, bounded adapters used only when selected by the reverse-engineering agent.
use crate::{process::ProcessSpec, protection};
use aegis_domain as d;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashSet},
    path::{Path, PathBuf},
    time::Duration,
};

pub const FLOSS_VERSION: &str = "3.1.1";
const MAX_STRINGS: usize = 512;
const MAX_STRING_BYTES: usize = 8192;
const FLOSS: protection::Adapter = protection::Adapter {
    name: "floss",
    kinds: &["PE"],
    binary: "floss",
    env: "AEGIS_FLOSS",
};

pub fn floss_path() -> Option<PathBuf> {
    protection::locate_tool(&FLOSS)
}

pub fn floss_spec(input: &Path, work: &Path) -> Result<ProcessSpec> {
    Ok(ProcessSpec {
        program: floss_path()
            .context("FLOSS 未安装；运行 py -3 scripts/install_reverse_tools.py")?,
        // v3.1.1 CLI; newer master uses different flags. Do not accept model-supplied flags.
        args: vec![
            "--json".into(),
            "--no".into(),
            "static".into(),
            "--".into(),
            input.to_string_lossy().into_owned(),
        ],
        directory: work.into(),
        env: BTreeMap::from([
            // Vivisect calls getpass.getuser(); without a name Python falls back to Unix-only pwd.
            ("USERNAME".into(), "aegis-tool".into()),
            ("FLOSS_SAVE_WORKSPACE".into(), "0".into()),
            ("FLOSS_CACHE_ENABLE".into(), "0".into()),
            (
                "FLOSS_CACHE_DIR".into(),
                work.to_string_lossy().into_owned(),
            ),
        ]),
        timeout: Duration::from_secs(180),
    })
}

fn optional_address(item: &Value, key: &str) -> Result<Option<u64>> {
    match item.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => Ok(Some(
            value
                .as_u64()
                .with_context(|| format!("FLOSS {key} 不是有效地址"))?,
        )),
    }
}

/// Normalize the pinned upstream JSON schema; plain static strings never count as deobfuscation.
pub fn floss_strings(raw: &Value, input: &[u8]) -> Result<d::RecoveredStrings> {
    ensure!(
        matches!(
            raw["metadata"]["version"].as_str(),
            Some("3.1.1" | "v3.1.1-0-g3cd3ee6")
        ),
        "FLOSS JSON 版本不匹配"
    );
    let mut strings = Vec::new();
    let mut omitted = 0;
    let mut seen = HashSet::new();
    for (field, kind) in [
        ("decoded_strings", "decoded"),
        ("stack_strings", "stack"),
        ("tight_strings", "tight"),
    ] {
        let items = raw["strings"][field]
            .as_array()
            .with_context(|| format!("FLOSS 缺少 {field} 数组"))?;
        for item in items {
            let text = item["string"].as_str().context("FLOSS 字符串格式无效")?;
            let function_address = optional_address(
                item,
                if kind == "decoded" {
                    "decoding_routine"
                } else {
                    "function"
                },
            )?;
            let call_address = optional_address(
                item,
                if kind == "decoded" {
                    "decoded_at"
                } else {
                    "program_counter"
                },
            )?;
            ensure!(
                function_address.is_some() && call_address.is_some(),
                "FLOSS 恢复结果缺少代码位置"
            );
            if text.is_empty() || text.len() > MAX_STRING_BYTES || strings.len() >= MAX_STRINGS {
                omitted += 1;
                continue;
            }
            if !seen.insert((text.to_owned(), function_address, call_address, kind)) {
                continue;
            }
            strings.push(d::RecoveredString {
                text: text.into(),
                kind: kind.into(),
                function_address,
                call_address,
                data_address: optional_address(item, "address")?,
                file_offset: None,
            });
        }
    }
    Ok(d::RecoveredStrings {
        schema_version: 1, input_sha256: d::sha256(input), tool: d::RecoveryTool::Floss, strings, omitted,
        limitations: vec!["FLOSS 使用静态分析与模拟执行恢复字符串；结果不代表已恢复控制流平坦化、虚拟化保护或完整源码".into()],
    })
}

pub fn builtin_strings(raw: &Value, input: &[u8]) -> Result<d::RecoveredStrings> {
    let candidates = raw["candidates"]
        .as_array()
        .context("内建恢复结果缺少候选数组")?;
    let strings = candidates
        .iter()
        .take(MAX_STRINGS)
        .filter_map(|item| {
            let text = item["text"].as_str()?;
            (text.len() <= MAX_STRING_BYTES).then(|| d::RecoveredString {
                text: text.into(),
                kind: format!("candidate:{}", item["kind"].as_str().unwrap_or("encoded")),
                function_address: None,
                call_address: None,
                data_address: None,
                // The existing detector returns section-relative offsets, NOT absolute file offsets.
                file_offset: None,
            })
        })
        .collect();
    Ok(d::RecoveredStrings {
        schema_version: 1,
        input_sha256: d::sha256(input),
        tool: d::RecoveryTool::BuiltinStrings,
        strings,
        omitted: candidates.len().saturating_sub(MAX_STRINGS),
        limitations: vec![
            "内建 XOR/Base64 结果是启发式候选，未经指令语义证明；不写入具体函数的伪代码".into(),
        ],
    })
}

fn address(value: &Value) -> Option<u64> {
    u64::from_str_radix(value.as_str()?.strip_prefix("0x")?, 16).ok()
}

/// Add attributable comments, never substitute guessed source or patch executable bytes.
pub fn annotate(
    result: &mut d::AnalysisResult,
    recovered: &d::RecoveredStrings,
    input_hash: &str,
) -> Result<usize> {
    ensure!(
        recovered.schema_version == 1 && recovered.input_sha256 == input_hash,
        "恢复字符串与反编译输入哈希不一致"
    );
    ensure!(
        recovered.strings.len() <= MAX_STRINGS,
        "恢复字符串超过数量限制"
    );
    let mut count = 0;
    for unit in &mut result.units {
        if unit.code.is_empty() {
            continue;
        }
        let entry = u64::from_str_radix(unit.address.trim_start_matches("0x"), 16).ok();
        let relevant: Vec<_> = recovered
            .strings
            .iter()
            .filter(|s| {
                // Decoded strings belong to the calling function. Stack strings belong to their reported function.
                let position = if s.kind == "decoded" {
                    s.call_address
                } else {
                    s.function_address
                };
                position.is_some_and(|position| {
                    entry == Some(position)
                        || unit.metadata["basic_blocks"]
                            .as_array()
                            .is_some_and(|blocks| {
                                blocks.iter().any(|block| {
                                    address(&block["start"])
                                        .zip(address(&block["end"]))
                                        .is_some_and(|(start, end)| {
                                            start <= position && position <= end
                                        })
                                })
                            })
                })
            })
            .take(32)
            .collect();
        if relevant.is_empty() {
            continue;
        }
        let mut prefix = String::from(
            "/* FLOSS recovered strings (emulation evidence, function-level association):\n",
        );
        for string in &relevant {
            ensure!(
                string.text.len() <= MAX_STRING_BYTES,
                "恢复字符串超过长度限制"
            );
            let escaped = serde_json::to_string(&string.text)?.replace("*/", "* / ");
            prefix.push_str(&format!(
                " * {} at 0x{:x}: {}\n",
                string.kind,
                string.call_address.or(string.function_address).unwrap_or(0),
                escaped
            ));
        }
        prefix.push_str(" */\n");
        unit.metadata["recovered_strings"] = serde_json::to_value(&relevant)?;
        unit.metadata["annotation_prefix_lines"] = json!(prefix.lines().count());
        unit.metadata["analysis_input_sha256"] = json!(input_hash);
        unit.code = prefix + &unit.code;
        unit.start_line = 1;
        unit.end_line = unit.code.split('\n').count() as u32;
        count += relevant.len();
    }
    result.metadata["recovered_string_count"] = json!(recovered.strings.len());
    result.metadata["annotated_string_count"] = json!(count);
    Ok(count)
}

pub fn readable_code(result: &d::AnalysisResult, input_hash: &str) -> String {
    let engine = if result.metadata["analysis_engine"] == "IDA_HEXRAYS_D810" {
        "IDA / Hex-Rays / D-810"
    } else {
        "Ghidra"
    };
    let mut text = format!(
        "/* {engine} pseudocode. Analysis input SHA-256: {input_hash}\n * Decompiled output is not the original source; address mapping is function-level.\n */\n\n"
    );
    for unit in &result.units {
        if unit.code.is_empty() {
            continue;
        }
        text.push_str(&format!(
            "/* Function {} @ {} */\n{}\n\n",
            unit.name.replace("*/", "* /"),
            unit.address,
            unit.code
        ));
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> Value {
        json!({"metadata":{"version":"3.1.1"}, "strings":{"decoded_strings":[
            {"string":"secret */ forged()", "decoding_routine":4096,"decoded_at":8193,"address":12288}],
            "stack_strings":[],"tight_strings":[],"static_strings":[{"string":"plain"}]}})
    }

    #[test]
    fn recovery_floss_requires_schema_and_real_locations() {
        let recovered = floss_strings(&report(), b"input").unwrap();
        assert_eq!(recovered.strings.len(), 1);
        let mut raw = report();
        raw["strings"]["decoded_strings"][0]["decoded_at"] = json!(-1);
        assert!(floss_strings(&raw, b"input").is_err());
        raw = report();
        raw["metadata"]["version"] = json!("999");
        assert!(floss_strings(&raw, b"input").is_err());
    }

    #[test]
    fn recovery_annotations_bind_hash_and_caller_and_escape_comments() {
        let mut result = d::AnalysisResult {
            units: vec![d::UnitInput {
                address: "0x2000".into(),
                code: "void f(void) {}".into(),
                metadata: json!({"basic_blocks":[{"start":"0x2000","end":"0x2010"}]}),
                ..Default::default()
            }],
            metadata: json!({}),
            ..Default::default()
        };
        let recovered = floss_strings(&report(), b"input").unwrap();
        assert!(annotate(&mut result, &recovered, &d::sha256(b"different")).is_err());
        assert_eq!(
            annotate(&mut result, &recovered, &d::sha256(b"input")).unwrap(),
            1
        );
        assert!(result.units[0].code.contains("secret * /  forged()"));
        assert!(result.units[0].code.ends_with("void f(void) {}"));
    }
}
