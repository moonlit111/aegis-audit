//! B04 保护识别与 B05 去壳链路。
//!
//! 壳签名与节区熵只是识别证据，不能单独证明可处理性，也不能证明闭源/正式样本资格。
//! 处理链只执行允许清单内的工具与固定参数，从不执行目标本身，也不覆盖原件。
use crate::process::{self, ProcessSpec};
use aegis_domain as d;
use aegis_domain::sha256;
use anyhow::{Context, Result, bail, ensure};
use object::{Object, ObjectSection, SectionFlags};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

/// 节区熵超过该值且体积足够时，作为加壳/加密线索。
const HIGH_ENTROPY: f64 = 7.2;
/// 低于该字节数的节区不参与熵判定，避免小节区噪声。
const MIN_ENTROPY_BYTES: u64 = 4096;

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const SHF_WRITE: u64 = 0x1;
const SHF_EXECINSTR: u64 = 0x4;

/// 已知保护器签名；按 (节区名子串, 保护类型) 匹配。仅作识别线索。
const SIGNATURES: &[(&str, &str)] = &[
    ("upx0", "UPX"),
    ("upx1", "UPX"),
    ("upx2", "UPX"),
    ("upx!", "UPX"),
    (".upx", "UPX"),
    (".aspack", "ASPack"),
    (".adata", "ASPack"),
    (".themida", "Themida/WinLicense"),
    (".winlice", "Themida/WinLicense"),
    (".vmp0", "VMProtect"),
    (".vmp1", "VMProtect"),
    (".vmp2", "VMProtect"),
    ("mpress1", "MPRESS"),
    ("mpress2", "MPRESS"),
    (".enigma1", "Enigma Protector"),
    (".enigma2", "Enigma Protector"),
    (".petite", "Petite"),
    (".nsp0", "NsPack"),
    (".nsp1", "NsPack"),
    ("nsp2", "NsPack"),
    (".pec1", "PECompact"),
    (".pec2", "PECompact"),
    (".pecompact", "PECompact"),
    (".packed", "未识别加壳器"),
];

/// 保护处理能力矩阵：声明是否存在已实现的处理链；工具是否安装由执行时判定。
fn processing(kind: &str) -> Value {
    match adapter_for(kind) {
        Some(adapter) => json!({"state":"SUPPORTED","tool":adapter.name,"adapter":adapter.name,
            "requires_tool":true,
            "reason":"已实现该保护类型的处理链；参数固定，执行前需在允许清单内定位工具"}),
        None if kind == "NONE" => {
            json!({"state":"NOT_REQUIRED","tool":"","reason":"未发现保护特征"})
        }
        None => json!({"state":"UNSUPPORTED","tool":"",
            "reason":"当前没有该保护类型的自动处理链路；保留识别证据与不确定性"}),
    }
}

/// 匹配节区名到已知保护器。
pub fn signature(section_name: &str) -> Option<&'static str> {
    let lower = section_name.to_ascii_lowercase();
    SIGNATURES
        .iter()
        .find(|(needle, _)| lower.contains(needle))
        .map(|(_, kind)| *kind)
}

/// 香农熵（bit/byte）。空输入返回 0。
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }
    let total = data.len() as f64;
    counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let probability = count as f64 / total;
            -probability * probability.log2()
        })
        .sum()
}

pub fn assess(bytes: &[u8]) -> Result<Value> {
    let format = if bytes.starts_with(b"MZ") {
        "PE"
    } else if bytes.starts_with(b"\x7fELF") {
        "ELF"
    } else {
        bail!("unsupported binary format: expected PE or ELF")
    };
    let file = object::File::parse(bytes).context("malformed PE/ELF file")?;
    let entry = file.entry();

    let mut evidence: Vec<String> = Vec::new();
    let mut matched: Option<&'static str> = None;
    let mut high_entropy_sections: Vec<String> = Vec::new();
    let mut writable_executable: Vec<String> = Vec::new();
    let mut entry_section: Option<String> = None;
    let mut overlay_end = 0u64;

    for section in file.sections() {
        let name = section.name().unwrap_or("<invalid>").to_owned();
        let address = section.address();
        let size = section.size();
        let (write, execute) = match section.flags() {
            SectionFlags::Coff { characteristics } => (
                characteristics & IMAGE_SCN_MEM_WRITE != 0,
                characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
            ),
            SectionFlags::Elf { sh_flags } => {
                (sh_flags & SHF_WRITE != 0, sh_flags & SHF_EXECINSTR != 0)
            }
            _ => (false, false),
        };
        if let Some((offset, file_size)) = section.file_range() {
            overlay_end = overlay_end.max(offset.saturating_add(file_size));
        }
        if entry >= address && entry < address.saturating_add(size.max(1)) {
            entry_section = Some(name.clone());
        }
        if matched.is_none() {
            matched = signature(&name);
        }
        if write && execute {
            writable_executable.push(name.clone());
            evidence.push(format!("节区 {name} 同时可写可执行"));
        }
        if size >= MIN_ENTROPY_BYTES
            && let Ok(data) = section.data()
        {
            let value = entropy(data);
            if value >= HIGH_ENTROPY {
                high_entropy_sections.push(format!("{name}(H={value:.2})"));
                evidence.push(format!(
                    "节区 {name} 熵 {value:.2}，接近随机（加壳/加密线索）"
                ));
            }
        }
    }

    if let Some(kind) = matched {
        evidence.insert(0, format!("节区名匹配已知保护器签名：{kind}"));
    }
    let imports = file.imports().map(|items| items.len()).unwrap_or_default();
    if imports == 0 && bytes.len() >= 64 * 1024 {
        evidence.push("无可解析导入表且体积较大（加壳线索）".into());
    }
    let overlay = bytes.len() as u64 - overlay_end.min(bytes.len() as u64);
    if overlay >= 4096 {
        evidence.push(format!("节区之后存在 {overlay} 字节 overlay 数据"));
    }

    let kind = if let Some(kind) = matched {
        kind
    } else if !high_entropy_sections.is_empty() || !writable_executable.is_empty() {
        "UNKNOWN_PROTECTION"
    } else {
        "NONE"
    };
    let confidence = if matched.is_some() {
        "HIGH"
    } else if kind == "UNKNOWN_PROTECTION" {
        "MEDIUM"
    } else {
        "HIGH"
    };

    Ok(json!({
        "kind": kind,
        "confidence": confidence,
        "format": format,
        "evidence": evidence,
        "signals": {
            "high_entropy_sections": high_entropy_sections,
            "writable_executable_sections": writable_executable,
            "entry_section": entry_section,
            "import_count": imports,
            "overlay_bytes": overlay,
        },
        "processing": processing(kind),
        "limitations": [
            "壳签名与节区熵仅作为识别证据，不能单独证明可处理性或正式样本资格",
            "未执行目标；运行时自解压、反调试与动态解混淆未观察",
            "自制夹具只证明机制，不能抵扣正式加壳/混淆对象",
        ],
        "target_executed": false,
    }))
}

/// 允许清单。参数固定写死在适配器内，调用方不能追加、替换或注入工具参数。
pub struct Adapter {
    pub name: &'static str,
    pub kinds: &'static [&'static str],
    pub binary: &'static str,
    pub env: &'static str,
}

pub const ADAPTERS: &[Adapter] = &[Adapter {
    name: "upx",
    kinds: &["UPX"],
    binary: "upx",
    env: "AEGIS_UPX",
}];

pub fn adapter_for(kind: &str) -> Option<&'static Adapter> {
    ADAPTERS
        .iter()
        .find(|adapter| adapter.kinds.contains(&kind))
}

pub fn adapter_by_name(name: &str) -> Option<&'static Adapter> {
    ADAPTERS.iter().find(|adapter| adapter.name == name)
}

/// 在允许清单内定位工具：先看显式环境变量，再查 PATH。找不到时不回退到其他命令。
pub fn locate_tool(adapter: &Adapter) -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os(adapter.env) {
        let path = PathBuf::from(explicit);
        return path.is_file().then_some(path);
    }
    let path = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&path) {
        for candidate in [format!("{}.exe", adapter.binary), adapter.binary.to_owned()] {
            let full = directory.join(candidate);
            if full.is_file() {
                return Some(full);
            }
        }
    }
    None
}

#[derive(Debug, Clone, Copy)]
pub struct ProcessLimits {
    pub timeout: Duration,
}
impl Default for ProcessLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(120),
        }
    }
}

const LOG_RECORD_LIMIT: usize = 8 * 1024;

fn clip(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    if text.len() <= LOG_RECORD_LIMIT {
        return text.into_owned();
    }
    let mut end = LOG_RECORD_LIMIT;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…[截断]", &text[..end])
}

/// 节区级结构摘要，用于处理前后对照；不做逐指令地址对应。
pub fn structure_summary(bytes: &[u8]) -> Result<Value> {
    let file = object::File::parse(bytes).context("malformed PE/ELF file")?;
    let sections: Vec<Value> = file
        .sections()
        .take(256)
        .map(|section| {
            let (offset, file_size) = section.file_range().unwrap_or((0, 0));
            json!({
                "name": section.name().unwrap_or("<invalid>"),
                "address": format!("0x{:x}", section.address()),
                "size": section.size(),
                "file_offset": offset,
                "file_size": file_size,
            })
        })
        .collect();
    Ok(json!({
        "format": if bytes.starts_with(b"MZ") { "PE" } else { "ELF" },
        "entry": format!("0x{:x}", file.entry()),
        "imports": file.imports().map(|items| items.len()).unwrap_or_default(),
        "sections": sections,
        "size": bytes.len(),
    }))
}

/// 对检测到的保护执行真实处理，保存原件与派生产物并记录前后映射。
///
/// - `requested` 为 None 时按识别结果自动选取允许清单中的适配器；指定时必须匹配且受支持。
/// - 失败、工具缺失、不支持都作为结构化结果返回，不抛出，也不虚报成功。
pub async fn process(
    bytes: &[u8],
    workdir: &Path,
    requested: Option<&str>,
    limits: ProcessLimits,
    cancel: CancellationToken,
) -> Result<Value> {
    let assessment = match assess(bytes) {
        Ok(value) => value,
        Err(error) => {
            return Ok(json!({"state":"UNSUPPORTED","kind":"UNKNOWN",
                "reason":format!("输入不是可解析的 PE/ELF：{error}"),"target_executed":false}));
        }
    };
    let kind = assessment["kind"].as_str().unwrap_or("UNKNOWN").to_owned();
    if kind == "NONE" {
        return Ok(json!({"state":"NOT_REQUIRED","kind":kind,
            "reason":"未发现保护特征","target_executed":false}));
    }
    let Some(adapter) = adapter_for(&kind) else {
        return Ok(json!({"state":"UNSUPPORTED","kind":kind,
            "reason":"当前没有该保护类型的自动处理链；保留识别证据与不确定性",
            "evidence":assessment["evidence"],"target_executed":false}));
    };
    if let Some(requested) = requested {
        ensure!(
            requested == adapter.name,
            "请求的工具 {requested} 不在 {kind} 的允许清单内"
        );
    }
    let Some(tool) = locate_tool(adapter) else {
        return Ok(
            json!({"state":"UNAVAILABLE","kind":kind,"adapter":adapter.name,
            "reason":format!("未找到允许清单内的工具 {}；不执行替代命令", adapter.binary),
            "target_executed":false}),
        );
    };

    let run_dir = workdir.join(format!("protection-{}", adapter.name));
    tokio::fs::create_dir_all(&run_dir).await?;
    let original = run_dir.join("original.bin");
    let derived = run_dir.join("derived.bin");
    ensure!(
        !derived.exists(),
        "派生产物路径已存在；每次处理使用新的工作目录"
    );
    tokio::fs::write(&original, bytes).await?;

    let version = process::run(
        ProcessSpec {
            program: tool.clone(),
            args: vec!["--version".into()],
            directory: run_dir.clone(),
            env: BTreeMap::new(),
            timeout: Duration::from_secs(20),
        },
        cancel.clone(),
        |_| {},
    )
    .await
    .ok()
    .and_then(|output| {
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .next()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
    })
    .unwrap_or_else(|| adapter.name.to_owned());

    let args: Vec<String> = vec![
        "-d".into(),
        "-o".into(),
        derived.to_string_lossy().into_owned(),
        original.to_string_lossy().into_owned(),
    ];
    let started_at = d::now();
    let outcome = process::run(
        ProcessSpec {
            program: tool.clone(),
            args: args.clone(),
            directory: run_dir.clone(),
            env: BTreeMap::new(),
            timeout: limits.timeout,
        },
        cancel,
        |_| {},
    )
    .await;
    let finished_at = d::now();
    let command =
        json!({"program": adapter.binary, "args": ["-d", "-o", "<derived>", "<original>"]});
    let record = match outcome {
        Err(error) => json!({"state":"FAILED","kind":kind,"adapter":adapter.name,
            "tool_version":version,"original_sha256":sha256(bytes),
            "command":command,"reason":format!("工具启动失败：{error}"),"target_executed":false,
            "started_at":started_at,"finished_at":finished_at}),
        Ok(output) => {
            let ok = output.exit_code == Some(0)
                && !output.timed_out
                && !output.cancelled
                && derived.is_file();
            if !ok {
                json!({"state":"FAILED","kind":kind,"adapter":adapter.name,
                    "tool_version":version,"original_sha256":sha256(bytes),
                    "command":command,"exit_code":output.exit_code,
                    "timed_out":output.timed_out,"cancelled":output.cancelled,
                    "stdout":clip(&output.stdout),"stderr":clip(&output.stderr),
                    "processes_reaped":output.processes_reaped,
                    "reason":"工具未成功完成；原件未被修改，派生产物不作为分析输入",
                    "target_executed":false,
                    "started_at":started_at,"finished_at":finished_at})
            } else {
                let derived_bytes = tokio::fs::read(&derived).await?;
                let before = structure_summary(bytes)?;
                let after = structure_summary(&derived_bytes)?;
                let derived_assessment = assess(&derived_bytes)?;
                let code_size = |summary: &Value| -> u64 {
                    summary["sections"]
                        .as_array()
                        .map(|sections| {
                            sections
                                .iter()
                                .filter_map(|section| section["file_size"].as_u64())
                                .max()
                                .unwrap_or_default()
                        })
                        .unwrap_or_default()
                };
                json!({"state":"PROCESSED","kind":kind,"adapter":adapter.name,
                    "tool_version":version,
                    "original_sha256":sha256(bytes),
                    "derived_sha256":sha256(&derived_bytes),
                    "command":command,"exit_code":output.exit_code,
                    "stdout":clip(&output.stdout),"stderr":clip(&output.stderr),
                    "truncated":output.truncated,
                    "before":before,"after":after,
                    "mapping":{
                        "entry":{"before":before["entry"].clone(),"after":after["entry"].clone()},
                        "sections":{"before":before["sections"].clone(),"after":after["sections"].clone()},
                        "granularity":"节区/入口级；UPX 静态恢复不提供逐指令地址对应",
                    },
                    "derived_assessment":derived_assessment,
                    "readability":{
                        "imports_before":before["imports"].clone(),"imports_after":after["imports"].clone(),
                        "largest_section_before":code_size(&before),
                        "largest_section_after":code_size(&after),
                        "size_before":before["size"].clone(),"size_after":after["size"].clone(),
                    },
                    "limitations":[
                        "UPX 恢复的映像与加壳前字节流不保证逐字节相同（PE 头字段被规范化），派生哈希因此不同",
                        "只证明机制；自制夹具不能代替正式闭源加壳对象",
                        "未执行目标；运行时自解压、反调试与动态解混淆仍未观察",
                    ],
                    "target_executed":false,
                    "started_at":started_at,"finished_at":finished_at})
            }
        }
    };
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn entropy_matches_known_distributions() {
        assert_eq!(entropy(&[]), 0.0);
        assert_eq!(entropy(&[7u8; 4096]), 0.0);
        let uniform: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        assert!((entropy(&uniform) - 8.0).abs() < 1e-9);
    }

    #[test]
    fn known_packer_section_names_are_classified() {
        assert_eq!(signature("UPX0"), Some("UPX"));
        assert_eq!(signature("upx1"), Some("UPX"));
        assert_eq!(signature(".vmp0"), Some("VMProtect"));
        assert_eq!(signature(".Themida"), Some("Themida/WinLicense"));
        assert_eq!(signature(".text"), None);
        assert_eq!(signature(".pdata"), None);
        assert_eq!(signature(".rsrc"), None);
    }

    fn fixture(name: &str) -> Vec<u8> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/binary")
            .join(name);
        std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
    }

    #[test]
    fn benign_fixtures_are_not_falsely_reported_as_packed() {
        for name in ["sample-pe32.exe", "sample-pe64.exe", "sample-elf64"] {
            let report = assess(&fixture(name)).unwrap();
            assert_eq!(report["kind"], "NONE", "{name}: {report}");
            assert_eq!(report["confidence"], "HIGH");
            assert_eq!(report["processing"]["state"], "NOT_REQUIRED");
            assert_eq!(report["target_executed"], false);
        }
    }

    #[test]
    fn unsupported_input_is_rejected_instead_of_guessed() {
        assert!(assess(b"not a binary").is_err());
    }

    fn protection_fixture(name: &str) -> Vec<u8> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/protection")
            .join(name);
        std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
    }

    #[test]
    fn packed_fixture_is_detected_with_an_implemented_processing_chain() {
        let report = assess(&protection_fixture("packable-upx.exe")).unwrap();
        assert_eq!(report["kind"], "UPX", "{report}");
        assert_eq!(report["confidence"], "HIGH");
        assert_eq!(report["processing"]["state"], "SUPPORTED");
        assert_eq!(report["processing"]["tool"], "upx");
        assert_eq!(report["target_executed"], false);
    }

    #[test]
    fn plain_fixture_requires_no_processing() {
        let report = assess(&protection_fixture("packable-plain.exe")).unwrap();
        assert_eq!(report["kind"], "NONE", "{report}");
        assert_eq!(report["processing"]["state"], "NOT_REQUIRED");
    }

    #[tokio::test]
    async fn unprotected_input_is_reported_as_not_required_without_running_a_tool() {
        let workdir = tempfile::tempdir().unwrap();
        let outcome = process(
            &protection_fixture("packable-plain.exe"),
            workdir.path(),
            None,
            ProcessLimits::default(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(outcome["state"], "NOT_REQUIRED", "{outcome}");
        assert_eq!(outcome["target_executed"], false);
        assert!(!workdir.path().join("protection-upx").exists());
    }

    #[tokio::test]
    async fn unparsable_input_is_unsupported_instead_of_guessed() {
        let workdir = tempfile::tempdir().unwrap();
        let outcome = process(
            b"not a binary",
            workdir.path(),
            None,
            ProcessLimits::default(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(outcome["state"], "UNSUPPORTED", "{outcome}");
        assert_eq!(outcome["target_executed"], false);
    }

    #[tokio::test]
    async fn a_tool_outside_the_allow_list_is_refused() {
        let workdir = tempfile::tempdir().unwrap();
        let error = process(
            &protection_fixture("packable-upx.exe"),
            workdir.path(),
            Some("some-other-unpacker"),
            ProcessLimits::default(),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("允许清单"), "{error}");
    }

    #[tokio::test]
    #[ignore = "requires a real UPX on PATH or AEGIS_UPX; run with --ignored"]
    async fn native_upx_processing_preserves_the_original_and_records_mapping() {
        let original = protection_fixture("packable-upx.exe");
        let before_hash = sha256(&original);
        let workdir = tempfile::tempdir().unwrap();
        let outcome = process(
            &original,
            workdir.path(),
            None,
            ProcessLimits::default(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        println!("PROTECTION_EVIDENCE {}", outcome);
        assert_eq!(outcome["state"], "PROCESSED", "{outcome}");
        assert_eq!(outcome["kind"], "UPX");
        assert_eq!(outcome["adapter"], "upx");
        assert_eq!(outcome["target_executed"], false);
        assert_eq!(outcome["original_sha256"], before_hash);
        assert_eq!(sha256(&original), before_hash, "输入字节不得被修改");
        assert_ne!(outcome["derived_sha256"], outcome["original_sha256"]);
        assert_eq!(outcome["derived_assessment"]["kind"], "NONE", "{outcome}");
        assert!(outcome["mapping"]["granularity"].as_str().is_some());
        assert!(outcome["mapping"]["entry"]["before"].as_str().is_some());
        assert!(outcome["mapping"]["entry"]["after"].as_str().is_some());
        let imports_before = outcome["readability"]["imports_before"].as_u64().unwrap();
        let imports_after = outcome["readability"]["imports_after"].as_u64().unwrap();
        assert!(imports_after > imports_before, "{outcome}");
        let largest_before = outcome["readability"]["largest_section_before"]
            .as_u64()
            .unwrap();
        let largest_after = outcome["readability"]["largest_section_after"]
            .as_u64()
            .unwrap();
        assert!(largest_after > largest_before, "{outcome}");
        let run_dir = workdir.path().join("protection-upx");
        assert_eq!(
            sha256(&std::fs::read(run_dir.join("original.bin")).unwrap()),
            before_hash
        );
        assert!(run_dir.join("derived.bin").is_file());
    }

    #[tokio::test]
    #[ignore = "requires a real UPX on PATH or AEGIS_UPX; run with --ignored"]
    async fn native_upx_corrupt_input_fails_without_claiming_success() {
        let mut corrupt = protection_fixture("packable-upx.exe");
        let start = corrupt.len() * 3 / 4;
        for byte in &mut corrupt[start..start + 4096] {
            *byte = 0xFF;
        }
        assert_eq!(
            assess(&corrupt).unwrap()["kind"],
            "UPX",
            "损坏样本仍应被识别"
        );
        let workdir = tempfile::tempdir().unwrap();
        let outcome = process(
            &corrupt,
            workdir.path(),
            None,
            ProcessLimits::default(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        println!("PROTECTION_EVIDENCE {}", outcome);
        assert_eq!(outcome["state"], "FAILED", "{outcome}");
        assert_eq!(outcome["target_executed"], false);
        assert_ne!(outcome["exit_code"], 0);
        assert!(
            !workdir
                .path()
                .join("protection-upx")
                .join("derived.bin")
                .exists()
        );
    }
}
