//! B06 解混淆：静态字符串/数据混淆的检测与恢复。
//!
//! 分类口径参考 Mandiant FLOSS（Apache-2.0）对字符串混淆的四分法：
//! static / stack / tight / decoded。本模块只提供内建的启发式候选恢复；
//! 智能体还可选择 recovery 中的原生 FLOSS、Ghidra 和 ida_d810 适配器。
//!
//! - decoded：单字节 XOR、重复密钥 XOR（假设空格/字母 e 频率）、base64 文本表；
//! - stack / tight strings：由独立 FLOSS 工具处理，本模块不模拟执行；
//! - 代码级混淆：由通过环境探测的 IDA/D-810 工具按规则处理，
//!   本模块不进行控制流或表达式转换。
//!
//! 参考实现思路而非代码：FLOSS 的字符串分类与“解码后必须有意义”的判据。
//! 本模块不执行目标，也不重建可执行映像。
use anyhow::{Context, Result};
use object::{Object, ObjectSection};
use serde_json::{Value, json};

/// 每个数据节区最多扫描的字节数，避免大文件拖垮导入。
const SECTION_SCAN_LIMIT: usize = 512 * 1024;
/// 候选串最短长度与最少字母数，用于压低误报。
const MIN_RUN: usize = 48;
const MIN_LETTERS: usize = 12;
/// 自然文本判据：小写字母占比、不同小写字母数、空格频率、允许字符集占比。
const MIN_LOWERCASE: f64 = 0.55;
const MIN_DISTINCT_LOWERCASE: u32 = 8;
const MIN_SPACES: f64 = 0.03;
const MIN_ALLOWED: f64 = 0.90;

fn printable(byte: u8) -> bool {
    (0x20..=0x7e).contains(&byte) || matches!(byte, b'\t' | b'\n' | b'\r')
}

fn allowed(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b' ' | b'.'
                | b','
                | b';'
                | b':'
                | b'_'
                | b'/'
                | b'\\'
                | b'='
                | b'-'
                | b'@'
                | b'\''
                | b'"'
                | b'('
                | b')'
                | b'['
                | b']'
                | b'{'
                | b'}'
                | b'<'
                | b'>'
                | b'!'
                | b'?'
                | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'*'
                | b'+'
                | b'~'
                | b'|'
                | b'^'
                | b'`'
                | b'\t'
                | b'\n'
                | b'\r'
        )
}

/// 常见英文词与配置类词表：真实字符串表几乎必含若干，机器数据 XOR 出的
/// “可打印噪声”几乎不含。用于把误报压到可复核范围。
const COMMON_WORDS: &[&str] = &[
    "the",
    "and",
    "for",
    "with",
    "this",
    "that",
    "from",
    "have",
    "not",
    "are",
    "was",
    "but",
    "you",
    "all",
    "can",
    "one",
    "our",
    "out",
    "get",
    "has",
    "his",
    "how",
    "new",
    "now",
    "see",
    "way",
    "who",
    "did",
    "its",
    "let",
    "put",
    "say",
    "she",
    "too",
    "use",
    "they",
    "will",
    "your",
    "what",
    "when",
    "where",
    "which",
    "while",
    "about",
    "after",
    "again",
    "because",
    "before",
    "being",
    "between",
    "during",
    "each",
    "more",
    "most",
    "other",
    "some",
    "such",
    "than",
    "their",
    "them",
    "then",
    "there",
    "these",
    "those",
    "through",
    "under",
    "until",
    "very",
    "were",
    "would",
    "should",
    "could",
    "is",
    "it",
    "to",
    "of",
    "in",
    "on",
    "at",
    "by",
    "or",
    "as",
    "be",
    "do",
    "if",
    "no",
    "so",
    "up",
    "we",
    "an",
    "my",
    "me",
    "he",
    "us",
    "am",
    "string",
    "table",
    "host",
    "port",
    "user",
    "password",
    "connection",
    "message",
    "hidden",
    "fixture",
    "server",
    "token",
    "secret",
    "error",
    "file",
    "path",
    "name",
    "value",
    "true",
    "false",
    "null",
    "none",
    "read",
    "write",
    "open",
    "close",
    "send",
    "load",
    "save",
];
const MIN_COMMON_WORDS: usize = 3;

fn common_words(decoded: &[u8]) -> usize {
    let text = String::from_utf8_lossy(decoded).to_ascii_lowercase();
    let mut seen: u128 = 0;
    for word in text.split(|c: char| !c.is_ascii_alphabetic()) {
        if let Some(index) = COMMON_WORDS.iter().position(|common| *common == word) {
            seen |= 1 << index;
        }
    }
    seen.count_ones() as usize
}

fn ratio(count: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        count as f64 / total as f64
    }
}

/// 解码游程的自然文本统计：用于区分真实字符串表与“恰好可打印”的机器数据。
#[derive(Default, Clone, Copy)]
struct Run {
    length: usize,
    spaces: usize,
    letters: usize,
    lowercase: usize,
    lowercase_mask: u32,
    allowed: usize,
    original_printable: usize,
}

impl Run {
    fn push(&mut self, decoded: u8, original: u8) {
        self.length += 1;
        if decoded == b' ' {
            self.spaces += 1;
        }
        if decoded.is_ascii_alphabetic() {
            self.letters += 1;
            if decoded.is_ascii_lowercase() {
                self.lowercase += 1;
                self.lowercase_mask |= 1 << (decoded - b'a');
            }
        }
        if allowed(decoded) {
            self.allowed += 1;
        }
        if printable(original) {
            self.original_printable += 1;
        }
    }

    fn textual(&self) -> bool {
        self.length >= MIN_RUN
            && self.letters >= MIN_LETTERS
            && ratio(self.lowercase, self.letters) >= MIN_LOWERCASE
            && self.lowercase_mask.count_ones() >= MIN_DISTINCT_LOWERCASE
            && ratio(self.spaces, self.length) >= MIN_SPACES
            && ratio(self.allowed, self.length) >= MIN_ALLOWED
    }
}

/// 数据节区：名称含 data/rodata/rdata 且不可执行。代码节区的 XOR 结果不算字符串证据。
fn data_sections(file: &object::File<'_>) -> Vec<(&'static str, Vec<u8>)> {
    let mut sections = Vec::new();
    for section in file.sections() {
        let name = section.name().unwrap_or("").to_ascii_lowercase();
        if !(name.contains("data") || name.contains("rodata") || name.contains("rdata")) {
            continue;
        }
        let Ok(bytes) = section.data() else { continue };
        let bytes = &bytes[..bytes.len().min(SECTION_SCAN_LIMIT)];
        let label: &'static str = match name.as_str() {
            ".rdata" => ".rdata",
            ".data" => ".data",
            ".rodata" => ".rodata",
            ".data.rel.ro" => ".data.rel.ro",
            _ => "其他数据节区",
        };
        sections.push((label, bytes.to_vec()));
    }
    sections
}

/// 单字节 XOR 候选：对每个密钥扫描最长的可打印游程，再用自然文本判据确认。
fn xor_candidates(section: &str, data: &[u8]) -> Vec<Value> {
    let mut candidates = Vec::new();
    for key in 1u8..=255 {
        let mut start = 0usize;
        let mut run = Run::default();
        for (index, &byte) in data.iter().enumerate() {
            let decoded = byte ^ key;
            if printable(decoded) {
                if run.length == 0 {
                    start = index;
                }
                run.push(decoded, byte);
            } else if run.length > 0 {
                push_if_text(&mut candidates, section, data, key, start, index, &run);
                run = Run::default();
            }
        }
        push_if_text(&mut candidates, section, data, key, start, data.len(), &run);
    }
    candidates
}

fn push_if_text(
    candidates: &mut Vec<Value>,
    section: &str,
    data: &[u8],
    key: u8,
    start: usize,
    end: usize,
    run: &Run,
) {
    if !run.textual() {
        return;
    }
    let decoded: Vec<u8> = data[start..end].iter().map(|byte| byte ^ key).collect();
    if common_words(&decoded) < MIN_COMMON_WORDS {
        return;
    }
    let text = String::from_utf8_lossy(&decoded).into_owned();
    candidates.push(json!({
        "kind": "XOR_SINGLE_BYTE",
        "section": section,
        "offset": start,
        "length": end - start,
        "key": format!("0x{key:02x}"),
        "original_printable_ratio": (ratio(run.original_printable, run.length) * 100.0).round() / 100.0,
        "common_words": common_words(&decoded),
        "text": text.chars().take(2000).collect::<String>(),
    }));
}

const BASE64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_decode(run: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for &byte in run {
        if byte == b'=' {
            break;
        }
        let value = BASE64.iter().position(|&c| c == byte)? as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

/// 重复密钥 XOR：窗口、步长与密钥长度范围。仅扫描每个数据节区的前 64KB。
/// 窗口需完整落在混淆表内；窗口起点相对表起点的偏移不影响还原（密钥相位会自行补偿）。
const REPEATING_SCAN_LIMIT: usize = 64 * 1024;
const REPEATING_WINDOW: usize = 256;
const REPEATING_STEP: usize = 64;
const REPEATING_MAX_KEY: usize = 8;

/// 英文字母与空格频率（%），用于逐列密钥评分。
const ENGLISH_FREQ: [f64; 26] = [
    8.17, 1.49, 2.78, 4.25, 12.70, 2.23, 2.02, 6.09, 6.97, 0.15, 0.77, 4.03, 2.41, 6.75, 7.51,
    1.93, 0.10, 5.99, 6.33, 9.06, 2.76, 0.98, 2.36, 0.15, 1.97, 0.07,
];

fn char_score(byte: u8) -> f64 {
    match byte {
        b'a'..=b'z' => ENGLISH_FREQ[(byte - b'a') as usize],
        b' ' => 13.0,
        b'\t' | b'\n' | b'\r' => 0.2,
        0x21..=0x7e => 0.05,
        _ => -8.0,
    }
}

/// 对一列字节按频率评分选最优密钥字节；短样本下比“众数=空格”更稳。
fn best_key_byte(column: &[u8]) -> u8 {
    let mut best = (f64::MIN, 0u8);
    for key in 0u16..=255 {
        let key = key as u8;
        let score: f64 = column.iter().map(|&byte| char_score(byte ^ key)).sum();
        if score > best.0 {
            best = (score, key);
        }
    }
    best.1
}

/// 重复密钥 XOR 候选：逐列频率评分推导密钥，再用文本判据校验。
fn repeating_xor_candidates(section: &str, data: &[u8]) -> Vec<Value> {
    let data = &data[..data.len().min(REPEATING_SCAN_LIMIT)];
    let mut candidates = Vec::new();
    if data.len() < REPEATING_WINDOW {
        return candidates;
    }
    let mut seen = Vec::new();
    for length in 2..=REPEATING_MAX_KEY {
        let mut start = 0;
        while start + REPEATING_WINDOW <= data.len() {
            let window = &data[start..start + REPEATING_WINDOW];
            let mut key = vec![0u8; length];
            for (index, slot) in key.iter_mut().enumerate() {
                *slot = best_key_byte(
                    &window[index..]
                        .iter()
                        .step_by(length)
                        .copied()
                        .collect::<Vec<_>>(),
                );
            }
            // 单字节密钥已由单字节扫描覆盖，避免重复。
            if key.iter().all(|&byte| byte == key[0]) {
                start += REPEATING_STEP;
                continue;
            }
            let decoded: Vec<u8> = window
                .iter()
                .enumerate()
                .map(|(index, &byte)| byte ^ key[index % length])
                .collect();
            if !looks_like_text(&decoded) {
                start += REPEATING_STEP;
                continue;
            }
            let key_hex = key
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join("");
            if !seen.contains(&key_hex) {
                seen.push(key_hex.clone());
                let text = String::from_utf8_lossy(&decoded).into_owned();
                candidates.push(json!({
                    "kind": "XOR_REPEATING_KEY",
                    "section": section,
                    "offset": start,
                    "length": REPEATING_WINDOW,
                    "key": key_hex,
                    "common_words": common_words(&decoded),
                    "text": text.chars().take(2000).collect::<String>(),
                }));
            }
            start += REPEATING_STEP;
        }
    }
    candidates
}

/// 解码后的字节是否像自然文本（用于 base64 文本表判定）。
fn looks_like_text(decoded: &[u8]) -> bool {
    let mut run = Run::default();
    for &byte in decoded {
        if !printable(byte) {
            return false;
        }
        run.push(byte, byte);
    }
    run.textual() && common_words(decoded) >= MIN_COMMON_WORDS
}

/// Base64 文本表：连续的 base64 字母表字符，解码后可读。
fn base64_candidates(section: &str, data: &[u8]) -> Vec<Value> {
    let mut candidates = Vec::new();
    let mut index = 0;
    while index < data.len() {
        if !BASE64.contains(&data[index]) {
            index += 1;
            continue;
        }
        let start = index;
        while index < data.len() && (BASE64.contains(&data[index]) || data[index] == b'=') {
            index += 1;
        }
        let run = &data[start..index];
        if run.len() < 32 {
            continue;
        }
        let Some(decoded) = base64_decode(run) else {
            continue;
        };
        if !looks_like_text(&decoded) {
            continue;
        }
        let text = String::from_utf8_lossy(&decoded).into_owned();
        candidates.push(json!({
            "kind": "BASE64_TEXT",
            "section": section,
            "offset": start,
            "length": run.len(),
            "key": "",
            "text": text.chars().take(2000).collect::<String>(),
        }));
    }
    candidates
}

/// 能力矩阵：按 FLOSS 的字符串分类声明支持边界。
pub fn patterns() -> Value {
    json!([
        {"pattern":"DECODED_XOR_SINGLE_BYTE","state":"SUPPORTED","reason":"单字节 XOR 字符串表可静态恢复"},
        {"pattern":"DECODED_XOR_REPEATING_KEY","state":"SUPPORTED","reason":"重复密钥 XOR 按空格/字母 e 频率推导密钥并校验"},
        {"pattern":"BASE64_TEXT","state":"SUPPORTED","reason":"base64 文本表可静态解码"},
        {"pattern":"STACK_STRINGS","state":"UNSUPPORTED","reason":"本模块不模拟执行；可由智能体选择独立 FLOSS 适配器"},
        {"pattern":"TIGHT_STRINGS","state":"UNSUPPORTED","reason":"本模块不模拟执行；可由智能体选择独立 FLOSS 适配器"},
        {"pattern":"CODE_LEVEL_CFF_MBA","state":"UNSUPPORTED","reason":"控制流平坦化/MBA/不透明谓词需要 IDA/Ghidra 微码（D-810）或符号执行（angr/Triton/Miasm）；不承诺通用解混淆"},
        {"pattern":"DYNAMIC_KEY","state":"UNSUPPORTED","reason":"运行期计算或按字节变化的密钥未观察，静态不猜测"},
    ])
}

/// 静态检测：返回候选模式与证据。不执行目标。
pub fn assess(bytes: &[u8]) -> Result<Value> {
    if !(bytes.starts_with(b"MZ") || bytes.starts_with(b"\x7fELF")) {
        anyhow::bail!("unsupported binary format: expected PE or ELF");
    }
    let file = object::File::parse(bytes).context("malformed PE/ELF file")?;
    let mut candidates = Vec::new();
    for (section, data) in data_sections(&file) {
        candidates.extend(xor_candidates(section, &data));
        candidates.extend(repeating_xor_candidates(section, &data));
        candidates.extend(base64_candidates(section, &data));
    }
    candidates.sort_by(|a, b| {
        b["length"]
            .as_u64()
            .unwrap_or_default()
            .cmp(&a["length"].as_u64().unwrap_or_default())
    });
    candidates.truncate(16);
    let confidence = match candidates.len() {
        0 => "NONE",
        1 => "MEDIUM",
        _ => "HIGH",
    };
    Ok(json!({
        "state": if candidates.is_empty() { "NOT_FOUND" } else { "CANDIDATES" },
        "confidence": confidence,
        "patterns": patterns(),
        "candidates": candidates,
        "limitations": [
            "只做静态模式检测；运行期解密、动态密钥与代码级混淆未观察",
            "XOR 候选按节区窗口统计，可能与合法编码数据混淆，需人工复核",
            "自制夹具只证明机制，不能代替正式混淆对象",
        ],
        "target_executed": false,
    }))
}

/// 恢复：把候选解码为可读字符串并写入派生产物；原件不变。
pub async fn recover(bytes: &[u8], workdir: &std::path::Path) -> Result<Value> {
    let assessment = assess(bytes)?;
    let candidates = assessment["candidates"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if candidates.is_empty() {
        return Ok(json!({
            "state":"NOT_FOUND",
            "reason":"未发现支持模式的可恢复候选；不猜测动态密钥",
            "candidates":[],
            "target_executed":false,
        }));
    }
    std::fs::create_dir_all(workdir)?;
    let derived = workdir.join("recovered.txt");
    anyhow::ensure!(
        !derived.exists(),
        "派生产物路径已存在；每次恢复使用新的工作目录"
    );
    let mut output = String::new();
    for candidate in &candidates {
        output.push_str(&format!(
            "== {} {} offset={} key={} length={} ==\n{}\n\n",
            candidate["kind"].as_str().unwrap_or("UNKNOWN"),
            candidate["section"].as_str().unwrap_or(""),
            candidate["offset"].as_u64().unwrap_or_default(),
            candidate["key"].as_str().unwrap_or(""),
            candidate["length"].as_u64().unwrap_or_default(),
            candidate["text"].as_str().unwrap_or(""),
        ));
    }
    std::fs::write(&derived, output.as_bytes())?;
    let recovered_bytes: usize = candidates
        .iter()
        .map(|candidate| candidate["text"].as_str().unwrap_or("").len())
        .sum();
    Ok(json!({
        "state":"RECOVERED",
        "candidates":candidates,
        "recovered_strings":candidates.len(),
        "recovered_text_bytes":recovered_bytes,
        "derived_sha256":aegis_domain::sha256(output.as_bytes()),
        "readability":{
            "candidates":candidates.len(),
            "note":"恢复后的文本可读；未重建可执行映像",
        },
        "limitations":[
            "只恢复支持模式的字符串/数据；不修改或重建原二进制",
            "运行期解密、动态密钥与代码级混淆仍未处理",
            "自制夹具只证明机制，不能代替正式混淆对象",
        ],
        "target_executed":false,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fixture(name: &str) -> Vec<u8> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/deobfuscation")
            .join(name);
        std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
    }

    #[test]
    fn obfuscated_fixture_yields_all_supported_patterns() {
        let report = assess(&fixture("obfuscated.exe")).unwrap();
        assert_eq!(report["state"], "CANDIDATES", "{report}");
        let candidates = report["candidates"].as_array().unwrap();
        let xor = candidates
            .iter()
            .find(|candidate| candidate["kind"] == "XOR_SINGLE_BYTE" && candidate["key"] == "0x5a")
            .unwrap_or_else(|| panic!("single-byte XOR candidate: {report}"));
        assert!(
            xor["text"]
                .as_str()
                .unwrap()
                .contains("AegisAudit deobfuscation fixture")
        );
        let repeating = candidates
            .iter()
            .find(|candidate| {
                candidate["kind"] == "XOR_REPEATING_KEY" && candidate["key"] == "37139b42"
            })
            .unwrap_or_else(|| panic!("repeating-key XOR candidate: {report}"));
        assert!(
            repeating["text"]
                .as_str()
                .unwrap()
                .contains("repeating key"),
            "窗口落在表内部，恢复的是该窗口覆盖的明文片段"
        );
        let base64 = candidates
            .iter()
            .find(|candidate| candidate["kind"] == "BASE64_TEXT")
            .expect("base64 candidate");
        assert!(
            base64["text"]
                .as_str()
                .unwrap()
                .contains("AegisAudit base64 fixture")
        );
        assert_eq!(report["target_executed"], false);
    }

    #[test]
    fn benign_binaries_are_not_falsely_flagged() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/binary/sample-pe64.exe");
        let report = assess(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(report["state"], "NOT_FOUND", "{report}");
    }

    #[test]
    fn unparsable_input_is_rejected_instead_of_guessed() {
        assert!(assess(b"not a binary").is_err());
    }

    #[test]
    fn code_level_and_dynamic_obfuscation_stay_unsupported() {
        let report = assess(&fixture("obfuscated.exe")).unwrap();
        let patterns = report["patterns"].as_array().unwrap();
        for name in [
            "STACK_STRINGS",
            "TIGHT_STRINGS",
            "CODE_LEVEL_CFF_MBA",
            "DYNAMIC_KEY",
        ] {
            let entry = patterns
                .iter()
                .find(|entry| entry["pattern"] == name)
                .unwrap_or_else(|| panic!("missing {name}"));
            assert_eq!(entry["state"], "UNSUPPORTED");
        }
    }

    #[tokio::test]
    async fn recovery_writes_derived_text_and_keeps_the_original() {
        let original = fixture("obfuscated.exe");
        let before = aegis_domain::sha256(&original);
        let workdir = tempfile::tempdir().unwrap();
        let outcome = recover(&original, workdir.path()).await.unwrap();
        println!("DEOBFUSCATION_EVIDENCE {outcome}");
        assert_eq!(outcome["state"], "RECOVERED", "{outcome}");
        assert_eq!(outcome["target_executed"], false);
        assert_eq!(
            aegis_domain::sha256(&original),
            before,
            "输入字节不得被修改"
        );
        let derived = std::fs::read(workdir.path().join("recovered.txt")).unwrap();
        assert_eq!(outcome["derived_sha256"], aegis_domain::sha256(&derived));
        let text = String::from_utf8_lossy(&derived);
        assert!(text.contains("AegisAudit"));
        assert!(text.contains("AegisAudit base64 fixture"));
    }

    #[tokio::test]
    async fn recovery_reports_not_found_for_plain_binaries() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/binary/sample-pe64.exe");
        let workdir = tempfile::tempdir().unwrap();
        let outcome = recover(&std::fs::read(path).unwrap(), workdir.path())
            .await
            .unwrap();
        assert_eq!(outcome["state"], "NOT_FOUND", "{outcome}");
        assert!(!workdir.path().join("recovered.txt").exists());
    }
}
