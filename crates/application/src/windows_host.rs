use crate::process::{self, ProcessSpec};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

use crate::runtime::windows_runtime::{
    WindowsRuntimeAdapter, WindowsRuntimeConfig, WindowsRuntimeEntry,
};

pub const HOST_RUNTIME_SCHEMA_VERSION: u32 = 1;
const RECEIPT_FILE: &str = "session.json";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum HostRuntimeEntrypoint {
    #[serde(rename = "ORIGINAL_PE")]
    OriginalPe,
    #[serde(rename = "WINDOWS_PYTHON")]
    WindowsPython,
    #[serde(rename = "WINDOWS_NATIVE_SOURCE")]
    WindowsNativeSource,
    #[serde(rename = "WINDOWS_LIBFUZZER_PREBUILT")]
    WindowsLibFuzzerPrebuilt,
}

impl HostRuntimeEntrypoint {
    fn script(self) -> &'static str {
        match self {
            Self::OriginalPe => "run-pe.ps1",
            Self::WindowsPython => "run-python.ps1",
            Self::WindowsNativeSource => "run-native-source.ps1",
            Self::WindowsLibFuzzerPrebuilt => "run-libfuzzer.ps1",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostRuntimeSession {
    pub run_id: String,
    pub attempt_id: String,
    pub session_id: String,
    pub target_sha256: String,
    pub config_sha256: String,
}

impl HostRuntimeSession {
    pub fn validate(&self) -> Result<()> {
        for (name, value) in [
            ("run_id", &self.run_id),
            ("attempt_id", &self.attempt_id),
            ("session_id", &self.session_id),
        ] {
            ensure!(
                is_identifier(value),
                "{name} must contain 1-128 ASCII letters, digits, hyphens, or underscores"
            );
        }
        ensure!(
            self.session_id
                .starts_with(&format!("{}-", self.attempt_id)),
            "session_id must be namespaced by attempt_id"
        );
        ensure!(
            is_sha256(&self.target_sha256) && is_sha256(&self.config_sha256),
            "target and configuration hashes must be SHA-256 values"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostRuntimeFileTransfer {
    pub source: PathBuf,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostRuntimeArtifact {
    pub path: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostRuntimeReceipt {
    pub schema_version: u32,
    pub run_id: String,
    pub attempt_id: String,
    pub session_id: String,
    pub status: String,
}

impl HostRuntimeReceipt {
    fn validate(&self, session: &HostRuntimeSession) -> Result<()> {
        ensure!(
            self.schema_version == HOST_RUNTIME_SCHEMA_VERSION,
            "unsupported host runtime receipt schema"
        );
        ensure!(
            self.run_id == session.run_id
                && self.attempt_id == session.attempt_id
                && self.session_id == session.session_id,
            "host runtime receipt belongs to another attempt"
        );
        ensure!(
            ["COMPLETED", "ERROR"].contains(&self.status.as_str()),
            "host runtime receipt status must be COMPLETED or ERROR"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostRuntimeOutputPolicy {
    pub required_files: BTreeSet<String>,
    pub optional_files: BTreeSet<String>,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
}

impl HostRuntimeOutputPolicy {
    pub fn original_pe() -> Self {
        Self::runtime_output()
    }

    pub fn windows_python() -> Self {
        Self::runtime_output()
    }

    pub fn windows_native_source() -> Self {
        Self {
            optional_files: BTreeSet::from([
                "compile.stderr.log".into(),
                "compile.stdout.log".into(),
                "guest-error.json".into(),
                "guest-observation.json".into(),
                "target-executed.txt".into(),
                "target.stderr.log".into(),
                "target.stdout.log".into(),
            ]),
            max_total_bytes: 4 * 1024 * 1024,
            ..Self::runtime_output()
        }
    }

    pub fn windows_lib_fuzzer() -> Self {
        let mut optional_files = BTreeSet::from([
            "crash-input.bin".into(),
            "guest-error.json".into(),
            "guest-observation.json".into(),
            "target-executed.txt".into(),
            "target.stderr.log".into(),
            "target.stdout.log".into(),
        ]);
        for index in 1..=16 {
            optional_files.insert(format!("crash-{index:02}-input.bin"));
            optional_files.insert(format!("crash-{index:02}-minimize.stdout.log"));
            optional_files.insert(format!("crash-{index:02}-minimize.stderr.log"));
        }
        Self {
            optional_files,
            max_total_bytes: 4 * 1024 * 1024,
            ..Self::runtime_output()
        }
    }

    fn runtime_output() -> Self {
        Self {
            required_files: BTreeSet::from([RECEIPT_FILE.into()]),
            optional_files: BTreeSet::from([
                "guest-error.json".into(),
                "guest-observation.json".into(),
                "target-executed.txt".into(),
                "target.stderr.log".into(),
                "target.stdout.log".into(),
            ]),
            max_file_bytes: 1024 * 1024,
            max_total_bytes: 2 * 1024 * 1024,
        }
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.required_files.contains(RECEIPT_FILE),
            "the host runtime output protocol requires session.json"
        );
        ensure!(
            self.required_files.is_disjoint(&self.optional_files),
            "required and optional output files overlap"
        );
        ensure!(
            self.max_file_bytes > 0
                && self.max_total_bytes >= self.max_file_bytes
                && self.max_total_bytes <= 64 * 1024 * 1024,
            "invalid host runtime output size policy"
        );
        for file in self.required_files.iter().chain(self.optional_files.iter()) {
            ensure!(
                relative_path(file).is_some(),
                "invalid output file path: {file}"
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostRuntimeOutput {
    pub receipt: HostRuntimeReceipt,
    pub artifacts: Vec<HostRuntimeArtifact>,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostRuntimeExecution {
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub cancelled: bool,
    pub processes_reaped: bool,
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedHostRuntime {
    pub entrypoint: HostRuntimeEntrypoint,
    pub session: HostRuntimeSession,
    pub root: PathBuf,
    pub tool_root: PathBuf,
    pub input: PathBuf,
    pub output: PathBuf,
    pub tools: PathBuf,
    pub script: PathBuf,
    pub manifest: PathBuf,
    pub input_files: Vec<HostRuntimeArtifact>,
    pub tool_files: Vec<HostRuntimeArtifact>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostRuntimeSpec {
    pub entrypoint: HostRuntimeEntrypoint,
    pub session: HostRuntimeSession,
    pub root: PathBuf,
    pub tool_root: PathBuf,
    pub inputs: Vec<HostRuntimeFileTransfer>,
    pub tools: Vec<HostRuntimeFileTransfer>,
    pub runtime_config: Option<WindowsRuntimeConfig>,
}

pub fn prepare(spec: &HostRuntimeSpec) -> Result<PreparedHostRuntime> {
    spec.session.validate()?;
    validate_entrypoint(spec)?;
    ensure!(
        spec.root.is_absolute(),
        "host runtime root must be absolute"
    );
    fs::create_dir_all(spec.root.join("input"))?;
    fs::create_dir_all(spec.root.join("output"))?;
    fs::create_dir_all(spec.root.join("tools"))?;
    let input_files = copy_files(&spec.inputs, &spec.root.join("input"), "input")?;
    let tool_files = copy_files(&spec.tools, &spec.root.join("tools"), "tools")?;
    let script = spec.root.join("tools").join(spec.entrypoint.script());
    ensure!(script.is_file(), "host runtime script is missing");
    let session_path = spec.root.join("input/session.json");
    write_json(
        &session_path,
        &json!({
            "schema_version": HOST_RUNTIME_SCHEMA_VERSION,
            "run_id": spec.session.run_id,
            "attempt_id": spec.session.attempt_id,
            "session_id": spec.session.session_id,
            "target_sha256": spec.session.target_sha256,
            "config_sha256": spec.session.config_sha256
        }),
    )?;
    let mut input_files = input_files;
    input_files.push(artifact(&session_path, RECEIPT_FILE)?);
    if let Some(config) = &spec.runtime_config {
        write_json(&spec.root.join("input/runtime-config.json"), &config)?;
    }
    let manifest = spec.root.join("manifest.json");
    write_json(
        &manifest,
        &json!({
            "schema_version": HOST_RUNTIME_SCHEMA_VERSION,
            "session": spec.session,
            "entrypoint": spec.entrypoint,
            "input_files": input_files,
            "tool_files": tool_files,
            "policy": {"execution": "HOST", "process_tree_reaping": "WINDOWS_JOB_OBJECT"}
        }),
    )?;
    Ok(PreparedHostRuntime {
        entrypoint: spec.entrypoint,
        session: spec.session.clone(),
        root: spec.root.clone(),
        tool_root: spec.tool_root.clone(),
        input: spec.root.join("input"),
        output: spec.root.join("output"),
        tools: spec.root.join("tools"),
        script,
        manifest,
        input_files,
        tool_files,
    })
}

pub fn verify_inputs(prepared: &PreparedHostRuntime) -> Result<()> {
    for artifact in prepared
        .input_files
        .iter()
        .chain(prepared.tool_files.iter())
    {
        ensure!(artifact.path.len() <= 512, "host runtime path is too long");
    }
    Ok(())
}

pub async fn run(
    prepared: &PreparedHostRuntime,
    timeout: Duration,
    cancel: CancellationToken,
) -> Result<HostRuntimeExecution> {
    let program = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
        .join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    let python_path = prepared.tool_root.join("windows-python");
    let zig_path = prepared.tool_root.join("zig");
    let output = process::run(
        ProcessSpec {
            program,
            args: {
                let mut args = vec![
                    "-NoProfile".into(),
                    "-ExecutionPolicy".into(),
                    "Bypass".into(),
                    "-File".into(),
                    prepared.script.to_string_lossy().into_owned(),
                    "-InputPath".into(),
                    prepared.input.to_string_lossy().into_owned(),
                    "-OutputPath".into(),
                    prepared.output.to_string_lossy().into_owned(),
                    "-PythonPath".into(),
                    python_path.to_string_lossy().into_owned(),
                    "-ZigPath".into(),
                    zig_path.to_string_lossy().into_owned(),
                ];
                if prepared.entrypoint == HostRuntimeEntrypoint::WindowsLibFuzzerPrebuilt {
                    args.push("-LlvmPath".into());
                    args.push(
                        prepared
                            .tool_root
                            .join("llvm-min")
                            .to_string_lossy()
                            .into_owned(),
                    );
                }
                args
            },
            directory: prepared.root.clone(),
            env: BTreeMap::new(),
            timeout,
        },
        cancel,
        |_| {},
    )
    .await?;
    Ok(HostRuntimeExecution {
        exit_code: output.exit_code,
        timed_out: output.timed_out,
        cancelled: output.cancelled,
        processes_reaped: output.processes_reaped,
        success: output.exit_code == Some(0)
            && output.processes_reaped
            && !output.timed_out
            && !output.cancelled,
        stdout: decode_guest_output(&output.stdout),
        stderr: decode_guest_output(&output.stderr),
    })
}

/// Decode captured guest output.
///
/// A redirected PowerShell stdout is written in the console output code page
/// (CP936 on a Chinese Windows), so a guest that prints a path or a message
/// containing non-ASCII characters delivers ANSI bytes. Decoding those as UTF-8
/// replaces every such character with U+FFFD, which turns a successful run that
/// merely mentioned a non-ASCII path into unreadable output. Prefer UTF-8 and
/// fall back to the OEM code page.
fn decode_guest_output(bytes: &[u8]) -> String {
    if let Ok(text) = std::str::from_utf8(bytes) {
        return text.to_owned();
    }
    #[cfg(windows)]
    if let Some(text) = decode_oem_code_page(bytes) {
        return text;
    }
    String::from_utf8_lossy(bytes).into_owned()
}

#[cfg(windows)]
fn decode_oem_code_page(bytes: &[u8]) -> Option<String> {
    use windows_sys::Win32::Globalization::{CP_OEMCP, MultiByteToWideChar};
    let length = i32::try_from(bytes.len()).ok()?;
    if length == 0 {
        return Some(String::new());
    }
    // A zero cchWideChar asks for the required buffer length; the conversion
    // does not NUL-terminate, so truncate to what was actually written.
    let needed = unsafe {
        MultiByteToWideChar(CP_OEMCP, 0, bytes.as_ptr(), length, std::ptr::null_mut(), 0)
    };
    if needed <= 0 {
        return None;
    }
    let mut wide = vec![0u16; needed as usize];
    let written = unsafe {
        MultiByteToWideChar(
            CP_OEMCP,
            0,
            bytes.as_ptr(),
            length,
            wide.as_mut_ptr(),
            needed,
        )
    };
    if written <= 0 {
        return None;
    }
    wide.truncate(written as usize);
    String::from_utf16(&wide).ok()
}

pub fn collect_output(
    prepared: &PreparedHostRuntime,
    policy: &HostRuntimeOutputPolicy,
) -> Result<HostRuntimeOutput> {
    policy.validate()?;
    let receipt: HostRuntimeReceipt = serde_json::from_slice(
        &fs::read(prepared.output.join(RECEIPT_FILE))
            .with_context(|| format!("cannot read host runtime receipt {RECEIPT_FILE}"))?,
    )?;
    receipt.validate(&prepared.session)?;
    let mut artifacts = vec![artifact(&prepared.output.join(RECEIPT_FILE), RECEIPT_FILE)?];
    let mut total_bytes = artifacts[0].size;
    for file in policy.optional_files.iter() {
        let path = prepared.output.join(file);
        if !path.exists() {
            continue;
        }
        ensure!(path.is_file(), "host runtime output is not a file: {file}");
        let item = artifact(&path, file)?;
        ensure!(
            item.size <= policy.max_file_bytes,
            "host runtime output file exceeds the size limit: {file}"
        );
        total_bytes += item.size;
        artifacts.push(item);
    }
    ensure!(
        total_bytes <= policy.max_total_bytes,
        "host runtime output exceeds the total size limit"
    );
    let allowed = policy
        .required_files
        .iter()
        .chain(policy.optional_files.iter())
        .collect::<BTreeSet<_>>();
    for entry in fs::read_dir(&prepared.output)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        ensure!(
            allowed.contains(&name),
            "unexpected host runtime output: {name}"
        );
    }
    Ok(HostRuntimeOutput {
        receipt,
        artifacts,
        total_bytes,
    })
}

fn validate_entrypoint(spec: &HostRuntimeSpec) -> Result<()> {
    let config = match (&spec.entrypoint, &spec.runtime_config) {
        (HostRuntimeEntrypoint::OriginalPe, Some(config)) => {
            config.validate()?;
            ensure!(
                matches!(
                    config.adapter,
                    WindowsRuntimeAdapter::OriginalPe32 | WindowsRuntimeAdapter::OriginalPe64
                ),
                "the original PE entrypoint requires a PE adapter"
            );
            ensure!(
                matches!(&config.entry, WindowsRuntimeEntry::CommandLine { .. }),
                "the original PE entrypoint requires a command-line entry"
            );
            config
        }
        (HostRuntimeEntrypoint::WindowsPython, Some(config)) => {
            config.validate()?;
            ensure!(
                config.adapter == WindowsRuntimeAdapter::PythonCall,
                "the Windows Python entrypoint requires a Python adapter"
            );
            ensure!(
                matches!(&config.entry, WindowsRuntimeEntry::Function { .. }),
                "the Windows Python entrypoint requires a function entry"
            );
            config
        }
        (HostRuntimeEntrypoint::WindowsNativeSource, Some(config)) => {
            config.validate()?;
            ensure!(
                config.adapter == WindowsRuntimeAdapter::NativeSource,
                "the native-source entrypoint requires a native source adapter"
            );
            ensure!(
                matches!(&config.entry, WindowsRuntimeEntry::CommandLine { .. }),
                "the native-source entrypoint requires a command-line entry"
            );
            config
        }
        (HostRuntimeEntrypoint::WindowsLibFuzzerPrebuilt, Some(config)) => {
            config.validate()?;
            ensure!(
                config.adapter == WindowsRuntimeAdapter::LibFuzzerPrebuilt,
                "the libFuzzer entrypoint requires a prebuilt libFuzzer adapter"
            );
            ensure!(
                matches!(&config.entry, WindowsRuntimeEntry::CommandLine { .. }),
                "the libFuzzer entrypoint requires a command-line entry"
            );
            config
        }
        _ => anyhow::bail!("host runtime entrypoint and configuration do not match"),
    };
    if let Some(input) = spec
        .inputs
        .iter()
        .find(|item| item.path == config.target_path)
    {
        ensure!(
            aegis_domain::sha256(&fs::read(&input.source)?) == config.target_sha256,
            "host runtime target hash mismatch"
        );
    } else {
        anyhow::bail!("host runtime target is missing");
    }
    Ok(())
}

fn copy_files(
    transfers: &[HostRuntimeFileTransfer],
    destination_root: &Path,
    name: &str,
) -> Result<Vec<HostRuntimeArtifact>> {
    let mut paths = BTreeSet::new();
    let mut artifacts = Vec::new();
    for transfer in transfers {
        ensure!(
            relative_path(&transfer.path).is_some(),
            "unsafe {name} path: {}",
            transfer.path
        );
        ensure!(
            paths.insert(transfer.path.clone()),
            "duplicate {name} path: {}",
            transfer.path
        );
        let source = &transfer.source;
        ensure!(source.is_file(), "{name} is not a file: {source:?}");
        let destination = destination_root.join(&transfer.path);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("cannot create {name} directory {parent:?}"))?;
        }
        ensure!(!destination.exists(), "{name} destination already exists");
        fs::copy(source, &destination)
            .with_context(|| format!("cannot copy {name} file {}", transfer.path))?;
        artifacts.push(artifact(&destination, &transfer.path)?);
    }
    Ok(artifacts)
}

fn artifact(path: &Path, relative: &str) -> Result<HostRuntimeArtifact> {
    let data = fs::read(path).with_context(|| format!("cannot read host runtime file {path:?}"))?;
    Ok(HostRuntimeArtifact {
        path: relative.into(),
        sha256: aegis_domain::sha256(&data),
        size: data.len() as u64,
    })
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, &bytes)?;
    fs::rename(&temporary, path)?;
    Ok(())
}

fn relative_path(path: &str) -> Option<&str> {
    (path.len() <= 512
        && !path.contains(['\\', ':', '\0', '\n', '\r'])
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != ".."))
    .then_some(path)
}

fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn libfuzzer_outputs_accept_all_bounded_crash_evidence() {
        let policy = HostRuntimeOutputPolicy::windows_lib_fuzzer();
        policy.validate().unwrap();
        for file in [
            "crash-input.bin",
            "crash-01-input.bin",
            "crash-01-minimize.stdout.log",
            "crash-01-minimize.stderr.log",
            "crash-16-input.bin",
            "crash-16-minimize.stderr.log",
        ] {
            assert!(
                policy.optional_files.contains(file),
                "missing output: {file}"
            );
        }
        assert!(!policy.optional_files.contains("crash-17-input.bin"));
        assert!(!policy.optional_files.contains("crash-01-minimize.log"));
    }
}
