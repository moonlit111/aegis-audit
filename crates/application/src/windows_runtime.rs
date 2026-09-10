//! A03 configuration model for the future Windows-native runtime contract.
//!
//! This module is intentionally independent of the legacy Linux/ELF contract.
//! It gives A a reviewable shape for C00 without changing shared protocol or
//! database types before the contract is frozen.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const WINDOWS_RUNTIME_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum WindowsRuntimeMode {
    #[serde(rename = "VERIFY")]
    Verify,
    #[serde(rename = "FUZZ")]
    Fuzz,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum WindowsRuntimeAdapter {
    #[serde(rename = "WINDOWS_PYTHON_CALL")]
    PythonCall,
    #[serde(rename = "WINDOWS_NATIVE_SOURCE")]
    NativeSource,
    #[serde(rename = "WINDOWS_ORIGINAL_PE32")]
    OriginalPe32,
    #[serde(rename = "WINDOWS_ORIGINAL_PE64")]
    OriginalPe64,
    #[serde(rename = "WINDOWS_LIBFUZZER_PREBUILT")]
    LibFuzzerPrebuilt,
}

impl WindowsRuntimeAdapter {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PythonCall => "WINDOWS_PYTHON_CALL",
            Self::NativeSource => "WINDOWS_NATIVE_SOURCE",
            Self::OriginalPe32 => "WINDOWS_ORIGINAL_PE32",
            Self::OriginalPe64 => "WINDOWS_ORIGINAL_PE64",
            Self::LibFuzzerPrebuilt => "WINDOWS_LIBFUZZER_PREBUILT",
        }
    }

    pub fn target_scope(self) -> &'static str {
        match self {
            Self::PythonCall => "COMPONENT",
            Self::NativeSource => "REBUILT_TARGET",
            Self::OriginalPe32 | Self::OriginalPe64 => "ORIGINAL",
            Self::LibFuzzerPrebuilt => "INSTRUMENTED_BUILD",
        }
    }

    pub fn pe_architecture(self) -> Option<&'static str> {
        match self {
            Self::OriginalPe32 => Some("x86"),
            Self::OriginalPe64 | Self::LibFuzzerPrebuilt => Some("x86_64"),
            _ => None,
        }
    }

    fn source(self) -> bool {
        matches!(self, Self::PythonCall | Self::NativeSource)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WindowsRuntimeEntry {
    Function {
        module: String,
        function: String,
    },
    CommandLine {
        path: String,
        #[serde(default)]
        arguments: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WindowsRuntimeInput {
    Stdin { value: String },
    File { path: String },
    Argument { value: String },
    PythonCall { invocation_json: String },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsRuntimeEnvironment {
    pub python_version: Option<String>,
    pub compiler: Option<String>,
    pub observer: Option<String>,
    pub marker_path: Option<String>,
    #[serde(default)]
    pub runtime_libraries: BTreeMap<String, String>,
    #[serde(default)]
    pub globals_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsFuzzOptions {
    pub engine: String,
    pub runs: u32,
    pub timeout_seconds: u32,
    pub budget_seconds: u32,
    pub random_seed: u64,
    pub max_input_bytes: u32,
    pub seeds: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsRuntimeConfig {
    pub schema_version: u32,
    pub config_version: String,
    pub mode: WindowsRuntimeMode,
    pub adapter: WindowsRuntimeAdapter,
    pub target_path: String,
    pub target_sha256: String,
    pub entry: WindowsRuntimeEntry,
    #[serde(default)]
    pub baseline_inputs: Vec<WindowsRuntimeInput>,
    #[serde(default)]
    pub probe_inputs: Vec<WindowsRuntimeInput>,
    pub repeats: u32,
    pub timeout_seconds: u32,
    pub environment: WindowsRuntimeEnvironment,
    #[serde(default)]
    pub fuzz: Option<WindowsFuzzOptions>,
}

impl WindowsRuntimeConfig {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == WINDOWS_RUNTIME_SCHEMA_VERSION,
            "unsupported Windows runtime schema"
        );
        ensure!(
            semantic_version(&self.config_version),
            "config_version must be a bounded semantic version"
        );
        ensure!(
            relative_path(&self.target_path),
            "target_path must be a bounded relative path"
        );
        ensure!(
            sha256(&self.target_sha256),
            "target_sha256 must be a SHA-256 value"
        );
        ensure!(
            (2..=5).contains(&self.repeats),
            "repeats must be between 2 and 5"
        );
        if let Some(observer) = self.environment.observer.as_deref() {
            ensure!(
                ["SANITIZER", "FILE_CREATED"].contains(&observer),
                "Windows runtime observer must be SANITIZER or FILE_CREATED"
            );
            if observer == "FILE_CREATED" {
                let marker = self.environment.marker_path.as_deref().unwrap_or_default();
                ensure!(
                    !marker.is_empty() && relative_path(marker),
                    "FILE_CREATED requires a safe marker path"
                );
            }
        }
        ensure!(
            (1..=900).contains(&self.timeout_seconds),
            "timeout_seconds must be between 1 and 900"
        );
        ensure!(
            self.baseline_inputs.len() <= 33 && self.probe_inputs.len() <= 33,
            "at most 32 arguments and one stdin input are allowed"
        );
        let globals: BTreeMap<String, Value> = if self.environment.globals_json.is_empty() {
            BTreeMap::new()
        } else {
            serde_json::from_str(&self.environment.globals_json)?
        };
        ensure!(
            globals.len() <= 16
                && globals
                    .keys()
                    .all(|key| identifier(key) && !key.starts_with("__"))
                && (self.adapter == WindowsRuntimeAdapter::PythonCall || globals.is_empty()),
            "only Python calls support bounded, ordinary JSON globals"
        );
        ensure!(
            !serde_json::to_string(self)?.contains("{{"),
            "Windows runtime does not expand template placeholders"
        );

        match self.adapter {
            WindowsRuntimeAdapter::PythonCall => {
                ensure!(
                    self.target_path.to_ascii_lowercase().ends_with(".py"),
                    "the Windows Python adapter requires a .py target"
                );
                ensure!(
                    self.environment
                        .python_version
                        .as_deref()
                        .is_some_and(nonempty_bounded),
                    "the Windows Python adapter requires a pinned Python version"
                );
            }
            WindowsRuntimeAdapter::NativeSource => {
                ensure!(
                    [".c", ".cc", ".cpp", ".cxx"].iter().any(|extension| self
                        .target_path
                        .to_ascii_lowercase()
                        .ends_with(extension)),
                    "the Windows native-source adapter requires a C/C++ target"
                );
                ensure!(
                    self.environment
                        .compiler
                        .as_deref()
                        .is_some_and(nonempty_bounded),
                    "the Windows native-source adapter requires a pinned compiler"
                );
            }
            WindowsRuntimeAdapter::OriginalPe32 | WindowsRuntimeAdapter::OriginalPe64 => {
                ensure!(
                    self.target_path.to_ascii_lowercase().ends_with(".exe"),
                    "the original PE adapter requires an .exe target"
                );
            }
            WindowsRuntimeAdapter::LibFuzzerPrebuilt => {
                ensure!(
                    self.target_path.to_ascii_lowercase().ends_with(".exe"),
                    "the prebuilt libFuzzer adapter requires an .exe target"
                );
            }
        }

        match self.mode {
            WindowsRuntimeMode::Verify => ensure!(
                self.fuzz.is_none() && self.adapter != WindowsRuntimeAdapter::LibFuzzerPrebuilt,
                "VERIFY configurations cannot contain fuzz options or use the prebuilt libFuzzer adapter"
            ),
            WindowsRuntimeMode::Fuzz => {
                let fuzz = self
                    .fuzz
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("FUZZ configurations require fuzz options"))?;
                ensure!(
                    fuzz.engine == "LLVM_LIBFUZZER",
                    "the Windows FUZZ mode currently supports LLVM libFuzzer only"
                );
                ensure!(
                    (1..=1_000_000).contains(&fuzz.runs),
                    "fuzz runs must be between 1 and 1,000,000"
                );
                ensure!(
                    (1..=900).contains(&fuzz.timeout_seconds),
                    "fuzz timeout_seconds must be between 1 and 900"
                );
                ensure!(
                    (1..=900).contains(&fuzz.budget_seconds),
                    "fuzz budget_seconds must be between 1 and 900"
                );
                ensure!(
                    (1..=1024 * 1024).contains(&fuzz.max_input_bytes),
                    "fuzz max_input_bytes must be between 1 and 1 MiB"
                );
                ensure!(
                    !fuzz.seeds.is_empty()
                        && fuzz.seeds.len() <= 32
                        && fuzz
                            .seeds
                            .iter()
                            .all(|seed| !seed.is_empty() && seed.len() <= 8192),
                    "fuzz seeds must contain 1-32 bounded non-empty values"
                );
                ensure!(
                    self.adapter == WindowsRuntimeAdapter::LibFuzzerPrebuilt,
                    "the Windows FUZZ mode supports prebuilt libFuzzer targets only"
                );
                ensure!(
                    self.target_path.to_ascii_lowercase().ends_with(".exe"),
                    "the prebuilt libFuzzer adapter requires an .exe target"
                );
                ensure!(
                    matches!(&self.entry, WindowsRuntimeEntry::CommandLine { .. }),
                    "prebuilt libFuzzer mode requires a command-line entry"
                );
                ensure!(
                    self.environment
                        .compiler
                        .as_deref()
                        .is_some_and(nonempty_bounded),
                    "the prebuilt libFuzzer adapter requires a pinned LLVM version"
                );
                ensure!(
                    self.baseline_inputs.is_empty() && self.probe_inputs.is_empty(),
                    "prebuilt libFuzzer mode uses seeds instead of baseline/probe inputs"
                );
            }
        }

        if let WindowsRuntimeEntry::Function { module, function } = &self.entry {
            ensure!(
                relative_path(module) && identifier(function),
                "function entries need a bounded module path and identifier"
            );
            ensure!(
                self.adapter.source(),
                "function entries are only valid for source adapters"
            );
            ensure!(
                self.adapter != WindowsRuntimeAdapter::PythonCall || module == &self.target_path,
                "Python entry must refer to the hashed target module"
            );
        }
        if let WindowsRuntimeEntry::CommandLine { path, arguments } = &self.entry {
            ensure!(
                relative_path(path) && path == &self.target_path,
                "command-line entry must refer to the hashed target"
            );
            ensure!(arguments.len() <= 32, "at most 32 arguments are allowed");
            for argument in arguments {
                ensure!(
                    argument.len() <= 4096
                        && !argument.contains(['\0', '\r', '\n'])
                        && !argument.contains("{{canary}}"),
                    "invalid command-line argument"
                );
            }
        }

        for input in self.baseline_inputs.iter().chain(self.probe_inputs.iter()) {
            match input {
                WindowsRuntimeInput::Stdin { value } => ensure!(
                    value.len() <= 128 * 1024 && !value.contains("{{canary}}"),
                    "stdin input is too large or contains an unsafe marker"
                ),
                WindowsRuntimeInput::File { .. } => {
                    anyhow::bail!("file inputs must be supplied as fixtures and explicit arguments")
                }
                WindowsRuntimeInput::Argument { value } => ensure!(
                    value.len() <= 4096
                        && !value.contains(['\0', '\r', '\n'])
                        && !value.contains("{{canary}}"),
                    "argument input is invalid"
                ),
                WindowsRuntimeInput::PythonCall { invocation_json } => {
                    let invocation: aegis_domain::Invocation =
                        serde_json::from_str(invocation_json)?;
                    ensure!(
                        self.adapter == WindowsRuntimeAdapter::PythonCall
                            && invocation.args.len() <= 32
                            && invocation.kwargs.len() <= 16
                            && invocation.stdin.len() <= 65536
                            && invocation
                                .kwargs
                                .keys()
                                .all(|key| identifier(key) && !key.starts_with("__")),
                        "invalid Python JSON invocation"
                    );
                }
            }
        }
        for inputs in [&self.baseline_inputs, &self.probe_inputs] {
            let calls = inputs
                .iter()
                .filter(|input| matches!(input, WindowsRuntimeInput::PythonCall { .. }))
                .count();
            ensure!(
                calls <= 1
                    && inputs
                        .iter()
                        .filter(|input| matches!(input, WindowsRuntimeInput::Stdin { .. }))
                        .count()
                        <= 1
                    && (calls == 0
                        || inputs.iter().all(|input| matches!(
                            input,
                            WindowsRuntimeInput::PythonCall { .. }
                                | WindowsRuntimeInput::Stdin { .. }
                        ))),
                "ambiguous Windows runtime inputs"
            );
            for input in inputs {
                if let WindowsRuntimeInput::PythonCall { invocation_json } = input {
                    let invocation: aegis_domain::Invocation =
                        serde_json::from_str(invocation_json)?;
                    let stdin = inputs
                        .iter()
                        .find_map(|input| match input {
                            WindowsRuntimeInput::Stdin { value } => Some(value.as_str()),
                            _ => None,
                        })
                        .unwrap_or_default();
                    ensure!(
                        invocation.stdin == stdin,
                        "Python stdin differs from its invocation receipt"
                    );
                }
            }
        }

        for (name, version) in &self.environment.runtime_libraries {
            ensure!(
                nonempty_bounded(name) && nonempty_bounded(version),
                "runtime library names and versions must be bounded"
            );
        }
        ensure!(
            serde_json::to_vec(self)
                .map_err(|_| anyhow::anyhow!("config is not serializable"))?
                .len()
                <= 512 * 1024,
            "encoded Windows runtime configuration exceeds 512 KiB"
        );
        Ok(())
    }

    pub fn fingerprint(&self) -> Result<String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        Ok(aegis_domain::sha256(&bytes))
    }

    pub fn environment_summary(&self) -> Result<Value> {
        self.validate()?;
        Ok(json!({
            "schema_version": WINDOWS_RUNTIME_SCHEMA_VERSION,
            "platform": "windows-x64",
            "adapter": self.adapter.as_str(),
            "target_scope": self.adapter.target_scope(),
            "pe_architecture": self.adapter.pe_architecture(),
            "python_version": self.environment.python_version,
            "compiler": self.environment.compiler,
            "runtime_libraries": self.environment.runtime_libraries,
            "mode": match self.mode {
                WindowsRuntimeMode::Verify => "VERIFY",
                WindowsRuntimeMode::Fuzz => "FUZZ",
            },
            "fuzz": self.fuzz
        }))
    }
}

pub fn legacy_linux_adapter(adapter: &str) -> bool {
    matches!(adapter, "PYTHON_CALL" | "NATIVE_SOURCE" | "ELF")
}

fn relative_path(path: &str) -> bool {
    path.len() <= 512
        && !path.is_empty()
        && !path.contains(['\\', ':', '\0', '\n', '\r'])
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().enumerate().all(|(index, byte)| {
            byte == b'_' || byte.is_ascii_alphabetic() || (index > 0 && byte.is_ascii_digit())
        })
}

fn nonempty_bounded(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128
}

fn semantic_version(value: &str) -> bool {
    if value.len() > 32 || value.is_empty() {
        return false;
    }
    let mut parts = 0;
    for part in value.split('.') {
        parts += 1;
        if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return false;
        }
    }
    (1..=4).contains(&parts)
}

fn sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(adapter: WindowsRuntimeAdapter) -> WindowsRuntimeConfig {
        WindowsRuntimeConfig {
            schema_version: WINDOWS_RUNTIME_SCHEMA_VERSION,
            config_version: "1".into(),
            mode: WindowsRuntimeMode::Verify,
            adapter,
            target_path: match adapter {
                WindowsRuntimeAdapter::PythonCall => "app.py".into(),
                WindowsRuntimeAdapter::NativeSource => "app.c".into(),
                WindowsRuntimeAdapter::OriginalPe32 | WindowsRuntimeAdapter::OriginalPe64 => {
                    "app.exe".into()
                }
                WindowsRuntimeAdapter::LibFuzzerPrebuilt => "fuzz.exe".into(),
            },
            target_sha256: "a".repeat(64),
            entry: match adapter {
                WindowsRuntimeAdapter::PythonCall | WindowsRuntimeAdapter::NativeSource => {
                    WindowsRuntimeEntry::Function {
                        module: "app.py".into(),
                        function: "main".into(),
                    }
                }
                WindowsRuntimeAdapter::OriginalPe32 | WindowsRuntimeAdapter::OriginalPe64 => {
                    WindowsRuntimeEntry::CommandLine {
                        path: "app.exe".into(),
                        arguments: vec!["--check".into()],
                    }
                }
                WindowsRuntimeAdapter::LibFuzzerPrebuilt => WindowsRuntimeEntry::CommandLine {
                    path: "fuzz.exe".into(),
                    arguments: vec![],
                },
            },
            baseline_inputs: vec![WindowsRuntimeInput::Stdin {
                value: "baseline".into(),
            }],
            probe_inputs: vec![WindowsRuntimeInput::Stdin {
                value: "probe".into(),
            }],
            repeats: 2,
            timeout_seconds: 5,
            fuzz: None,
            environment: match adapter {
                WindowsRuntimeAdapter::PythonCall => WindowsRuntimeEnvironment {
                    python_version: Some("3.11.9".into()),
                    ..Default::default()
                },
                WindowsRuntimeAdapter::NativeSource => WindowsRuntimeEnvironment {
                    compiler: Some("clang-cl 19".into()),
                    ..Default::default()
                },
                WindowsRuntimeAdapter::LibFuzzerPrebuilt => WindowsRuntimeEnvironment {
                    compiler: Some("llvm 23.1.1".into()),
                    ..Default::default()
                },
                _ => WindowsRuntimeEnvironment::default(),
            },
        }
    }

    #[test]
    fn windows_adapters_have_scopes_and_architectures() {
        for adapter in [
            WindowsRuntimeAdapter::PythonCall,
            WindowsRuntimeAdapter::NativeSource,
            WindowsRuntimeAdapter::OriginalPe32,
            WindowsRuntimeAdapter::OriginalPe64,
        ] {
            let value = config(adapter);
            value.validate().unwrap();
            assert_eq!(
                value.environment_summary().unwrap()["adapter"],
                adapter.as_str()
            );
        }
        assert_eq!(
            WindowsRuntimeAdapter::OriginalPe32.pe_architecture(),
            Some("x86")
        );
        assert_eq!(
            WindowsRuntimeAdapter::OriginalPe64.pe_architecture(),
            Some("x86_64")
        );
        assert_eq!(
            WindowsRuntimeAdapter::PythonCall.target_scope(),
            "COMPONENT"
        );
    }

    #[test]
    fn invalid_windows_adapters_and_entries_are_rejected() {
        let mut python = config(WindowsRuntimeAdapter::PythonCall);
        python.environment.python_version = None;
        assert!(python.validate().is_err());

        let mut native = config(WindowsRuntimeAdapter::NativeSource);
        native.target_path = "app.exe".into();
        assert!(native.validate().is_err());

        let mut pe = config(WindowsRuntimeAdapter::OriginalPe64);
        pe.entry = WindowsRuntimeEntry::Function {
            module: "app.py".into(),
            function: "main".into(),
        };
        assert!(pe.validate().is_err());

        let mut path = config(WindowsRuntimeAdapter::OriginalPe64);
        path.target_path = "../outside.exe".into();
        assert!(path.validate().is_err());
    }

    #[test]
    fn legacy_linux_contract_is_not_reinterpreted() {
        assert!(legacy_linux_adapter("ELF"));
        assert!(legacy_linux_adapter("NATIVE_SOURCE"));
        assert!(legacy_linux_adapter("PYTHON_CALL"));
        assert!(!legacy_linux_adapter("WINDOWS_ORIGINAL_PE64"));
    }

    #[test]
    fn fuzz_mode_requires_a_bounded_libfuzzer_recipe() {
        let mut config = config(WindowsRuntimeAdapter::LibFuzzerPrebuilt);
        config.mode = WindowsRuntimeMode::Fuzz;
        assert!(config.validate().is_err());

        config.fuzz = Some(WindowsFuzzOptions {
            engine: "LLVM_LIBFUZZER".into(),
            runs: 1000,
            timeout_seconds: 30,
            budget_seconds: 60,
            random_seed: 71413,
            max_input_bytes: 64,
            seeds: vec!["seed".into()],
        });
        config.baseline_inputs.clear();
        config.probe_inputs.clear();
        config.validate().unwrap();
        assert_eq!(config.environment_summary().unwrap()["mode"], "FUZZ");

        config.fuzz.as_mut().unwrap().runs = 0;
        assert!(config.validate().is_err());
    }
}
