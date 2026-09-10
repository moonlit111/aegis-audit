use crate::{ToolExecution, sha256};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const VERIFY_SCOPE: &str = "RUNTIME_VERIFICATION";
pub const FUZZ_SCOPE: &str = "DYNAMIC_TESTING";
pub const WINDOWS_RUNTIME_ADAPTERS: &[&str] = &[
    "WINDOWS_PYTHON_CALL",
    "WINDOWS_NATIVE_SOURCE",
    "WINDOWS_ORIGINAL_PE32",
    "WINDOWS_ORIGINAL_PE64",
];

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Invocation {
    pub args: Vec<Value>,
    pub kwargs: BTreeMap<String, Value>,
    pub stdin: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeFixture {
    pub path: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FuzzOptions {
    pub engine: String,
    pub input_mode: String,
    pub seeds: Vec<String>,
    pub max_cases: u32,
    pub budget_seconds: u32,
    pub random_seed: u64,
}
impl Default for FuzzOptions {
    fn default() -> Self {
        Self {
            engine: "MUTATION".into(),
            input_mode: "STDIN".into(),
            seeds: vec!["hello".into()],
            max_cases: 256,
            budget_seconds: 30,
            random_seed: 71413,
        }
    }
}

/// A declarative local test recipe. It contains data and an adapter, never a host command.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeConfig {
    pub mode: String,
    pub adapter: String,
    pub path: String,
    pub function: String,
    pub globals: BTreeMap<String, Value>,
    pub fixtures: Vec<RuntimeFixture>,
    pub baseline: Invocation,
    pub probe: Invocation,
    pub observer: String,
    pub marker_path: String,
    pub repeats: u32,
    pub timeout_seconds: u32,
    pub fuzz: FuzzOptions,
}
impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            mode: "VERIFY".into(),
            adapter: "NATIVE_SOURCE".into(),
            path: String::new(),
            function: String::new(),
            globals: BTreeMap::new(),
            fixtures: vec![],
            baseline: Invocation::default(),
            probe: Invocation::default(),
            observer: "SANITIZER".into(),
            marker_path: "marker.txt".into(),
            repeats: 2,
            timeout_seconds: 5,
            fuzz: FuzzOptions::default(),
        }
    }
}

pub fn target_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 512
        && !path.contains(['\\', ':', '\0', '\n', '\r'])
        && path
            .split('/')
            .all(|p| !p.is_empty() && p != "." && p != "..")
}
pub fn is_windows_runtime_adapter(adapter: &str) -> bool {
    WINDOWS_RUNTIME_ADAPTERS.contains(&adapter)
}
fn identifier(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with("__")
        && name.len() <= 100
        && name
            .bytes()
            .enumerate()
            .all(|(i, b)| b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit()))
}
impl RuntimeConfig {
    pub fn scope(&self) -> &'static str {
        if self.mode == "FUZZ" {
            FUZZ_SCOPE
        } else {
            VERIFY_SCOPE
        }
    }
    pub fn target_scope(&self) -> &'static str {
        match self.adapter.as_str() {
            "PYTHON_CALL" | "WINDOWS_PYTHON_CALL" => "COMPONENT",
            "NATIVE_SOURCE" | "WINDOWS_NATIVE_SOURCE" => "INSTRUMENTED_BUILD",
            _ => "ORIGINAL",
        }
    }
    pub fn deadline(&self) -> u32 {
        if self.mode == "FUZZ" {
            self.fuzz.budget_seconds + 240
        } else {
            (self.repeats + 1) * (self.timeout_seconds + 5) + 150
        }
    }
    pub fn fingerprint(&self) -> String {
        sha256(&serde_json::to_vec(self).expect("serializable runtime configuration"))
    }
    pub fn validate(&self) -> Result<(), String> {
        let legacy_adapter =
            ["PYTHON_CALL", "NATIVE_SOURCE", "ELF"].contains(&self.adapter.as_str());
        if !["VERIFY", "FUZZ"].contains(&self.mode.as_str())
            || !(legacy_adapter || is_windows_runtime_adapter(&self.adapter))
            || !target_path(&self.path)
            || self.fixtures.len() > 16
            || self.globals.len() > 16
            || serde_json::to_vec(self).map_err(|e| e.to_string())?.len() > 128 * 1024
        {
            return Err("运行配置需要 mode=VERIFY/FUZZ、adapter=PYTHON_CALL/NATIVE_SOURCE/ELF、快照内相对 path；最多 16 个测试文件/全局变量，总大小不超过 128 KiB".into());
        }
        if !(2..=5).contains(&self.repeats) {
            return Err("repeats 必须为 2—5 次；正常输入另执行一次".into());
        }
        if !(1..=15).contains(&self.timeout_seconds) {
            return Err(
                "timeout_seconds 必须为 1—15 秒，例如 5；这是单次目标执行时限，编译使用独立时限"
                    .into(),
            );
        }
        if (self.observer == "FILE_CREATED" || !self.marker_path.is_empty())
            && !target_path(&self.marker_path)
        {
            return Err(
                "marker_path 必须为测试目录内的相对文件路径；仅 FILE_CREATED 要求非空".into(),
            );
        }
        if self.adapter == "PYTHON_CALL" || self.adapter == "WINDOWS_PYTHON_CALL" {
            if !self.path.ends_with(".py")
                || !identifier(&self.function)
                || self.globals.keys().any(|k| !identifier(k))
            {
                return Err("Python 运行适配器需要目标中的 .py 文件和普通函数名".into());
            }
        } else if !self.globals.is_empty() || !self.function.is_empty() {
            return Err("原生程序配置不能修改 Python 全局变量".into());
        }
        if (self.adapter == "NATIVE_SOURCE" || self.adapter == "WINDOWS_NATIVE_SOURCE")
            && ![".c", ".cc", ".cpp", ".cxx"]
                .iter()
                .any(|s| self.path.ends_with(s))
        {
            return Err("当前构建适配器支持单入口 C/C++ 文件及其本地头文件".into());
        }
        if matches!(
            self.adapter.as_str(),
            "WINDOWS_ORIGINAL_PE32" | "WINDOWS_ORIGINAL_PE64"
        ) && !self.path.to_ascii_lowercase().ends_with(".exe")
        {
            return Err("Windows 原始 PE 适配器需要目标中的 .exe 文件".into());
        }
        let mut seen = std::collections::HashSet::new();
        for file in &self.fixtures {
            if !target_path(&file.path)
                || file.path == self.marker_path
                || file.path == self.path
                || !seen.insert(&file.path)
                || file.content.len() > 16384
            {
                return Err("测试文件路径重复、越界或内容过大".into());
            }
        }
        for (label, input) in [("baseline", &self.baseline), ("probe", &self.probe)] {
            if serde_json::to_string(input)
                .map_err(|e| e.to_string())?
                .contains("{{canary}}")
            {
                return Err(format!(
                    "{label} 不能包含 {{{{canary}}}}：随机秘密只放在 fixtures 的文件内容或 globals 的受控数据中。参数应使用文件名/用户标识等实际输入，不能直接传入预期返回值。若无法设计这样的测试，请返回 NEEDS_CONFIGURATION 和 config=null"
                ));
            }
            if input.args.len() > 32
                || input.kwargs.len() > 16
                || input.stdin.len() > 65536
                || input.kwargs.keys().any(|k| !identifier(k))
            {
                return Err("测试输入无效；观察用随机标记只能放在受控文件或测试数据中".into());
            }
            if self.adapter != "PYTHON_CALL"
                && self.adapter != "WINDOWS_PYTHON_CALL"
                && (!input.kwargs.is_empty()
                    || input.args.iter().any(|v| {
                        v.as_str()
                            .is_none_or(|s| s.contains('\0') || s.len() > 65536)
                    }))
            {
                return Err("原生程序参数必须为不含 NUL 的字符串".into());
            }
        }
        let python_adapter = self.adapter == "PYTHON_CALL" || self.adapter == "WINDOWS_PYTHON_CALL";
        if !["RETURN_CANARY", "FILE_CREATED", "SANITIZER"].contains(&self.observer.as_str())
            || (self.observer == "SANITIZER" && python_adapter)
            || (is_windows_runtime_adapter(&self.adapter) && self.observer == "RETURN_CANARY")
        {
            return Err("该适配器不支持所选观察方式".into());
        }
        if self.observer == "RETURN_CANARY"
            && self.mode == "VERIFY"
            && !serde_json::to_string(&(&self.fixtures, &self.globals))
                .map_err(|e| e.to_string())?
                .contains("{{canary}}")
        {
            return Err("返回值观察需要含随机标记的受控测试文件或测试数据".into());
        }
        if self.mode == "FUZZ" {
            if is_windows_runtime_adapter(&self.adapter) {
                return Err("Windows 宿主机产品链当前只支持 VERIFY；libFuzzer 仍是引擎实验".into());
            }
            let fuzz = &self.fuzz;
            if self.adapter == "PYTHON_CALL"
                || !self.globals.is_empty()
                || !self.fixtures.is_empty()
                || !["MUTATION", "AFLPP"].contains(&fuzz.engine.as_str())
                || !["STDIN", "ARGUMENT", "FILE"].contains(&fuzz.input_mode.as_str())
                || (fuzz.engine == "AFLPP"
                    && (self.adapter != "NATIVE_SOURCE" || fuzz.input_mode == "ARGUMENT"))
                || !(1..=4096).contains(&fuzz.max_cases)
                || !(5..=600).contains(&fuzz.budget_seconds)
                || fuzz.seeds.is_empty()
                || fuzz.seeds.len() > 32
                || fuzz.seeds.iter().any(|s| s.is_empty() || s.len() > 8192)
                || (fuzz.input_mode != "STDIN"
                    && !self
                        .baseline
                        .args
                        .iter()
                        .any(|a| a.as_str().is_some_and(|s| s.contains("{{input}}"))))
            {
                return Err("模糊测试配置无效；AFL++ 支持 C/C++ 的标准输入或文件入口".into());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeTrial {
    pub label: String,
    pub input_json: String,
    pub input_sha256: String,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub processes_reaped: bool,
    pub observed: bool,
    pub exception: String,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    pub crash_signature: String,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CrashSample {
    pub input_hex: String,
    pub input_sha256: String,
    pub signature: String,
    pub reproduced: bool,
    pub minimized: bool,
    pub replays: Vec<RuntimeTrial>,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeObservation {
    pub schema_version: u32,
    pub mode: String,
    pub adapter: String,
    pub path: String,
    pub build: Value,
    pub trials: Vec<RuntimeTrial>,
    pub fuzz: Value,
    pub crashes: Vec<CrashSample>,
    pub error: String,
}
impl RuntimeObservation {
    pub fn validate(&self, config: &RuntimeConfig) -> Result<(), String> {
        if self.schema_version != 1
            || self.mode != config.mode
            || self.adapter != config.adapter
            || self.path != config.path
            || self.trials.len() > 12
            || self.crashes.len() > 16
        {
            return Err("运行观察与冻结的配置不一致".into());
        }
        if self.error.is_empty()
            && config.mode == "VERIFY"
            && (self.trials.len() != config.repeats as usize + 1
                || self.trials[0].label != "baseline"
                || self.trials.iter().skip(1).any(|t| t.label != "probe"))
        {
            return Err("验证缺少正常输入或重复执行记录".into());
        }
        if self.error.is_empty() && self.build["status"] != "READY" {
            return Err("运行结果缺少成功的入口准备记录".into());
        }
        for (index, trial) in self.trials.iter().enumerate() {
            let input: Invocation =
                serde_json::from_str(&trial.input_json).map_err(|_| "运行输入记录无效")?;
            let expected = if index == 0 {
                &config.baseline
            } else {
                &config.probe
            };
            if trial.input_json.len() > 128 * 1024
                || sha256(trial.input_json.as_bytes()) != trial.input_sha256
                || serde_json::to_value(&input).map_err(|e| e.to_string())?
                    != serde_json::to_value(expected).map_err(|e| e.to_string())?
                || trial.stdout.len() > 256 * 1024
                || trial.stderr.len() > 256 * 1024
                || trial.exception.len() > 4096
            {
                return Err("实际测试输入、哈希或输出大小与冻结配置不符".into());
            }
        }
        if config.mode == "FUZZ"
            && self.error.is_empty()
            && (self.fuzz["executions"].as_u64().is_none_or(|n| n == 0)
                || self.fuzz["engine"] != config.fuzz.engine
                || self.fuzz["coverage_feedback"] != (config.fuzz.engine == "AFLPP"))
        {
            return Err("模糊测试没有有效的执行与覆盖模式记录".into());
        }
        for sample in &self.crashes {
            let bytes = hex::decode(&sample.input_hex).map_err(|_| "异常输入格式无效")?;
            if bytes.len() > 65536
                || sha256(&bytes) != sample.input_sha256
                || sample.signature.is_empty()
                || sample.signature.len() > 2048
                || sample.replays.len() > 2
            {
                return Err("异常输入哈希或大小无效".into());
            }
            for replay in &sample.replays {
                if replay.input_sha256 != sample.input_sha256
                    || replay.label != "replay"
                    || replay.stdout.len() > 256 * 1024
                    || replay.stderr.len() > 256 * 1024
                {
                    return Err("异常复测记录与输入不一致".into());
                }
            }
            let repeated = sample.replays.len() == 2
                && sample.replays.iter().all(|r| {
                    r.processes_reaped
                        && !r.timed_out
                        && !r.truncated
                        && r.observed
                        && r.crash_signature == sample.signature
                });
            if sample.reproduced != repeated {
                return Err("异常复现结论缺少两次一致的原始运行记录".into());
            }
        }
        Ok(())
    }
    pub fn verdict(&self, config: &RuntimeConfig) -> &'static str {
        if !self.error.is_empty()
            || self.build["status"] == "ERROR"
            || self.trials.iter().any(|t| !t.processes_reaped)
        {
            return "ERROR";
        }
        if config.mode == "FUZZ" {
            return if self.crashes.iter().any(|c| c.reproduced) {
                "REPRODUCED"
            } else if !self.crashes.is_empty()
                || self.fuzz["timeouts"].as_u64().is_some_and(|n| n > 0)
            {
                "INCONCLUSIVE"
            } else {
                "NO_CRASH_OBSERVED"
            };
        }
        let Some(baseline) = self.trials.first() else {
            return "ERROR";
        };
        if baseline.timed_out || baseline.exit_code != Some(0) || !baseline.exception.is_empty() {
            return "ERROR";
        }
        if baseline.observed || baseline.truncated {
            return "INCONCLUSIVE";
        }
        let probes = &self.trials[1..];
        if probes.iter().any(|t| t.timed_out || t.truncated) {
            return "INCONCLUSIVE";
        }
        if !probes.is_empty() && probes.iter().all(|t| t.observed) {
            return if config.adapter == "PYTHON_CALL" || config.adapter == "WINDOWS_PYTHON_CALL" {
                "VERIFIED_COMPONENT"
            } else {
                "REPRODUCED"
            };
        }
        if probes.iter().any(|t| t.observed) {
            "INCONCLUSIVE"
        } else if probes.iter().any(|t| {
            t.exit_code != Some(0)
                || (!t.exception.is_empty()
                    && ![
                        "ValueError",
                        "PermissionError",
                        "KeyError",
                        "FileNotFoundError",
                        "CalledProcessError",
                    ]
                    .contains(&t.exception.as_str()))
        }) {
            "ERROR"
        } else {
            "NOT_REPRODUCED"
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeResult {
    pub target_sha256: String,
    pub config_hash: String,
    pub image_id: String,
    pub target_scope: String,
    pub recipe_artifact_id: String,
    pub observation_artifact_id: String,
    pub observation: RuntimeObservation,
    pub tools: Vec<ToolExecution>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeRecord {
    pub id: String,
    pub run_id: String,
    pub source_run_id: String,
    pub finding_id: String,
    pub status: String,
    pub created_at: String,
    pub config: RuntimeConfig,
    pub result: Option<RuntimeResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationPlan {
    pub status: String,
    pub rationale: String,
    #[serde(default)]
    pub limitations: Vec<String>,
    pub config: Option<RuntimeConfig>,
}

impl VerificationPlan {
    pub fn validate(&self) -> Result<(), String> {
        if !["READY", "NEEDS_CONFIGURATION", "UNSUPPORTED"].contains(&self.status.as_str())
            || self.rationale.trim().is_empty()
            || self.rationale.len() > 12000
            || self.limitations.len() > 30
            || self.limitations.iter().any(|s| s.len() > 4000)
            || (self.status == "READY") != self.config.is_some()
        {
            return Err("验证方案状态、依据或配置无效".into());
        }
        if let Some(config) = &self.config {
            config.validate()?;
            if config.mode != "VERIFY" {
                return Err("发现验证方案必须包含正常输入和重复测试".into());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_configuration_distinguishes_unused_fields_from_unsafe_inputs() {
        let mut config = RuntimeConfig {
            path: "main.c".into(),
            marker_path: String::new(),
            ..Default::default()
        };
        assert!(config.validate().is_ok());
        config.timeout_seconds = 30;
        assert!(config.validate().unwrap_err().contains("timeout_seconds"));
        config.timeout_seconds = 5;
        config.observer = "FILE_CREATED".into();
        assert!(config.validate().is_err());
        config.marker_path = "../host-file".into();
        assert!(config.validate().is_err());
        config.marker_path = "marker.txt".into();
        assert!(config.validate().is_ok());
        config.probe.stdin = "{{canary}}".into();
        assert!(config.validate().is_err());
    }

    #[test]
    fn windows_adapters_are_validated_without_reinterpreting_legacy_configs() {
        let mut config = RuntimeConfig {
            mode: "VERIFY".into(),
            adapter: "WINDOWS_NATIVE_SOURCE".into(),
            path: "main.c".into(),
            observer: "SANITIZER".into(),
            ..Default::default()
        };
        config.validate().unwrap();
        assert_eq!(config.target_scope(), "INSTRUMENTED_BUILD");

        config.adapter = "WINDOWS_ORIGINAL_PE64".into();
        config.path = "target.exe".into();
        config.validate().unwrap();
        assert_eq!(config.target_scope(), "ORIGINAL");

        config.observer = "RETURN_CANARY".into();
        assert!(config.validate().is_err());
        config.observer = "SANITIZER".into();
        config.mode = "FUZZ".into();
        assert!(config.validate().is_err());
        assert!(is_windows_runtime_adapter("WINDOWS_ORIGINAL_PE64"));
        assert!(!is_windows_runtime_adapter("ELF"));
    }

    #[test]
    fn execution_verdict_requires_clean_control_repeated_observations_and_exact_inputs() {
        let config = RuntimeConfig {
            path: "main.c".into(),
            ..Default::default()
        };
        let input_json = serde_json::to_string(&config.baseline).unwrap();
        let baseline = RuntimeTrial {
            label: "baseline".into(),
            input_sha256: sha256(input_json.as_bytes()),
            input_json,
            exit_code: Some(0),
            processes_reaped: true,
            ..Default::default()
        };
        let probe = RuntimeTrial {
            label: "probe".into(),
            observed: true,
            ..baseline.clone()
        };
        let mut observation = RuntimeObservation {
            schema_version: 1,
            mode: config.mode.clone(),
            adapter: config.adapter.clone(),
            path: config.path.clone(),
            build: serde_json::json!({"status":"READY"}),
            trials: vec![baseline, probe.clone(), probe],
            ..Default::default()
        };
        assert!(observation.validate(&config).is_ok());
        assert_eq!(observation.verdict(&config), "REPRODUCED");
        observation.trials[0].observed = true;
        assert_eq!(observation.verdict(&config), "INCONCLUSIVE");
        observation.trials[0].observed = false;
        observation.trials[2].observed = false;
        assert_eq!(observation.verdict(&config), "INCONCLUSIVE");
        observation.trials[1].processes_reaped = false;
        assert_eq!(observation.verdict(&config), "ERROR");
        observation.trials[1].input_json = "{}".into();
        assert!(observation.validate(&config).is_err());
    }
}
