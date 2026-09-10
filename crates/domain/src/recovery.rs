//! Declarative, target-scoped reverse-engineering tools. Model output never supplies commands.
use crate::{AnalysisResult, ToolExecution};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const MAX_RECOVERY_STEPS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryTool {
    Upx,
    Floss,
    Ghidra,
    IdaD810,
    BuiltinStrings,
}

impl RecoveryTool {
    pub fn capability(self) -> &'static str {
        match self {
            Self::Upx => "upx",
            Self::Floss => "floss",
            Self::Ghidra => "ghidra",
            Self::IdaD810 => "ida-d810",
            Self::BuiltinStrings => "string-recovery",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryInput {
    Original,
    Unpacked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryStep {
    pub tool: RecoveryTool,
    pub input: RecoveryInput,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<D810Profile>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum D810Profile {
    Instructions,
    ControlFlow,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPlan {
    pub assessment: String,
    pub evidence: Vec<String>,
    pub steps: Vec<RecoveryStep>,
    pub limitations: Vec<String>,
}

impl RecoveryPlan {
    pub fn validate(&self) -> Result<(), String> {
        if self.assessment.trim().is_empty()
            || self.assessment.len() > 8192
            || self.evidence.is_empty()
            || self.evidence.len() > 16
            || self.steps.len() > MAX_RECOVERY_STEPS
            || self.limitations.len() > 16
            || self
                .evidence
                .iter()
                .chain(&self.limitations)
                .any(|s| s.len() > 4096)
            || self.steps.iter().any(|s| {
                s.reason.trim().is_empty()
                    || s.reason.len() > 4096
                    || (s.tool != RecoveryTool::IdaD810 && s.profile.is_some())
            })
        {
            return Err("逆向计划必须包含特征依据、每步理由，且最多 8 个受支持的工具步骤".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryConclusion {
    pub summary: String,
    pub limitations: Vec<String>,
}

impl RecoveryConclusion {
    pub fn validate(&self) -> Result<(), String> {
        if self.summary.trim().is_empty()
            || self.summary.len() > 8192
            || self.limitations.len() > 32
            || self.limitations.iter().any(|s| s.len() > 4096)
        {
            return Err("逆向结论为空或超过长度限制".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveredString {
    pub text: String,
    pub kind: String,
    pub function_address: Option<u64>,
    pub call_address: Option<u64>,
    pub data_address: Option<u64>,
    pub file_offset: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveredStrings {
    pub schema_version: u32,
    pub input_sha256: String,
    pub tool: RecoveryTool,
    pub strings: Vec<RecoveredString>,
    pub omitted: usize,
    pub limitations: Vec<String>,
}

/// Worker output is validated against its lease and uploaded artifacts by the controller.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryResult {
    pub schema_version: u32,
    pub tool: RecoveryTool,
    pub status: String,
    pub input_artifact_id: String,
    pub input_sha256: String,
    pub output_artifact_id: String,
    pub output_sha256: String,
    pub strings_artifact_id: String,
    pub readable_artifact_id: String,
    pub analysis: Option<AnalysisResult>,
    pub tools: Vec<ToolExecution>,
    pub observation: Value,
    pub warnings: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn recovery_plan_rejects_commands_unknown_tools_and_unbounded_steps() {
        let base = json!({"assessment":"UPX section evidence", "evidence":["section UPX0"],
            "steps":[{"tool":"upx","input":"original","reason":"Inspect unpacked image"}],"limitations":[]});
        let mut invalid = base.clone();
        invalid["steps"][0]["command"] = json!("arbitrary.exe");
        assert!(serde_json::from_value::<RecoveryPlan>(invalid).is_err());
        let mut invalid = base.clone();
        invalid["steps"][0]["tool"] = json!("shell");
        assert!(serde_json::from_value::<RecoveryPlan>(invalid).is_err());
        let mut plan: RecoveryPlan = serde_json::from_value(base).unwrap();
        plan.validate().unwrap();
        plan.steps = vec![plan.steps[0].clone(); MAX_RECOVERY_STEPS + 1];
        assert!(plan.validate().is_err());
    }
}
