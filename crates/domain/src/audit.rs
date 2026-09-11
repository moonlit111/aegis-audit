use crate::{ProgramUnit, sha256};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

pub const AUDIT_SCOPE: &str = "SECURITY_AUDIT";
pub const PROMPT_VERSION: &str = "audit-13-json-actions";
pub const MAX_MODEL_TIMEOUT_SECONDS: u32 = 3_600;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct AuditConfig {
    pub max_model_calls: u32,
    pub max_units: u32,
    pub max_tool_rounds: u32,
    pub timeout_seconds: u32,
    pub max_output_tokens: u32,
    pub reasoning_effort: String,
    pub model_timeout_seconds: u32,
}
impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            max_model_calls: 240,
            max_units: 80,
            max_tool_rounds: 24,
            timeout_seconds: 10_800,
            // Zero means omit max_tokens and let the provider apply its own limit.
            max_output_tokens: 0,
            reasoning_effort: "high".into(),
            model_timeout_seconds: 900,
        }
    }
}
impl AuditConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !(4..=2000).contains(&self.max_model_calls)
            || !(1..=500).contains(&self.max_units)
            || !(1..=100).contains(&self.max_tool_rounds)
            || !(60..=86_400).contains(&self.timeout_seconds)
        {
            return Err(
                "审计限制应为 4-2000 次模型调用、1-500 个程序单元、1-100 轮工具查询、60-86400 秒"
                    .into(),
            );
        }
        if self.max_output_tokens == u32::MAX {
            return Err("单次输出预算无效；0 表示交由模型服务决定".into());
        }
        if !["low", "high", "max"].contains(&self.reasoning_effort.as_str()) {
            return Err("模型思考强度应为 low、high 或 max".into());
        }
        if !(30..=MAX_MODEL_TIMEOUT_SECONDS).contains(&self.model_timeout_seconds) {
            return Err("单次模型请求时限应为 30-3600 秒".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceInput {
    pub unit_id: String,
    pub start_line: u32,
    pub end_line: u32,
    #[serde(default)]
    pub quote: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRef {
    pub unit_id: String,
    pub artifact_id: String,
    pub path: String,
    pub start_line: u32,
    pub end_line: u32,
    pub address: String,
    pub quote: String,
}

pub fn evidence(
    input: &[EvidenceInput],
    units: &HashMap<String, ProgramUnit>,
) -> Result<Vec<EvidenceRef>, String> {
    if input.is_empty() || input.len() > 16 {
        return Err("每条结论必须引用 1—16 处原始代码证据".into());
    }
    input
        .iter()
        .map(|reference| {
            let unit = units
                .get(&reference.unit_id)
                .ok_or("证据引用了当前任务以外的程序单元")?;
            let base = if unit.unit.language == "binary" {
                1
            } else {
                unit.unit.start_line
            };
            let lines: Vec<_> = unit.unit.code.split('\n').collect();
            if reference.start_line < base
                || reference.end_line < reference.start_line
                || (reference.end_line - base) as usize >= lines.len()
                || reference.end_line - reference.start_line > 100
                || reference.quote.len() > 8192
            {
                return Err("证据的行范围或引用文本无效".into());
            }
            let excerpt = lines
                [(reference.start_line - base) as usize..=(reference.end_line - base) as usize]
                .join("\n");
            let normalized_excerpt=excerpt.lines().map(str::trim).collect::<Vec<_>>().join("\n");
            let normalized_quote=reference.quote.trim().lines().map(str::trim).collect::<Vec<_>>().join("\n");
            if !reference.quote.trim().is_empty() && !excerpt.contains(reference.quote.trim()) && !normalized_excerpt.contains(&normalized_quote) {
                return Err(format!("证据引用文本与对应行的原始代码不一致：{} L{}–{}。请纠正行范围；可省略 quote，由服务读取原始代码。该范围实际代码：\n{}",
                    unit.unit.path, reference.start_line, reference.end_line, excerpt.chars().take(2200).collect::<String>()));
            }
            Ok(EvidenceRef {
                unit_id: unit.id.clone(),
                artifact_id: unit.artifact_id.clone(),
                path: unit.unit.path.clone(),
                start_line: reference.start_line,
                end_line: reference.end_line,
                address: unit.unit.address.clone(),
                // Preserve the original indentation and complete cited lines in the canonical evidence.
                quote: excerpt,
            })
        })
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingDraft {
    pub title: String,
    pub category: String,
    pub cwe: String,
    pub severity: String,
    pub severity_reason: String,
    pub unit_id: String,
    pub input_source: String,
    pub sink: String,
    pub missing_guard: String,
    pub preconditions: String,
    pub impact: String,
    pub recommendation: String,
    pub evidence: Vec<EvidenceInput>,
}
impl FindingDraft {
    pub fn validate(
        &self,
        units: &HashMap<String, ProgramUnit>,
    ) -> Result<Vec<EvidenceRef>, String> {
        if ![
            "INJECTION",
            "PATH_TRAVERSAL",
            "AUTHORIZATION",
            "MEMORY_BOUNDS",
        ]
        .contains(&self.category.as_str())
            || !["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"].contains(&self.severity.as_str())
            || !(self.cwe == "UNKNOWN"
                || self.cwe.strip_prefix("CWE-").is_some_and(|n| {
                    !n.is_empty() && n.len() <= 5 && n.bytes().all(|b| b.is_ascii_digit())
                }))
        {
            return Err("漏洞类型、CWE 或严重程度无效".into());
        }
        for text in [
            &self.title,
            &self.severity_reason,
            &self.input_source,
            &self.sink,
            &self.missing_guard,
            &self.preconditions,
            &self.impact,
            &self.recommendation,
        ] {
            if text.trim().is_empty() || text.len() > 8192 {
                return Err("发现缺少必要依据或文本过长".into());
            }
        }
        if self.title.len() > 300 || !self.evidence.iter().any(|e| e.unit_id == self.unit_id) {
            return Err("主位置必须有原始代码证据，标题不得超过 300 字节".into());
        }
        evidence(&self.evidence, units)
    }
    pub fn fingerprint(&self, snapshot: &str, unit: &ProgramUnit) -> String {
        let location = self
            .evidence
            .iter()
            .find(|e| e.unit_id == self.unit_id)
            .map(|e| e.end_line);
        sha256(
            format!(
                "{snapshot}:{}:{}:{location:?}:{}",
                unit.unit.path, unit.unit.address, self.category
            )
            .as_bytes(),
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub run_id: String,
    pub fingerprint: String,
    pub created_at: String,
    pub model_call_id: String,
    pub revision: u32,
    pub review_status: String,
    pub verification_status: String,
    #[serde(default)]
    pub static_scope: String,
    pub draft: FindingDraft,
    pub evidence: Vec<EvidenceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewDraft {
    pub verdict: String,
    pub rationale: String,
    pub counter_evidence: String,
    pub missing_information: String,
    pub evidence: Vec<EvidenceInput>,
    #[serde(default)]
    pub assessments: Vec<ReviewAssessment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewAssessment {
    pub check: String,
    pub status: String,
    pub rationale: String,
    pub evidence: Vec<EvidenceInput>,
}
impl ReviewDraft {
    /// The model must justify the attack prerequisites separately from its overall verdict.
    /// Older saved reviews and human revisions remain readable without these model-only fields.
    pub fn validate_model(&self, units: &HashMap<String, ProgramUnit>) -> Result<(), String> {
        self.validate(units)?;
        if self.assessments.len() < 3 || self.assessments.len() > 12 {
            return Err("模型复核须分别提供 INPUT_CONTROL、REACHABILITY、DEFENSE_GAP 的 assessments，并列出额外攻击前提".into());
        }
        for required in ["INPUT_CONTROL", "REACHABILITY", "DEFENSE_GAP"] {
            if self
                .assessments
                .iter()
                .filter(|a| a.check == required)
                .count()
                != 1
            {
                return Err(format!("复核 assessments 必须且只能包含一项 {required}"));
            }
        }
        for assessment in &self.assessments {
            if ![
                "INPUT_CONTROL",
                "REACHABILITY",
                "DEFENSE_GAP",
                "EXTRA_PRECONDITION",
            ]
            .contains(&assessment.check.as_str())
                || !["SUPPORTED", "REFUTED", "UNKNOWN"].contains(&assessment.status.as_str())
                || assessment.rationale.trim().is_empty()
                || assessment.rationale.len() > 4000
            {
                return Err("复核 assessment 的检查项、证据状态或依据无效".into());
            }
            if assessment.status != "UNKNOWN" || !assessment.evidence.is_empty() {
                evidence(&assessment.evidence, units)?;
            }
        }
        if self.verdict == "VALIDATED" && self.assessments.iter().any(|a| a.status != "SUPPORTED") {
            return Err("存在未知或被反证的必要攻击条件，不能判为 VALIDATED；请使用 INCONCLUSIVE 或 REJECTED".into());
        }
        if self.verdict == "REJECTED" && !self.assessments.iter().any(|a| a.status == "REFUTED") {
            return Err("REJECTED 必须至少有一项原始代码支持的 REFUTED 反证".into());
        }
        Ok(())
    }
    pub fn validate(
        &self,
        units: &HashMap<String, ProgramUnit>,
    ) -> Result<Vec<EvidenceRef>, String> {
        if !["VALIDATED", "REJECTED", "INCONCLUSIVE"].contains(&self.verdict.as_str())
            || self.rationale.trim().is_empty()
            || self.rationale.len() > 8192
            || self.counter_evidence.len() > 8192
            || self.missing_information.len() > 8192
        {
            return Err("复核结论或说明无效".into());
        }
        evidence(&self.evidence, units)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Review {
    pub id: String,
    pub finding_id: String,
    pub actor: String,
    pub model_call_id: String,
    pub created_at: String,
    pub revision: u32,
    pub draft: ReviewDraft,
    pub evidence: Vec<EvidenceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnnotationDraft {
    pub unit_id: String,
    pub tag: String,
    /// 子类型（B03）。人工修订可留空；非空时必须属于该标签的允许集合。
    #[serde(default)]
    pub subtype: String,
    pub rationale: String,
    pub evidence: Vec<EvidenceInput>,
}
impl AnnotationDraft {
    pub fn validate(
        &self,
        units: &HashMap<String, ProgramUnit>,
    ) -> Result<Vec<EvidenceRef>, String> {
        let subtypes: &[&str] = match self.tag.as_str() {
            "AUTHENTICATION" => &["PASSWORD", "SESSION", "TOKEN"],
            "CRYPTOGRAPHY" => &["PASSWORD_HASH", "HASH", "SYMMETRIC", "ASYMMETRIC", "RANDOM"],
            "REGISTRATION" => &["ACCOUNT"],
            _ => &[],
        };
        if !["AUTHENTICATION", "CRYPTOGRAPHY", "REGISTRATION"].contains(&self.tag.as_str())
            || (!self.subtype.is_empty() && !subtypes.contains(&self.subtype.as_str()))
            || self.rationale.trim().is_empty()
            || self.rationale.len() > 8192
            || !self.evidence.iter().any(|e| e.unit_id == self.unit_id)
        {
            return Err("关键逻辑标签、子类型或依据无效".into());
        }
        evidence(&self.evidence, units)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogicAnnotation {
    pub id: String,
    pub run_id: String,
    pub revision: u32,
    pub actor: String,
    pub model_call_id: String,
    pub updated_at: String,
    pub draft: AnnotationDraft,
    pub evidence: Vec<EvidenceRef>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentTask {
    pub id: String,
    pub run_id: String,
    pub role: String,
    pub item_key: String,
    pub status: String,
    pub created_at: String,
    pub finished_at: String,
    pub result_artifact_id: String,
    pub result: Value,
    pub error: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditEvidence {
    pub findings: Vec<Finding>,
    pub reviews: Vec<Review>,
    pub annotations: Vec<LogicAnnotation>,
    pub model_calls: Vec<crate::ModelCall>,
    pub tasks: Vec<AgentTask>,
    #[serde(default)]
    pub runtime: Vec<crate::RuntimeRecord>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn audit_budgets_are_configurable_and_old_records_keep_their_limits() {
        let default = AuditConfig::default();
        assert!(default.validate().is_ok());
        assert_eq!(default.max_model_calls, 240);
        assert_eq!(default.max_output_tokens, 0);
        let legacy: AuditConfig = serde_json::from_value(json!({
            "max_model_calls":40,"max_units":3,"max_tool_rounds":8,"timeout_seconds":900
        }))
        .unwrap();
        assert_eq!(legacy.max_model_calls, 40);
        assert_eq!(legacy.max_units, 3);
        assert_eq!(legacy.max_output_tokens, default.max_output_tokens);
        assert!(legacy.validate().is_ok());
        let extended = AuditConfig {
            max_model_calls: 2000,
            max_units: 500,
            max_tool_rounds: 100,
            timeout_seconds: 86_400,
            max_output_tokens: 1_000_000,
            reasoning_effort: "max".into(),
            model_timeout_seconds: MAX_MODEL_TIMEOUT_SECONDS,
        };
        assert!(extended.validate().is_ok());
        for (field, value) in [
            ("max_model_calls", json!(2001)),
            ("max_tool_rounds", json!(101)),
            ("timeout_seconds", json!(86_401)),
            ("max_output_tokens", json!(u32::MAX)),
            ("reasoning_effort", json!("disabled")),
            ("model_timeout_seconds", json!(29)),
            (
                "model_timeout_seconds",
                json!(MAX_MODEL_TIMEOUT_SECONDS + 1),
            ),
        ] {
            let mut data = serde_json::to_value(&default).unwrap();
            data[field] = value;
            assert!(
                serde_json::from_value::<AuditConfig>(data)
                    .unwrap()
                    .validate()
                    .is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn line_citations_are_resolved_from_original_code_and_explicit_fabrication_is_rejected() {
        let unit = ProgramUnit {
            id: "u".into(),
            run_id: "r".into(),
            snapshot_id: "s".into(),
            artifact_id: "a".into(),
            unit: crate::UnitInput {
                path: "example.py".into(),
                language: "python".into(),
                start_line: 7,
                code: "def f(name):\n    return open(name).read()".into(),
                ..Default::default()
            },
        };
        let units = HashMap::from([("u".into(), unit)]);
        let mut reference: EvidenceInput =
            serde_json::from_value(json!({"unit_id":"u","start_line":8,"end_line":8})).unwrap();
        let resolved = evidence(&[reference.clone()], &units).unwrap();
        assert_eq!(resolved[0].quote, "    return open(name).read()");
        assert_eq!(resolved[0].artifact_id, "a");
        reference.quote = "invented()".into();
        assert!(evidence(&[reference.clone()], &units).is_err());
        reference.quote.clear();
        reference.end_line = 99;
        assert!(evidence(&[reference], &units).is_err());
    }

    #[test]
    fn unknown_attack_prerequisites_cannot_be_validated_or_silently_rejected() {
        let unit = ProgramUnit {
            id: "u".into(),
            run_id: "r".into(),
            snapshot_id: "s".into(),
            artifact_id: "a".into(),
            unit: crate::UnitInput {
                path: "example.py".into(),
                language: "python".into(),
                start_line: 1,
                code: "return open(name).read()".into(),
                ..Default::default()
            },
        };
        let units = HashMap::from([("u".into(), unit)]);
        let citation = json!({"unit_id":"u","start_line":1,"end_line":1,"quote":"open(name)"});
        let mut review: ReviewDraft = serde_json::from_value(json!({"verdict":"VALIDATED","rationale":"read without directory restriction",
            "counter_evidence":"none in this expression","missing_information":"","evidence":[citation],
            "assessments":(["INPUT_CONTROL","REACHABILITY","DEFENSE_GAP"].map(|check|json!({"check":check,"status":"SUPPORTED","rationale":"visible in the component","evidence":[citation]})))})).unwrap();
        assert!(review.validate_model(&units).is_ok());
        review.assessments.push(ReviewAssessment { check: "EXTRA_PRECONDITION".into(), status: "UNKNOWN".into(),
            rationale: "attacker-controlled concurrent symlink replacement has not been established".into(), evidence: vec![] });
        assert!(review.validate_model(&units).is_err());
        review.verdict = "INCONCLUSIVE".into();
        assert!(review.validate_model(&units).is_ok());
        review.verdict = "REJECTED".into();
        assert!(review.validate_model(&units).is_err());
        review.assessments[0].evidence[0].quote = "invented()".into();
        review.verdict = "INCONCLUSIVE".into();
        assert!(review.validate_model(&units).is_err());
    }

    #[test]
    fn key_logic_subtypes_are_checked_but_manual_edits_may_omit_them() {
        let unit = ProgramUnit {
            id: "u".into(),
            run_id: "r".into(),
            snapshot_id: "s".into(),
            artifact_id: "a".into(),
            unit: crate::UnitInput {
                path: "accounts.py".into(),
                language: "python".into(),
                start_line: 1,
                code: "def login(password):\n    return bcrypt.checkpw(password, stored)".into(),
                ..Default::default()
            },
        };
        let units = HashMap::from([("u".into(), unit)]);
        let draft = |tag: &str, subtype: &str| AnnotationDraft {
            unit_id: "u".into(),
            tag: tag.into(),
            subtype: subtype.into(),
            rationale: "实际调用 bcrypt 校验口令".into(),
            evidence: vec![
                serde_json::from_value(json!({"unit_id":"u","start_line":2,"end_line":2})).unwrap(),
            ],
        };
        assert!(
            draft("CRYPTOGRAPHY", "PASSWORD_HASH")
                .validate(&units)
                .is_ok()
        );
        assert!(draft("AUTHENTICATION", "PASSWORD").validate(&units).is_ok());
        assert!(draft("REGISTRATION", "").validate(&units).is_ok());
        assert!(draft("CRYPTOGRAPHY", "SYMMETRIC").validate(&units).is_ok());
        assert!(draft("CRYPTOGRAPHY", "PASSWORD").validate(&units).is_err());
        assert!(
            draft("AUTHENTICATION", "PASSWORD_HASH")
                .validate(&units)
                .is_err()
        );
        assert!(draft("UNKNOWN", "PASSWORD").validate(&units).is_err());
    }
}
