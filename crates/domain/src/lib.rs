use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

pub mod audit;
pub use audit::*;
pub mod runtime;
pub use runtime::*;

pub mod recovery;
pub use recovery::*;

pub const SCOPE: &str = "STRUCTURE_ANALYSIS";
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModelCall {
    pub id: String,
    pub model: String,
    pub purpose: String,
    pub status: String,
    pub created_at: String,
    pub finished_at: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    pub usage_available: bool,
    pub latency_ms: u64,
    pub provider_request_id: String,
    pub artifact_id: String,
    pub error: String,
    #[serde(default)]
    pub run_id: String,
    #[serde(default)]
    pub task_id: String,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub prompt_version: String,
    #[serde(default)]
    pub request_artifact_id: String,
    #[serde(default)]
    pub finish_reason: String,
}

pub fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}
pub fn id() -> String {
    uuid::Uuid::new_v4().to_string()
}
pub fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RunState {
    Queued,
    Running,
    WaitingExecutor,
    Cancelling,
    Completed,
    Partial,
    Failed,
    Cancelled,
    LimitReached,
}

impl RunState {
    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Partial | Self::Failed | Self::Cancelled | Self::LimitReached
        )
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "QUEUED",
            Self::Running => "RUNNING",
            Self::WaitingExecutor => "WAITING_EXECUTOR",
            Self::Cancelling => "CANCELLING",
            Self::Completed => "COMPLETED",
            Self::Partial => "PARTIAL",
            Self::Failed => "FAILED",
            Self::Cancelled => "CANCELLED",
            Self::LimitReached => "LIMIT_REACHED",
        }
    }
    pub fn can_transition(self, next: Self) -> bool {
        if self == next {
            return true;
        }
        match self {
            Self::Queued | Self::WaitingExecutor => matches!(
                next,
                Self::Running
                    | Self::WaitingExecutor
                    | Self::Cancelling
                    | Self::Cancelled
                    | Self::Failed
            ),
            Self::Running => matches!(
                next,
                Self::Cancelling
                    | Self::Completed
                    | Self::Partial
                    | Self::Failed
                    | Self::LimitReached
            ),
            Self::Cancelling => matches!(next, Self::Cancelled | Self::Failed),
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: String,
    pub name: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Snapshot {
    pub id: String,
    pub project_id: String,
    pub kind: String,
    pub state: String,
    pub name: String,
    pub original_artifact_id: String,
    pub normalized_artifact_id: String,
    pub manifest_artifact_id: String,
    pub resolved_revision: String,
    pub target_sha256: String,
    pub file_count: u64,
    pub total_bytes: u64,
    pub metadata: Value,
    pub error: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRun {
    pub id: String,
    pub project_id: String,
    pub snapshot_id: String,
    pub state: RunState,
    pub scope: String,
    pub created_at: String,
    pub started_at: String,
    pub finished_at: String,
    pub unit_count: u64,
    pub summary: Value,
    pub error: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Artifact {
    pub id: String,
    pub sha256: String,
    pub size: u64,
    pub name: String,
    pub media_type: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileRecord {
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub language: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Exclusion {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotManifest {
    pub schema_version: u32,
    pub kind: String,
    pub normalized_artifact_id: String,
    pub target_sha256: String,
    pub files: Vec<FileRecord>,
    pub exclusions: Vec<Exclusion>,
    pub metadata: Value,
    pub resolved_revision: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct UnitInput {
    pub key: String,
    pub name: String,
    pub path: String,
    pub language: String,
    pub start_line: u32,
    pub end_line: u32,
    pub start_byte: u64,
    pub end_byte: u64,
    pub address: String,
    pub code: String,
    pub quality: String,
    pub metadata: Value,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct EdgeInput {
    pub source_key: String,
    pub target_key: String,
    pub target_name: String,
    pub kind: String,
    pub certainty: String,
    pub line: u32,
    pub address: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileResult {
    pub path: String,
    pub language: String,
    pub status: String,
    pub reason: String,
    pub unit_count: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolExecution {
    pub name: String,
    pub version: String,
    pub command: Vec<String>,
    pub started_at: String,
    pub finished_at: String,
    pub exit_code: Option<i32>,
    pub terminated: bool,
    pub log_artifact_id: String,
    pub details: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub schema_version: u32,
    pub units: Vec<UnitInput>,
    pub edges: Vec<EdgeInput>,
    pub files: Vec<FileResult>,
    pub tools: Vec<ToolExecution>,
    pub warnings: Vec<String>,
    pub metadata: Value,
}

impl Default for AnalysisResult {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            units: vec![],
            edges: vec![],
            files: vec![],
            tools: vec![],
            warnings: vec![],
            metadata: Value::Null,
        }
    }
}

impl AnalysisResult {
    pub fn partial(&self) -> bool {
        self.files
            .iter()
            .any(|f| !matches!(f.status.as_str(), "PARSED" | "NOT_SOURCE"))
            || self.units.iter().any(|u| u.quality != "PARSED")
            || !self.warnings.is_empty()
    }
    pub fn validate(&self, manifest: &SnapshotManifest) -> Result<(), String> {
        if self.schema_version != SCHEMA_VERSION {
            return Err("unsupported analysis schema".into());
        }
        if self.units.len() > 50_000 || self.edges.len() > 500_000 {
            return Err("analysis result exceeds limits".into());
        }
        let mut keys = HashSet::new();
        let files: HashMap<_, _> = manifest
            .files
            .iter()
            .map(|f| (f.path.as_str(), f))
            .collect();
        let mut unit_counts: HashMap<&str, u64> = HashMap::new();
        for unit in &self.units {
            if unit.key.is_empty() || !keys.insert(unit.key.as_str()) {
                return Err("empty or duplicate program unit key".into());
            }
            let file = files
                .get(unit.path.as_str())
                .ok_or("program unit references a file outside the snapshot")?;
            if file.language != unit.language
                || !matches!(unit.quality.as_str(), "PARSED" | "PARTIAL" | "FAILED")
            {
                return Err("program unit has inconsistent language or quality".into());
            }
            *unit_counts.entry(unit.path.as_str()).or_default() += 1;
            if unit.language == "binary" {
                if !unit.address.starts_with("0x")
                    || u64::from_str_radix(&unit.address[2..], 16).is_err()
                {
                    return Err("invalid binary address".into());
                }
            } else if unit.start_line == 0
                || unit.end_line < unit.start_line
                || unit.start_byte > unit.end_byte
                || unit.end_byte > file.size
                || unit.end_byte - unit.start_byte != unit.code.len() as u64
            {
                return Err("source location is outside the original file".into());
            }
        }
        let mut covered = HashSet::new();
        for result in &self.files {
            let file = files
                .get(result.path.as_str())
                .ok_or("coverage references a file outside the snapshot")?;
            if !covered.insert(result.path.as_str())
                || result.language != file.language
                || result.unit_count != *unit_counts.get(result.path.as_str()).unwrap_or(&0)
                || !matches!(
                    result.status.as_str(),
                    "PARSED" | "PARTIAL" | "FAILED" | "UNSUPPORTED" | "NOT_SOURCE"
                )
            {
                return Err("coverage status, count or file identity is inconsistent".into());
            }
        }
        if covered.len() != files.len() {
            return Err("analysis omitted file coverage records".into());
        }
        for edge in &self.edges {
            if !keys.contains(edge.source_key.as_str())
                || (!edge.target_key.is_empty() && !keys.contains(edge.target_key.as_str()))
            {
                return Err("edge references an unknown program unit".into());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramUnit {
    pub id: String,
    pub run_id: String,
    pub snapshot_id: String,
    pub artifact_id: String,
    #[serde(flatten)]
    pub unit: UnitInput,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramEdge {
    pub source_id: String,
    pub target_id: String,
    pub target_name: String,
    pub kind: String,
    pub certainty: String,
    pub line: u32,
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunEvent {
    pub run_id: String,
    pub seq: u64,
    pub created_at: String,
    pub kind: String,
    pub message: String,
    pub work_item_id: String,
    pub current: u64,
    pub total: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub id: String,
    pub run_id: String,
    pub format: String,
    pub artifact_id: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolCapability {
    pub name: String,
    pub version: String,
    pub available: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Executor {
    pub id: String,
    pub name: String,
    pub platform: String,
    pub architecture: String,
    pub last_seen: String,
    pub capabilities: Vec<ToolCapability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkLease {
    pub work_item_id: String,
    pub attempt_id: String,
    pub lease_token: String,
    pub kind: String,
    pub snapshot_id: String,
    pub run_id: String,
    pub input_artifact_id: String,
    pub payload: Value,
    pub timeout_seconds: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancellation_requires_a_distinct_reaping_phase() {
        assert!(!RunState::Running.can_transition(RunState::Cancelled));
        assert!(RunState::Running.can_transition(RunState::Cancelling));
        assert!(RunState::Cancelling.can_transition(RunState::Cancelled));
        assert!(!RunState::Cancelled.can_transition(RunState::Running));
    }
    #[test]
    fn fabricated_source_locations_are_rejected() {
        let manifest = SnapshotManifest {
            schema_version: 1,
            kind: "SOURCE".into(),
            normalized_artifact_id: "a".into(),
            target_sha256: "hash".into(),
            files: vec![FileRecord {
                path: "a.py".into(),
                size: 10,
                language: "python".into(),
                ..Default::default()
            }],
            exclusions: vec![],
            metadata: Value::Null,
            resolved_revision: String::new(),
        };
        let mut result = AnalysisResult::default();
        result.units.push(UnitInput {
            key: "f".into(),
            name: "f".into(),
            path: "a.py".into(),
            language: "python".into(),
            start_line: 1,
            end_line: 2,
            end_byte: 99,
            code: "0123456789".into(),
            quality: "PARSED".into(),
            ..Default::default()
        });
        assert!(result.validate(&manifest).is_err());
        result.units[0].end_byte = 10;
        result.files.push(FileResult {
            path: "a.py".into(),
            language: "python".into(),
            status: "PARSED".into(),
            unit_count: 1,
            ..Default::default()
        });
        assert!(result.validate(&manifest).is_ok());
        result.files[0].unit_count = 2;
        assert!(result.validate(&manifest).is_err());
        result.files.clear();
        assert!(result.validate(&manifest).is_err());
    }
}
