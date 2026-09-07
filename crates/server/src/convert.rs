use aegis_domain as d;
use aegis_protocol as p;

pub fn model_call(value: d::ModelCall) -> p::ModelCall {
    p::ModelCall {
        id: value.id,
        model: value.model,
        purpose: value.purpose,
        status: value.status,
        created_at: value.created_at,
        finished_at: value.finished_at,
        input_tokens: value.input_tokens,
        output_tokens: value.output_tokens,
        total_tokens: value.total_tokens,
        usage_available: value.usage_available,
        latency_ms: value.latency_ms,
        provider_request_id: value.provider_request_id,
        artifact_id: value.artifact_id,
        error: value.error,
        ..Default::default()
    }
}

pub fn project(v: d::Project) -> p::Project {
    p::Project {
        id: v.id,
        name: v.name,
        created_at: v.created_at,
        ..Default::default()
    }
}
pub fn snapshot(v: d::Snapshot) -> p::Snapshot {
    p::Snapshot {
        id: v.id,
        project_id: v.project_id,
        kind: match v.kind.as_str() {
            "SOURCE" => p::TargetKind::Source,
            "BINARY" => p::TargetKind::Binary,
            "GIT" => p::TargetKind::Git,
            _ => p::TargetKind::Unspecified,
        }
        .into(),
        state: match v.state.as_str() {
            "IMPORTING" => p::SnapshotState::Importing,
            "READY" => p::SnapshotState::Ready,
            "PARTIAL" => p::SnapshotState::Partial,
            "FAILED" => p::SnapshotState::Failed,
            _ => p::SnapshotState::Unspecified,
        }
        .into(),
        name: v.name,
        original_artifact_id: v.original_artifact_id,
        normalized_artifact_id: v.normalized_artifact_id,
        manifest_artifact_id: v.manifest_artifact_id,
        resolved_revision: v.resolved_revision,
        target_sha256: v.target_sha256,
        file_count: v.file_count,
        total_bytes: v.total_bytes,
        metadata_json: v.metadata.to_string(),
        error: v.error,
        created_at: v.created_at,
        ..Default::default()
    }
}
pub fn run(v: d::AuditRun) -> p::AuditRun {
    p::AuditRun {
        id: v.id,
        project_id: v.project_id,
        snapshot_id: v.snapshot_id,
        state: match v.state {
            d::RunState::Queued => p::RunState::Queued,
            d::RunState::Running => p::RunState::Running,
            d::RunState::WaitingExecutor => p::RunState::WaitingExecutor,
            d::RunState::Cancelling => p::RunState::Cancelling,
            d::RunState::Completed => p::RunState::Completed,
            d::RunState::Partial => p::RunState::Partial,
            d::RunState::Failed => p::RunState::Failed,
            d::RunState::Cancelled => p::RunState::Cancelled,
            d::RunState::LimitReached => p::RunState::LimitReached,
        }
        .into(),
        scope: v.scope,
        created_at: v.created_at,
        started_at: v.started_at,
        finished_at: v.finished_at,
        unit_count: v.unit_count,
        summary_json: v.summary.to_string(),
        error: v.error,
        ..Default::default()
    }
}
pub fn artifact(v: d::Artifact) -> p::Artifact {
    p::Artifact {
        id: v.id,
        sha256: v.sha256,
        size: v.size,
        name: v.name,
        media_type: v.media_type,
        ..Default::default()
    }
}
pub fn unit(v: d::ProgramUnit) -> p::ProgramUnit {
    p::ProgramUnit {
        id: v.id,
        run_id: v.run_id,
        snapshot_id: v.snapshot_id,
        artifact_id: v.artifact_id,
        name: v.unit.name,
        path: v.unit.path,
        language: v.unit.language,
        start_line: v.unit.start_line,
        end_line: v.unit.end_line,
        start_byte: v.unit.start_byte,
        end_byte: v.unit.end_byte,
        address: v.unit.address,
        code: v.unit.code,
        quality: v.unit.quality,
        metadata_json: v.unit.metadata.to_string(),
        ..Default::default()
    }
}
pub fn edge(v: d::ProgramEdge) -> p::ProgramEdge {
    p::ProgramEdge {
        source_id: v.source_id,
        target_id: v.target_id,
        target_name: v.target_name,
        kind: v.kind,
        certainty: v.certainty,
        line: v.line,
        address: v.address,
        ..Default::default()
    }
}
pub fn event(v: d::RunEvent) -> p::RunEvent {
    p::RunEvent {
        run_id: v.run_id,
        seq: v.seq,
        created_at: v.created_at,
        kind: v.kind,
        message: v.message,
        work_item_id: v.work_item_id,
        current: v.current,
        total: v.total,
        ..Default::default()
    }
}
pub fn report(v: d::Report) -> p::Report {
    p::Report {
        id: v.id,
        run_id: v.run_id,
        format: v.format,
        artifact_id: v.artifact_id,
        created_at: v.created_at,
        ..Default::default()
    }
}
pub fn capability(v: d::ToolCapability) -> p::ToolCapability {
    p::ToolCapability {
        name: v.name,
        version: v.version,
        available: v.available,
        detail: v.detail,
        ..Default::default()
    }
}
pub fn executor(v: d::Executor) -> p::Executor {
    p::Executor {
        id: v.id,
        name: v.name,
        platform: v.platform,
        architecture: v.architecture,
        last_seen: v.last_seen,
        capabilities: v.capabilities.into_iter().map(capability).collect(),
        ..Default::default()
    }
}
pub fn lease(v: d::WorkLease) -> p::WorkLease {
    p::WorkLease {
        work_item_id: v.work_item_id,
        attempt_id: v.attempt_id,
        lease_token: v.lease_token,
        kind: v.kind,
        snapshot_id: v.snapshot_id,
        run_id: v.run_id,
        input_artifact_id: v.input_artifact_id,
        payload_json: v.payload.to_string(),
        timeout_seconds: v.timeout_seconds,
        ..Default::default()
    }
}
