use aegis_domain as d;
use aegis_protocol as p;

pub fn evidence(v: d::EvidenceRef) -> p::EvidenceRef {
    p::EvidenceRef {
        unit_id: v.unit_id,
        artifact_id: v.artifact_id,
        path: v.path,
        start_line: v.start_line,
        end_line: v.end_line,
        address: v.address,
        quote: v.quote,
        ..Default::default()
    }
}
pub fn finding(v: d::Finding) -> p::Finding {
    p::Finding {
        static_scope: v.static_scope,
        id: v.id,
        run_id: v.run_id,
        title: v.draft.title,
        category: v.draft.category,
        cwe: v.draft.cwe,
        severity: v.draft.severity,
        severity_reason: v.draft.severity_reason,
        unit_id: v.draft.unit_id,
        input_source: v.draft.input_source,
        sink: v.draft.sink,
        missing_guard: v.draft.missing_guard,
        preconditions: v.draft.preconditions,
        impact: v.draft.impact,
        recommendation: v.draft.recommendation,
        evidence: v.evidence.into_iter().map(evidence).collect(),
        review_status: v.review_status,
        verification_status: v.verification_status,
        revision: v.revision,
        model_call_id: v.model_call_id,
        created_at: v.created_at,
        ..Default::default()
    }
}
pub fn review(v: d::Review) -> p::Review {
    p::Review {
        assessments_json: serde_json::to_string(&v.draft.assessments).unwrap_or_default(),
        id: v.id,
        finding_id: v.finding_id,
        actor: v.actor,
        verdict: v.draft.verdict,
        rationale: v.draft.rationale,
        counter_evidence: v.draft.counter_evidence,
        missing_information: v.draft.missing_information,
        evidence: v.evidence.into_iter().map(evidence).collect(),
        model_call_id: v.model_call_id,
        revision: v.revision,
        created_at: v.created_at,
        ..Default::default()
    }
}
pub fn annotation(v: d::LogicAnnotation) -> p::LogicAnnotation {
    p::LogicAnnotation {
        id: v.id,
        run_id: v.run_id,
        unit_id: v.draft.unit_id,
        tag: v.draft.tag,
        rationale: v.draft.rationale,
        evidence: v.evidence.into_iter().map(evidence).collect(),
        actor: v.actor,
        revision: v.revision,
        model_call_id: v.model_call_id,
        updated_at: v.updated_at,
        ..Default::default()
    }
}
pub fn agent_task(v: d::AgentTask) -> p::AgentTask {
    let plan = if v.role == "PLANNER" && v.status == "SUCCEEDED" {
        serde_json::from_value::<aegis_application::audit::Plan>(v.result.clone())
            .ok()
            .map(|plan| p::AuditPlan {
                approach: plan.approach,
                priorities: plan
                    .priorities
                    .into_iter()
                    .map(|priority| p::AuditPriority {
                        unit_id: priority.unit_id,
                        reason: priority.reason,
                        ..Default::default()
                    })
                    .collect(),
                limitations: plan.limitations,
                ..Default::default()
            })
    } else {
        None
    };
    p::AgentTask {
        plan: plan.into(),
        id: v.id,
        run_id: v.run_id,
        role: v.role,
        item_key: v.item_key,
        status: v.status,
        created_at: v.created_at,
        finished_at: v.finished_at,
        result_artifact_id: v.result_artifact_id,
        result_json: v.result.to_string(),
        error: v.error,
        ..Default::default()
    }
}

pub fn runtime_record(v: d::RuntimeRecord) -> p::RuntimeRecord {
    p::RuntimeRecord {
        id: v.id,
        run_id: v.run_id,
        source_run_id: v.source_run_id,
        finding_id: v.finding_id,
        status: v.status,
        created_at: v.created_at,
        config_json: serde_json::to_string(&v.config).expect("serializable runtime config"),
        result_json: v
            .result
            .map(|result| serde_json::to_string(&result).expect("serializable runtime result"))
            .unwrap_or_default(),
        ..Default::default()
    }
}

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
        run_id: value.run_id,
        task_id: value.task_id,
        role: value.role,
        prompt_version: value.prompt_version,
        request_artifact_id: value.request_artifact_id,
        finish_reason: value.finish_reason,
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
        phase_id: v.phase_id,
        phase_order: v.phase_order,
        phase_count: v.phase_count,
        ..Default::default()
    }
}
pub fn phase(v: d::RunPhase) -> p::RunPhase {
    p::RunPhase {
        id: v.id,
        title: v.title,
        order: v.order,
        status: v.status,
        current: v.current,
        total: v.total,
        detail: v.detail,
        role: v.role,
        unit_id: v.unit_id,
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
