#![allow(refining_impl_trait)]
use crate::{convert as c, store::Store};
use aegis_domain as d;
use aegis_protocol as p;
use connectrpc::{
    ConnectError, RequestContext, Response, ServiceRequest, ServiceResult, ServiceStream,
};
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct ExecutorIdentity(pub String);
#[derive(Clone)]
pub struct Api {
    pub store: Store,
    pub shutdown: CancellationToken,
}

fn identity(ctx: &RequestContext) -> Result<String, ConnectError> {
    ctx.extensions()
        .get::<ExecutorIdentity>()
        .map(|x| x.0.clone())
        .ok_or_else(|| ConnectError::permission_denied("需要执行器身份"))
}
fn matching_identity(ctx: &RequestContext, expected: &str) -> Result<String, ConnectError> {
    let id = identity(ctx)?;
    if id != expected {
        return Err(ConnectError::permission_denied("执行器身份不匹配"));
    }
    Ok(id)
}

pub fn router(api: Arc<Api>) -> connectrpc::Router {
    let router = connectrpc::Router::new();
    let router = p::ProjectServiceExt::register(api.clone(), router);
    let router = p::RunServiceExt::register(api.clone(), router);
    let router = p::ProgramServiceExt::register(api.clone(), router);
    let router = p::FindingServiceExt::register(api.clone(), router);
    let router = p::RuntimeServiceExt::register(api.clone(), router);
    let router = p::ReportServiceExt::register(api.clone(), router);
    let router = p::ExecutorServiceExt::register(api.clone(), router);
    p::SystemServiceExt::register(api, router)
}

impl p::ProjectService for Api {
    async fn create_project(
        &self,
        _: RequestContext,
        req: ServiceRequest<'_, p::CreateProjectRequest>,
    ) -> ServiceResult<p::CreateProjectResponse> {
        let project = self.store.create_project(req.request_id, req.name).await?;
        Response::ok(p::CreateProjectResponse {
            project: c::project(project).into(),
            ..Default::default()
        })
    }
    async fn list_projects(
        &self,
        _: RequestContext,
        _req: ServiceRequest<'_, p::ListProjectsRequest>,
    ) -> ServiceResult<p::ListProjectsResponse> {
        Response::ok(p::ListProjectsResponse {
            projects: self
                .store
                .projects()
                .await?
                .into_iter()
                .map(c::project)
                .collect(),
            ..Default::default()
        })
    }
    async fn get_project(
        &self,
        _: RequestContext,
        req: ServiceRequest<'_, p::GetProjectRequest>,
    ) -> ServiceResult<p::GetProjectResponse> {
        let project = self.store.get("projects", req.project_id).await?;
        Response::ok(p::GetProjectResponse {
            project: c::project(project).into(),
            snapshots: self
                .store
                .snapshots(req.project_id)
                .await?
                .into_iter()
                .map(c::snapshot)
                .collect(),
            ..Default::default()
        })
    }
    async fn create_snapshot(
        &self,
        _: RequestContext,
        req: ServiceRequest<'_, p::CreateSnapshotRequest>,
    ) -> ServiceResult<p::CreateSnapshotResponse> {
        let kind = if req.kind == p::TargetKind::Source {
            "SOURCE"
        } else if req.kind == p::TargetKind::Binary {
            "BINARY"
        } else if req.kind == p::TargetKind::Git {
            "GIT"
        } else {
            return Err(ConnectError::invalid_argument("请选择目标类型"));
        };
        let snapshot = self
            .store
            .create_snapshot(
                req.request_id,
                req.project_id,
                kind,
                req.artifact_id,
                req.git_url,
                req.git_revision,
                req.name,
            )
            .await?;
        Response::ok(p::CreateSnapshotResponse {
            snapshot: c::snapshot(snapshot).into(),
            ..Default::default()
        })
    }
    async fn get_snapshot(
        &self,
        _: RequestContext,
        req: ServiceRequest<'_, p::GetSnapshotRequest>,
    ) -> ServiceResult<p::GetSnapshotResponse> {
        Response::ok(p::GetSnapshotResponse {
            snapshot: c::snapshot(self.store.get("snapshots", req.snapshot_id).await?).into(),
            ..Default::default()
        })
    }
}
impl p::RunService for Api {
    async fn create_run(
        &self,
        _: RequestContext,
        req: ServiceRequest<'_, p::CreateRunRequest>,
    ) -> ServiceResult<p::CreateRunResponse> {
        let mut config = d::AuditConfig::default();
        if req.max_model_calls > 0 {
            config.max_model_calls = req.max_model_calls;
        }
        if req.max_units > 0 {
            config.max_units = req.max_units;
        }
        if req.max_tool_rounds > 0 {
            config.max_tool_rounds = req.max_tool_rounds;
        }
        if req.timeout_seconds > 0 {
            config.timeout_seconds = req.timeout_seconds;
        }
        Response::ok(p::CreateRunResponse {
            run: c::run(
                self.store
                    .create_run_with_options(
                        req.request_id,
                        req.snapshot_id,
                        if req.scope.is_empty() {
                            d::SCOPE
                        } else {
                            req.scope
                        },
                        config,
                    )
                    .await?,
            )
            .into(),
            ..Default::default()
        })
    }
    async fn list_runs(
        &self,
        _: RequestContext,
        req: ServiceRequest<'_, p::ListRunsRequest>,
    ) -> ServiceResult<p::ListRunsResponse> {
        Response::ok(p::ListRunsResponse {
            runs: self
                .store
                .runs(req.project_id)
                .await?
                .into_iter()
                .map(c::run)
                .collect(),
            ..Default::default()
        })
    }
    async fn get_run(
        &self,
        _: RequestContext,
        req: ServiceRequest<'_, p::GetRunRequest>,
    ) -> ServiceResult<p::GetRunResponse> {
        Response::ok(p::GetRunResponse {
            run: c::run(self.store.get("audit_runs", req.run_id).await?).into(),
            artifacts: self
                .store
                .run_artifacts(req.run_id)
                .await?
                .into_iter()
                .map(c::artifact)
                .collect(),
            ..Default::default()
        })
    }
    async fn watch_run(
        &self,
        _: RequestContext,
        req: ServiceRequest<'_, p::WatchRunRequest>,
    ) -> ServiceResult<ServiceStream<p::WatchRunResponse>> {
        let run_id = req.run_id.to_owned();
        let mut cursor = req.after_seq;
        let store = self.store.clone();
        let shutdown = self.shutdown.clone();
        let _: d::AuditRun = store.get("audit_runs", &run_id).await?;
        let stream = async_stream::try_stream! {
            loop {
                let notified=store.changed.notified();tokio::pin!(notified);notified.as_mut().enable();
                let events=store.events(&run_id,cursor).await.map_err(ConnectError::from)?;
                if !events.is_empty() {
                    for event in events {cursor=event.seq;yield p::WatchRunResponse{event:c::event(event).into(),..Default::default()};}
                    continue;
                }
                let run:d::AuditRun=store.get("audit_runs",&run_id).await.map_err(ConnectError::from)?;
                if run.state.terminal(){break;}
                tokio::select!{_=&mut notified=>{},_=tokio::time::sleep(Duration::from_secs(1))=>{},_=shutdown.cancelled()=>break}
            }
        };
        Response::ok(Box::pin(stream) as ServiceStream<p::WatchRunResponse>)
    }
    async fn cancel_run(
        &self,
        _: RequestContext,
        req: ServiceRequest<'_, p::CancelRunRequest>,
    ) -> ServiceResult<p::CancelRunResponse> {
        Response::ok(p::CancelRunResponse {
            run: c::run(self.store.cancel_run(req.run_id).await?).into(),
            ..Default::default()
        })
    }
}
impl p::ProgramService for Api {
    async fn update_annotation(
        &self,
        _: RequestContext,
        req: ServiceRequest<'_, p::UpdateAnnotationRequest>,
    ) -> ServiceResult<p::UpdateAnnotationResponse> {
        Response::ok(p::UpdateAnnotationResponse {
            annotation: c::annotation(
                self.store
                    .update_annotation(
                        req.request_id,
                        req.annotation_id,
                        req.expected_revision,
                        req.tag,
                        req.rationale,
                    )
                    .await?,
            )
            .into(),
            ..Default::default()
        })
    }
    async fn list_units(
        &self,
        _: RequestContext,
        req: ServiceRequest<'_, p::ListUnitsRequest>,
    ) -> ServiceResult<p::ListUnitsResponse> {
        let (units, total) = self
            .store
            .list_units(req.run_id, req.query, req.language, req.offset, req.limit)
            .await?;
        Response::ok(p::ListUnitsResponse {
            units: units.into_iter().map(c::unit).collect(),
            total,
            ..Default::default()
        })
    }
    async fn get_unit(
        &self,
        _: RequestContext,
        req: ServiceRequest<'_, p::GetUnitRequest>,
    ) -> ServiceResult<p::GetUnitResponse> {
        Response::ok(p::GetUnitResponse {
            unit: c::unit(self.store.get("program_units", req.unit_id).await?).into(),
            edges: self
                .store
                .edges(req.unit_id)
                .await?
                .into_iter()
                .map(c::edge)
                .collect(),
            ..Default::default()
        })
    }
    async fn get_graph(
        &self,
        _: RequestContext,
        req: ServiceRequest<'_, p::GetGraphRequest>,
    ) -> ServiceResult<p::GetGraphResponse> {
        let (units, edges) = self.store.graph(req.unit_id).await?;
        Response::ok(p::GetGraphResponse {
            units: units.into_iter().map(c::unit).collect(),
            edges: edges.into_iter().map(c::edge).collect(),
            ..Default::default()
        })
    }
}
impl p::FindingService for Api {
    async fn get_audit(
        &self,
        _: RequestContext,
        req: ServiceRequest<'_, p::GetAuditRequest>,
    ) -> ServiceResult<p::GetAuditResponse> {
        let data = self.store.audit_evidence(req.run_id).await?;
        Response::ok(p::GetAuditResponse {
            findings: data.findings.into_iter().map(c::finding).collect(),
            reviews: data.reviews.into_iter().map(c::review).collect(),
            annotations: data.annotations.into_iter().map(c::annotation).collect(),
            model_calls: data.model_calls.into_iter().map(c::model_call).collect(),
            tasks: data.tasks.into_iter().map(c::agent_task).collect(),
            runtime: data.runtime.into_iter().map(c::runtime_record).collect(),
            ..Default::default()
        })
    }
    async fn list_findings(
        &self,
        _: RequestContext,
        req: ServiceRequest<'_, p::ListFindingsRequest>,
    ) -> ServiceResult<p::ListFindingsResponse> {
        let (findings, total) = self
            .store
            .findings(req.run_id, req.review_status, req.offset, req.limit)
            .await?;
        Response::ok(p::ListFindingsResponse {
            findings: findings.into_iter().map(c::finding).collect(),
            total,
            ..Default::default()
        })
    }
    async fn get_finding(
        &self,
        _: RequestContext,
        req: ServiceRequest<'_, p::GetFindingRequest>,
    ) -> ServiceResult<p::GetFindingResponse> {
        Response::ok(p::GetFindingResponse {
            finding: c::finding(self.store.get("findings", req.finding_id).await?).into(),
            reviews: self
                .store
                .finding_reviews(req.finding_id)
                .await?
                .into_iter()
                .map(c::review)
                .collect(),
            ..Default::default()
        })
    }
    async fn submit_review(
        &self,
        _: RequestContext,
        req: ServiceRequest<'_, p::SubmitReviewRequest>,
    ) -> ServiceResult<p::SubmitReviewResponse> {
        let draft = d::ReviewDraft {
            verdict: req.verdict.into(),
            rationale: req.rationale.into(),
            counter_evidence: req.counter_evidence.into(),
            missing_information: req.missing_information.into(),
            evidence: vec![],
            assessments: vec![],
        };
        let (finding, review) = self
            .store
            .submit_review(req.request_id, req.finding_id, req.expected_revision, draft)
            .await?;
        Response::ok(p::SubmitReviewResponse {
            finding: c::finding(finding).into(),
            review: c::review(review).into(),
            ..Default::default()
        })
    }
}
impl p::RuntimeService for Api {
    async fn create_runtime(
        &self,
        _: RequestContext,
        req: ServiceRequest<'_, p::CreateRuntimeRequest>,
    ) -> ServiceResult<p::CreateRuntimeResponse> {
        let config = if req.config_json.is_empty() {
            None
        } else {
            if req.config_json.len() > 128 * 1024 {
                return Err(ConnectError::invalid_argument("运行配置超过 128 KiB"));
            }
            Some(serde_json::from_str(req.config_json).map_err(|error| {
                ConnectError::invalid_argument(format!("运行配置无效：{error}"))
            })?)
        };
        Response::ok(p::CreateRuntimeResponse {
            record: c::runtime_record(
                self.store
                    .create_runtime(req.request_id, req.source_run_id, req.finding_id, config)
                    .await?,
            )
            .into(),
            ..Default::default()
        })
    }
    async fn get_runtime(
        &self,
        _: RequestContext,
        req: ServiceRequest<'_, p::GetRuntimeRequest>,
    ) -> ServiceResult<p::GetRuntimeResponse> {
        Response::ok(p::GetRuntimeResponse {
            record: c::runtime_record(self.store.runtime_record(req.record_id).await?).into(),
            ..Default::default()
        })
    }
    async fn list_runtime(
        &self,
        _: RequestContext,
        req: ServiceRequest<'_, p::ListRuntimeRequest>,
    ) -> ServiceResult<p::ListRuntimeResponse> {
        let _: d::AuditRun = self.store.get("audit_runs", req.run_id).await?;
        Response::ok(p::ListRuntimeResponse {
            records: self
                .store
                .runtime_records(req.run_id)
                .await?
                .into_iter()
                .map(c::runtime_record)
                .collect(),
            ..Default::default()
        })
    }
}
impl p::ReportService for Api {
    async fn create_report(
        &self,
        _: RequestContext,
        req: ServiceRequest<'_, p::CreateReportRequest>,
    ) -> ServiceResult<p::CreateReportResponse> {
        Response::ok(p::CreateReportResponse {
            report: c::report(
                self.store
                    .create_report(req.request_id, req.run_id, req.format)
                    .await?,
            )
            .into(),
            ..Default::default()
        })
    }
    async fn get_report(
        &self,
        _: RequestContext,
        req: ServiceRequest<'_, p::GetReportRequest>,
    ) -> ServiceResult<p::GetReportResponse> {
        Response::ok(p::GetReportResponse {
            report: c::report(self.store.get("report_exports", req.report_id).await?).into(),
            ..Default::default()
        })
    }
}
impl p::ExecutorService for Api {
    async fn register_executor(
        &self,
        _: RequestContext,
        req: ServiceRequest<'_, p::RegisterExecutorRequest>,
    ) -> ServiceResult<p::RegisterExecutorResponse> {
        let req = req.to_owned_message();
        let capabilities = req
            .capabilities
            .into_iter()
            .map(|x| d::ToolCapability {
                name: x.name,
                version: x.version,
                available: x.available,
                detail: x.detail,
            })
            .collect();
        let (executor, token) = self
            .store
            .register_executor(&req.name, &req.platform, &req.architecture, capabilities)
            .await?;
        Response::ok(p::RegisterExecutorResponse {
            executor: c::executor(executor).into(),
            executor_token: token,
            ..Default::default()
        })
    }
    async fn claim_work(
        &self,
        ctx: RequestContext,
        req: ServiceRequest<'_, p::ClaimWorkRequest>,
    ) -> ServiceResult<p::ClaimWorkResponse> {
        matching_identity(&ctx, req.executor_id)?;
        let lease = self.store.claim_work(req.executor_id).await?;
        Response::ok(p::ClaimWorkResponse {
            lease: lease.map(c::lease).into(),
            ..Default::default()
        })
    }
    async fn heartbeat(
        &self,
        ctx: RequestContext,
        req: ServiceRequest<'_, p::HeartbeatRequest>,
    ) -> ServiceResult<p::HeartbeatResponse> {
        matching_identity(&ctx, req.executor_id)?;
        let req = req.to_owned_message();
        if !req.capabilities.is_empty() {
            let capabilities = req
                .capabilities
                .iter()
                .map(|x| d::ToolCapability {
                    name: x.name.clone(),
                    version: x.version.clone(),
                    available: x.available,
                    detail: x.detail.clone(),
                })
                .collect();
            self.store
                .refresh_capabilities(&req.executor_id, capabilities)
                .await?;
        }
        let (cancel_requested, lease_valid) = self
            .store
            .heartbeat(
                &req.executor_id,
                &req.work_item_id,
                &req.attempt_id,
                &req.lease_token,
            )
            .await?;
        Response::ok(p::HeartbeatResponse {
            cancel_requested,
            lease_valid,
            ..Default::default()
        })
    }
    async fn report_progress(
        &self,
        ctx: RequestContext,
        req: ServiceRequest<'_, p::ReportProgressRequest>,
    ) -> ServiceResult<p::ReportProgressResponse> {
        let executor = identity(&ctx)?;
        self.store
            .progress(
                &executor,
                req.work_item_id,
                req.attempt_id,
                req.lease_token,
                req.message,
                req.current,
                req.total,
            )
            .await?;
        Response::ok(p::ReportProgressResponse::default())
    }
    async fn complete_work(
        &self,
        ctx: RequestContext,
        req: ServiceRequest<'_, p::CompleteWorkRequest>,
    ) -> ServiceResult<p::CompleteWorkResponse> {
        let executor = identity(&ctx)?;
        let accepted = self
            .store
            .complete_work(
                &executor,
                req.work_item_id,
                req.attempt_id,
                req.lease_token,
                req.outcome,
                req.result_artifact_id,
                req.error,
                req.processes_reaped,
            )
            .await?;
        Response::ok(p::CompleteWorkResponse {
            accepted,
            ..Default::default()
        })
    }
}
impl p::SystemService for Api {
    async fn get_capabilities(
        &self,
        _: RequestContext,
        _req: ServiceRequest<'_, p::GetCapabilitiesRequest>,
    ) -> ServiceResult<p::GetCapabilitiesResponse> {
        Response::ok(p::GetCapabilitiesResponse {
            version: env!("CARGO_PKG_VERSION").into(),
            scope: d::SCOPE.into(),
            executors: self
                .store
                .executors()
                .await?
                .into_iter()
                .map(c::executor)
                .collect(),
            pending_features: vec![
                "去壳与解混淆".into(),
                "动态模糊测试与自动利用".into(),
                "六项正式软件验收".into(),
            ],
            model_connection: self.store.model_connection().await?.into(),
            ..Default::default()
        })
    }

    async fn check_model_connection(
        &self,
        _: RequestContext,
        req: ServiceRequest<'_, p::CheckModelConnectionRequest>,
    ) -> ServiceResult<p::CheckModelConnectionResponse> {
        Response::ok(p::CheckModelConnectionResponse {
            call: c::model_call(self.store.start_model_probe(req.request_id).await?).into(),
            ..Default::default()
        })
    }
}
