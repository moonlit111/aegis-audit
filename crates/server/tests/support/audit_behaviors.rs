use super::*;
use aegis_application::model::{ModelClient, ModelRequest, ModelResponse, ProbeResult};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

struct ScriptedModel {
    invalid_quote: bool,
    invalid_review: bool,
    invalid_verifier: bool,
    failing_role: Option<&'static str>,
    audit_tool_requests: usize,
    truncate_first: bool,
    delay_ms: u64,
    in_flight: Arc<AtomicUsize>,
    peak_in_flight: Arc<AtomicUsize>,
    requests: Mutex<Vec<ModelRequest>>,
}
impl ScriptedModel {
    fn new(invalid_quote: bool) -> Self {
        Self {
            invalid_quote,
            invalid_review: false,
            invalid_verifier: false,
            failing_role: None,
            audit_tool_requests: 0,
            truncate_first: false,
            delay_ms: 0,
            in_flight: Arc::new(AtomicUsize::new(0)),
            peak_in_flight: Arc::new(AtomicUsize::new(0)),
            requests: Mutex::new(vec![]),
        }
    }
}
impl ModelClient for ScriptedModel {
    fn complete<'a>(
        &'a self,
        request: &'a ModelRequest,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<ModelResponse>> + Send + 'a>> {
        Box::pin(async move {
            let active = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak_in_flight.fetch_max(active, Ordering::SeqCst);
            if self.delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(self.delay_ms)).await;
            }
            let outcome = async {
            self.requests.lock().unwrap().push(request.clone());
            let system = request.messages[0]["content"].as_str().unwrap();
            if self
                .failing_role
                .is_some_and(|role| system.contains(&format!("ROLE: {role}")))
            {
                anyhow::bail!("provider unavailable");
            }
            let input: Value =
                serde_json::from_str(request.messages[1]["content"].as_str().unwrap()).unwrap();
            let result = if system.contains("ROLE: PLANNER") || system.contains("ROLE: REVERSE") {
                json!({"approach":"fixture workflow behavior, not model efficacy","priorities":[],"limitations":[]})
            } else if system.contains("ROLE: AUDITOR") {
                let focus = &input["focus"];
                let id = focus["unit_id"].as_str().unwrap();
                let name = focus["name"].as_str().unwrap();
                let mut findings = vec![];
                let mut annotations = vec![];
                if name == "download" {
                    findings.push(json!({"title":"Unrestricted document path","category":"PATH_TRAVERSAL","cwe":"CWE-22","severity":"HIGH","severity_reason":"untrusted name reaches file read","unit_id":id,
                        "input_source":"function argument name","sink":"open(name)","missing_guard":"no permitted root check","preconditions":"caller accepts an external name","impact":"read files outside document root","recommendation":"resolve and constrain the path",
                        "evidence":[{"unit_id":id,"start_line":2,"end_line":2,"quote":if self.invalid_quote {"fabricated_code()"} else {"return open(name, encoding=\"utf-8\").read()"}}]}));
                }
                if name == "login" {
                    annotations.push(json!({"unit_id":id,"tag":"AUTHENTICATION","rationale":"checks a submitted password","evidence":[{"unit_id":id,"start_line":5,"end_line":5,"quote":"return password == expected"}]}));
                }
                json!({"audited_unit_ids":[id],"findings":findings,"annotations":annotations,"limitations":[]})
            } else if system.contains("ROLE: REVIEWER") {
                assert!(input.get("audit_approach").is_none());
                assert!(input.get("original_code").is_some());
                json!({"verdict":"VALIDATED","rationale":"original code has an unconstrained path argument","counter_evidence":"no guard in supplied code","missing_information":"external routing is not dynamically tested","evidence":input["candidate"]["evidence"],"assessments":(["INPUT_CONTROL","REACHABILITY","DEFENSE_GAP"].map(|check|json!({"check":check,"status":if self.invalid_review && check == "INPUT_CONTROL" {"UNKNOWN"} else {"SUPPORTED"},"rationale":"the fixture function receives and opens the supplied name without a guard","evidence":input["candidate"]["evidence"]})))})
            } else if system.contains("ROLE: VERIFIER") {
                json!({"status":if self.invalid_verifier {"INVALID"} else {"NEEDS_CONFIGURATION"},"rationale":"fixture test does not provide deployment input","limitations":["runtime not executed"],"config":null})
            } else {
                json!({"summary":"static fixture analysis only","recommendations":[],"limitations":["runtime not executed"]})
            };
            let tool_results = request
                .messages
                .iter()
                .filter(|message| {
                    message["role"] == "user"
                        && message["content"].as_str().is_some_and(|text| {
                            serde_json::from_str::<Value>(text)
                                .ok()
                                .is_some_and(|value| value.get("remaining_tool_requests").is_some())
                        })
                })
                .count();
            let truncated = self.truncate_first && self.requests.lock().unwrap().len() == 1;
            let content = if truncated {
                "{\"action\":".into()
            } else if system.contains("ROLE: AUDITOR") && tool_results < self.audit_tool_requests {
                json!({"action":"tool","name":"inspect_target","arguments":{}}).to_string()
            } else {
                json!({"action":"finish","result":result}).to_string()
            };
            let finish_reason = if truncated { "length" } else { "stop" };
            Ok(ModelResponse {
                content: content.clone(),
                finish_reason: finish_reason.into(),
                result: ProbeResult {
                    response: json!({"choices":[{"message":{"content":content},"finish_reason":finish_reason}],"usage":{"prompt_tokens":100,"completion_tokens":20,"total_tokens":120}}),
                    provider_request_id: d::id(),
                    input_tokens: 100,
                    output_tokens: 20,
                    total_tokens: 120,
                    usage_available: true,
                },
            })
            }
            .await;
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            outcome
        })
    }
}
async fn prepared(store: &Store, config: d::AuditConfig) -> d::AuditRun {
    tokio::fs::write(store.root.join("deepseek.token"), "fixture-only-key")
        .await
        .unwrap();
    let fixture=Fixture::with_source(store,"def download(name):\n    return open(name, encoding=\"utf-8\").read()\n\ndef login(password, expected):\n    return password == expected\n").await;
    let request = d::id();
    let run = store
        .create_run_with_options(
            &request,
            &fixture.snapshot.id,
            d::AUDIT_SCOPE,
            config.clone(),
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .create_run_with_options(&request, &fixture.snapshot.id, d::AUDIT_SCOPE, config)
            .await
            .unwrap()
            .id,
        run.id
    );
    let lease = store
        .claim_work(&fixture.executor.id)
        .await
        .unwrap()
        .unwrap();
    let analysis = source::analyze_sources(
        fixture.source.path(),
        &fixture.manifest.files,
        &CancellationToken::new(),
        |_, _, _| {},
    )
    .unwrap();
    let result = put(
        store,
        &serde_json::to_vec(&analysis).unwrap(),
        "analysis.json",
        Some(&lease),
    )
    .await;
    store
        .complete_work(
            &fixture.executor.id,
            &lease.work_item_id,
            &lease.attempt_id,
            &lease.lease_token,
            "COMPLETED",
            &result.id,
            "",
            true,
        )
        .await
        .unwrap();
    let run: d::AuditRun = store.get("audit_runs", &run.id).await.unwrap();
    assert_eq!(run.state, d::RunState::Running);
    run
}

#[tokio::test]
async fn model_settings_stay_fixed_until_audit_cancellation_completes() {
    use aegis_server::model_settings::ModelSettingsInput;
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).await.unwrap();
    let run = prepared(&store, d::AuditConfig::default()).await;
    let before = store.model_connection().await.unwrap();
    assert!(before.settings_locked);
    let update = || ModelSettingsInput {
        provider_kind: "OPENAI_COMPATIBLE",
        endpoint: "http://127.0.0.1:12345/v1",
        model: "fixture-model",
        api_key: "replacement-fixture-key",
        key_action: "REPLACE",
        expected_revision: &before.revision,
    };
    assert!(matches!(
        store.save_model_settings(&d::id(), update()).await,
        Err(AppError::Precondition(_))
    ));
    let unchanged = store.model_connection().await.unwrap();
    assert_eq!(unchanged.revision, before.revision);
    assert_eq!(unchanged.endpoint, before.endpoint);
    let cancelled = store.cancel_run(&run.id).await.unwrap();
    assert_eq!(cancelled.state, d::RunState::Cancelled);
    let saved = store.save_model_settings(&d::id(), update()).await.unwrap();
    assert!(!saved.settings_locked);
    assert_ne!(saved.revision, before.revision);
    assert_eq!(saved.model, "fixture-model");
}

#[tokio::test]
async fn audit_review_revision_and_report_use_real_persisted_code() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).await.unwrap();
    let config = d::AuditConfig::default();
    let run = prepared(&store, config.clone()).await;
    let model = ScriptedModel::new(false);
    store
        .drive_audit_with_model(
            &run.id,
            "fixture-model",
            &config,
            &model,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    store.finish_audit(&run.id, None).await.unwrap();
    let result: d::AuditRun = store.get("audit_runs", &run.id).await.unwrap();
    assert_eq!(result.state, d::RunState::Completed);
    let data = store.audit_evidence(&run.id).await.unwrap();
    assert_eq!(data.findings.len(), 1);
    assert_eq!(data.reviews.len(), 1);
    assert_eq!(data.annotations.len(), 1);
    let phases = store.run_phases(&run.id).await.unwrap();
    assert_eq!(phases.len(), 5);
    assert!(phases.iter().all(|phase| phase.status == "COMPLETED"));
    let planner = data
        .tasks
        .iter()
        .find(|task| task.role == "PLANNER")
        .unwrap();
    let typed = aegis_server::convert::agent_task(planner.clone());
    assert_eq!(
        typed.plan.approach,
        "fixture workflow behavior, not model efficacy"
    );
    let events = store.events(&run.id, 0).await.unwrap();
    assert!(
        events
            .iter()
            .all(|event| !event.phase_id.is_empty() && event.phase_count == 5)
    );
    assert!(
        events
            .iter()
            .any(|event| event.kind == "MODEL_STARTED" && event.phase_id == "AUDIT_REVIEW")
    );
    let reopened_phases = Store::open(directory.path())
        .await
        .unwrap()
        .run_phases(&run.id)
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(&phases).unwrap(),
        serde_json::to_value(&reopened_phases).unwrap()
    );
    let finding = &data.findings[0];
    assert_eq!(finding.review_status, "VALIDATED");
    assert_eq!(finding.verification_status, "NOT_RUN");
    assert_eq!(
        data.model_calls.iter().map(|c| c.total_tokens).sum::<u64>(),
        data.model_calls.len() as u64 * 120
    );
    let review = d::ReviewDraft {
        assessments: vec![],
        verdict: "INCONCLUSIVE".into(),
        rationale: "entry routing still needs confirmation".into(),
        counter_evidence: "unknown caller".into(),
        missing_information: "normal endpoint".into(),
        evidence: vec![],
    };
    let request = d::id();
    let (revised, saved) = store
        .submit_review(&request, &finding.id, finding.revision, review.clone())
        .await
        .unwrap();
    assert_eq!(revised.verification_status, "NOT_RUN");
    assert_eq!(revised.review_status, "INCONCLUSIVE");
    assert_eq!(
        store
            .submit_review(&request, &finding.id, finding.revision, review.clone())
            .await
            .unwrap()
            .1
            .id,
        saved.id
    );
    assert!(matches!(
        store
            .submit_review(&d::id(), &finding.id, finding.revision, review)
            .await,
        Err(AppError::Conflict(_))
    ));
    let annotation = &data.annotations[0];
    store
        .update_annotation(
            &d::id(),
            &annotation.id,
            annotation.revision,
            "AUTHENTICATION",
            "人工核对密码检查",
        )
        .await
        .unwrap();
    assert!(
        store
            .update_annotation(
                &d::id(),
                &annotation.id,
                annotation.revision,
                "AUTHENTICATION",
                "stale"
            )
            .await
            .is_err()
    );
    for format in ["json", "html", "markdown"] {
        let report = store
            .create_report(&d::id(), &run.id, format)
            .await
            .unwrap();
        let bytes = store
            .artifact_bytes(&report.artifact_id, 16 * 1024 * 1024)
            .await
            .unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("Unrestricted document path"));
        assert!(text.contains("人工核对密码检查"));
        assert!(!text.contains("fixture-only-key"));
        if format == "json" {
            let doc: Value = serde_json::from_str(&text).unwrap();
            assert_eq!(doc["checks"]["vulnerability_audit"], "COMPLETED");
            assert_eq!(doc["checks"]["exploitation"], "NOT_RUN");
            assert_eq!(doc["audit"]["reviews"].as_array().unwrap().len(), 2);
        }
    }
    let artifacts = store.run_artifacts(&run.id).await.unwrap();
    assert!(
        artifacts
            .iter()
            .any(|a| a.id == data.model_calls[0].request_artifact_id)
    );
    let reopened = Store::open(directory.path()).await.unwrap();
    assert_eq!(
        reopened.audit_evidence(&run.id).await.unwrap().findings[0].review_status,
        "INCONCLUSIVE"
    );
}

#[tokio::test]
async fn manual_annotations_are_validated_versioned_and_reused_only_for_identical_snapshot_code() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).await.unwrap();
    let config = d::AuditConfig::default();
    let run = prepared(&store, config.clone()).await;
    let (units, _) = store.list_units(&run.id, "", "", 0, 200).await.unwrap();
    let login = units.iter().find(|u| u.unit.name == "login").unwrap();
    let mut draft = d::AnnotationDraft {
        unit_id: login.id.clone(),
        tag: "AUTHENTICATION".into(),
        subtype: "PASSWORD".into(),
        rationale: "人工核对密码逻辑；仍须独立验证".into(),
        evidence: vec![d::EvidenceInput {
            unit_id: login.id.clone(),
            start_line: 5,
            end_line: 5,
            quote: "fabricated()".into(),
        }],
    };
    assert!(matches!(
        store
            .create_annotation(&d::id(), &run.id, draft.clone())
            .await,
        Err(AppError::Invalid(_))
    ));
    assert!(store.annotations(&run.id).await.unwrap().is_empty());
    draft.evidence[0].quote.clear();
    let request = d::id();
    let annotation = store
        .create_annotation(&request, &run.id, draft.clone())
        .await
        .unwrap();
    assert_eq!(annotation.actor, "HUMAN");
    assert_eq!(
        annotation.evidence[0].quote,
        "    return password == expected"
    );
    assert_eq!(
        store
            .create_annotation(&request, &run.id, draft.clone())
            .await
            .unwrap()
            .id,
        annotation.id
    );
    assert!(matches!(
        store
            .create_annotation(&d::id(), &run.id, draft.clone())
            .await,
        Err(AppError::Conflict(_))
    ));
    let edited = store
        .update_annotation(
            &d::id(),
            &annotation.id,
            1,
            "CRYPTOGRAPHY",
            "人工标注修订：密码比较需要进一步核对",
        )
        .await
        .unwrap();
    assert_eq!(edited.revision, 2);
    assert!(edited.draft.subtype.is_empty());
    assert!(matches!(
        store
            .update_annotation(&d::id(), &annotation.id, 1, "AUTHENTICATION", "stale")
            .await,
        Err(AppError::Conflict(_))
    ));
    let history: i64 =
        sqlx::query_scalar("SELECT count(*) FROM annotation_revisions WHERE annotation_id=?")
            .bind(&annotation.id)
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(history, 2);
    store.finish_audit(&run.id, None).await.unwrap();
    let next = store
        .create_run_with_options(&d::id(), &run.snapshot_id, d::AUDIT_SCOPE, config.clone())
        .await
        .unwrap();
    let executor = store.executors().await.unwrap().remove(0);
    let lease = store.claim_work(&executor.id).await.unwrap().unwrap();
    assert_eq!(lease.run_id, next.id);
    let result_id = run.summary["result_artifact_id"].as_str().unwrap();
    let original = store
        .artifact_bytes(result_id, 16 * 1024 * 1024)
        .await
        .unwrap();
    let artifact = put(&store, &original, "analysis.json", Some(&lease)).await;
    store
        .complete_work(
            &executor.id,
            &lease.work_item_id,
            &lease.attempt_id,
            &lease.lease_token,
            "COMPLETED",
            &artifact.id,
            "",
            true,
        )
        .await
        .unwrap();
    let model = ScriptedModel::new(false);
    store
        .drive_audit_with_model(
            &next.id,
            "fixture-model",
            &config,
            &model,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    store.finish_audit(&next.id, None).await.unwrap();
    {
        let requests = model.requests.lock().unwrap();
        let planner: Value =
            serde_json::from_str(requests[0].messages[1]["content"].as_str().unwrap()).unwrap();
        assert_eq!(
            planner["human_annotations"]["items"][0]["annotation_id"],
            annotation.id
        );
        assert_eq!(planner["human_annotations"]["items"][0]["revision"], 2);
        assert_eq!(
            planner["human_annotations"]["items"][0]["source_run_id"],
            run.id
        );
        assert!(
            planner["human_annotations"]["items"][0]["unit_id"]
                .as_str()
                .unwrap()
                .starts_with('U')
        );
        let login_request = requests
            .iter()
            .find(|request| {
                request.messages[0]["content"]
                    .as_str()
                    .unwrap()
                    .contains("ROLE: AUDITOR")
                    && serde_json::from_str::<Value>(
                        request.messages[1]["content"].as_str().unwrap(),
                    )
                    .unwrap()["focus"]["name"]
                        == "login"
            })
            .unwrap();
        let input: Value =
            serde_json::from_str(login_request.messages[1]["content"].as_str().unwrap()).unwrap();
        assert_eq!(
            input["human_annotations"]["items"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert!(
            input["human_annotations"]["items"][0]["evidence"][0]["quote"]
                .as_str()
                .unwrap()
                .contains("password == expected")
        );
    }
    let other = prepared(&store, config.clone()).await;
    assert_ne!(other.snapshot_id, run.snapshot_id);
    assert!(
        store
            .create_annotation(&d::id(), &other.id, draft)
            .await
            .is_err()
    );
    let other_model = ScriptedModel::new(false);
    store
        .drive_audit_with_model(
            &other.id,
            "fixture-model",
            &config,
            &other_model,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    let request = &other_model.requests.lock().unwrap()[0];
    let input: Value =
        serde_json::from_str(request.messages[1]["content"].as_str().unwrap()).unwrap();
    assert!(
        input["human_annotations"]["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
#[ignore = "requires local Edge or Chrome; exports an isolated fixture and never calls a real model"]
async fn pdf_export_does_not_block_cancellation_and_preserves_a_factual_snapshot() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).await.unwrap();
    let config = d::AuditConfig::default();
    let run = prepared(&store, config.clone()).await;
    store
        .drive_audit_with_model(
            &run.id,
            "fixture-model",
            &config,
            &ScriptedModel::new(false),
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    let copy = store.clone();
    let run_id = run.id.clone();
    let export = tokio::spawn(async move { copy.create_report(&d::id(), &run_id, "pdf").await });
    tokio::time::sleep(Duration::from_millis(250)).await;
    let cancelled = tokio::time::timeout(Duration::from_secs(1), store.cancel_run(&run.id))
        .await
        .expect("PDF formatting must not hold the write lock")
        .unwrap();
    assert_eq!(cancelled.state, d::RunState::Cancelled);
    let report = export.await.unwrap().unwrap();
    assert!(report.interim);
    assert_eq!(report.snapshot_state, "RUNNING");
    let artifact: d::Artifact = store.get("artifacts", &report.artifact_id).await.unwrap();
    assert_eq!(artifact.media_type, "application/pdf");
    let bytes = store
        .artifact_bytes(&report.artifact_id, 64 * 1024 * 1024)
        .await
        .unwrap();
    assert!(bytes.starts_with(b"%PDF-"));
    if let Some(path) = std::env::var_os("AEGIS_PDF_EVIDENCE") {
        tokio::fs::write(path, bytes).await.unwrap();
    }
}

#[tokio::test]
async fn hallucinated_quotes_never_become_findings_and_calls_keep_usage() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).await.unwrap();
    let config = d::AuditConfig::default();
    let run = prepared(&store, config.clone()).await;
    let model = ScriptedModel::new(true);
    let result = store
        .drive_audit_with_model(
            &run.id,
            "fixture-model",
            &config,
            &model,
            &CancellationToken::new(),
        )
        .await;
    assert!(result.is_ok());
    store
        .finish_audit(&run.id, result.err().map(|e| e.to_string()))
        .await
        .unwrap();
    let data = store.audit_evidence(&run.id).await.unwrap();
    assert!(data.findings.is_empty());
    assert_eq!(
        data.model_calls
            .iter()
            .filter(|c| c.status == "INVALID_RESPONSE")
            .count(),
        3
    );
    assert!(data.model_calls.iter().all(|c| c.usage_available));
    assert!(
        model
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| request.reasoning_effort == config.reasoning_effort)
    );
    let result: d::AuditRun = store.get("audit_runs", &run.id).await.unwrap();
    assert_eq!(result.state, d::RunState::Partial);
    assert_eq!(
        data.annotations.len(),
        1,
        "later units must still be audited"
    );
    assert!(
        data.tasks
            .iter()
            .any(|task| task.role == "REPORTER" && task.status == "SUCCEEDED")
    );
    let requests = model.requests.lock().unwrap();
    let report = requests
        .iter()
        .find(|request| {
            request.messages[0]["content"]
                .as_str()
                .unwrap()
                .contains("ROLE: REPORTER")
        })
        .unwrap();
    let input: Value =
        serde_json::from_str(report.messages[1]["content"].as_str().unwrap()).unwrap();
    assert_eq!(input["audited_units"], result.summary["audited_unit_count"]);
    assert!(input["audited_units"].as_u64().unwrap() < input["total_units"].as_u64().unwrap());
    assert_eq!(input["failed_tasks"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn invalid_reviews_do_not_abort_later_units_or_become_validated() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).await.unwrap();
    let config = d::AuditConfig::default();
    let run = prepared(&store, config.clone()).await;
    let mut model = ScriptedModel::new(false);
    model.invalid_review = true;
    store
        .drive_audit_with_model(
            &run.id,
            "fixture-model",
            &config,
            &model,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    store.finish_audit(&run.id, None).await.unwrap();
    let result: d::AuditRun = store.get("audit_runs", &run.id).await.unwrap();
    let data = store.audit_evidence(&run.id).await.unwrap();
    assert_eq!(result.state, d::RunState::Partial);
    assert_eq!(
        result.summary["audited_unit_count"],
        result.summary["eligible_unit_count"]
    );
    assert_eq!(result.summary["independent_review"], "PARTIAL");
    assert_eq!(data.findings.len(), 1);
    assert_eq!(data.findings[0].review_status, "UNREVIEWED");
    assert_eq!(data.findings[0].verification_status, "NOT_RUN");
    assert!(data.reviews.is_empty());
    assert_eq!(data.annotations.len(), 1);
    assert_eq!(
        data.model_calls
            .iter()
            .filter(|call| call.role == "REVIEWER")
            .count(),
        3,
        "failed reviews must not be retried for each later unit"
    );
    assert!(!data.tasks.iter().any(|task| task.role == "VERIFIER"));
    assert!(
        data.tasks
            .iter()
            .any(|task| task.role == "REPORTER" && task.status == "SUCCEEDED")
    );
    assert_eq!(result.summary["incomplete_agent_tasks"], 1);
}

#[tokio::test]
async fn invalid_verifier_output_remains_partial_but_provider_errors_stop_work() {
    for failing_role in [None, Some("REVIEWER"), Some("VERIFIER")] {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).await.unwrap();
        let config = d::AuditConfig::default();
        let run = prepared(&store, config.clone()).await;
        let mut model = ScriptedModel::new(false);
        model.invalid_verifier = true;
        model.failing_role = failing_role;
        let outcome = store
            .drive_audit_with_model(
                &run.id,
                "fixture-model",
                &config,
                &model,
                &CancellationToken::new(),
            )
            .await;
        assert_eq!(outcome.is_err(), failing_role.is_some());
        store
            .finish_audit(&run.id, outcome.err().map(|error| error.to_string()))
            .await
            .unwrap();
        let result: d::AuditRun = store.get("audit_runs", &run.id).await.unwrap();
        let data = store.audit_evidence(&run.id).await.unwrap();
        assert_eq!(result.state, d::RunState::Partial);
        assert_eq!(
            data.tasks.iter().any(|task| task.role == "REPORTER"),
            failing_role.is_none()
        );
        assert_eq!(
            data.model_calls
                .iter()
                .filter(|call| call.status == "INVALID_RESPONSE")
                .count(),
            if failing_role.is_none() { 3 } else { 0 }
        );
    }
}

#[tokio::test]
async fn extended_budget_and_truncation_repairs_keep_the_configured_reasoning() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).await.unwrap();
    let config = d::AuditConfig {
        max_model_calls: 1200,
        max_tool_rounds: 24,
        timeout_seconds: 21_600,
        max_output_tokens: 131_072,
        reasoning_effort: "max".into(),
        model_timeout_seconds: 1800,
        ..Default::default()
    };
    let run = prepared(&store, config.clone()).await;
    let mut model = ScriptedModel::new(false);
    model.truncate_first = true;
    model.audit_tool_requests = 13;
    store
        .drive_audit_with_model(
            &run.id,
            "fixture-model",
            &config,
            &model,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    store.finish_audit(&run.id, None).await.unwrap();
    let result: d::AuditRun = store.get("audit_runs", &run.id).await.unwrap();
    assert_eq!(result.state, d::RunState::Completed);
    assert_eq!(
        result.summary["audit_config"],
        serde_json::to_value(&config).unwrap()
    );
    let evidence = store.audit_evidence(&run.id).await.unwrap();
    let truncated = evidence
        .model_calls
        .iter()
        .find(|call| call.finish_reason == "length")
        .unwrap();
    assert_eq!(truncated.status, "INVALID_RESPONSE");
    assert!(truncated.error.contains("131072"));
    let requests = model.requests.lock().unwrap();
    assert!(requests.len() > 26);
    assert!(requests.iter().all(|request| request.max_tokens == 131_072
        && request.reasoning_effort == "max"
        && request.timeout_seconds == 1800));
}

#[tokio::test]
async fn independent_audit_units_overlap_without_losing_coverage() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).await.unwrap();
    let config = d::AuditConfig {
        max_model_calls: 60,
        max_units: 8,
        max_tool_rounds: 1,
        ..Default::default()
    };
    let run = prepared(&store, config.clone()).await;
    let mut model = ScriptedModel::new(false);
    model.delay_ms = 25;
    let peak = model.peak_in_flight.clone();
    store
        .drive_audit_with_model(
            &run.id,
            "fixture-model",
            &config,
            &model,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    store.finish_audit(&run.id, None).await.unwrap();
    assert!(
        peak.load(Ordering::SeqCst) >= 2,
        "independent audit units never overlapped; the loop is still serial"
    );
    let evidence = store.audit_evidence(&run.id).await.unwrap();
    let record: d::AuditRun = store.get("audit_runs", &run.id).await.unwrap();
    let eligible = record.summary["eligible_unit_count"].as_u64().unwrap();
    assert!(eligible >= 2, "the fixture must expose independent units");
    assert_eq!(
        record.summary["audited_unit_count"].as_u64().unwrap(),
        eligible,
        "parallel auditing must still cover every eligible unit"
    );
    let reviewed = evidence
        .findings
        .iter()
        .filter(|finding| {
            evidence
                .reviews
                .iter()
                .any(|review| review.finding_id == finding.id && review.actor == "MODEL")
        })
        .count();
    assert_eq!(reviewed, evidence.findings.len());
}

#[tokio::test]
async fn audit_budget_is_persisted_and_does_not_claim_full_coverage() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).await.unwrap();
    let config = d::AuditConfig {
        max_model_calls: 4,
        ..Default::default()
    };
    let run = prepared(&store, config.clone()).await;
    let result = store
        .drive_audit_with_model(
            &run.id,
            "fixture-model",
            &config,
            &ScriptedModel::new(false),
            &CancellationToken::new(),
        )
        .await;
    assert!(result.is_err());
    store
        .finish_audit(&run.id, result.err().map(|e| e.to_string()))
        .await
        .unwrap();
    assert_eq!(
        store
            .audit_evidence(&run.id)
            .await
            .unwrap()
            .model_calls
            .len(),
        4
    );
    let result: d::AuditRun = store.get("audit_runs", &run.id).await.unwrap();
    assert_eq!(result.state, d::RunState::Partial);
    assert_eq!(result.summary["vulnerability_audit"], "PARTIAL");
}

#[tokio::test]
async fn audit_budget_rpc_preserves_custom_values_and_rejects_invalid_limits() {
    let directory = tempfile::tempdir().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let state = web::create_state(directory.path(), address, None, shutdown.clone())
        .await
        .unwrap();
    let store = state.store.clone();
    tokio::fs::write(store.root.join("deepseek.token"), "fixture-only-key")
        .await
        .unwrap();
    let fixture = Fixture::new(&store).await;
    let app = web::router(state, Path::new("missing-static-dir").to_owned());
    let signal = shutdown.clone();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(signal.cancelled_owned())
        .await
        .unwrap();
    });
    let base = format!("http://{address}");
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let session = client
        .get(format!("{base}/api/session"))
        .send()
        .await
        .unwrap();
    let cookie = session.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let csrf = session.json::<Value>().await.unwrap()["csrf_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let request = json!({"requestId":d::id(),"snapshotId":fixture.snapshot.id,"scope":d::AUDIT_SCOPE,
        "maxModelCalls":1000,"maxUnits":25,"maxToolRounds":48,"timeoutSeconds":21600,
        "maxOutputTokens":131072,"reasoningEffort":"max","modelTimeoutSeconds":1800});
    let send = |body: Value| {
        client
            .post(format!("{base}/rpc/audit.v1.RunService/CreateRun"))
            .header("cookie", &cookie)
            .header("x-aegis-csrf", &csrf)
            .header("connect-protocol-version", "1")
            .json(&body)
            .send()
    };
    let response = send(request.clone()).await.unwrap();
    assert_eq!(response.status(), 200);
    let response: Value = response.json().await.unwrap();
    let id = response["run"]["id"].as_str().unwrap();
    let run: d::AuditRun = store.get("audit_runs", id).await.unwrap();
    let config: String = sqlx::query_scalar("SELECT config FROM audit_workflows WHERE run_id=?")
        .bind(id)
        .fetch_one(&store.pool)
        .await
        .unwrap();
    let expected = json!({"max_model_calls":1000,"max_units":25,"max_tool_rounds":48,
        "timeout_seconds":21600,"max_output_tokens":131072,"reasoning_effort":"max","model_timeout_seconds":1800});
    assert_eq!(serde_json::from_str::<Value>(&config).unwrap(), expected);
    assert_eq!(run.summary["audit_config"], expected);
    assert_eq!(
        send(request.clone())
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap()["run"]["id"],
        id
    );
    for (field, value) in [
        ("maxOutputTokens", json!(u32::MAX)),
        ("reasoningEffort", json!("unlimited")),
        ("modelTimeoutSeconds", json!(3601)),
        ("maxToolRounds", json!(101)),
    ] {
        let mut invalid = request.clone();
        invalid["requestId"] = json!(d::id());
        invalid[field] = value;
        assert_eq!(send(invalid).await.unwrap().status(), 400, "{field}");
    }
    let default_request =
        json!({"requestId":d::id(),"snapshotId":fixture.snapshot.id,"scope":d::AUDIT_SCOPE});
    let response = send(default_request)
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let run: d::AuditRun = store
        .get("audit_runs", response["run"]["id"].as_str().unwrap())
        .await
        .unwrap();
    assert_eq!(
        run.summary["audit_config"],
        serde_json::to_value(d::AuditConfig::default()).unwrap()
    );
    shutdown.cancel();
    server.await.unwrap();
}

struct BlockingModel(Arc<tokio::sync::Notify>);
impl ModelClient for BlockingModel {
    fn complete<'a>(
        &'a self,
        _: &'a ModelRequest,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<ModelResponse>> + Send + 'a>> {
        Box::pin(async move {
            self.0.notify_one();
            std::future::pending().await
        })
    }
}
#[tokio::test]
async fn cancellation_interrupts_model_work_and_restart_keeps_unknown_usage() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).await.unwrap();
    let config = d::AuditConfig::default();
    let run = prepared(&store, config.clone()).await;
    let entered = Arc::new(tokio::sync::Notify::new());
    let clone = store.clone();
    let id = run.id.clone();
    let signal = entered.clone();
    let task = tokio::spawn(async move {
        clone
            .drive_audit_with_model(
                &id,
                "fixture-model",
                &config,
                &BlockingModel(signal),
                &CancellationToken::new(),
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), entered.notified())
        .await
        .unwrap();
    assert_eq!(
        store.cancel_run(&run.id).await.unwrap().state,
        d::RunState::Cancelling
    );
    let result = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_err());
    store
        .finish_audit(&run.id, result.err().map(|e| e.to_string()))
        .await
        .unwrap();
    let result: d::AuditRun = store.get("audit_runs", &run.id).await.unwrap();
    assert_eq!(result.state, d::RunState::Cancelled);
    let data = store.audit_evidence(&run.id).await.unwrap();
    assert!(data.findings.is_empty());
    assert!(!data.model_calls[0].usage_available);
    store.recover_audits().await.unwrap();
    assert_eq!(
        store
            .get::<d::AuditRun>("audit_runs", &run.id)
            .await
            .unwrap()
            .state,
        d::RunState::Cancelled
    );
}
