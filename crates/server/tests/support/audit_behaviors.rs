use super::*;
use aegis_application::model::{ModelClient, ModelRequest, ModelResponse, ProbeResult};
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};

struct ScriptedModel {
    invalid_quote: bool,
    requests: Mutex<Vec<ModelRequest>>,
}
impl ScriptedModel {
    fn new(invalid_quote: bool) -> Self {
        Self {
            invalid_quote,
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
            self.requests.lock().unwrap().push(request.clone());
            let system = request.messages[0]["content"].as_str().unwrap();
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
                json!({"verdict":"VALIDATED","rationale":"original code has an unconstrained path argument","counter_evidence":"no guard in supplied code","missing_information":"external routing is not dynamically tested","evidence":input["candidate"]["evidence"],"assessments":(["INPUT_CONTROL","REACHABILITY","DEFENSE_GAP"].map(|check|json!({"check":check,"status":"SUPPORTED","rationale":"the fixture function receives and opens the supplied name without a guard","evidence":input["candidate"]["evidence"]})))})
            } else if system.contains("ROLE: VERIFIER") {
                json!({"status":"NEEDS_CONFIGURATION","rationale":"fixture test does not provide deployment input","limitations":["runtime not executed"],"config":null})
            } else {
                json!({"summary":"static fixture analysis only","recommendations":[],"limitations":["runtime not executed"]})
            };
            let content = json!({"action":"finish","result":result}).to_string();
            Ok(ModelResponse {
                content: content.clone(),
                finish_reason: "stop".into(),
                result: ProbeResult {
                    response: json!({"choices":[{"message":{"content":content},"finish_reason":"stop"}],"usage":{"prompt_tokens":100,"completion_tokens":20,"total_tokens":120}}),
                    provider_request_id: d::id(),
                    input_tokens: 100,
                    output_tokens: 20,
                    total_tokens: 120,
                    usage_available: true,
                },
            })
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
async fn hallucinated_quotes_never_become_findings_and_calls_keep_usage() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).await.unwrap();
    let config = d::AuditConfig::default();
    let run = prepared(&store, config.clone()).await;
    let result = store
        .drive_audit_with_model(
            &run.id,
            "fixture-model",
            &config,
            &ScriptedModel::new(true),
            &CancellationToken::new(),
        )
        .await;
    assert!(result.is_err());
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
    let result: d::AuditRun = store.get("audit_runs", &run.id).await.unwrap();
    assert_eq!(result.state, d::RunState::Partial);
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
