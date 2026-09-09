use super::*;
use aegis_application::import::{self, ImportLimits};
use aegis_domain as d;
use aegis_server::{store::Store, web};
use serde_json::{Value, json};
use std::net::SocketAddr;

#[tokio::test]
#[ignore = "requires native Git; checks Windows executable lookup without running target code"]
async fn native_git_lookup_does_not_select_an_executable_from_the_target_directory() {
    use aegis_application::process::{self, ProcessSpec};
    use std::collections::BTreeMap;

    let source = tempfile::Builder::new()
        .prefix("aegis git shadow ")
        .tempdir()
        .unwrap();
    std::fs::copy(
        std::env::var_os("COMSPEC").unwrap(),
        source.path().join("git.exe"),
    )
    .unwrap();
    let output = process::run(
        ProcessSpec {
            program: "git".into(),
            args: vec!["--version".into()],
            directory: source.path().into(),
            env: BTreeMap::new(),
            timeout: Duration::from_secs(10),
        },
        CancellationToken::new(),
        |_| {},
    )
    .await
    .unwrap();
    assert_eq!(output.exit_code, Some(0));
    assert!(output.processes_reaped && !output.timed_out && !output.cancelled);
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("git version"));
}

#[test]
fn desktop_recovery_never_assumes_dynamic_or_unowned_work_was_reaped() {
    let mut active = Active {
        lease: p::WorkLease {
            kind: "RUNTIME".into(),
            ..Default::default()
        },
        completion: None,
        process_job: Some(aegis_application::windows_job::DesktopJob {
            name: "Global\\AegisAudit-fixture".into(),
            machine_identity: "fixture-host".into(),
        }),
    };
    assert!(recoverable_owner(&active).is_err());
    for kind in ["IMPORT", "ANALYZE"] {
        active.lease.kind = kind.into();
        assert!(recoverable_owner(&active).is_ok());
    }
    active.process_job = None;
    assert!(recoverable_owner(&active).is_err());
}

async fn execute_claim(control: &Control, tools: &Tools, work: &Path) -> String {
    let lease = control
        .rpc
        .claim_work(p::ClaimWorkRequest {
            executor_id: control.executor_id.clone(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_owned()
        .lease
        .unwrap();
    tokio::fs::create_dir_all(work).await.unwrap();
    let reaped = Arc::new(AtomicBool::new(true));
    let (progress, _messages) = mpsc::channel(256);
    let result = jobs::execute(
        JobContext {
            control: control.clone(),
            lease: lease.clone(),
            tools: tools.clone(),
            cancel: CancellationToken::new(),
            progress,
            reaped: reaped.clone(),
        },
        work,
    )
    .await
    .unwrap();
    assert!(reaped.load(Ordering::SeqCst));
    assert!(
        control
            .complete(p::CompleteWorkRequest {
                work_item_id: lease.work_item_id.clone(),
                attempt_id: lease.attempt_id.clone(),
                lease_token: lease.lease_token.clone(),
                outcome: "COMPLETED".into(),
                result_artifact_id: result.clone(),
                processes_reaped: true,
                ..Default::default()
            })
            .await
            .unwrap()
    );
    result
}

#[tokio::test]
#[ignore = "requires the pinned native Windows tools; no model API is called"]
async fn native_sast_preparation_persists_real_artifacts() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let options = Options::parse_from([
        "aegis-executor".as_ref(),
        "--semgrep-rules".as_ref(),
        root.join("tools/runtime/rules.yml").as_os_str(),
        "--script-dir".as_ref(),
        root.join("tools/ghidra").as_os_str(),
    ]);
    let (tools, caps) = capabilities(&options).await;
    assert!(
        caps.iter()
            .any(|cap| cap.name == "semgrep" && cap.available)
    );
    let temporary = tempfile::Builder::new()
        .prefix("aegis pipeline \u{5ba1}\u{8ba1} ")
        .tempdir()
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let state = web::create_state(
        &temporary.path().join("server"),
        address,
        None,
        shutdown.clone(),
    )
    .await
    .unwrap();
    let store = state.store.clone();
    let app = web::router(state, root.join("frontend/dist"));
    let signal = shutdown.clone();
    // Only the real HTTP/store layer is started. The model scheduler is never run.
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
    let bootstrap = tokio::fs::read_to_string(store.root.join("executor-bootstrap.token"))
        .await
        .unwrap();
    let control = Control::new(&base, bootstrap.trim(), String::new()).unwrap();
    let registered = control
        .rpc
        .register_executor(p::RegisterExecutorRequest {
            name: "native-sast-regression".into(),
            platform: "windows".into(),
            architecture: "x86_64".into(),
            capabilities: caps,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_owned();
    let control = Control::new(
        &base,
        &registered.executor_token,
        registered.executor.id.clone(),
    )
    .unwrap();
    let source = temporary.path().join("input/tests/\u{5ba1}\u{8ba1} input");
    tokio::fs::create_dir_all(&source).await.unwrap();
    for file in ["accounts.py", "commands.py", "documents.py", "messages.c"] {
        tokio::fs::copy(
            root.join("tests/fixtures/audit/source").join(file),
            source.join(file),
        )
        .await
        .unwrap();
    }
    let zip = temporary.path().join("input.zip");
    import::pack_directory(
        &temporary.path().join("input"),
        &zip,
        ImportLimits::default(),
    )
    .unwrap();
    let artifact = store
        .stage_bytes(
            &tokio::fs::read(zip).await.unwrap(),
            "input.zip",
            "application/zip",
        )
        .await
        .unwrap();
    {
        let _guard = store.writes.lock().await;
        let mut tx = store.pool.begin().await.unwrap();
        Store::insert_artifact(&mut tx, &artifact, None, None, None)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    let project = store
        .create_project(&d::id(), "Windows native SAST regression")
        .await
        .unwrap();
    let snapshot = store
        .create_snapshot(
            &d::id(),
            &project.id,
            "SOURCE",
            &artifact.id,
            "",
            "",
            "input.zip",
        )
        .await
        .unwrap();
    execute_claim(&control, &tools, &temporary.path().join("import job")).await;
    let snapshot: d::Snapshot = store.get("snapshots", &snapshot.id).await.unwrap();
    assert_eq!(snapshot.state, "READY");
    tokio::fs::write(
        store.root.join("deepseek.token"),
        "fixture-only-not-a-real-api-key",
    )
    .await
    .unwrap();
    let run = store
        .create_run_with_options(
            &d::id(),
            &snapshot.id,
            d::AUDIT_SCOPE,
            d::AuditConfig::default(),
        )
        .await
        .unwrap();
    let result_id = execute_claim(
        &control,
        &tools,
        &temporary.path().join("deeply nested analysis job/work"),
    )
    .await;
    let run: d::AuditRun = store.get("audit_runs", &run.id).await.unwrap();
    let summary = &run.summary["metadata"]["semgrep"];
    assert_eq!(summary["status"], "COMPLETED", "{summary}");
    assert_eq!(summary["scanned_file_count"], 4);
    assert_eq!(summary["results"].as_array().unwrap().len(), 2);
    assert_eq!(summary["target_execution"], false);
    let raw_id = summary["artifact_id"].as_str().unwrap();
    let raw_bytes = store
        .artifact_bytes(raw_id, 16 * 1024 * 1024)
        .await
        .unwrap();
    let raw: Value = serde_json::from_slice(&raw_bytes).unwrap();
    assert_eq!(raw["results"], summary["results"]);
    let result = store
        .artifact_bytes(&result_id, 64 * 1024 * 1024)
        .await
        .unwrap();
    let result: d::AnalysisResult = serde_json::from_slice(&result).unwrap();
    assert!(!result.units.is_empty());
    let tool = result
        .tools
        .iter()
        .find(|tool| tool.name == "semgrep")
        .unwrap();
    assert_eq!(tool.details["processes_reaped"], true);
    assert_eq!(tool.details["process_supervision"], "WINDOWS_JOB_OBJECT");
    assert_eq!(tool.exit_code, Some(0));
    assert!(!tool.log_artifact_id.is_empty());
    assert!(
        tool.command
            .iter()
            .any(|arg| arg == "semgrep.console_scripts.entrypoint")
    );
    assert_eq!(run.summary["verification"], "NOT_RUN");
    assert_eq!(run.summary["vulnerability_audit"], "QUEUED");
    assert!(
        store
            .audit_evidence(&run.id)
            .await
            .unwrap()
            .model_calls
            .is_empty()
    );
    assert_eq!(
        store.cancel_run(&run.id).await.unwrap().state,
        d::RunState::Cancelled
    );
    if let Some(output) = std::env::var_os("AEGIS_NATIVE_SAST_EVIDENCE") {
        let output = Path::new(&output);
        std::fs::create_dir_all(output).unwrap();
        std::fs::write(output.join("pipeline-semgrep.json"), &raw_bytes).unwrap();
        std::fs::write(
            output.join("pipeline-semgrep.log"),
            store
                .artifact_bytes(&tool.log_artifact_id, 16 * 1024 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        std::fs::write(output.join("pipeline.json"), serde_json::to_vec_pretty(&json!({
            "observed_at": d::now(), "platform": "windows/x86_64",
            "purpose": "real import, leased executor preparation and persisted native scanner artifacts",
            "target_sha256": snapshot.target_sha256, "run_id": run.id,
            "semgrep": summary, "tool": tool, "unit_count": result.units.len(),
            "raw_semgrep_sha256": d::sha256(&raw_bytes),
            "model_api_called": false, "vulnerability_acceptance": "NOT_RUN",
            "model_workflow_cancelled_after_static_preparation": true
        })).unwrap()).unwrap();
    }
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
    store.pool.close().await;
}
