//! Real tools and HTTP handoffs; a scripted provider tests orchestration, not model efficacy.
use super::*;
use aegis_application::model::{ModelClient, ModelRequest, ModelResponse, ProbeResult};
use aegis_domain as d;
use aegis_server::{store::Store, web};
use serde_json::{Value, json};
use std::{future::Future, net::SocketAddr, pin::Pin};

struct RecoveryModel {
    ida: bool,
}
impl ModelClient for RecoveryModel {
    fn complete<'a>(
        &'a self,
        request: &'a ModelRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ModelResponse>> + Send + 'a>> {
        Box::pin(async move {
            let system = request.messages[0]["content"].as_str().unwrap();
            let action = if system.contains("reverse-engineering agent") {
                let outputs: Vec<Value> = request
                    .messages
                    .iter()
                    .skip(2)
                    .filter_map(|message| {
                        (message["role"] == "user")
                            .then(|| {
                                serde_json::from_str(message["content"].as_str().unwrap()).ok()
                            })
                            .flatten()
                    })
                    .collect();
                if outputs.is_empty() {
                    let mut steps = vec![
                        json!({"tool":"upx","input":"original","reason":"UPX sections in the imported fixture"}),
                        json!({"tool":"floss","input":"unpacked","reason":"recover encoded strings from the unpacked image"}),
                        json!({"tool":"ghidra","input":"unpacked","reason":"decompile the same image with string evidence"}),
                    ];
                    if self.ida {
                        steps.push(json!({"tool":"ida_d810","input":"unpacked","profile":"instructions","reason":"simplify the fixture MBA expression using local Hex-Rays microcode"}));
                    }
                    json!({"action":"tool","name":"plan_recovery","arguments":{"assessment":"fixture UPX and encoded-string/MBA mechanisms","evidence":["import metadata records UPX sections"],"steps":steps,"limitations":["scripted provider verifies engineering, not autonomous model accuracy"]}})
                } else if outputs
                    .iter()
                    .filter(|v| v["tool"] == "run_recovery_step")
                    .count()
                    < if self.ida { 4 } else { 3 }
                {
                    json!({"action":"tool","name":"run_recovery_step","arguments":{}})
                } else {
                    json!({"action":"finish","result":{"summary":"tool outputs and readable code are persisted","limitations":["benign development fixture"]}})
                }
            } else if system.contains("ROLE: PLANNER") {
                json!({"action":"finish","result":{"approach":"audit the recovered program","priorities":[],"limitations":[]}})
            } else if system.contains("ROLE: AUDITOR") {
                let input: Value =
                    serde_json::from_str(request.messages[1]["content"].as_str().unwrap())?;
                json!({"action":"finish","result":{"audited_unit_ids":[input["focus"]["unit_id"]],"findings":[],"annotations":[],"limitations":[]}})
            } else {
                json!({"action":"finish","result":{"summary":"fixture workflow report","recommendations":[],"limitations":["not a model efficacy evaluation"]}})
            };
            Ok(ModelResponse {
                content: action.to_string(),
                finish_reason: "stop".into(),
                result: ProbeResult {
                    response: json!({"scripted_provider":true}),
                    provider_request_id: d::id(),
                    input_tokens: 1,
                    output_tokens: 1,
                    total_tokens: 2,
                    usage_available: true,
                },
            })
        })
    }
}

async fn run_job(
    control: &Control,
    tools: &Tools,
    lease: p::WorkLease,
    directory: &Path,
) -> Result<()> {
    tokio::fs::create_dir_all(directory).await?;
    let reaped = Arc::new(AtomicBool::new(true));
    let cancel = CancellationToken::new();
    let (progress, mut messages) = mpsc::channel(256);
    let job = jobs::execute(
        JobContext {
            control: control.clone(),
            lease: lease.clone(),
            tools: tools.clone(),
            cancel: cancel.clone(),
            progress,
            reaped: reaped.clone(),
        },
        directory,
    );
    tokio::pin!(job);
    let mut interval = tokio::time::interval(Duration::from_secs(2));
    let result = loop {
        tokio::select! {
            result=&mut job=>break result,
            _=messages.recv()=>{},
            _=interval.tick()=>{
                let heartbeat=control.rpc.heartbeat(p::HeartbeatRequest {executor_id:control.executor_id.clone(),work_item_id:lease.work_item_id.clone(),attempt_id:lease.attempt_id.clone(),lease_token:lease.lease_token.clone(),..Default::default()}).await?.into_owned();
                if heartbeat.cancel_requested || !heartbeat.lease_valid {cancel.cancel();}
            }
        }
    };
    let (outcome, id, error) = match result {
        Ok(id) => ("COMPLETED", id, String::new()),
        Err(e) => ("FAILED", String::new(), e.to_string()),
    };
    if !id.is_empty() {
        let evidence = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join(".data/verification/agent-recovery");
        tokio::fs::create_dir_all(&evidence).await?;
        control
            .download(
                &lease,
                &id,
                &evidence.join(format!("work-{}.json", lease.work_item_id)),
                &CancellationToken::new(),
            )
            .await?;
    }
    let context = format!(
        "work {} kind {} payload {}",
        lease.work_item_id, lease.kind, lease.payload_json
    );
    ensure!(
        control
            .complete(p::CompleteWorkRequest {
                work_item_id: lease.work_item_id,
                attempt_id: lease.attempt_id,
                lease_token: lease.lease_token,
                outcome: outcome.into(),
                result_artifact_id: id,
                error: error.clone(),
                processes_reaped: reaped.load(Ordering::SeqCst),
                ..Default::default()
            })
            .await
            .context(context)?,
        "result rejected"
    );
    ensure!(outcome == "COMPLETED", "worker failed: {error}");
    Ok(())
}

async fn worker(
    control: Control,
    tools: Tools,
    work: PathBuf,
    stop: CancellationToken,
) -> Result<()> {
    loop {
        if stop.is_cancelled() {
            return Ok(());
        }
        let response = control
            .rpc
            .claim_work(p::ClaimWorkRequest {
                executor_id: control.executor_id.clone(),
                ..Default::default()
            })
            .await?
            .into_owned();
        if !response.lease.work_item_id.is_empty() {
            let lease = (*response.lease).clone();
            let directory = work.join(&lease.work_item_id);
            run_job(&control, &tools, lease, &directory).await?;
        } else {
            tokio::select! {_=stop.cancelled()=>return Ok(()),_=tokio::time::sleep(Duration::from_millis(30))=>{}}
        }
    }
}

#[tokio::test]
#[ignore = "requires real UPX, FLOSS, Ghidra; optional locally verified IDA/D-810; no live model API"]
async fn native_agent_recovery_preserves_inputs_and_emits_readable_code() {
    exercise_recovery(false).await;
}

pub(super) async fn exercise_recovery(live: bool) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let options = Options::parse_from([
        "aegis-executor".as_ref(),
        "--script-dir".as_ref(),
        root.join("tools/ghidra").as_os_str(),
    ]);
    let (tools, caps) = capabilities(&options).await;
    for name in ["upx", "floss", "ghidra"] {
        assert!(
            caps.iter().any(|c| c.name == name && c.available),
            "{name} unavailable"
        );
    }
    let ida = caps.iter().any(|c| c.name == "ida-d810" && c.available);
    if std::env::var("AEGIS_REQUIRE_D810_TEST").as_deref() == Ok("1") {
        assert!(ida, "configured IDA/D-810 required for this test run");
    }
    let temporary = root
        .join(".data/verification/agent-recovery/cases")
        .join(d::id());
    tokio::fs::create_dir_all(&temporary).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let state = web::create_state(
        &temporary.as_path().join("server"),
        address,
        None,
        shutdown.clone(),
    )
    .await
    .unwrap();
    let store = state.store.clone();
    let bootstrap = tokio::fs::read_to_string(store.root.join("executor-bootstrap.token"))
        .await
        .unwrap();
    let app = web::router(state, root.join("frontend/dist"));
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
    let control = Control::new(
        &format!("http://{address}"),
        bootstrap.trim(),
        String::new(),
    )
    .unwrap();
    let registered = control
        .rpc
        .register_executor(p::RegisterExecutorRequest {
            name: "native-recovery-test".into(),
            platform: "windows".into(),
            architecture: "x86_64".into(),
            capabilities: caps,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_owned();
    let control = Control::new(
        &format!("http://{address}"),
        &registered.executor_token,
        registered.executor.id.clone(),
    )
    .unwrap();
    let target = tokio::fs::read(root.join("tests/fixtures/recovery/sample-upx.exe"))
        .await
        .unwrap();
    let original_hash = d::sha256(&target);
    let artifact = store
        .stage_bytes(&target, "fixture.exe", "application/octet-stream")
        .await
        .unwrap();
    {
        let mut tx = store.pool.begin().await.unwrap();
        Store::insert_artifact(&mut tx, &artifact, None, None, None)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    let project = store
        .create_project(&d::id(), "Native recovery regression")
        .await
        .unwrap();
    let snapshot = store
        .create_snapshot(
            &d::id(),
            &project.id,
            "BINARY",
            &artifact.id,
            "",
            "",
            "fixture.exe",
        )
        .await
        .unwrap();
    let import = control
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
    run_job(
        &control,
        &tools,
        import,
        &temporary.as_path().join("import"),
    )
    .await
    .unwrap();
    let snapshot: d::Snapshot = store.get("snapshots", &snapshot.id).await.unwrap();
    assert_eq!(snapshot.metadata["protection"]["kind"], "UPX");
    assert!(
        snapshot.metadata["protection"]
            .get("derived_artifact_id")
            .is_none(),
        "import must not run UPX before the agent plans it"
    );
    tokio::fs::write(
        store.root.join("deepseek.token"),
        "test-provider-not-a-real-api-key",
    )
    .await
    .unwrap();
    let config = d::AuditConfig {
        max_units: 1,
        max_tool_rounds: 12,
        max_model_calls: 24,
        timeout_seconds: 900,
    };
    let run = store
        .create_run_with_options(&d::id(), &snapshot.id, d::AUDIT_SCOPE, config.clone())
        .await
        .unwrap();
    let prepare = control
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
    run_job(
        &control,
        &tools,
        prepare,
        &temporary.as_path().join("prepare"),
    )
    .await
    .unwrap();
    let prepared: d::AuditRun = store.get("audit_runs", &run.id).await.unwrap();
    assert_eq!(
        prepared.unit_count, 0,
        "decompilation is selected by the agent"
    );
    let stop = CancellationToken::new();
    let mut worker_task = tokio::spawn(worker(
        control,
        tools,
        temporary.as_path().join("steps"),
        stop.clone(),
    ));
    let (model, model_name): (Box<dyn ModelClient>, String) = if live {
        let protected = std::fs::read_to_string(root.join(".data/server/deepseek.token"))
            .expect("Configure the official model before the explicit live check");
        let key = aegis_application::credentials::decode(protected.trim())
            .expect("Cannot decrypt the locally configured model credential");
        let settings: Value =
            serde_json::from_slice(&std::fs::read(root.join(".data/server/model.json")).unwrap())
                .unwrap();
        let name = settings["model"]
            .as_str()
            .unwrap_or("deepseek-v4-flash")
            .to_owned();
        (
            Box::new(aegis_application::model::DeepSeek::new(key).unwrap()),
            name,
        )
    } else {
        (
            Box::new(RecoveryModel { ida }),
            "scripted-recovery-provider".into(),
        )
    };
    let outcome = tokio::select! {
        result=store.drive_audit_with_model(&run.id,&model_name,&config,model.as_ref(),&shutdown)=>result,
        result=&mut worker_task=>panic!("worker ended unexpectedly: {result:?}"),
        _=tokio::time::sleep(Duration::from_secs(850))=>panic!("recovery workflow timed out"),
    };
    stop.cancel();
    worker_task.await.unwrap().unwrap();
    outcome.unwrap();
    store.finish_audit(&run.id, None).await.unwrap();
    let finished: d::AuditRun = store.get("audit_runs", &run.id).await.unwrap();
    let history = finished.summary["recovery"]["history"].as_array().unwrap();
    if live {
        assert!(
            history
                .iter()
                .any(|h| h["tool"] == "upx" && h["status"] == "PROCESSED"),
            "The live agent did not demonstrate unpacking"
        );
        assert!(
            finished.unit_count > 0,
            "The live agent did not produce readable program units"
        );
    } else {
        assert_eq!(history.len(), if ida { 4 } else { 3 });
        assert_eq!(history[0]["status"], "PROCESSED", "{history:#?}");
        assert_eq!(history[0]["input_sha256"], original_hash);
        for step in &history[1..] {
            assert_eq!(step["input_sha256"], history[0]["output_sha256"]);
        }
        assert_eq!(history[1]["status"], "RECOVERED", "{history:#?}");
        let string_bytes = store
            .artifact_bytes(
                history[1]["strings_artifact_id"].as_str().unwrap(),
                8 * 1024 * 1024,
            )
            .await
            .unwrap();
        let strings: d::RecoveredStrings = serde_json::from_slice(&string_bytes).unwrap();
        assert!(
            strings
                .strings
                .iter()
                .any(|s| s.text.contains("AegisAudit recovered test string")),
            "{strings:#?}"
        );
        assert_eq!(history[2]["status"], "COMPLETED", "{history:#?}");
        let readable = store
            .artifact_bytes(
                history[2]["readable_artifact_id"].as_str().unwrap(),
                8 * 1024 * 1024,
            )
            .await
            .unwrap();
        assert!(
            String::from_utf8_lossy(&readable).contains("AegisAudit recovered test string"),
            "string evidence must reach readable pseudocode"
        );
        if ida {
            assert_eq!(history[3]["status"], "COMPLETED", "{history:#?}");
            assert!(
                history[3]["observation"]["changed_functions"]
                    .as_u64()
                    .unwrap_or(0)
                    > 0,
                "D-810 must actually change a function: {history:#?}"
            );
        }
    }
    assert_eq!(
        store
            .artifact_bytes(&snapshot.normalized_artifact_id, 1024 * 1024)
            .await
            .unwrap(),
        target
    );
    let evidence = root.join(".data/verification/agent-recovery");
    tokio::fs::create_dir_all(&evidence).await.unwrap();
    let label = if live { "live" } else { "native" };
    for format in ["json", "html", "markdown"] {
        let report = store
            .create_report(&d::id(), &run.id, format)
            .await
            .unwrap();
        let bytes = store
            .artifact_bytes(&report.artifact_id, 32 * 1024 * 1024)
            .await
            .unwrap();
        tokio::fs::write(evidence.join(format!("{label}-report.{format}")), bytes)
            .await
            .unwrap();
    }
    let audit = store.audit_evidence(&run.id).await.unwrap();
    tokio::fs::write(evidence.join(format!("{label}-workflow.json")),serde_json::to_vec_pretty(&json!({"scripted_provider":!live,"real_tools":true,"ida_d810_executed":history.iter().any(|h|h["tool"]=="ida_d810"),"target_executed":false,"case_directory":temporary,"summary":finished.summary,"audit":audit})).unwrap()).await.unwrap();
    shutdown.cancel();
    server.await.unwrap();
}
