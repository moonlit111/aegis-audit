use super::*;

#[tokio::test]
async fn verified_behaviour_stages_a_reusable_reuse_poc() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).await.unwrap();
    let fixture = Fixture::new(&store).await;
    let (run, structure_lease) = fixture.run(&store).await;
    let analysis = source::analyze_sources(
        fixture.source.path(),
        &fixture.manifest.files,
        &CancellationToken::new(),
        |_, _, _| {},
    )
    .unwrap();
    let artifact = put(
        &store,
        &serde_json::to_vec(&analysis).unwrap(),
        "analysis.json",
        Some(&structure_lease),
    )
    .await;
    store
        .complete_work(
            &fixture.executor.id,
            &structure_lease.work_item_id,
            &structure_lease.attempt_id,
            &structure_lease.lease_token,
            "COMPLETED",
            &artifact.id,
            "",
            true,
        )
        .await
        .unwrap();
    let mut config = d::RuntimeConfig {
        adapter: "WINDOWS_PYTHON_CALL".into(),
        path: "中文.py".into(),
        function: "helper".into(),
        observer: "FILE_CREATED".into(),
        marker_path: "marker.txt".into(),
        repeats: 2,
        ..Default::default()
    };
    config.probe.args = vec![json!("poc")];
    let record = store
        .create_runtime(&d::id(), &run.id, "", Some(config.clone()))
        .await
        .unwrap();
    let (executor, _) = store
        .register_executor(
            "poc runtime test",
            "windows",
            "x86_64",
            vec![d::ToolCapability {
                name: "windows-host".into(),
                available: true,
                ..Default::default()
            }],
        )
        .await
        .unwrap();
    let lease = store.claim_work(&executor.id).await.unwrap().unwrap();
    let recipe = put(
        &store,
        &serde_json::to_vec(&json!({"config": record.config})).unwrap(),
        "recipe.json",
        Some(&lease),
    )
    .await;
    let trial = |label: &str, invocation: &d::Invocation, observed: bool| {
        let input_json = serde_json::to_string(invocation).unwrap();
        json!({
            "label": label,
            "input_json": input_json,
            "input_sha256": d::sha256(input_json.as_bytes()),
            "exit_code": 0,
            "timed_out": false,
            "processes_reaped": true,
            "observed": observed,
            "exception": "",
            "stdout": "",
            "stderr": "",
            "truncated": false,
            "crash_signature": "",
        })
    };
    let observation = json!({
        "schema_version": 1,
        "mode": "VERIFY",
        "adapter": "WINDOWS_PYTHON_CALL",
        "path": "中文.py",
        "build": {"status": "READY"},
        "trials": [
            trial("baseline", &config.baseline, false),
            trial("probe", &config.probe, true),
            trial("probe", &config.probe, true),
        ],
        "fuzz": {},
        "crashes": [],
        "error": "",
    });
    let observation_artifact = put(
        &store,
        &serde_json::to_vec(&observation).unwrap(),
        "observation.json",
        Some(&lease),
    )
    .await;
    let log = put(&store, b"host log", "run.log", Some(&lease)).await;
    let image_id = format!("sha256:{}", "b".repeat(64));
    let result = json!({
        "target_sha256": fixture.snapshot.target_sha256,
        "config_hash": record.config.fingerprint(),
        "image_id": image_id,
        "target_scope": "COMPONENT",
        "recipe_artifact_id": recipe.id,
        "observation_artifact_id": observation_artifact.id,
        "observation": observation,
        "tools": [{
            "name": "powershell.exe",
            "version": image_id,
            "command": ["powershell.exe", "-File", "run-python.ps1"],
            "started_at": d::now(),
            "finished_at": d::now(),
            "exit_code": 0,
            "terminated": false,
            "log_artifact_id": log.id,
            "details": {"processes_reaped": true, "network": "HOST",
                        "execution": "WINDOWS_HOST", "raw_log_artifact_ids": [log.id]},
        }],
    });
    let result_artifact = put(
        &store,
        &serde_json::to_vec(&result).unwrap(),
        "result.json",
        Some(&lease),
    )
    .await;
    store
        .complete_work(
            &executor.id,
            &lease.work_item_id,
            &lease.attempt_id,
            &lease.lease_token,
            "COMPLETED",
            &result_artifact.id,
            "",
            true,
        )
        .await
        .unwrap();
    let saved = store.runtime_record(&record.id).await.unwrap();
    assert_eq!(saved.status, "VERIFIED_COMPONENT");
    let runtime_run: d::AuditRun = store.get("audit_runs", &saved.run_id).await.unwrap();
    assert_eq!(runtime_run.summary["exploitation"], "COMPLETED");
    let evidence_id = runtime_run.summary["exploitation_artifact_id"]
        .as_str()
        .unwrap();
    let evidence_artifact: d::Artifact = store.get("artifacts", evidence_id).await.unwrap();
    assert_eq!(
        evidence_artifact.name,
        format!("exploit-{}.json", record.id)
    );
    let evidence: Value =
        serde_json::from_slice(&store.artifact_bytes(evidence_id, 512 * 1024).await.unwrap())
            .unwrap();
    assert_eq!(evidence["kind"], "BEHAVIOR_POC");
    assert_eq!(evidence["reproductions"], 2);
    assert_eq!(evidence["expected_reproductions"], 2);
    assert_eq!(evidence["observer"], "FILE_CREATED");
    let runner_id = evidence["runner_artifact_id"].as_str().unwrap();
    let runner =
        String::from_utf8(store.artifact_bytes(runner_id, 512 * 1024).await.unwrap()).unwrap();
    assert!(runner.starts_with("#!/usr/bin/env python3"));
    assert!(runner.contains("--recipe"));
    let recipe_id = runtime_run.summary["exploitation_input_artifact_id"]
        .as_str()
        .unwrap();
    let replay: Value =
        serde_json::from_slice(&store.artifact_bytes(recipe_id, 512 * 1024).await.unwrap())
            .unwrap();
    assert_eq!(replay["probe"]["args"], json!(["poc"]));
    assert_eq!(replay["target_path"], "中文.py");
}

#[tokio::test]
async fn runtime_is_idempotent_and_cannot_ingest_success_without_execution_artifacts() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).await.unwrap();
    let fixture = Fixture::new(&store).await;
    let (run, lease) = fixture.run(&store).await;
    let analysis = source::analyze_sources(
        fixture.source.path(),
        &fixture.manifest.files,
        &CancellationToken::new(),
        |_, _, _| {},
    )
    .unwrap();
    let artifact = put(
        &store,
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
            &artifact.id,
            "",
            true,
        )
        .await
        .unwrap();
    let mut config = d::RuntimeConfig {
        adapter: "WINDOWS_PYTHON_CALL".into(),
        path: "中文.py".into(),
        function: "helper".into(),
        observer: "FILE_CREATED".into(),
        marker_path: "marker.txt".into(),
        globals: Default::default(),
        ..Default::default()
    };
    let unsupported = {
        let mut config = config.clone();
        config.baseline.stdin = "{{work}}".into();
        config
    };
    assert!(
        store
            .create_runtime(&d::id(), &run.id, "", Some(unsupported))
            .await
            .is_err()
    );
    config.baseline.args = vec![json!(7), json!([true, null])];
    config
        .baseline
        .kwargs
        .insert("name".into(), json!("baseline"));
    config
        .globals
        .insert("settings".into(), json!({"enabled": true}));
    let request = d::id();
    let record = store
        .create_runtime(&request, &run.id, "", Some(config.clone()))
        .await
        .unwrap();
    assert_eq!(record.status, "WAITING_EXECUTOR");
    assert_eq!(record.config.baseline.args, config.baseline.args);
    assert_eq!(record.config.baseline.kwargs, config.baseline.kwargs);
    assert_eq!(record.config.globals, config.globals);
    assert_eq!(
        store
            .create_runtime(&request, &run.id, "", Some(config.clone()))
            .await
            .unwrap()
            .id,
        record.id
    );
    config.timeout_seconds = 6;
    assert!(matches!(
        store
            .create_runtime(&request, &run.id, "", Some(config.clone()))
            .await,
        Err(AppError::Conflict(_))
    ));
    config.path = "../outside.py".into();
    assert!(
        store
            .create_runtime(&d::id(), &run.id, "", Some(config))
            .await
            .is_err()
    );
    let (executor, _) = store
        .register_executor(
            "runtime test",
            "linux",
            "x86_64",
            vec![d::ToolCapability {
                name: "windows-host".into(),
                available: true,
                ..Default::default()
            }],
        )
        .await
        .unwrap();
    let lease = store.claim_work(&executor.id).await.unwrap().unwrap();
    // Default VERIFY deadline is 180s; the lease adds host runtime
    // startup/cleanup/evidence time instead of cutting it to 300s.
    assert_eq!(lease.timeout_seconds, 360);
    // A guessed verdict cannot replace the supervisor recipe, raw observations and owned tool logs.
    let fabricated = json!({"target_sha256":fixture.snapshot.target_sha256,"config_hash":record.config.fingerprint(),
        "image_id":format!("sha256:{}", "a".repeat(64)),"target_scope":"COMPONENT","recipe_artifact_id":"","observation_artifact_id":"",
        "observation":{"schema_version":1,"mode":"VERIFY","adapter":"WINDOWS_PYTHON_CALL","path":"中文.py"},"tools":[]});
    let artifact = put(
        &store,
        &serde_json::to_vec(&fabricated).unwrap(),
        "unsubstantiated-result.json",
        Some(&lease),
    )
    .await;
    assert!(
        store
            .complete_work(
                &executor.id,
                &lease.work_item_id,
                &lease.attempt_id,
                &lease.lease_token,
                "COMPLETED",
                &artifact.id,
                "",
                true
            )
            .await
            .is_err()
    );
    let saved = store.runtime_record(&record.id).await.unwrap();
    assert!(saved.result.is_none());
    assert_ne!(saved.status, "VERIFIED_COMPONENT");
    assert_ne!(saved.status, "REPRODUCED");
}
