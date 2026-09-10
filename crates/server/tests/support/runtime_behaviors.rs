use super::*;

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
