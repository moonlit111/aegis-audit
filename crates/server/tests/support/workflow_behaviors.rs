use super::*;

#[tokio::test]
async fn snapshot_workflow_deduplicates_distinct_requests_across_connections() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).await.unwrap();
    let other = Store::open(directory.path()).await.unwrap();
    let fixture = Fixture::new(&store).await;
    let (first_request, second_request) = (d::id(), d::id());
    let (a, b) = tokio::join!(
        store.create_run(&first_request, &fixture.snapshot.id),
        other.create_run(&second_request, &fixture.snapshot.id),
    );
    let a = a.unwrap();
    assert_eq!(a.id, b.unwrap().id);
    assert_eq!(store.runs("").await.unwrap().len(), 1);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM work_items WHERE run_id=?")
        .bind(&a.id)
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    let lease = store
        .claim_work(&fixture.executor.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        store
            .create_run(&d::id(), &fixture.snapshot.id)
            .await
            .unwrap()
            .id,
        a.id
    );
    store.cancel_run(&a.id).await.unwrap();
    assert_eq!(
        store
            .create_run(&d::id(), &fixture.snapshot.id)
            .await
            .unwrap()
            .state,
        d::RunState::Cancelling
    );
    store
        .complete_work(
            &fixture.executor.id,
            &lease.work_item_id,
            &lease.attempt_id,
            &lease.lease_token,
            "CANCELLED",
            "",
            "cancelled",
            true,
        )
        .await
        .unwrap();
    let next = store
        .create_run(&d::id(), &fixture.snapshot.id)
        .await
        .unwrap();
    assert_ne!(next.id, a.id);
    // Retrying either original request still refers to its original round.
    assert_eq!(
        store
            .create_run(&second_request, &fixture.snapshot.id)
            .await
            .unwrap()
            .id,
        a.id
    );
}

#[tokio::test]
async fn snapshot_workflow_rejects_overlapping_modes_and_changed_audit_budgets() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).await.unwrap();
    tokio::fs::write(store.root.join("deepseek.token"), "fixture-only-key")
        .await
        .unwrap();
    let fixture = Fixture::new(&store).await;
    store
        .refresh_capabilities(&fixture.executor.id, vec![])
        .await
        .unwrap();
    let structure = store
        .create_run(&d::id(), &fixture.snapshot.id)
        .await
        .unwrap();
    assert_eq!(structure.state, d::RunState::WaitingExecutor);
    let config = d::AuditConfig::default();
    assert!(matches!(
        store
            .create_run_with_options(
                &d::id(),
                &fixture.snapshot.id,
                d::AUDIT_SCOPE,
                config.clone()
            )
            .await,
        Err(AppError::Conflict(_))
    ));
    store.cancel_run(&structure.id).await.unwrap();
    let audit = store
        .create_run_with_options(
            &d::id(),
            &fixture.snapshot.id,
            d::AUDIT_SCOPE,
            config.clone(),
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .create_run_with_options(
                &d::id(),
                &fixture.snapshot.id,
                d::AUDIT_SCOPE,
                config.clone()
            )
            .await
            .unwrap()
            .id,
        audit.id
    );
    assert!(matches!(
        store.create_run(&d::id(), &fixture.snapshot.id).await,
        Err(AppError::Conflict(_))
    ));
    let mut changed = config;
    changed.max_units += 1;
    assert!(matches!(
        store
            .create_run_with_options(&d::id(), &fixture.snapshot.id, d::AUDIT_SCOPE, changed)
            .await,
        Err(AppError::Conflict(_))
    ));
}

async fn binary_structure(store: &Store) -> (d::Snapshot, d::Executor, d::AuditRun) {
    let bytes = include_bytes!("../../../../tests/fixtures/binary/sample-pe64.exe");
    let input = put(store, bytes, "target.exe", None).await;
    let project = store
        .create_project(&d::id(), "workflow fixture")
        .await
        .unwrap();
    let (executor, _) = store
        .register_executor(
            "fixture",
            "test",
            "test",
            vec![
                d::ToolCapability {
                    name: "import".into(),
                    available: true,
                    ..Default::default()
                },
                d::ToolCapability {
                    name: "ghidra".into(),
                    version: "12.1.3".into(),
                    available: true,
                    ..Default::default()
                },
            ],
        )
        .await
        .unwrap();
    let snapshot = store
        .create_snapshot(
            &d::id(),
            &project.id,
            "BINARY",
            &input.id,
            "",
            "",
            "target.exe",
        )
        .await
        .unwrap();
    let lease = store.claim_work(&executor.id).await.unwrap().unwrap();
    let normalized = put(store, bytes, "target.exe", Some(&lease)).await;
    let manifest = d::SnapshotManifest {
        schema_version: 1,
        kind: "BINARY".into(),
        normalized_artifact_id: normalized.id,
        target_sha256: normalized.sha256.clone(),
        files: vec![d::FileRecord {
            path: "target.exe".into(),
            sha256: normalized.sha256,
            size: bytes.len() as u64,
            language: "binary".into(),
        }],
        exclusions: vec![],
        metadata: import::inspect_binary(bytes).unwrap(),
        resolved_revision: String::new(),
    };
    let artifact = put(
        store,
        &serde_json::to_vec(&manifest).unwrap(),
        "manifest.json",
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
            &artifact.id,
            "",
            true,
        )
        .await
        .unwrap();
    let snapshot: d::Snapshot = store.get("snapshots", &snapshot.id).await.unwrap();
    let run = store.create_run(&d::id(), &snapshot.id).await.unwrap();
    let lease = store.claim_work(&executor.id).await.unwrap().unwrap();
    let log = put(store, b"fixture decompiler log", "ghidra.log", Some(&lease)).await;
    let analysis = d::AnalysisResult {
        units: (0..2)
            .map(|n| d::UnitInput {
                key: format!("f{n}"),
                name: format!("f{n}"),
                path: "target.exe".into(),
                language: "binary".into(),
                code: format!("int f{n}(void) {{ return 0; }}"),
                address: format!("0x14000100{n}"),
                quality: "PARSED".into(),
                metadata: json!({"kind":"function"}),
                ..Default::default()
            })
            .collect(),
        edges: vec![d::EdgeInput {
            source_key: "f0".into(),
            target_key: "f1".into(),
            target_name: "f1".into(),
            kind: "CALL".into(),
            certainty: "INFERRED".into(),
            line: 0,
            address: String::new(),
        }],
        files: vec![d::FileResult {
            path: "target.exe".into(),
            language: "binary".into(),
            status: "PARSED".into(),
            reason: String::new(),
            unit_count: 2,
        }],
        tools: vec![d::ToolExecution {
            name: "ghidra".into(),
            version: "12.1.3".into(),
            command: [
                "headless",
                "project",
                "analysis",
                "-import",
                "input",
                "-scriptPath",
                "scripts",
                "-postScript",
                "ExportProgram.java",
                "output",
                "target.bin",
                "-deleteProject",
                "-analysisTimeoutPerFile",
                "120",
                "-max-cpu",
                "2",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            started_at: d::now(),
            finished_at: d::now(),
            exit_code: Some(0),
            terminated: false,
            log_artifact_id: log.id,
            details: json!({"processes_reaped":true,"timed_out":false,"cancelled":false}),
        }],
        ..Default::default()
    };
    let artifact = put(
        store,
        &serde_json::to_vec(&analysis).unwrap(),
        "analysis.json",
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
            &artifact.id,
            "",
            true,
        )
        .await
        .unwrap();
    (
        snapshot,
        executor,
        store.get("audit_runs", &run.id).await.unwrap(),
    )
}

#[tokio::test]
async fn snapshot_workflow_reuses_binary_code_with_traceable_run_local_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).await.unwrap();
    let (snapshot, executor, previous) = binary_structure(&store).await;
    tokio::fs::write(store.root.join("deepseek.token"), "fixture-only-key")
        .await
        .unwrap();
    let audit = store
        .create_run_with_options(
            &d::id(),
            &snapshot.id,
            d::AUDIT_SCOPE,
            d::AuditConfig::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        audit.summary["analysis_reuse"]["source_run_id"],
        previous.id
    );
    assert_ne!(
        audit.summary["result_artifact_id"],
        previous.summary["result_artifact_id"]
    );
    assert_eq!(audit.unit_count, 2);
    assert!(store.claim_work(&executor.id).await.unwrap().is_none());
    let (listed, _) = store.list_units(&audit.id, "", "", 0, 50).await.unwrap();
    let (units, edges) = store.graph(&listed[0].id).await.unwrap();
    assert!(
        units
            .iter()
            .all(|u| u.run_id == audit.id && u.snapshot_id == snapshot.id)
    );
    assert!(units.iter().any(|u| u.id == edges[0].source_id));
    assert!(units.iter().any(|u| u.id == edges[0].target_id));
    let log = audit.summary["tools"][0]["log_artifact_id"]
        .as_str()
        .unwrap();
    assert_ne!(
        log,
        previous.summary["tools"][0]["log_artifact_id"]
            .as_str()
            .unwrap()
    );
    assert!(
        store
            .run_artifacts(&audit.id)
            .await
            .unwrap()
            .iter()
            .any(|a| a.id == log)
    );
    assert_eq!(
        store.artifact_bytes(log, 1024).await.unwrap(),
        b"fixture decompiler log"
    );
    let original: d::AuditRun = store.get("audit_runs", &previous.id).await.unwrap();
    assert!(original.summary["analysis_reuse"].is_null());
    assert_eq!(original.state, d::RunState::Completed);
    let events = store.events(&audit.id, 0).await.unwrap();
    assert!(
        events
            .iter()
            .any(|e| e.kind == "STRUCTURE_REUSED" && e.phase_id == "PREPARATION")
    );
}

#[tokio::test]
async fn snapshot_workflow_changed_tools_do_not_reuse_and_preparation_is_not_decompilation() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).await.unwrap();
    let (snapshot, mut executor, _) = binary_structure(&store).await;
    executor.capabilities[1].version = "different-version".into();
    store
        .refresh_capabilities(&executor.id, executor.capabilities.clone())
        .await
        .unwrap();
    tokio::fs::write(store.root.join("deepseek.token"), "fixture-only-key")
        .await
        .unwrap();
    let audit = store
        .create_run_with_options(
            &d::id(),
            &snapshot.id,
            d::AUDIT_SCOPE,
            d::AuditConfig::default(),
        )
        .await
        .unwrap();
    assert!(audit.summary["analysis_reuse"].is_null());
    let lease = store.claim_work(&executor.id).await.unwrap().unwrap();
    let preparation = d::AnalysisResult {
        files: vec![d::FileResult {
            path: "target.exe".into(),
            language: "binary".into(),
            status: "PARTIAL".into(),
            reason: "waiting for reverse".into(),
            unit_count: 0,
        }],
        metadata: json!({"recovery_preparation":"WAITING_AGENT"}),
        ..Default::default()
    };
    let artifact = put(
        &store,
        &serde_json::to_vec(&preparation).unwrap(),
        "preparation.json",
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
            &artifact.id,
            "",
            true,
        )
        .await
        .unwrap();
    let audit: d::AuditRun = store.get("audit_runs", &audit.id).await.unwrap();
    assert_eq!(audit.unit_count, 0);
    assert!(audit.summary["result_artifact_id"].is_null());
    let phases = store.run_phases(&audit.id).await.unwrap();
    assert_eq!(
        (phases[0].id.as_str(), phases[0].status.as_str()),
        ("PREPARATION", "COMPLETED")
    );
    assert_eq!(
        (phases[1].id.as_str(), phases[1].status.as_str()),
        ("RECOVERY", "WAITING")
    );
    let events = store.events(&audit.id, 0).await.unwrap();
    assert!(events.iter().any(|e| e.kind == "PREPARATION_COMPLETED"));
    assert!(!events.iter().any(|e| e.kind == "STRUCTURE_COMPLETED"));
}
