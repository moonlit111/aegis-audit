use aegis_application::{import, source};
use aegis_domain as d;
use aegis_server::{error::AppError, store::Store, web};
use serde_json::{Value, json};
use std::{net::SocketAddr, path::Path};
use tokio_util::sync::CancellationToken;

async fn put(store: &Store, bytes: &[u8], name: &str, lease: Option<&d::WorkLease>) -> d::Artifact {
    let artifact = store
        .stage_bytes(bytes, name, "application/octet-stream")
        .await
        .unwrap();
    let _guard = store.writes.lock().await;
    let mut tx = store.pool.begin().await.unwrap();
    Store::insert_artifact(
        &mut tx,
        &artifact,
        lease.map(|l| l.snapshot_id.as_str()),
        lease.map(|l| l.work_item_id.as_str()),
        lease.map(|l| l.attempt_id.as_str()),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    artifact
}

struct Fixture {
    source: tempfile::TempDir,
    manifest: d::SnapshotManifest,
    snapshot: d::Snapshot,
    executor: d::Executor,
}
impl Fixture {
    async fn new(store: &Store) -> Self {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join("中文.py"),
            "def helper(value):\n    return value\n\ndef main():\n    return helper('中文')\n",
        )
        .unwrap();
        let zip = tempfile::NamedTempFile::new().unwrap();
        let bundle = import::pack_directory(
            directory.path(),
            zip.path(),
            import::ImportLimits::default(),
        )
        .unwrap();
        let input = put(
            store,
            &std::fs::read(zip.path()).unwrap(),
            "source.zip",
            None,
        )
        .await;
        let project = store
            .create_project(&d::id(), "<script>test</script>")
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
                        name: "tree-sitter".into(),
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
                "SOURCE",
                &input.id,
                "",
                "",
                "source.zip",
            )
            .await
            .unwrap();
        let lease = store.claim_work(&executor.id).await.unwrap().unwrap();
        let normalized = put(
            store,
            &std::fs::read(zip.path()).unwrap(),
            "normalized.zip",
            Some(&lease),
        )
        .await;
        let manifest = d::SnapshotManifest {
            schema_version: 1,
            kind: "SOURCE".into(),
            normalized_artifact_id: normalized.id,
            target_sha256: normalized.sha256,
            files: bundle.files,
            exclusions: bundle.exclusions,
            metadata: bundle.metadata,
            resolved_revision: String::new(),
        };
        let result = put(
            store,
            &serde_json::to_vec(&manifest).unwrap(),
            "manifest.json",
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
                    &result.id,
                    "",
                    true
                )
                .await
                .unwrap()
        );
        let snapshot = store.get("snapshots", &snapshot.id).await.unwrap();
        Self {
            source: directory,
            manifest,
            snapshot,
            executor,
        }
    }
    async fn run(&self, store: &Store) -> (d::AuditRun, d::WorkLease) {
        let run = store.create_run(&d::id(), &self.snapshot.id).await.unwrap();
        let lease = store.claim_work(&self.executor.id).await.unwrap().unwrap();
        (run, lease)
    }
}

#[tokio::test]
async fn concurrent_idempotent_creates_and_conflicting_bodies() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).await.unwrap();
    let request = d::id();
    let (a, b) = tokio::join!(
        store.create_project(&request, "same project"),
        store.create_project(&request, "same project")
    );
    assert_eq!(a.unwrap().id, b.unwrap().id);
    assert_eq!(store.projects().await.unwrap().len(), 1);
    assert!(matches!(
        store.create_project(&request, "different").await,
        Err(AppError::Conflict(_))
    ));
    let fixture = Fixture::new(&store).await;
    let request = d::id();
    let a = store
        .create_run(&request, &fixture.snapshot.id)
        .await
        .unwrap();
    let b = store
        .create_run(&request, &fixture.snapshot.id)
        .await
        .unwrap();
    assert_eq!(a.id, b.id);
    assert_eq!(store.events(&a.id, 0).await.unwrap().len(), 1);
    assert!(store.create_run("bad", &fixture.snapshot.id).await.is_err());
}

#[tokio::test]
async fn real_source_results_reports_events_and_restart_persist() {
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
    for _ in 0..2 {
        assert!(
            store
                .complete_work(
                    &fixture.executor.id,
                    &lease.work_item_id,
                    &lease.attempt_id,
                    &lease.lease_token,
                    "COMPLETED",
                    &artifact.id,
                    "",
                    true
                )
                .await
                .unwrap()
        );
    }
    assert!(matches!(
        store
            .complete_work(
                &fixture.executor.id,
                &lease.work_item_id,
                &lease.attempt_id,
                &lease.lease_token,
                "FAILED",
                "",
                "changed",
                true
            )
            .await,
        Err(AppError::Conflict(_))
    ));
    let (units, count) = store
        .list_units(&run.id, "helper", "python", 0, 10)
        .await
        .unwrap();
    assert_eq!(count, 1);
    let full: d::ProgramUnit = store.get("program_units", &units[0].id).await.unwrap();
    let original = std::fs::read_to_string(fixture.source.path().join(&full.unit.path)).unwrap();
    assert_eq!(
        full.unit.code,
        &original[full.unit.start_byte as usize..full.unit.end_byte as usize]
    );
    assert_eq!(
        store.edges(&full.id).await.unwrap()[0].certainty,
        "INFERRED"
    );
    let events = store.events(&run.id, 0).await.unwrap();
    assert_eq!(
        events.iter().map(|e| e.seq).collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert_eq!(
        store.events(&run.id, 2).await.unwrap()[0].kind,
        "RUN_COMPLETED"
    );
    let report = store
        .create_report(&d::id(), &run.id, "json")
        .await
        .unwrap();
    let document: Value = serde_json::from_slice(
        &store
            .artifact_bytes(&report.artifact_id, 10_000_000)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(document["checks"]["exploitation"], "NOT_RUN");
    assert_eq!(document["run"]["state"], "COMPLETED");
    assert_eq!(document["units"].as_array().unwrap().len(), 3);
    for artifact in document["artifacts"].as_array().unwrap() {
        let saved: d::Artifact = store
            .get("artifacts", artifact["id"].as_str().unwrap())
            .await
            .unwrap();
        assert_eq!(saved.sha256, artifact["sha256"]);
    }
    let report = store
        .create_report(&d::id(), &run.id, "html")
        .await
        .unwrap();
    let html = String::from_utf8(
        store
            .artifact_bytes(&report.artifact_id, 10_000_000)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(!html.contains("<script>test</script>"));
    assert!(html.contains("&lt;script&gt;test&lt;/script&gt;"));
    store.pool.close().await;
    let reopened = Store::open(directory.path()).await.unwrap();
    let loaded: d::AuditRun = reopened.get("audit_runs", &run.id).await.unwrap();
    assert_eq!(loaded.state, d::RunState::Completed);
    assert_eq!(loaded.unit_count, 3);
    assert_eq!(reopened.events(&run.id, 0).await.unwrap().len(), 3);
    assert_eq!(
        reopened
            .get::<d::Report>("report_exports", &report.id)
            .await
            .unwrap()
            .artifact_id,
        report.artifact_id
    );
}

#[tokio::test]
async fn expired_leases_are_fenced_and_repeated_late_completion_stays_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).await.unwrap();
    let fixture = Fixture::new(&store).await;
    let (run, lease) = fixture.run(&store).await;
    let guard = store.writes.lock().await;
    let pending = {
        let store = store.clone();
        let lease = lease.clone();
        let executor = fixture.executor.id.clone();
        tokio::spawn(async move {
            store
                .progress(
                    &executor,
                    &lease.work_item_id,
                    &lease.attempt_id,
                    &lease.lease_token,
                    "late",
                    0,
                    0,
                )
                .await
        })
    };
    sqlx::query("UPDATE work_items SET lease_expires=0 WHERE id=?")
        .bind(&lease.work_item_id)
        .execute(&store.pool)
        .await
        .unwrap();
    drop(guard);
    assert!(pending.await.unwrap().is_err());
    store.expire_leases().await.unwrap();
    assert!(
        store
            .claim_work(&fixture.executor.id)
            .await
            .unwrap()
            .is_none()
    );
    for _ in 0..2 {
        assert!(
            !store
                .complete_work(
                    &fixture.executor.id,
                    &lease.work_item_id,
                    &lease.attempt_id,
                    &lease.lease_token,
                    "COMPLETED",
                    "not-an-artifact",
                    "",
                    true
                )
                .await
                .unwrap()
        );
    }
    let loaded: d::AuditRun = store.get("audit_runs", &run.id).await.unwrap();
    assert_eq!(loaded.state, d::RunState::Failed);
    assert_eq!(loaded.unit_count, 0);
    assert!(
        !store
            .heartbeat(
                &fixture.executor.id,
                &lease.work_item_id,
                &lease.attempt_id,
                &lease.lease_token
            )
            .await
            .unwrap()
            .1
    );
    store
        .create_run(&d::id(), &fixture.snapshot.id)
        .await
        .unwrap();
    assert!(
        store
            .claim_work(&fixture.executor.id)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn cancellation_waits_for_reaping_and_never_ingests_a_late_success() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).await.unwrap();
    let fixture = Fixture::new(&store).await;
    let queued = store
        .create_run(&d::id(), &fixture.snapshot.id)
        .await
        .unwrap();
    assert_eq!(
        store.cancel_run(&queued.id).await.unwrap().state,
        d::RunState::Cancelled
    );
    assert!(
        store
            .claim_work(&fixture.executor.id)
            .await
            .unwrap()
            .is_none()
    );
    let (run, lease) = fixture.run(&store).await;
    assert_eq!(
        store.cancel_run(&run.id).await.unwrap().state,
        d::RunState::Cancelling
    );
    assert!(
        store
            .heartbeat(
                &fixture.executor.id,
                &lease.work_item_id,
                &lease.attempt_id,
                &lease.lease_token
            )
            .await
            .unwrap()
            .0
    );
    store
        .complete_work(
            &fixture.executor.id,
            &lease.work_item_id,
            &lease.attempt_id,
            &lease.lease_token,
            "COMPLETED",
            "no-result",
            "",
            true,
        )
        .await
        .unwrap();
    let result: d::AuditRun = store.get("audit_runs", &run.id).await.unwrap();
    assert_eq!(result.state, d::RunState::Cancelled);
    assert_eq!(result.unit_count, 0);
    let (_, lease) = fixture.run(&store).await;
    store
        .complete_work(
            &fixture.executor.id,
            &lease.work_item_id,
            &lease.attempt_id,
            &lease.lease_token,
            "FAILED",
            "",
            "cannot reap",
            false,
        )
        .await
        .unwrap();
    assert!(
        store
            .claim_work(&fixture.executor.id)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn executor_capability_refresh_changes_what_can_be_claimed() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path()).await.unwrap();
    let fixture = Fixture::new(&store).await;
    store
        .refresh_capabilities(&fixture.executor.id, vec![])
        .await
        .unwrap();
    let run = store
        .create_run(&d::id(), &fixture.snapshot.id)
        .await
        .unwrap();
    assert_eq!(run.state, d::RunState::WaitingExecutor);
    assert!(
        store
            .claim_work(&fixture.executor.id)
            .await
            .unwrap()
            .is_none()
    );
    store
        .refresh_capabilities(
            &fixture.executor.id,
            vec![d::ToolCapability {
                name: "tree-sitter".into(),
                available: true,
                ..Default::default()
            }],
        )
        .await
        .unwrap();
    assert!(
        store
            .claim_work(&fixture.executor.id)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn http_sessions_origins_roles_ranges_and_foreign_artifacts() {
    let directory = tempfile::tempdir().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let state = web::create_state(directory.path(), address, None, shutdown.clone())
        .await
        .unwrap();
    let store = state.store.clone();
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
    assert_eq!(session.status(), 200);
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
    let rpc = format!("{base}/rpc/audit.v1.ProjectService/ListProjects");
    assert_eq!(
        client
            .post(&rpc)
            .json(&json!({}))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        client
            .post(&rpc)
            .header("cookie", &cookie)
            .json(&json!({}))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        client
            .post(&rpc)
            .header("cookie", &cookie)
            .header("x-aegis-csrf", &csrf)
            .header("origin", "https://attacker.invalid")
            .json(&json!({}))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        client
            .get(format!("{base}/api/session"))
            .header("host", "attacker.invalid")
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    assert_eq!(
        client
            .post(format!("{base}/rpc/audit.v1.ExecutorService/ClaimWork"))
            .header("cookie", &cookie)
            .header("x-aegis-csrf", &csrf)
            .json(&json!({}))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let artifact = put(&store, b"0123456789", "bytes.bin", None).await;
    let path = format!("{base}/api/artifacts/{}", artifact.id);
    assert_eq!(client.get(&path).send().await.unwrap().status(), 401);
    let response = client
        .get(&path)
        .header("cookie", &cookie)
        .header("range", "bytes=2-4")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 206);
    assert_eq!(response.headers()["x-aegis-sha256"], artifact.sha256);
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"234");
    let fixture = Fixture::new(&store).await;
    let (_, lease) = fixture.run(&store).await;
    let lease_get = |path: &str| {
        client
            .get(path)
            .header("authorization", format!("Lease {}", lease.lease_token))
            .header("x-aegis-work-id", &lease.work_item_id)
            .header("x-aegis-attempt-id", &lease.attempt_id)
    };
    assert_eq!(lease_get(&path).send().await.unwrap().status(), 403);
    assert_eq!(
        lease_get(&format!(
            "{base}/api/artifacts/{}",
            fixture.snapshot.normalized_artifact_id
        ))
        .send()
        .await
        .unwrap()
        .status(),
        200
    );
    assert_eq!(lease_get(&rpc).send().await.unwrap().status(), 403);
    sqlx::query("UPDATE work_items SET lease_expires=0 WHERE id=?")
        .bind(&lease.work_item_id)
        .execute(&store.pool)
        .await
        .unwrap();
    assert_eq!(
        lease_get(&format!(
            "{base}/api/artifacts/{}",
            fixture.snapshot.normalized_artifact_id
        ))
        .send()
        .await
        .unwrap()
        .status(),
        403
    );
    let upload = client
        .post(format!("{base}/api/uploads?name=empty.zip"))
        .header("cookie", &cookie)
        .header("x-aegis-csrf", &csrf)
        .body("")
        .send()
        .await
        .unwrap();
    assert_eq!(upload.status(), 400);
    shutdown.cancel();
    server.await.unwrap();
}
