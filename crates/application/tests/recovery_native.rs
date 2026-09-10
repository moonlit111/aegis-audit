use aegis_application::{process, recovery};
use std::path::Path;
use tokio_util::sync::CancellationToken;

#[tokio::test]
#[ignore = "requires the pinned FLOSS executable; no target execution or model calls"]
async fn native_floss_uses_the_supervised_private_environment() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let work = tempfile::Builder::new()
        .prefix("aegis floss ")
        .tempdir()
        .unwrap();
    let bytes = std::fs::read(root.join("tests/fixtures/recovery/sample.exe")).unwrap();
    let input = work.path().join("target.bin");
    std::fs::write(&input, &bytes).unwrap();
    let output = process::run(
        recovery::floss_spec(&input, work.path()).unwrap(),
        CancellationToken::new(),
        |_| {},
    )
    .await
    .unwrap();
    assert_eq!(
        output.exit_code,
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.processes_reaped && !output.truncated && !output.timed_out);
    let raw = serde_json::from_slice(&output.stdout).unwrap();
    let strings = recovery::floss_strings(&raw, &bytes).unwrap();
    assert!(
        strings
            .strings
            .iter()
            .any(|s| s.text.contains("AegisAudit recovered test string"))
    );
}
