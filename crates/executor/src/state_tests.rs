use super::*;
use std::{fs::OpenOptions, os::windows::fs::OpenOptionsExt};

#[test]
fn atomic_state_save_survives_a_transient_windows_sharing_lock() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("active.json");
    private_json(&path, &json!({"phase":"running"})).unwrap();
    // A scanner/reader permits reads and writes but temporarily denies replacement.
    let locked = OpenOptions::new()
        .read(true)
        .share_mode(0x1 | 0x2)
        .open(&path)
        .unwrap();
    let release = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(250));
        drop(locked);
    });
    let result = private_json(&path, &json!({"phase":"completed","processes_reaped":true}));
    release.join().unwrap();
    result.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(value, json!({"phase":"completed","processes_reaped":true}));
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[test]
fn a_persistent_state_file_lock_preserves_the_previous_record_and_returns_an_error() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("active.json");
    let previous = json!({"phase":"running","processes_reaped":false});
    private_json(&path, &previous).unwrap();
    let locked = OpenOptions::new()
        .read(true)
        .share_mode(0x1 | 0x2)
        .open(&path)
        .unwrap();
    let started = Instant::now();
    assert!(private_json(&path, &json!({"phase":"completed"})).is_err());
    assert!(started.elapsed() < Duration::from_secs(5));
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(value, previous);
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    drop(locked);
}
