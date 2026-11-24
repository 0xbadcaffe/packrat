use packrat_tui::model::project::{ProjectSaveMode, ProjectState};
use packrat_tui::storage::project_store;

#[test]
fn project_loader_rejects_directories_and_accepts_case_files() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("case.json");
    let state = ProjectState::new("Case", ProjectSaveMode::Lightweight);
    project_store::save(&state, &path).unwrap();
    assert_eq!(project_store::load(&path).unwrap().metadata.name, "Case");

    let error = project_store::load(root.path()).err().unwrap();
    assert!(format!("{error:#}").contains("Project is not a regular file"));
}

#[cfg(unix)]
#[test]
fn project_loader_follows_regular_file_aliases_but_never_waits_on_pipes() {
    use std::ffi::CString;
    use std::os::unix::{ffi::OsStrExt, fs::symlink};
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use packrat_tui::analysis::alert_center::AlertCenter;

    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("case.json");
    let alias = root.path().join("alias.json");
    let pipe = root.path().join("pipe.json");
    let pipe_alias = root.path().join("pipe-alias.json");
    let log = root.path().join("alerts.jsonl");
    project_store::save(
        &ProjectState::new("Case", ProjectSaveMode::Lightweight),
        &path,
    )
    .unwrap();
    let mut center = AlertCenter::default();
    center.record(1, "IDS", "MEDIUM", "Fixture", "Test project loading");
    center.items[0].capture_id = Some("capture-a".into());
    std::fs::write(
        &log,
        serde_json::json!({
            "schema_version": 1, "record_type": "alert", "session_id": "s", "alert": center.items[0]
        })
        .to_string(),
    )
    .unwrap();
    symlink(&path, &alias).unwrap();
    assert_eq!(project_store::load(&alias).unwrap().metadata.name, "Case");

    let fifo = CString::new(pipe.as_os_str().as_bytes()).unwrap();
    // SAFETY: fifo is a valid, null-terminated path in the fixture directory.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    symlink(&pipe, &pipe_alias).unwrap();

    let run = |input: &Path| {
        let mut child = Command::new(env!("CARGO_BIN_EXE_packrat-archive"))
            .arg("--project-alert-status")
            .arg(input)
            .arg(&log)
            .args(["s", "capture-a", "1"])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                let _ = child.kill();
                child.wait().unwrap();
                panic!("Project loader blocked on {}", input.display());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        child.wait_with_output().unwrap()
    };
    let output = run(&alias);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    for input in [&pipe, &pipe_alias] {
        let output = run(input);
        assert!(!output.status.success());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains("Project is not a regular file"), "{error}");
    }
}
