use packrat_tui::analysis::impact::read_endpoint_evidence;

const RECORD: &str = r#"{"incident_id":1,"capture_id":"capture-a","target":"192.0.2.10","source":"audit","evidence_id":"event-1","category":"file","subject":"/srv/record","action":"read","successful":true}"#;

#[test]
fn endpoint_evidence_accepts_regular_ndjson_and_counts_the_exact_byte_limit() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("endpoint.ndjson");
    std::fs::write(&path, format!("{RECORD}\r\n\r\n{RECORD}")).unwrap();
    assert_eq!(read_endpoint_evidence(&path).unwrap().len(), 2);
    assert_eq!(
        read_endpoint_evidence(root.path()).unwrap_err(),
        "Endpoint evidence is not a regular file"
    );

    let mut body = RECORD.as_bytes().to_vec();
    body.resize(8 * 1024 * 1024, b' ');
    std::fs::write(&path, &body).unwrap();
    assert_eq!(read_endpoint_evidence(&path).unwrap().len(), 1);
    body.push(b'\n');
    std::fs::write(&path, body).unwrap();
    assert_eq!(
        read_endpoint_evidence(&path).unwrap_err(),
        "Endpoint evidence exceeds import limits"
    );
}

#[cfg(unix)]
#[test]
fn endpoint_evidence_rejects_pipes_without_waiting_for_a_writer() {
    use std::ffi::CString;
    use std::os::unix::{ffi::OsStrExt, fs::symlink};
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    const INPUT: &str = "PACKRAT_TEST_ENDPOINT_EVIDENCE_PIPE";
    if let Some(path) = std::env::var_os(INPUT) {
        assert_eq!(
            read_endpoint_evidence(&PathBuf::from(path)).unwrap_err(),
            "Endpoint evidence is not a regular file"
        );
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("regular.ndjson");
    let alias = root.path().join("regular-alias.ndjson");
    std::fs::write(&file, RECORD).unwrap();
    symlink(&file, &alias).unwrap();
    assert_eq!(read_endpoint_evidence(&alias).unwrap().len(), 1);

    let fifo = root.path().join("pipe.ndjson");
    let fifo_alias = root.path().join("pipe-alias.ndjson");
    let name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: name is a null-terminated path in the temporary test directory.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    symlink(&fifo, &fifo_alias).unwrap();
    for path in [fifo, fifo_alias] {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "endpoint_evidence_rejects_pipes_without_waiting_for_a_writer",
            ])
            .env(INPUT, &path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if child.try_wait().unwrap().is_some() {
                let result = child.wait_with_output().unwrap();
                let output = String::from_utf8_lossy(&result.stdout);
                assert!(
                    result.status.success() && output.contains("1 passed"),
                    "{output}"
                );
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                child.wait().unwrap();
                panic!("Endpoint evidence reader blocked on {}", path.display());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
