use super::*;

#[test]
fn parses_tls12_and_tls13_key_log_lines() {
    let path = std::env::temp_dir().join(format!("packrat-keys-{}.log", std::process::id()));
    let random = "00".repeat(32);
    let secret = "11".repeat(48);
    std::fs::write(
        &path,
        format!("CLIENT_RANDOM {random} {secret}\nCLIENT_TRAFFIC_SECRET_0 {random} {secret}\n"),
    ).unwrap();
    let mut shelf = KeyShelf::default();
    assert_eq!(shelf.load(&path).unwrap(), 2);
    assert!(shelf.has_client_random(&random));
    let _ = std::fs::remove_file(path);
}

#[test]
fn malformed_unicode_hex_never_panics_or_replaces_loaded_secrets() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("keys.log");
    let random = "00".repeat(32);
    let secret = "11".repeat(48);
    std::fs::write(&path, format!("CLIENT_RANDOM {random} {secret}\n")).unwrap();
    let mut shelf = KeyShelf::default();
    shelf.load(&path).unwrap();
    for value in ["a\u{20ac}", "\u{1f400}", "\u{00e9}aa", "0x11", "zz", "1", ""] {
        assert!(decode_hex(value).is_none() || value.is_empty());
        std::fs::write(&path, format!("CLIENT_RANDOM {random} {value}\n")).unwrap();
        if value.is_empty() { continue; }
        assert!(shelf.load(&path).is_err());
        assert_eq!(shelf.secret_count(), 1);
        assert!(shelf.has_client_random(&random));
    }
}

#[test]
fn duplicates_are_idempotent_and_conflicting_or_invalid_keys_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("keys.log");
    let random = "AA".repeat(32);
    let line = format!("CLIENT_TRAFFIC_SECRET_0 {random} {}\n", "11".repeat(32));
    std::fs::write(&path, line.repeat(3)).unwrap();
    let mut shelf = KeyShelf::default();
    assert_eq!(shelf.load(&path).unwrap(), 1);
    std::fs::write(&path, format!("{line}CLIENT_TRAFFIC_SECRET_0 {random} {}\n", "22".repeat(32))).unwrap();
    assert!(shelf.reload().unwrap_err().contains("conflicting"));
    assert_eq!(shelf.secret_count(), 1);
    for (random, secret) in [("11", "22".repeat(48)), (&random[..], "22".repeat(3))] {
        std::fs::write(&path, format!("CLIENT_RANDOM {random} {secret}\n")).unwrap();
        assert!(shelf.load(&path).is_err());
    }
}

#[test]
fn oversized_key_logs_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("keys.log");
    std::fs::write(&path, vec![b' '; MAX_KEY_LOG_BYTES as usize + 1]).unwrap();
    assert!(KeyShelf::default().load(&path).unwrap_err().contains("size limit"));
}
