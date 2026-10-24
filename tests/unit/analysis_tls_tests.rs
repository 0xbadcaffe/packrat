use super::*;

fn packet(bytes: Vec<u8>) -> Packet {
    Packet { capture: None,
        no: 9,
        timestamp: 9.0,
        src: "192.0.2.10".into(),
        dst: "198.51.100.7".into(),
        protocol: "TLS".into(),
        length: bytes.len() as u16,
        info: String::new(),
        src_port: Some(50000),
        dst_port: Some(443),
        vlan_id: None,
        vlan_pcp: None,
        vlan_dei: None,
        outer_vlan_id: None,
        bytes,
    }
}

#[cfg(unix)]
#[test]
fn helper_authenticated_tls_record_is_retained() {
    use std::os::unix::fs::PermissionsExt;

    let path = std::env::temp_dir().join(format!("packrat-tls-helper-{}-{}.sh", std::process::id(), unique_test_suffix()));
    std::fs::write(
        &path,
        "#!/bin/sh\nwhile IFS= read -r line; do printf '%s\\n' '{\"ok\":true,\"content_type\":\"http\",\"plaintext_hex\":\"474554202f20485454502f312e31\",\"detail\":\"auth ok\"}'; done\n",
    ).unwrap();
    let mut permissions = std::fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&path, permissions).unwrap();

    let mut tracker = TlsTracker::default();
    tracker.decrypt_helper_path = Some(path.clone());
    tracker.insert(TlsSession {
        flow_id: "192.0.2.10:50000-198.51.100.7:443".into(),
        client_random: Some("00".repeat(32)),
        key_material: true,
        first_seen: 1.0,
        ..Default::default()
    });
    tracker.ingest(&packet(vec![0x17, 0x03, 0x03, 0x00, 0x04, 1, 2, 3, 4]));
    let session = tracker.get("192.0.2.10:50000-198.51.100.7:443").unwrap();
    assert_eq!(session.decrypted_records.len(), 1);
    assert_eq!(session.decrypted_records[0].plaintext, b"GET / HTTP/1.1");
    let _ = std::fs::remove_file(path);
}

#[cfg(unix)]
#[test]
fn tls_helper_process_is_reused_for_multiple_records() {
    use std::os::unix::fs::PermissionsExt;
    let suffix = unique_test_suffix();
    let path = std::env::temp_dir().join(format!("packrat-tls-persistent-{suffix}.sh"));
    let starts = std::env::temp_dir().join(format!("packrat-tls-persistent-{suffix}.starts"));
    std::fs::write(&path, format!(
        "#!/bin/sh\nprintf 'start\\n' >> '{}'\nwhile IFS= read -r line; do printf '%s\\n' '{{\"ok\":true,\"content_type\":\"data\",\"plaintext_hex\":\"61\"}}'; done\n",
        starts.display()
    )).unwrap();
    let mut permissions = std::fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&path, permissions).unwrap();
    let mut tracker = TlsTracker::default();
    tracker.decrypt_helper_path = Some(path.clone());
    tracker.insert(TlsSession {
        flow_id: "192.0.2.10:50000-198.51.100.7:443".into(),
        client_random: Some("00".repeat(32)), key_material: true, ..Default::default()
    });
    tracker.ingest(&packet(vec![0x17, 0x03, 0x03, 0, 1, 1]));
    tracker.ingest(&packet(vec![0x17, 0x03, 0x03, 0, 1, 2]));
    assert_eq!(tracker.get("192.0.2.10:50000-198.51.100.7:443").unwrap().decrypted_records.len(), 2);
    assert_eq!(std::fs::read_to_string(&starts).unwrap().lines().count(), 1);
    drop(tracker);
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(starts);
}

#[cfg(unix)]
fn unique_test_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}
