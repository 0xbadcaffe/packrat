use super::*;

fn packet(bytes: Vec<u8>) -> Packet {
    let mut tagged = tagged_record(9, 0x8100, &bytes);
    tagged.bytes.drain(12..16);
    crate::net::parser::parse_ethernet(&tagged.bytes, 9, 9.0)
}

fn tagged_record(no: u64, tpid: u16, payload: &[u8]) -> Packet {
    let mut frame = vec![0; 58];
    frame[12..14].copy_from_slice(&tpid.to_be_bytes());
    frame[14..16].copy_from_slice(&20_u16.to_be_bytes());
    frame[16..18].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[18] = 0x45;
    frame[20..22].copy_from_slice(&(40 + payload.len() as u16).to_be_bytes());
    frame[26] = 64;
    frame[27] = 6;
    frame[30..38].copy_from_slice(&[192, 0, 2, 10, 198, 51, 100, 7]);
    frame[38..40].copy_from_slice(&50_000_u16.to_be_bytes());
    frame[40..42].copy_from_slice(&443_u16.to_be_bytes());
    frame[50] = 0x50;
    frame[51] = 0x18;
    frame.extend_from_slice(payload);
    crate::net::parser::parse_ethernet(&frame, no, no as f64)
}

#[test]
fn distinct_tls_tag_paths_keep_separate_records_and_link_only_observed_packets() {
    let alert = [0x15, 3, 3, 0, 2, 2, 40];
    let customer = tagged_record(1, 0x8100, &alert);
    let provider = tagged_record(2, 0x88a8, &alert);
    let mut tracker = TlsTracker::default();
    tracker.ingest(&customer);
    tracker.ingest(&provider);
    assert_eq!(tracker.len(), 2);
    assert_eq!(tracker.for_packet(&customer).unwrap().alert_desc, Some(40));
    assert!(tracker.for_packet(&tagged_record(2, 0x8100, &alert)).is_none());
    assert!(tracker.for_packet(&provider).is_some());
}

#[test]
fn tls_record_shape_in_tcp_padding_or_inside_unrelated_payload_is_not_evidence() {
    let record = [0x15, 3, 3, 0, 2, 2, 40];
    let mut padding = tagged_record(1, 0x8100, &[]);
    padding.bytes.extend(record);
    let mut tracker = TlsTracker::default();
    tracker.ingest(&padding);
    let mut unrelated = vec![b'A'];
    unrelated.extend(record);
    tracker.ingest(&tagged_record(2, 0x8100, &unrelated));
    assert!(tracker.is_empty());
}

fn hello_record(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut record = vec![0x16, 3, 3];
    record.extend((4 + body.len() as u16).to_be_bytes());
    record.extend([kind, 0, 0, body.len() as u8]);
    record.extend(body);
    record
}

#[test]
fn tls_version_requires_a_server_selection_and_a_new_client_random_retires_old_links() {
    let mut body = vec![3, 3];
    body.extend([1; 32]);
    body.extend([0, 0, 2, 0x13, 1, 1, 0, 0, 7, 0, 43, 0, 3, 2, 3, 4]);
    let client = tagged_record(1, 0x8100, &hello_record(1, &body));
    let mut tracker = TlsTracker::default();
    tracker.ingest(&client);
    let first = tracker.for_packet(&client).unwrap();
    assert_eq!(first.offered_version.as_deref(), Some("TLS 1.3"));
    assert_eq!(first.tls_version, None);

    let mut server = vec![3, 3];
    server.extend([2; 32]);
    server.extend([0, 0xc0, 0x2f, 0]);
    let selected = tagged_record(2, 0x8100, &hello_record(2, &server));
    tracker.ingest(&selected);
    assert_eq!(tracker.for_packet(&client).unwrap().version_str(), "TLS 1.2");
    assert_eq!(tracker.for_packet(&selected).unwrap().cipher_suite, Some(0xc02f));
    let protected = tagged_record(3, 0x8100, &[0x17, 3, 3, 0, 1, 1]);
    tracker.ingest(&protected);
    assert!(tracker.for_packet(&protected).is_none());

    body[2] = 3;
    let next = tagged_record(4, 0x8100, &hello_record(1, &body));
    tracker.ingest(&next);
    assert!(tracker.for_packet(&client).is_none());
    assert!(tracker.for_packet(&selected).is_none());
    assert_eq!(tracker.for_packet(&next).unwrap().tls_version, None);
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
