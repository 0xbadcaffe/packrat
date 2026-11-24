use super::*;

fn quic_packet() -> Packet {
    let mut bytes = vec![0_u8; 42];
    bytes.extend_from_slice(&[0xc0, 0, 0, 0, 1, 8]);
    bytes.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    bytes.push(4);
    bytes.extend_from_slice(&[9, 10, 11, 12]);
    let frame_len = bytes.len() as u16;
    bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    bytes[14] = 0x45;
    bytes[16..18].copy_from_slice(&(frame_len - 14).to_be_bytes());
    bytes[22] = 64;
    bytes[23] = 17;
    bytes[26..34].copy_from_slice(&[192, 0, 2, 10, 198, 51, 100, 7]);
    bytes[34..36].copy_from_slice(&50_000_u16.to_be_bytes());
    bytes[36..38].copy_from_slice(&443_u16.to_be_bytes());
    bytes[38..40].copy_from_slice(&(frame_len - 34).to_be_bytes());
    crate::net::parser::parse_ethernet(&bytes, 11, 11.0)
}

#[cfg(unix)]
#[test]
fn helper_authenticated_quic_frames_are_retained() {
    use std::os::unix::fs::PermissionsExt;

    let path = std::env::temp_dir().join(format!("packrat-quic-helper-{}-{}.sh", std::process::id(), unique_test_suffix()));
    std::fs::write(
        &path,
        "#!/bin/sh\nwhile IFS= read -r line; do printf '%s\\n' '{\"ok\":true,\"frames\":[{\"frame_type\":\"headers\",\"detail\":\"GET /\"}],\"detail\":\"auth ok\"}'; done\n",
    ).unwrap();
    let mut permissions = std::fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&path, permissions).unwrap();

    let mut scope = QuicScope { decode_helper_path: Some(path.clone()), ..Default::default() };
    scope.ingest(&quic_packet());
    let connection = scope.all()[0];
    assert_eq!(connection.decoded_frames.len(), 1);
    assert_eq!(connection.decoded_frames[0].frame_type, "headers");
    assert_eq!(connection.decoded_frames[0].detail, "GET /");
    let _ = std::fs::remove_file(path);
}

#[cfg(unix)]
#[test]
fn quic_helper_process_is_reused_for_multiple_packets() {
    use std::os::unix::fs::PermissionsExt;
    let suffix = unique_test_suffix();
    let path = std::env::temp_dir().join(format!("packrat-quic-persistent-{suffix}.sh"));
    let starts = std::env::temp_dir().join(format!("packrat-quic-persistent-{suffix}.starts"));
    std::fs::write(&path, format!(
        "#!/bin/sh\nprintf 'start\\n' >> '{}'\nwhile IFS= read -r line; do printf '%s\\n' '{{\"ok\":true,\"frames\":[{{\"frame_type\":\"ping\",\"detail\":\"ok\"}}]}}'; done\n",
        starts.display()
    )).unwrap();
    let mut permissions = std::fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&path, permissions).unwrap();
    let mut scope = QuicScope { decode_helper_path: Some(path.clone()), ..Default::default() };
    scope.ingest(&quic_packet());
    scope.ingest(&quic_packet());
    assert_eq!(scope.all()[0].decoded_frames.len(), 2);
    assert_eq!(std::fs::read_to_string(&starts).unwrap().lines().count(), 1);
    drop(scope);
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
