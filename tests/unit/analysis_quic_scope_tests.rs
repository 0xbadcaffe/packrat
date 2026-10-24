use super::*;

fn quic_packet() -> Packet {
    let mut bytes = vec![0_u8; 42];
    bytes.extend_from_slice(&[0xc0, 0, 0, 0, 1, 8]);
    bytes.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    bytes.push(4);
    bytes.extend_from_slice(&[9, 10, 11, 12]);
    Packet { capture: None,
        no: 11,
        timestamp: 11.0,
        src: "192.0.2.10".into(),
        dst: "198.51.100.7".into(),
        protocol: "QUIC".into(),
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
