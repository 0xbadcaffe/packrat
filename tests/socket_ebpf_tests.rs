use packrat_tui::analysis::socket_ebpf::{
    compatibility_report, KernelVersion, SocketEbpfEvent, SocketEventKind, SOCKET_EVENT_SIZE,
    SOCKET_EVENT_VERSION,
};
use packrat_tui::analysis::socket_scope::SocketScope;

fn event_bytes(family: u16) -> Vec<u8> {
    let mut bytes = vec![0_u8; SOCKET_EVENT_SIZE];
    bytes[0..2].copy_from_slice(&SOCKET_EVENT_VERSION.to_ne_bytes());
    bytes[2..4].copy_from_slice(&(SOCKET_EVENT_SIZE as u16).to_ne_bytes());
    bytes[4..8].copy_from_slice(&4242_u32.to_ne_bytes());
    bytes[8..12].copy_from_slice(&1000_u32.to_ne_bytes());
    bytes[12..14].copy_from_slice(&family.to_ne_bytes());
    bytes[14] = 6;
    bytes[15] = SocketEventKind::TcpConnect as u8;
    bytes[16..18].copy_from_slice(&50_000_u16.to_ne_bytes());
    bytes[18..20].copy_from_slice(&443_u16.to_ne_bytes());
    bytes[24..32].copy_from_slice(&123_456_u64.to_ne_bytes());
    bytes[32..36].copy_from_slice(b"curl");
    if family == 2 {
        bytes[48..52].copy_from_slice(&[192, 0, 2, 10]);
        bytes[64..68].copy_from_slice(&[198, 51, 100, 7]);
    } else {
        bytes[48..64].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        bytes[64..80].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    }
    bytes
}

#[test]
fn decodes_ipv4_and_socket_scope_csv() {
    let event = SocketEbpfEvent::decode(&event_bytes(2)).unwrap();
    assert_eq!(event.local_addr.to_string(), "192.0.2.10");
    assert_eq!(event.remote_addr.to_string(), "198.51.100.7");
    assert_eq!(event.local_port, 50_000);
    assert_eq!(event.process, "curl");
    assert_eq!(event.kind, SocketEventKind::TcpConnect);
    assert_eq!(event.socket_fd, None);
    assert_eq!(
        event.to_socket_scope_csv(),
        "TCP,192.0.2.10,50000,198.51.100.7,443,4242,1000,curl,curl"
    );
}

#[test]
fn decodes_ipv6_addresses() {
    let event = SocketEbpfEvent::decode(&event_bytes(10)).unwrap();
    assert_eq!(event.local_addr.to_string(), "2001:db8::1");
    assert_eq!(event.remote_addr.to_string(), "2001:db8::2");
}

#[test]
fn rejects_wrong_size_version_family_protocol_and_process() {
    assert!(SocketEbpfEvent::decode(&event_bytes(2)[..20]).is_err());
    let mut bytes = event_bytes(2);
    bytes[0..2].copy_from_slice(&99_u16.to_ne_bytes());
    assert!(SocketEbpfEvent::decode(&bytes).is_err());
    let mut bytes = event_bytes(99);
    assert!(SocketEbpfEvent::decode(&bytes).is_err());
    bytes = event_bytes(2);
    bytes[14] = 17;
    assert!(SocketEbpfEvent::decode(&bytes).is_err());
    bytes = event_bytes(2);
    bytes[15] = 99;
    assert!(SocketEbpfEvent::decode(&bytes).is_err());
    bytes = event_bytes(2);
    bytes[32..48].fill(0);
    assert!(SocketEbpfEvent::decode(&bytes).is_err());
}

#[test]
fn decodes_fd_lifecycle_events_without_inventing_endpoints() {
    for (kind, fd) in [
        (SocketEventKind::TcpAccept, 7_u32),
        (SocketEventKind::UdpSend, 8),
        (SocketEventKind::UdpReceive, 9),
    ] {
        let mut bytes = event_bytes(2);
        bytes[12..16].fill(0);
        bytes[15] = kind as u8;
        bytes[20..24].copy_from_slice(&fd.to_ne_bytes());
        let event = SocketEbpfEvent::decode(&bytes).unwrap();
        assert_eq!(event.kind, kind);
        assert_eq!(event.socket_fd, Some(fd as i32));
        assert!(event.local_addr.is_unspecified());
        assert!(event.remote_addr.is_unspecified());
    }
}

#[test]
fn evaluates_kernel_compatibility_without_root() {
    assert_eq!(
        KernelVersion::parse("6.8.0-52-generic").unwrap(),
        KernelVersion { major: 6, minor: 8 }
    );
    let supported = compatibility_report("6.8.0", true, true);
    assert!(supported.compatible);
    let old = compatibility_report("5.4.0", true, true);
    assert!(!old.compatible);
    assert!(old.reasons.iter().any(|reason| reason.contains("5.8")));
    let missing = compatibility_report("6.8.0", false, false);
    assert!(!missing.compatible);
    assert_eq!(missing.reasons.len(), 2);
}

#[test]
fn socket_scope_incrementally_imports_events_and_loss_stats() {
    use std::io::Write;
    let path = std::env::temp_dir().join(format!("packrat-ebpf-events-{}.csv", std::process::id()));
    std::fs::write(&path, "# socket events\n").unwrap();
    let mut scope = SocketScope::default();
    assert_eq!(scope.load_event_file(&path).unwrap(), 0);
    let event = SocketEbpfEvent::decode(&event_bytes(2)).unwrap();
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    writeln!(file, "{}", event.to_socket_scope_csv()).unwrap();
    writeln!(
        file,
        "# packrat-ebpf-stats received=1 kernel_lost=7 userspace_invalid=2"
    )
    .unwrap();
    assert_eq!(scope.refresh_event_file().unwrap(), 1);
    assert_eq!(scope.imported_events, 1);
    assert_eq!(scope.ebpf_lost_events, 7);
    assert_eq!(scope.ebpf_invalid_events, 2);
    assert_eq!(scope.owners[0].pid, 4242);
    assert_eq!(scope.refresh_event_file().unwrap(), 0);
    let _ = std::fs::remove_file(path);
}
