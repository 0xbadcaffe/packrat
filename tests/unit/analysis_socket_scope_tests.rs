use super::*;

#[test]
fn parses_linux_ipv4_socket_row() {
    let row = parse_socket_row(
        "  0: 0100007F:1F90 070000CB:C350 01 00000000:00000000 00:00000000 00000000 1000 0 12345 1",
        "TCP",
        false,
    ).unwrap();
    assert_eq!(row.local_addr, "127.0.0.1".parse::<IpAddr>().unwrap());
    assert_eq!(row.local_port, 8080);
    assert_eq!(row.remote_addr, "203.0.0.7".parse::<IpAddr>().unwrap());
    assert_eq!(row.remote_port, 50000);
    assert_eq!(row.inode, 12345);
}

#[test]
fn imported_event_owner_attributes_matching_packet() {
    let path = std::env::temp_dir().join(format!("packrat-socket-events-{}.csv", std::process::id()));
    std::fs::write(
        &path,
        "tcp,192.0.2.10,4444,198.51.100.7,443,4242,1000,curl,curl https://example.test\n",
    ).unwrap();
    let mut scope = SocketScope::default();
    assert_eq!(scope.load_event_file(&path).unwrap(), 1);
    let packet = Packet { capture: None,
        no: 1,
        timestamp: 7.0,
        src: "192.0.2.10".into(),
        dst: "198.51.100.7".into(),
        protocol: "TCP".into(),
        length: 120,
        info: String::new(),
        src_port: Some(4444),
        dst_port: Some(443),
        vlan_id: None,
        vlan_pcp: None,
        vlan_dei: None,
        outer_vlan_id: None,
        bytes: Vec::new(),
    };
    assert_eq!(scope.observe(&packet).as_deref(), Some("curl"));
    let usage = scope.traffic.get(&4242).unwrap();
    assert_eq!(usage.bytes_out, 120);
    assert_eq!(usage.packets_out, 1);
    let _ = std::fs::remove_file(path);
}
