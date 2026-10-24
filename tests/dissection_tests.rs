#[path = "support/packets.rs"]
mod packets;

use packrat_tui::net::tree::build_tree;

#[test]
fn every_simulated_protocol_keeps_its_dissection_layers() {
    let protocols = [
        "ARP",
        "ICMP",
        "ICMPv6",
        "DNS",
        "mDNS",
        "DHCP",
        "NTP",
        "QUIC",
        "TCP",
        "UDP",
        "TLS",
        "HTTP",
        "SSH",
        "Modbus",
        "MQTT",
        "MQTT-TLS",
        "OPC-UA",
        "DNP3",
        "CoAP",
        "CoAP-DTLS",
        "BACnet",
        "S7comm",
        "EtherNet/IP",
        "PTP",
        "SIP",
        "SIPS",
        "BGP",
        "FTP",
        "Telnet",
        "LDAP",
        "DHCPv6",
        "VXLAN",
        "WireGuard",
        "GRE",
        "IGMP",
        "VRRP",
        "ESP",
        "AH",
        "GTP",
        "Radius",
        "DoIP",
        "SOME/IP",
        "MPLS",
        "PPPoE",
        "WoL",
        "SMB",
        "RDP",
        "Kerberos",
        "NetBIOS-SSN",
        "RTSP",
        "Kafka",
        "AMQP",
        "NATS",
        "Memcached",
        "VNC",
        "Docker",
        "Prometheus",
        "etcd",
        "NBNS",
        "TFTP",
        "STUN",
        "SSDP",
        "RIP",
        "RTP",
        "OSPF",
        "EIGRP",
        "PIM",
    ];
    for protocol in protocols {
        let mut packet = packets::tcp(7, 100, 0x18, b"sample");
        packet.protocol = protocol.into();
        let sections = build_tree(&packet, true);
        assert!(sections.len() >= 3, "missing base layers for {protocol}");
        assert!(
            sections.iter().all(|section| !section.title.is_empty()),
            "{protocol}"
        );
        for length in [0, 1, 13, 14, 34, 53] {
            let mut truncated = packet.clone();
            truncated.bytes.truncate(length);
            assert!(
                !build_tree(&truncated, true).is_empty(),
                "{protocol}: {length}"
            );
        }
    }
}

#[test]
fn real_dissection_never_uses_the_simulated_protocol_fixture() {
    let mut packet = packets::tcp(9, 1234, 0x18, b"payload");
    packet.protocol = "MQTT".into();
    let sections = build_tree(&packet, false);
    let fields: Vec<_> = sections
        .iter()
        .flat_map(|section| section.fields.iter())
        .collect();
    assert!(fields.iter().any(|field| field.val == "1234"));
    assert!(
        !sections
            .iter()
            .any(|section| section.title.contains("MQTT"))
    );
}
