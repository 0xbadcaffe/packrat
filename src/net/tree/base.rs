use super::*;

pub(super) fn base_layers(pkt: &Packet) -> Vec<TreeSection> {
    let raw = &pkt.bytes;
    let eth_extra = match (pkt.outer_vlan_id.is_some(), pkt.vlan_id.is_some()) {
        (true, _) => 8usize,     // QinQ: two 4-byte tags
        (false, true) => 4usize, // single tag
        (false, false) => 0usize,
    };
    let ip_off = 14 + eth_extra;
    let mut sections = Vec::new();

    // Frame section
    sections.push(TreeSection {
        title: format!("Frame {}: {} bytes on wire", pkt.no, pkt.length),
        expanded: true,
        fields: vec![
            tf("Frame Number:", &pkt.no.to_string(), FieldColor::Cyan),
            tf(
                "Frame Length:",
                &format!("{} bytes", pkt.length),
                FieldColor::Yellow,
            ),
            tf(
                "Capture Length:",
                &format!("{} bytes", pkt.length),
                FieldColor::Default,
            ),
            tf(
                "Protocols:",
                &format!(
                    "eth:{}:{}",
                    if pkt.protocol == "ARP" { "arp" } else { "ip" },
                    pkt.protocol.to_lowercase()
                ),
                FieldColor::Green,
            ),
        ],
    });

    // VLAN tag(s) — outer S-TAG (QinQ) then inner C-TAG
    if let Some(ovid) = pkt.outer_vlan_id {
        sections.push(TreeSection {
            title: format!("802.1ad QinQ S-TAG, ID: {}", ovid),
            expanded: true,
            fields: vec![
                tf("Outer VLAN ID:", &ovid.to_string(), FieldColor::Cyan),
                tf("Tag Type:", "S-TAG (0x88a8, Provider)", FieldColor::Default),
            ],
        });
    }
    if let Some(vid) = pkt.vlan_id {
        let pcp = pkt.vlan_pcp.unwrap_or(0);
        let dei = pkt.vlan_dei.unwrap_or(0);
        let pcp_name = match pcp {
            0 => "Best Effort",
            1 => "Background",
            2 => "Spare",
            3 => "Excellent Effort",
            4 => "Controlled",
            5 => "Video < 100ms",
            6 => "Voice < 10ms",
            7 => "Network Control",
            _ => "Unknown",
        };
        sections.push(TreeSection {
            title: format!(
                "802.1Q Virtual LAN, PRI: {}, DEI: {}, ID: {}",
                pcp, dei, vid
            ),
            expanded: true,
            fields: vec![
                tf("VLAN ID:", &vid.to_string(), FieldColor::Cyan),
                tf(
                    "Priority (PCP):",
                    &format!("{} ({})", pcp, pcp_name),
                    FieldColor::Default,
                ),
                tf("DEI:", &dei.to_string(), FieldColor::Default),
            ],
        });
    }

    // Ethernet — read real MACs from bytes 0-11
    let dst_mac = parse_mac(raw, 0);
    let src_mac = parse_mac(raw, 6);
    let eth_type = if pkt.protocol == "ARP" {
        "ARP (0x0806)"
    } else {
        "IPv4 (0x0800)"
    };
    sections.push(TreeSection {
        title: format!("Ethernet II, Src: {}, Dst: {}", src_mac, dst_mac),
        expanded: true,
        fields: vec![
            tf("Destination:", &dst_mac, FieldColor::Cyan),
            tf("Source:", &src_mac, FieldColor::Cyan),
            tf("Type:", eth_type, FieldColor::Yellow),
        ],
    });

    if pkt.protocol == "ARP" {
        sections.push(TreeSection {
            title: "Address Resolution Protocol".into(),
            expanded: true,
            fields: vec![
                tf("Hardware type:", "Ethernet (1)", FieldColor::Default),
                tf("Protocol type:", "IPv4 (0x0800)", FieldColor::Default),
                tf("Opcode:", "request (1)", FieldColor::Yellow),
                tf("Sender IP:", &pkt.src, FieldColor::Green),
                tf("Target IP:", &pkt.dst, FieldColor::Red),
            ],
        });
        return sections;
    }

    // IP layer — read TTL and ID from real bytes
    let ttl: u8 = u8_at(raw, ip_off + 8);
    let id: u16 = u16_be(raw, ip_off + 4);
    let proto_num = match pkt.protocol.as_str() {
        "TCP" | "HTTP" | "HTTPS" | "TLS" | "SSH" | "SMTP" | "MySQL" | "Redis" | "PostgreSQL"
        | "IMAP" | "IMAPS" | "POP3" | "MongoDB" | "Elasticsearch" | "Modbus" | "MQTT"
        | "MQTT-TLS" | "OPC-UA" | "DNP3" | "S7comm" | "EtherNet/IP" | "IEC-104" | "SIP"
        | "SIPS" | "BGP" | "FTP" | "Telnet" | "LDAP" | "DoIP" | "SOME/IP" | "SMB" | "RDP"
        | "Kerberos" | "NetBIOS-SSN" | "RTSP" | "Kafka" | "AMQP" | "NATS" | "Memcached" | "VNC"
        | "Docker" | "Prometheus" | "etcd" => "6 (TCP)",
        "UDP" | "DNS" | "mDNS" | "DHCP" | "NTP" | "QUIC" | "SNMP" | "CoAP" | "CoAP-DTLS"
        | "BACnet" | "PTP" | "DHCPv6" | "VXLAN" | "WireGuard" | "GTP" | "Radius" | "WoL"
        | "SNMP-trap" | "Syslog" | "NBNS" | "TFTP" | "STUN" | "SSDP" | "RIP" | "RTP" => "17 (UDP)",
        "OSPF" => "89 (OSPF)",
        "EIGRP" => "88 (EIGRP)",
        "PIM" => "103 (PIM)",
        "ICMP" => "1 (ICMP)",
        "IGMP" => "2 (IGMP)",
        "GRE" => "47 (GRE)",
        "ESP" => "50 (ESP)",
        "AH" => "51 (AH)",
        "ICMPv6" => "58 (ICMPv6)",
        "VRRP" => "112 (VRRP)",
        _ => "6 (TCP)",
    };
    sections.push(TreeSection {
        title: format!(
            "Internet Protocol Version 4, Src: {}, Dst: {}",
            pkt.src, pkt.dst
        ),
        expanded: true,
        fields: vec![
            tf("Version:", "4", FieldColor::Default),
            tf("Header Length:", "20 bytes (5)", FieldColor::Default),
            tf("Total Length:", &pkt.length.to_string(), FieldColor::Yellow),
            tf(
                "Identification:",
                &format!("0x{:04x} ({})", id, id),
                FieldColor::Default,
            ),
            tf(
                "TTL:",
                &ttl.to_string(),
                if ttl < 64 {
                    FieldColor::Red
                } else {
                    FieldColor::Green
                },
            ),
            tf("Protocol:", proto_num, FieldColor::Cyan),
            tf("Src Address:", &pkt.src, FieldColor::Green),
            tf("Dst Address:", &pkt.dst, FieldColor::Orange),
        ],
    });

    // Transport layer
    sections
}
