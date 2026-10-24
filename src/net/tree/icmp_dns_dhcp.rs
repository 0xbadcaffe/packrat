use super::*;

pub(super) fn icmp(raw: &[u8], tp_off: usize, sections: &mut Vec<TreeSection>) {
    let icmp_type = u8_at(raw, tp_off);
    let icmp_code = u8_at(raw, tp_off + 1);
    let icmp_id = u16_be(raw, tp_off + 4);
    let icmp_seq = u16_be(raw, tp_off + 6);
    let type_str = match icmp_type {
        0 => "0 (Echo Reply)",
        3 => "3 (Destination Unreachable)",
        8 => "8 (Echo Request)",
        11 => "11 (Time Exceeded)",
        _ => "unknown",
    };
    sections.push(TreeSection {
        title: "Internet Control Message Protocol".into(),
        expanded: true,
        fields: vec![
            tf("Type:", type_str, FieldColor::Yellow),
            tf("Code:", &icmp_code.to_string(), FieldColor::Default),
            tf(
                "Identifier:",
                &format!("0x{:04x}", icmp_id),
                FieldColor::Cyan,
            ),
            tf(
                "Sequence Number:",
                &icmp_seq.to_string(),
                FieldColor::Default,
            ),
        ],
    });
}

pub(super) fn dns(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(12345);
    let tid: u16 = (pkt.no.wrapping_mul(4294967291u64).wrapping_add(50u64) as u16);
    let name = DNS_NAMES[stable(pkt.no, DNS_NAMES.len())];
    let is_query = (pkt.no & 1) == 0;
    sections.push(TreeSection {
        title: format!("User Datagram Protocol, Src Port: {}, Dst Port: 53", sp),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", "53", FieldColor::Yellow),
        ],
    });
    let mut dns_fields = vec![
        tf(
            "Transaction ID:",
            &format!("0x{:04x}", tid),
            FieldColor::Cyan,
        ),
        tf(
            "Flags:",
            if is_query {
                "0x0100 Standard query"
            } else {
                "0x8180 Response"
            },
            FieldColor::Yellow,
        ),
        tf("Questions:", "1", FieldColor::Default),
        tf("Query Name:", name, FieldColor::Green),
        tf("Query Type:", "A", FieldColor::Cyan),
    ];
    if !is_query {
        dns_fields.push(tf(
            "Answer Addr:",
            &format!(
                "{}.{}.{}.{}",
                (1u8 + (pkt.no.wrapping_mul(2654435761u64).wrapping_add(300u64) % 253u64) as u8),
                (pkt.no.wrapping_mul(2246822519u64).wrapping_add(1u64) as u8),
                (pkt.no.wrapping_mul(3266489917u64).wrapping_add(2u64) as u8),
                (1u8 + (pkt.no.wrapping_mul(2246822519u64).wrapping_add(301u64) % 253u64) as u8)
            ),
            FieldColor::Orange,
        ));
    }
    sections.push(TreeSection {
        title: format!(
            "Domain Name System ({})",
            if is_query { "query" } else { "response" }
        ),
        expanded: true,
        fields: dns_fields,
    });
}

pub(super) fn dhcp(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(68);
    let dp = pkt.dst_port.unwrap_or(67);
    sections.push(TreeSection {
        title: format!("User Datagram Protocol, Src Port: {}, Dst Port: {}", sp, dp),
        expanded: true,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", &dp.to_string(), FieldColor::Yellow),
        ],
    });
    sections.push(TreeSection {
        title: "Dynamic Host Configuration Protocol".into(),
        expanded: true,
        fields: vec![
            tf("Message type:", "DHCP Discover (1)", FieldColor::Yellow),
            tf("Client IP:", "0.0.0.0", FieldColor::Default),
            tf("Your IP:", "0.0.0.0", FieldColor::Default),
            tf("Server IP:", "0.0.0.0", FieldColor::Default),
        ],
    });
}
