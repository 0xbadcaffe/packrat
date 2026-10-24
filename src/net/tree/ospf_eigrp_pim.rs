use super::*;

pub(super) fn ospf(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let msg_types = [
        "Hello",
        "Database Description",
        "Link State Request",
        "Link State Update",
        "Link State Acknowledgment",
    ];
    let mt_idx = stable(pkt.no, msg_types.len());
    let mt_name = msg_types[mt_idx];
    let router_id = format!(
        "{}.{}.{}.{}",
        (1u8 + (pkt.no.wrapping_mul(2147483647u64).wrapping_add(171u64) % 10u64) as u8),
        (pkt.no.wrapping_mul(668265263u64).wrapping_add(43u64) as u8),
        (pkt.no.wrapping_mul(374761393u64).wrapping_add(44u64) as u8),
        (1u8 + (pkt.no.wrapping_mul(1073741827u64).wrapping_add(172u64) % 10u64) as u8)
    );
    let area_id = format!(
        "0.0.0.{}",
        (0u8 + (pkt.no.wrapping_mul(536870923u64).wrapping_add(173u64) % 4u64) as u8)
    );
    let hello_or_lsa = if mt_idx == 0 {
        tf("Hello Interval:", "10", FieldColor::Default)
    } else {
        tf(
            "LSA Count:",
            &(1u8 + (pkt.no.wrapping_mul(268435459u64).wrapping_add(174u64) % 10u64) as u8)
                .to_string(),
            FieldColor::Default,
        )
    };
    sections.push(TreeSection {
        title: format!("Open Shortest Path First v2 — {}", mt_name),
        expanded: true,
        fields: vec![
            tf("Version:", "2", FieldColor::Cyan),
            tf(
                "Message Type:",
                &format!("{} ({})", mt_idx + 1, mt_name),
                FieldColor::Yellow,
            ),
            tf("Router ID:", &router_id, FieldColor::Green),
            tf("Area ID:", &area_id, FieldColor::Cyan),
            tf("Auth Type:", "0 (None)", FieldColor::Default),
            hello_or_lsa,
        ],
    });
}

pub(super) fn eigrp(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let ops = [
        (1u8, "Update"),
        (3, "Query"),
        (4, "Reply"),
        (5, "Hello"),
        (10, "SIA-Query"),
        (11, "SIA-Reply"),
    ];
    let (op, op_name) = ops[stable(pkt.no, ops.len())];
    let asn: u16 =
        ((1u64 + (pkt.no.wrapping_mul(134217757u64).wrapping_add(175u64) % 65535u64)) as u16);
    sections.push(TreeSection {
        title: format!("Enhanced Interior Gateway Routing Protocol — {}", op_name),
        expanded: true,
        fields: vec![
            tf("Version:", "2", FieldColor::Cyan),
            tf(
                "Opcode:",
                &format!("{} ({})", op, op_name),
                FieldColor::Yellow,
            ),
            tf("AS Number:", &asn.to_string(), FieldColor::Green),
            tf(
                "Sequence:",
                &(pkt.no.wrapping_mul(2870177450u64).wrapping_add(45u64) as u32).to_string(),
                FieldColor::Default,
            ),
            tf(
                "Ack:",
                &(pkt.no.wrapping_mul(1145919239u64).wrapping_add(46u64) as u32).to_string(),
                FieldColor::Default,
            ),
        ],
    });
}

pub(super) fn pim(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let types = [
        "Hello",
        "Register",
        "Register-Stop",
        "Join/Prune",
        "Bootstrap",
        "Assert",
    ];
    let mt_idx = stable(pkt.no, types.len());
    let mt_name = types[mt_idx];
    let group = format!(
        "239.{}.{}.{}",
        (1u8 + (pkt.no.wrapping_mul(67108859u64).wrapping_add(176u64) % 2u64) as u8),
        (pkt.no.wrapping_mul(3264354801u64).wrapping_add(47u64) as u8),
        (1u8 + (pkt.no.wrapping_mul(33554467u64).wrapping_add(177u64) % 254u64) as u8)
    );
    sections.push(TreeSection {
        title: format!("Protocol Independent Multicast — {}", mt_name),
        expanded: true,
        fields: vec![
            tf("Version:", "2", FieldColor::Cyan),
            tf(
                "Type:",
                &format!("{} ({})", mt_idx, mt_name),
                FieldColor::Yellow,
            ),
            tf("Group:", &group, FieldColor::Green),
            tf(
                "Checksum:",
                &format!(
                    "0x{:04x}",
                    (pkt.no.wrapping_mul(1452813781u64).wrapping_add(48u64) as u16)
                ),
                FieldColor::Default,
            ),
        ],
    });
}
