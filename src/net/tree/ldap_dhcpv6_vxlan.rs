use super::*;

pub(super) fn ldap(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(
        (1024u16 + (pkt.no.wrapping_mul(33554467u64).wrapping_add(117u64) % 64512u64) as u16),
    );
    sections.push(TreeSection {
        title: format!(
            "Transmission Control Protocol, Src Port: {}, Dst Port: 389",
            sp
        ),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", "389", FieldColor::Yellow),
        ],
    });
    let ops = [
        (0u8, "BindRequest"),
        (1, "BindResponse"),
        (3, "SearchRequest"),
        (4, "SearchResultEntry"),
        (5, "SearchResultDone"),
        (6, "ModifyRequest"),
        (8, "AddRequest"),
        (10, "DelRequest"),
    ];
    let (op, op_name) = ops[stable(pkt.no, ops.len())];
    let msg_id: u32 =
        ((1u64 + (pkt.no.wrapping_mul(16777259u64).wrapping_add(118u64) % 9999u64)) as u32);
    sections.push(TreeSection {
        title: format!("Lightweight Directory Access Protocol (LDAP) — {}", op_name),
        expanded: true,
        fields: vec![
            tf("Message ID:", &msg_id.to_string(), FieldColor::Cyan),
            tf(
                "Operation:",
                &format!("{} ({})", op_name, op),
                FieldColor::Yellow,
            ),
            tf("Base Object:", "dc=example,dc=com", FieldColor::Green),
            tf("Scope:", "2 (wholeSubtree)", FieldColor::Default),
            tf("Filter:", "(objectClass=*)", FieldColor::Cyan),
        ],
    });
}

pub(super) fn dhcpv6(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(546);
    let dp = pkt.dst_port.unwrap_or(547);
    sections.push(TreeSection {
        title: format!("User Datagram Protocol, Src Port: {}, Dst Port: {}", sp, dp),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", &dp.to_string(), FieldColor::Yellow),
        ],
    });
    let msg_types = [
        (1u8, "Solicit"),
        (2, "Advertise"),
        (3, "Request"),
        (5, "Renew"),
        (7, "Reply"),
        (8, "Release"),
        (11, "Inform-request"),
    ];
    let (mt, mt_name) = msg_types[stable(pkt.no, msg_types.len())];
    let tid: u32 = (pkt.no.wrapping_mul(268435459u64).wrapping_add(14u64) as u32) & 0xFFFFFF;
    sections.push(TreeSection {
        title: format!("DHCPv6 — {}", mt_name),
        expanded: true,
        fields: vec![
            tf(
                "Message type:",
                &format!("{} ({})", mt, mt_name),
                FieldColor::Yellow,
            ),
            tf(
                "Transaction ID:",
                &format!("0x{:06x}", tid),
                FieldColor::Cyan,
            ),
            tf(
                "Client DUID:",
                &format!(
                    "0003000100{:012x}",
                    pkt.no.wrapping_mul(134217757u64).wrapping_add(15u64) & 0xFFFFFFFFFFFF
                ),
                FieldColor::Default,
            ),
            tf(
                "IA_NA:",
                &format!(
                    "IAID=0x{:08x}",
                    (pkt.no.wrapping_mul(67108859u64).wrapping_add(16u64) as u32)
                ),
                FieldColor::Default,
            ),
        ],
    });
}

pub(super) fn vxlan(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(
        (1024u16 + (pkt.no.wrapping_mul(8388617u64).wrapping_add(119u64) % 64512u64) as u16),
    );
    sections.push(TreeSection {
        title: format!("User Datagram Protocol, Src Port: {}, Dst Port: 4789", sp),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", "4789", FieldColor::Yellow),
        ],
    });
    let vni: u32 =
        ((1u64 + (pkt.no.wrapping_mul(2654435761u64).wrapping_add(120u64) % 16777215u64)) as u32);
    let inner_src = format!(
        "{}.{}.{}.{}",
        10u8,
        (pkt.no.wrapping_mul(33554467u64).wrapping_add(17u64) as u8),
        (pkt.no.wrapping_mul(16777259u64).wrapping_add(18u64) as u8),
        (1u8 + (pkt.no.wrapping_mul(3266489917u64).wrapping_add(122u64) % 254u64) as u8)
    );
    let inner_dst = format!(
        "{}.{}.{}.{}",
        10u8,
        (pkt.no.wrapping_mul(8388617u64).wrapping_add(19u64) as u8),
        (pkt.no.wrapping_mul(2654435761u64).wrapping_add(20u64) as u8),
        (1u8 + (pkt.no.wrapping_mul(374761393u64).wrapping_add(124u64) % 254u64) as u8)
    );
    sections.push(TreeSection {
        title: format!("Virtual eXtensible Local Area Network (VNI={})", vni),
        expanded: true,
        fields: vec![
            tf("Flags:", "0x08 (VNI present)", FieldColor::Default),
            tf("VNI:", &vni.to_string(), FieldColor::Yellow),
            tf("Reserved:", "0x000000", FieldColor::Default),
            tf(
                "Inner Src MAC:",
                &format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    ((pkt.no.wrapping_mul(4294967291u64).wrapping_add(190u64) >> 40) & 0xff) as u8,
                    ((pkt.no.wrapping_mul(2147483647u64).wrapping_add(191u64) >> 32) & 0xff) as u8,
                    ((pkt.no.wrapping_mul(1073741827u64).wrapping_add(192u64) >> 24) & 0xff) as u8,
                    ((pkt.no.wrapping_mul(536870923u64).wrapping_add(193u64) >> 16) & 0xff) as u8,
                    ((pkt.no.wrapping_mul(268435459u64).wrapping_add(194u64) >> 8) & 0xff) as u8,
                    (pkt.no.wrapping_mul(134217757u64).wrapping_add(195u64) & 0xff) as u8
                ),
                FieldColor::Cyan,
            ),
            tf(
                "Inner Dst MAC:",
                &format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    ((pkt.no.wrapping_mul(67108859u64).wrapping_add(196u64) >> 40) & 0xff) as u8,
                    ((pkt.no.wrapping_mul(33554467u64).wrapping_add(197u64) >> 32) & 0xff) as u8,
                    ((pkt.no.wrapping_mul(16777259u64).wrapping_add(198u64) >> 24) & 0xff) as u8,
                    ((pkt.no.wrapping_mul(8388617u64).wrapping_add(199u64) >> 16) & 0xff) as u8,
                    ((pkt.no.wrapping_mul(2654435761u64).wrapping_add(200u64) >> 8) & 0xff) as u8,
                    (pkt.no.wrapping_mul(2246822519u64).wrapping_add(201u64) & 0xff) as u8
                ),
                FieldColor::Cyan,
            ),
            tf("Inner Src IP:", &inner_src, FieldColor::Green),
            tf("Inner Dst IP:", &inner_dst, FieldColor::Orange),
        ],
    });
}
