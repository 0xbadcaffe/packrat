use super::*;

pub(super) fn some_ip(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(
        (1024u16 + (pkt.no.wrapping_mul(67108859u64).wrapping_add(136u64) % 64512u64) as u16),
    );
    let dp = pkt.dst_port.unwrap_or(30490);
    sections.push(TreeSection {
        title: format!("User Datagram Protocol, Src Port: {}, Dst Port: {}", sp, dp),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", &dp.to_string(), FieldColor::Yellow),
        ],
    });
    let service_id: u16 =
        (0x0100u16 + (pkt.no.wrapping_mul(374761393u64).wrapping_add(304u64) % 257u64) as u16);
    let method_id: u16 =
        (0x0001u16 + (pkt.no.wrapping_mul(2870177450u64).wrapping_add(305u64) % 15u64) as u16);
    let msg_types = [
        (0x00u8, "REQUEST"),
        (0x01, "REQUEST_NO_RETURN"),
        (0x02, "NOTIFICATION"),
        (0x80, "RESPONSE"),
        (0x81, "ERROR"),
    ];
    let (mt, mt_name) = msg_types[stable(pkt.no, msg_types.len())];
    let client_id: u16 = (pkt.no.wrapping_mul(987654323u64).wrapping_add(69u64) as u16);
    let session_id: u16 = (pkt.no.wrapping_mul(4294967291u64).wrapping_add(70u64) as u16);
    sections.push(TreeSection {
        title: format!("SOME/IP — {} (Service 0x{:04x})", mt_name, service_id),
        expanded: true,
        fields: vec![
            tf(
                "Service ID:",
                &format!("0x{:04x}", service_id),
                FieldColor::Cyan,
            ),
            tf(
                "Method ID:",
                &format!("0x{:04x}", method_id),
                FieldColor::Yellow,
            ),
            tf("Length:", &pkt.length.to_string(), FieldColor::Default),
            tf(
                "Client ID:",
                &format!("0x{:04x}", client_id),
                FieldColor::Default,
            ),
            tf(
                "Session ID:",
                &format!("0x{:04x}", session_id),
                FieldColor::Default,
            ),
            tf("Interface Version:", "1", FieldColor::Default),
            tf(
                "Message Type:",
                &format!("0x{:02x} ({})", mt, mt_name),
                FieldColor::Green,
            ),
            tf("Return Code:", "0x00 (E_OK)", FieldColor::Green),
        ],
    });
}

pub(super) fn mpls(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let label: u32 =
        ((16u64 + (pkt.no.wrapping_mul(33554467u64).wrapping_add(137u64) % 1048560u64)) as u32);
    let tc: u8 = ((0u64 + (pkt.no.wrapping_mul(16777259u64).wrapping_add(138u64) % 8u64)) as u8);
    sections.push(TreeSection {
        title: format!("MultiProtocol Label Switching (Label={})", label),
        expanded: true,
        fields: vec![
            tf("Label:", &label.to_string(), FieldColor::Cyan),
            tf("Traffic Class:", &tc.to_string(), FieldColor::Default),
            tf("Bottom of Stack:", "1", FieldColor::Default),
            tf(
                "TTL:",
                &(48u8 + (pkt.no.wrapping_mul(8388617u64).wrapping_add(139u64) % 81u64) as u8)
                    .to_string(),
                FieldColor::Default,
            ),
        ],
    });
}

pub(super) fn pppoe(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let code_names = ["PADI", "PADO", "PADR", "PADS", "PADT", "Session"];
    let cn = code_names[stable(pkt.no, code_names.len())];
    sections.push(TreeSection {
        title: format!("Point-to-Point Protocol over Ethernet ({})", cn),
        expanded: true,
        fields: vec![
            tf("Version:", "1", FieldColor::Default),
            tf("Type:", "1", FieldColor::Default),
            tf("Code:", cn, FieldColor::Yellow),
            tf(
                "Session ID:",
                &format!(
                    "0x{:04x}",
                    (pkt.no.wrapping_mul(2147483647u64).wrapping_add(31u64) as u16)
                ),
                FieldColor::Cyan,
            ),
            tf(
                "Payload Length:",
                &pkt.length.saturating_sub(6).to_string(),
                FieldColor::Default,
            ),
        ],
    });
}

pub(super) fn wol(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let mac = format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        ((pkt.no.wrapping_mul(3266489917u64).wrapping_add(202u64) >> 40) & 0xff) as u8,
        ((pkt.no.wrapping_mul(668265263u64).wrapping_add(203u64) >> 32) & 0xff) as u8,
        ((pkt.no.wrapping_mul(374761393u64).wrapping_add(204u64) >> 24) & 0xff) as u8,
        ((pkt.no.wrapping_mul(2870177450u64).wrapping_add(205u64) >> 16) & 0xff) as u8,
        ((pkt.no.wrapping_mul(1145919239u64).wrapping_add(206u64) >> 8) & 0xff) as u8,
        (pkt.no.wrapping_mul(3264354801u64).wrapping_add(207u64) & 0xff) as u8
    );
    sections.push(TreeSection {
        title: "Wake on LAN (Magic Packet)".into(),
        expanded: true,
        fields: vec![
            tf("Sync Stream:", "0xffffffffffff", FieldColor::Default),
            tf("Target MAC:", &mac, FieldColor::Cyan),
            tf("MAC Repetitions:", "16", FieldColor::Default),
        ],
    });
}

pub(super) fn smb(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(
        (1024u16 + (pkt.no.wrapping_mul(2654435761u64).wrapping_add(140u64) % 64512u64) as u16),
    );
    sections.push(TreeSection {
        title: format!(
            "Transmission Control Protocol, Src Port: {}, Dst Port: 445",
            sp
        ),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", "445", FieldColor::Yellow),
        ],
    });
    let cmds = [
        "Negotiate",
        "SessionSetup",
        "TreeConnect",
        "Create",
        "Read",
        "Write",
        "Close",
        "Ioctl",
        "QueryInfo",
    ];
    let cmd = cmds[stable(pkt.no, cmds.len())];
    let dialects = ["SMB 2.0.2", "SMB 2.1", "SMB 3.0", "SMB 3.1.1"];
    let dialect = dialects[stable(pkt.no, dialects.len())];
    let session: u64 = pkt.no.wrapping_mul(1073741827u64).wrapping_add(32u64) & 0xFFFFFFFFFFFF;
    let tree_id: u32 = (pkt.no.wrapping_mul(2147483647u64).wrapping_add(71u64) as u32);
    sections.push(TreeSection {
        title: format!("SMB2 (Server Message Block 2) — {}", cmd),
        expanded: true,
        fields: vec![
            tf("Protocol ID:", "0xfe534d42 (SMB2)", FieldColor::Cyan),
            tf("Header Length:", "64", FieldColor::Default),
            tf("Dialect:", dialect, FieldColor::Yellow),
            tf("Command:", cmd, FieldColor::Green),
            tf(
                "NT Status:",
                "0x00000000 (STATUS_SUCCESS)",
                FieldColor::Default,
            ),
            tf(
                "Session ID:",
                &format!("0x{:012x}", session),
                FieldColor::Cyan,
            ),
            tf(
                "Tree ID:",
                &format!("0x{:08x}", tree_id),
                FieldColor::Default,
            ),
            tf(
                "Message ID:",
                &pkt.no
                    .wrapping_mul(536870923u64)
                    .wrapping_add(33u64)
                    .to_string(),
                FieldColor::Default,
            ),
        ],
    });
}
