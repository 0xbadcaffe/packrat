use super::*;

pub(super) fn ah(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let spi: u32 = (pkt.no.wrapping_mul(2870177450u64).wrapping_add(65u64) as u32);
    let seq: u32 = (pkt.no.wrapping_mul(1145919239u64).wrapping_add(66u64) as u32);
    sections.push(TreeSection {
        title: "IPSec Authentication Header (AH)".into(),
        expanded: true,
        fields: vec![
            tf("Next Header:", "6 (TCP)", FieldColor::Default),
            tf("Length:", "4", FieldColor::Default),
            tf("SPI:", &format!("0x{:08x}", spi), FieldColor::Cyan),
            tf("Sequence Number:", &seq.to_string(), FieldColor::Default),
            tf(
                "ICV:",
                &format!(
                    "0x{:032x}",
                    pkt.no.wrapping_mul(1452813781u64).wrapping_add(28u64)
                ),
                FieldColor::Green,
            ),
        ],
    });
}

pub(super) fn gtp(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(
        (1024u16 + (pkt.no.wrapping_mul(1073741827u64).wrapping_add(132u64) % 64512u64) as u16),
    );
    sections.push(TreeSection {
        title: format!("User Datagram Protocol, Src Port: {}, Dst Port: 2152", sp),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", "2152", FieldColor::Yellow),
        ],
    });
    let msg_types = [
        (0xffu8, "G-PDU"),
        (16, "Create PDP Ctx Req"),
        (17, "Create PDP Ctx Resp"),
        (18, "Update PDP Ctx Req"),
        (26, "Error Indication"),
    ];
    let (mt, mt_name) = msg_types[stable(pkt.no, msg_types.len())];
    let teid: u32 = (pkt.no.wrapping_mul(3264354801u64).wrapping_add(67u64) as u32);
    sections.push(TreeSection {
        title: format!("GPRS Tunneling Protocol v1 (GTP) — {}", mt_name),
        expanded: true,
        fields: vec![
            tf("Version:", "1", FieldColor::Cyan),
            tf("PT:", "1 (GTP)", FieldColor::Default),
            tf(
                "Message Type:",
                &format!("0x{:02x} ({})", mt, mt_name),
                FieldColor::Yellow,
            ),
            tf("Length:", &pkt.length.to_string(), FieldColor::Default),
            tf("TEID:", &format!("0x{:08x}", teid), FieldColor::Cyan),
            tf(
                "Sequence Number:",
                &(pkt.no.wrapping_mul(987654323u64).wrapping_add(29u64) as u16).to_string(),
                FieldColor::Default,
            ),
        ],
    });
}

pub(super) fn radius(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(
        (1024u16 + (pkt.no.wrapping_mul(536870923u64).wrapping_add(133u64) % 64512u64) as u16),
    );
    let dp = pkt.dst_port.unwrap_or(1812);
    sections.push(TreeSection {
        title: format!("User Datagram Protocol, Src Port: {}, Dst Port: {}", sp, dp),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", &dp.to_string(), FieldColor::Yellow),
        ],
    });
    let codes = [
        (1u8, "Access-Request"),
        (2, "Access-Accept"),
        (3, "Access-Reject"),
        (4, "Accounting-Request"),
        (5, "Accounting-Response"),
        (11, "Access-Challenge"),
    ];
    let (code, code_name) = codes[stable(pkt.no, codes.len())];
    let id: u8 = (pkt.no.wrapping_mul(1452813781u64).wrapping_add(68u64) as u8);
    sections.push(TreeSection {
        title: format!("RADIUS — {}", code_name),
        expanded: true,
        fields: vec![
            tf(
                "Code:",
                &format!("{} ({})", code, code_name),
                FieldColor::Yellow,
            ),
            tf("ID:", &id.to_string(), FieldColor::Cyan),
            tf("Length:", &pkt.length.to_string(), FieldColor::Default),
            tf(
                "Authenticator:",
                &format!(
                    "0x{:032x}",
                    pkt.no.wrapping_mul(4294967291u64).wrapping_add(30u64)
                ),
                FieldColor::Default,
            ),
            tf("User-Name:", "user@example.com", FieldColor::Green),
            tf("NAS-IP-Address:", &pkt.src, FieldColor::Cyan),
            tf(
                "NAS-Port:",
                &(1u32 + (pkt.no.wrapping_mul(268435459u64).wrapping_add(134u64) % 100u64) as u32)
                    .to_string(),
                FieldColor::Default,
            ),
        ],
    });
}

pub(super) fn doip(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(
        (1024u16 + (pkt.no.wrapping_mul(134217757u64).wrapping_add(135u64) % 64512u64) as u16),
    );
    sections.push(TreeSection {
        title: format!(
            "Transmission Control Protocol, Src Port: {}, Dst Port: 13400",
            sp
        ),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", "13400", FieldColor::Yellow),
        ],
    });
    let payloads = [
        (0x0001u16, "Routing Activation Request"),
        (0x0002, "Routing Activation Response"),
        (0x8001, "Diagnostic Message"),
        (0x8002, "Diagnostic Message Positive Ack"),
        (0x8003, "Diagnostic Message Negative Ack"),
        (0x4001, "Vehicle Announcement"),
    ];
    let (pt, pt_name) = payloads[stable(pkt.no, payloads.len())];
    let src_addr: u16 =
        (0x0e00u16 + (pkt.no.wrapping_mul(3266489917u64).wrapping_add(302u64) % 256u64) as u16);
    let tgt_addr: u16 =
        (0x0001u16 + (pkt.no.wrapping_mul(668265263u64).wrapping_add(303u64) % 255u64) as u16);
    sections.push(TreeSection {
        title: format!("Diagnostic over IP (DoIP) — {}", pt_name),
        expanded: true,
        fields: vec![
            tf(
                "Protocol Version:",
                "0x02 (ISO 13400-2:2012)",
                FieldColor::Cyan,
            ),
            tf("Inverse Version:", "0xfd", FieldColor::Default),
            tf(
                "Payload Type:",
                &format!("0x{:04x} ({})", pt, pt_name),
                FieldColor::Yellow,
            ),
            tf(
                "Payload Length:",
                &pkt.length.to_string(),
                FieldColor::Default,
            ),
            tf(
                "Source Address:",
                &format!("0x{:04x}", src_addr),
                FieldColor::Green,
            ),
            tf(
                "Target Address:",
                &format!("0x{:04x}", tgt_addr),
                FieldColor::Orange,
            ),
        ],
    });
}
