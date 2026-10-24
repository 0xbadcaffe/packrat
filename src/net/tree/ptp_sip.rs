use super::*;

pub(super) fn ptp(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(319);
    let dp = pkt.dst_port.unwrap_or(319);
    sections.push(TreeSection {
        title: format!("User Datagram Protocol, Src Port: {}, Dst Port: {}", sp, dp),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", &dp.to_string(), FieldColor::Yellow),
        ],
    });
    let msg_types = [
        (0u8, "Sync"),
        (1, "Delay_Req"),
        (8, "Follow_Up"),
        (9, "Delay_Resp"),
        (11, "Announce"),
        (12, "Signaling"),
    ];
    let (mt, mt_name) = msg_types[stable(pkt.no, msg_types.len())];
    let domain: u8 =
        ((0u64 + (pkt.no.wrapping_mul(2870177450u64).wrapping_add(105u64) % 4u64)) as u8);
    let seq_id: u16 = (pkt.no.wrapping_mul(33554467u64).wrapping_add(57u64) as u16);
    let clock_hi: u32 = (pkt.no.wrapping_mul(16777259u64).wrapping_add(58u64) as u32);
    let clock_lo: u32 = (pkt.no.wrapping_mul(8388617u64).wrapping_add(59u64) as u32);
    sections.push(TreeSection {
        title: format!("Precision Time Protocol v2 (IEEE 1588) — {}", mt_name),
        expanded: true,
        fields: vec![
            tf(
                "Message Type:",
                &format!("0x{:02x} ({})", mt, mt_name),
                FieldColor::Yellow,
            ),
            tf("Version PTP:", "2", FieldColor::Cyan),
            tf("Message Length:", "44", FieldColor::Default),
            tf("Domain Number:", &domain.to_string(), FieldColor::Default),
            tf("Flags:", "0x0000", FieldColor::Default),
            tf("Correction Field:", "0 ns", FieldColor::Default),
            tf(
                "Clock Identity:",
                &format!("0x{:08x}{:08x}", clock_hi, clock_lo),
                FieldColor::Cyan,
            ),
            tf("Source Port ID:", "1", FieldColor::Default),
            tf("Sequence ID:", &seq_id.to_string(), FieldColor::Yellow),
            tf(
                "Control Field:",
                &format!("0x{:02x}", mt),
                FieldColor::Default,
            ),
            tf("Log Message Interval:", "-1", FieldColor::Default),
        ],
    });
}

pub(super) fn sip(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(
        (5060u16 + (pkt.no.wrapping_mul(1145919239u64).wrapping_add(106u64) % 11u64) as u16),
    );
    let dp = pkt.dst_port.unwrap_or(5060);
    sections.push(TreeSection {
        title: format!("User Datagram Protocol, Src Port: {}, Dst Port: {}", sp, dp),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", &dp.to_string(), FieldColor::Yellow),
        ],
    });
    let methods = [
        ("INVITE", "Initiate session"),
        ("BYE", "Terminate session"),
        ("ACK", "Acknowledge"),
        ("REGISTER", "Register UA"),
        ("OPTIONS", "Query capabilities"),
        ("CANCEL", "Cancel pending request"),
    ];
    let (method, _desc) = methods[stable(pkt.no, methods.len())];
    let ext: u16 =
        ((1000u64 + (pkt.no.wrapping_mul(3264354801u64).wrapping_add(107u64) % 9000u64)) as u16);
    let call_id = format!(
        "{:08x}-{:04x}@sip.local",
        (pkt.no.wrapping_mul(987654323u64).wrapping_add(9u64) as u32),
        (pkt.no.wrapping_mul(4294967291u64).wrapping_add(10u64) as u16)
    );
    let cseq: u32 =
        ((1u64 + (pkt.no.wrapping_mul(1452813781u64).wrapping_add(108u64) % 100u64)) as u32);
    sections.push(TreeSection {
        title: format!("Session Initiation Protocol — {}", method),
        expanded: true,
        fields: vec![
            tf("Method:", method, FieldColor::Green),
            tf(
                "Request-URI:",
                &format!("sip:{}@{}", ext, pkt.dst),
                FieldColor::Cyan,
            ),
            tf(
                "Via:",
                &format!(
                    "SIP/2.0/UDP {};branch=z9hG4bK{:08x}",
                    pkt.src,
                    (pkt.no.wrapping_mul(2147483647u64).wrapping_add(11u64) as u32)
                ),
                FieldColor::Default,
            ),
            tf(
                "From:",
                &format!("<sip:user@{}>", pkt.src),
                FieldColor::Yellow,
            ),
            tf("To:", &format!("<sip:{}>", ext), FieldColor::Yellow),
            tf("Call-ID:", &call_id, FieldColor::Cyan),
            tf(
                "CSeq:",
                &format!("{} {}", cseq, method),
                FieldColor::Default,
            ),
            tf("Max-Forwards:", "70", FieldColor::Default),
            tf("Content-Length:", "0", FieldColor::Default),
        ],
    });
}
