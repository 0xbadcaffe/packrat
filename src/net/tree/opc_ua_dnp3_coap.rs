use super::*;

pub(super) fn opc_ua(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(1024);
    sections.push(TreeSection {
        title: format!(
            "Transmission Control Protocol, Src Port: {}, Dst Port: 4840",
            sp
        ),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", "4840", FieldColor::Yellow),
        ],
    });
    let services = [
        (631u32, "ReadRequest"),
        (634, "ReadResponse"),
        (673, "WriteRequest"),
        (676, "WriteResponse"),
        (527, "CreateSessionRequest"),
        (461, "Browse"),
        (839, "PublishRequest"),
        (842, "PublishResponse"),
    ];
    let (svc_id, svc_name) = services[stable(pkt.no, services.len())];
    let ns: u8 = ((1u64 + (pkt.no.wrapping_mul(16777259u64).wrapping_add(98u64) % 3u64)) as u8);
    let node: u16 =
        ((1000u64 + (pkt.no.wrapping_mul(8388617u64).wrapping_add(99u64) % 9000u64)) as u16);
    let req_id: u32 =
        ((1u64 + (pkt.no.wrapping_mul(2654435761u64).wrapping_add(100u64) % 9999u64)) as u32);
    sections.push(TreeSection {
        title: "OPC UA Binary".into(),
        expanded: true,
        fields: vec![
            tf("Message Type:", "MSG", FieldColor::Cyan),
            tf("Chunk Type:", "F (Final)", FieldColor::Default),
            tf(
                "Message Size:",
                &pkt.length.to_string(),
                FieldColor::Default,
            ),
            tf(
                "Security Channel ID:",
                &format!(
                    "0x{:08x}",
                    (pkt.no.wrapping_mul(1145919239u64).wrapping_add(6u64) as u32)
                ),
                FieldColor::Default,
            ),
            tf("Request ID:", &req_id.to_string(), FieldColor::Yellow),
            tf(
                "Service:",
                &format!("{} (id={})", svc_name, svc_id),
                FieldColor::Green,
            ),
            tf(
                "Node ID:",
                &format!("ns={};i={}", ns, node),
                FieldColor::Cyan,
            ),
        ],
    });
}

pub(super) fn dnp3(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(1024);
    sections.push(TreeSection {
        title: format!(
            "Transmission Control Protocol, Src Port: {}, Dst Port: 20000",
            sp
        ),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", "20000", FieldColor::Yellow),
        ],
    });
    let fn_codes = [
        (1u8, "Read"),
        (2, "Write"),
        (3, "Select"),
        (4, "Operate"),
        (5, "Direct Operate"),
        (129, "Response"),
        (130, "Unsolicited Response"),
    ];
    let (fc, fc_name) = fn_codes[stable(pkt.no, fn_codes.len())];
    let dst_addr: u16 =
        ((1u64 + (pkt.no.wrapping_mul(2246822519u64).wrapping_add(101u64) % 10u64)) as u16);
    let src_addr: u16 =
        ((1u64 + (pkt.no.wrapping_mul(3266489917u64).wrapping_add(102u64) % 5u64)) as u16);
    sections.push(TreeSection {
        title: "DNP3 Application Layer".into(),
        expanded: true,
        fields: vec![
            tf("Start:", "0x0564", FieldColor::Cyan),
            tf("Length:", &pkt.length.to_string(), FieldColor::Default),
            tf("Control:", "0x44", FieldColor::Default),
            tf("Destination:", &dst_addr.to_string(), FieldColor::Yellow),
            tf("Source:", &src_addr.to_string(), FieldColor::Green),
            tf(
                "Function Code:",
                &format!("{} ({})", fc, fc_name),
                FieldColor::Green,
            ),
            tf("IIN:", "0x0000", FieldColor::Default),
        ],
    });
}

pub(super) fn coap(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(1024);
    let dp = if pkt.protocol == "CoAP-DTLS" {
        5684u16
    } else {
        5683
    };
    sections.push(TreeSection {
        title: format!("User Datagram Protocol, Src Port: {}, Dst Port: {}", sp, dp),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", &dp.to_string(), FieldColor::Yellow),
        ],
    });
    let coap_types = [(0u8, "CON"), (1, "NON"), (2, "ACK"), (3, "RST")];
    let (ct, ct_name) = coap_types[stable(pkt.no, coap_types.len())];
    let codes = [(1u8, "GET"), (2, "POST"), (3, "PUT"), (4, "DELETE")];
    let (code, code_name) = codes[stable(pkt.no, codes.len())];
    let mid: u16 = (pkt.no.wrapping_mul(268435459u64).wrapping_add(54u64) as u16);
    let resources = [
        "/sensors/temp",
        "/sensors/pressure",
        "/actuators/relay",
        "/status",
    ];
    let res = resources[stable(pkt.no, resources.len())];
    sections.push(TreeSection {
        title: "Constrained Application Protocol".into(),
        expanded: true,
        fields: vec![
            tf("Version:", "1", FieldColor::Default),
            tf(
                "Type:",
                &format!("{} ({})", ct, ct_name),
                FieldColor::Yellow,
            ),
            tf("Token Length:", "4", FieldColor::Default),
            tf(
                "Code:",
                &format!("0.0{} {}", code, code_name),
                FieldColor::Green,
            ),
            tf("Message ID:", &format!("0x{:04x}", mid), FieldColor::Cyan),
            tf(
                "Token:",
                &format!(
                    "0x{:08x}",
                    (pkt.no.wrapping_mul(3264354801u64).wrapping_add(7u64) as u32)
                ),
                FieldColor::Default,
            ),
            tf("Uri-Path:", res, FieldColor::Cyan),
        ],
    });
}
