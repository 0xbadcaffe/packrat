use super::*;

pub(super) fn bacnet(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(1024);
    sections.push(TreeSection {
        title: format!("User Datagram Protocol, Src Port: {}, Dst Port: 47808", sp),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", "47808 (0xBAC0)", FieldColor::Yellow),
        ],
    });
    let bvlc_fns = [
        (0x0au8, "Original-Unicast-NPDU"),
        (0x0b, "Original-Broadcast-NPDU"),
        (0x04, "Forwarded-NPDU"),
    ];
    let (bvlc_fn, bvlc_name) = bvlc_fns[stable(pkt.no, bvlc_fns.len())];
    let services = [
        "ReadProperty-Request",
        "WriteProperty-Request",
        "Who-Is",
        "I-Am",
        "SubscribeCOV-Request",
    ];
    let svc = services[stable(pkt.no, services.len())];
    let objs = [
        "Analog Input 1",
        "Analog Output 1",
        "Binary Input 2",
        "Binary Value 5",
        "Analog Value 10",
    ];
    let obj = objs[stable(pkt.no, objs.len())];
    let props = [
        "present-value",
        "object-name",
        "units",
        "description",
        "status-flags",
    ];
    let prop = props[stable(pkt.no, props.len())];
    sections.push(TreeSection {
        title: "BACnet/IP".into(),
        expanded: true,
        fields: vec![
            tf(
                "BVLC Function:",
                &format!("0x{:02x} ({})", bvlc_fn, bvlc_name),
                FieldColor::Cyan,
            ),
            tf("BVLC Length:", &pkt.length.to_string(), FieldColor::Default),
            tf("NPDU Version:", "1", FieldColor::Default),
            tf("Service:", svc, FieldColor::Green),
            tf("Object ID:", obj, FieldColor::Yellow),
            tf("Property:", prop, FieldColor::Cyan),
        ],
    });
}

pub(super) fn s7comm(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(1024);
    sections.push(TreeSection {
        title: format!(
            "Transmission Control Protocol, Src Port: {}, Dst Port: 102",
            sp
        ),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", "102 (ISO-TSAP)", FieldColor::Yellow),
        ],
    });
    let fns = [
        (0x04u8, "Read Var"),
        (0x05, "Write Var"),
        (0x1a, "Request Download"),
        (0x1b, "Download Block"),
        (0x29, "PLC Stop"),
        (0x28, "PLC Start"),
    ];
    let (fc, fc_name) = fns[stable(pkt.no, fns.len())];
    let db: u16 =
        ((1u64 + (pkt.no.wrapping_mul(668265263u64).wrapping_add(103u64) % 100u64)) as u16);
    let offset: u16 =
        ((0u64 + (pkt.no.wrapping_mul(374761393u64).wrapping_add(104u64) % 513u64)) as u16);
    let pdu_ref: u16 = (pkt.no.wrapping_mul(134217757u64).wrapping_add(55u64) as u16);
    sections.push(TreeSection {
        title: "S7 Communication".into(),
        expanded: true,
        fields: vec![
            tf("Header:", "0x32 (S7comm)", FieldColor::Cyan),
            tf("ROSCTR:", "1 (Job)", FieldColor::Yellow),
            tf(
                "PDU Reference:",
                &format!("0x{:04x}", pdu_ref),
                FieldColor::Default,
            ),
            tf(
                "Function:",
                &format!("0x{:02x} ({})", fc, fc_name),
                FieldColor::Green,
            ),
            tf("Item Count:", "1", FieldColor::Default),
            tf("Area:", "Data Block", FieldColor::Default),
            tf("DB Number:", &db.to_string(), FieldColor::Cyan),
            tf(
                "Byte Offset:",
                &format!("0x{:04x} ({})", offset, offset),
                FieldColor::Default,
            ),
        ],
    });
}

pub(super) fn ethernet_ip(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(1024);
    sections.push(TreeSection {
        title: format!(
            "Transmission Control Protocol, Src Port: {}, Dst Port: 44818",
            sp
        ),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf(
                "Destination Port:",
                "44818 (EtherNet/IP)",
                FieldColor::Yellow,
            ),
        ],
    });
    let cmds = [
        (0x0065u16, "RegisterSession"),
        (0x0066, "UnRegisterSession"),
        (0x0063, "ListIdentity"),
        (0x0064, "ListInterfaces"),
        (0x0065, "SendRRData"),
        (0x0070, "SendUnitData"),
    ];
    let (cmd, cmd_name) = cmds[stable(pkt.no, cmds.len())];
    let session: u32 = (pkt.no.wrapping_mul(67108859u64).wrapping_add(56u64) as u32);
    sections.push(TreeSection {
        title: "EtherNet/IP (ENIP)".into(),
        expanded: true,
        fields: vec![
            tf(
                "Command:",
                &format!("0x{:04x} ({})", cmd, cmd_name),
                FieldColor::Green,
            ),
            tf("Length:", &pkt.length.to_string(), FieldColor::Default),
            tf(
                "Session Handle:",
                &format!("0x{:08x}", session),
                FieldColor::Cyan,
            ),
            tf("Status:", "0x00000000 (Success)", FieldColor::Default),
            tf(
                "Sender Context:",
                &format!(
                    "0x{:016x}",
                    pkt.no.wrapping_mul(1452813781u64).wrapping_add(8u64)
                ),
                FieldColor::Default,
            ),
            tf("Service:", "Get Attribute Single", FieldColor::Yellow),
            tf("Class:", "0x01 (Identity)", FieldColor::Default),
            tf("Instance:", "0x01", FieldColor::Default),
        ],
    });
}
