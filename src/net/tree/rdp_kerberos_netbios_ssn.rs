use super::*;

pub(super) fn rdp(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(
        (1024u16 + (pkt.no.wrapping_mul(2246822519u64).wrapping_add(141u64) % 64512u64) as u16),
    );
    sections.push(TreeSection {
        title: format!(
            "Transmission Control Protocol, Src Port: {}, Dst Port: 3389",
            sp
        ),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", "3389", FieldColor::Yellow),
        ],
    });
    let pdus = [
        "X.224 Connection Request",
        "X.224 Connection Confirm",
        "MCS Connect Initial",
        "MCS Connect Response",
        "Client Security Exchange",
        "Client Info",
        "License Request",
        "Demand Active PDU",
        "Confirm Active PDU",
        "Bitmap Update",
    ];
    let pdu = pdus[stable(pkt.no, pdus.len())];
    let channel: u16 =
        ((1001u64 + (pkt.no.wrapping_mul(3266489917u64).wrapping_add(142u64) % 7u64)) as u16);
    sections.push(TreeSection {
        title: format!("Remote Desktop Protocol — {}", pdu),
        expanded: true,
        fields: vec![
            tf("TPKT Version:", "3", FieldColor::Default),
            tf("PDU Type:", pdu, FieldColor::Yellow),
            tf("MCS Channel:", &channel.to_string(), FieldColor::Cyan),
            tf("Encryption:", "128-bit RC4", FieldColor::Magenta),
            tf("PDU Length:", &pkt.length.to_string(), FieldColor::Default),
        ],
    });
}

pub(super) fn kerberos(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(
        (1024u16 + (pkt.no.wrapping_mul(668265263u64).wrapping_add(143u64) % 64512u64) as u16),
    );
    sections.push(TreeSection {
        title: format!(
            "Transmission Control Protocol, Src Port: {}, Dst Port: 88",
            sp
        ),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", "88 (Kerberos)", FieldColor::Yellow),
        ],
    });
    let msg_types = [
        (10u8, "AS-REQ"),
        (11, "AS-REP"),
        (12, "TGS-REQ"),
        (13, "TGS-REP"),
        (14, "AP-REQ"),
        (15, "AP-REP"),
        (30, "KRB-ERROR"),
    ];
    let (mt, mt_name) = msg_types[stable(pkt.no, msg_types.len())];
    let realms = ["CORP.EXAMPLE.COM", "EXAMPLE.LOCAL", "INTERNAL.NET"];
    let realm = realms[stable(pkt.no, realms.len())];
    let users = [
        "administrator",
        "svc_backup",
        "john.doe",
        "svc_sql",
        "krbtgt",
    ];
    let user = users[stable(pkt.no, users.len())];
    let etype = [
        "aes256-cts-hmac-sha1-96",
        "aes128-cts-hmac-sha1-96",
        "rc4-hmac",
    ];
    let enc = etype[stable(pkt.no, etype.len())];
    sections.push(TreeSection {
        title: format!("Kerberos — {} (msg-type={})", mt_name, mt),
        expanded: true,
        fields: vec![
            tf("pvno:", "5", FieldColor::Default),
            tf(
                "msg-type:",
                &format!("{} ({})", mt, mt_name),
                FieldColor::Yellow,
            ),
            tf("realm:", realm, FieldColor::Cyan),
            tf("cname:", user, FieldColor::Green),
            tf("sname:", "krbtgt", FieldColor::Default),
            tf("etype:", enc, FieldColor::Magenta),
            tf(
                "nonce:",
                &format!(
                    "0x{:08x}",
                    (pkt.no.wrapping_mul(268435459u64).wrapping_add(34u64) as u32)
                ),
                FieldColor::Default,
            ),
        ],
    });
}

pub(super) fn netbios_ssn(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(
        (1024u16 + (pkt.no.wrapping_mul(374761393u64).wrapping_add(144u64) % 64512u64) as u16),
    );
    sections.push(TreeSection {
        title: format!(
            "Transmission Control Protocol, Src Port: {}, Dst Port: 139",
            sp
        ),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", "139 (NetBIOS-SSN)", FieldColor::Yellow),
        ],
    });
    let types = [
        (0x00u8, "Session Message"),
        (0x81, "Session Request"),
        (0x82, "Positive Session Response"),
        (0x83, "Negative Session Response"),
    ];
    let (mt, mt_name) = types[stable(pkt.no, types.len())];
    sections.push(TreeSection {
        title: "NetBIOS Session Service".into(),
        expanded: true,
        fields: vec![
            tf(
                "Message Type:",
                &format!("0x{:02x} ({})", mt, mt_name),
                FieldColor::Yellow,
            ),
            tf("Length:", &pkt.length.to_string(), FieldColor::Default),
            tf("Called Name:", "FILESERVER<20>", FieldColor::Cyan),
            tf("Calling Name:", "WORKSTATION<00>", FieldColor::Green),
        ],
    });
}
