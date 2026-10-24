use super::*;

pub(super) fn bgp(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(
        (1024u16 + (pkt.no.wrapping_mul(987654323u64).wrapping_add(109u64) % 64512u64) as u16),
    );
    sections.push(TreeSection {
        title: format!(
            "Transmission Control Protocol, Src Port: {}, Dst Port: 179",
            sp
        ),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", "179", FieldColor::Yellow),
        ],
    });
    let types = [
        (1u8, "OPEN"),
        (2, "UPDATE"),
        (3, "NOTIFICATION"),
        (4, "KEEPALIVE"),
    ];
    let (bt, bt_name) = types[stable(pkt.no, types.len())];
    let asn: u32 =
        ((64512u64 + (pkt.no.wrapping_mul(4294967291u64).wrapping_add(110u64) % 1023u64)) as u32);
    let hold: u16 = 90;
    let mut fields = vec![
        tf(
            "Marker:",
            "0xffffffffffffffffffffffffffffffff",
            FieldColor::Default,
        ),
        tf("Length:", &pkt.length.to_string(), FieldColor::Default),
        tf(
            "Type:",
            &format!("{} ({})", bt, bt_name),
            FieldColor::Yellow,
        ),
    ];
    if bt == 1 {
        fields.push(tf("Version:", "4", FieldColor::Cyan));
        fields.push(tf("My AS:", &asn.to_string(), FieldColor::Green));
        fields.push(tf("Hold Time:", &hold.to_string(), FieldColor::Default));
        fields.push(tf("BGP ID:", &pkt.src, FieldColor::Cyan));
    } else if bt == 2 {
        let prefix = format!(
            "{}.0.0/8",
            (1u8 + (pkt.no.wrapping_mul(2147483647u64).wrapping_add(111u64) % 254u64) as u8)
        );
        let next_hop = format!(
            "{}.{}.{}.{}",
            (1u8 + (pkt.no.wrapping_mul(1073741827u64).wrapping_add(112u64) % 254u64) as u8),
            (pkt.no.wrapping_mul(1073741827u64).wrapping_add(12u64) as u8),
            (pkt.no.wrapping_mul(536870923u64).wrapping_add(13u64) as u8),
            (1u8 + (pkt.no.wrapping_mul(536870923u64).wrapping_add(113u64) % 254u64) as u8)
        );
        fields.push(tf("NLRI Prefix:", &prefix, FieldColor::Cyan));
        fields.push(tf("Next Hop:", &next_hop, FieldColor::Green));
        fields.push(tf(
            "AS Path:",
            &format!(
                "AS{} AS{}",
                asn,
                (1u32 + (pkt.no.wrapping_mul(268435459u64).wrapping_add(114u64) % 64511u64) as u32)
            ),
            FieldColor::Yellow,
        ));
        fields.push(tf("Origin:", "IGP (0)", FieldColor::Default));
    }
    sections.push(TreeSection {
        title: format!("Border Gateway Protocol — {}", bt_name),
        expanded: true,
        fields,
    });
}

pub(super) fn ftp(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(
        (1024u16 + (pkt.no.wrapping_mul(134217757u64).wrapping_add(115u64) % 64512u64) as u16),
    );
    sections.push(TreeSection {
        title: format!(
            "Transmission Control Protocol, Src Port: {}, Dst Port: 21",
            sp
        ),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", "21", FieldColor::Yellow),
        ],
    });
    let cmds = [
        ("USER", "anonymous"),
        ("PASS", "guest@example.com"),
        ("LIST", ""),
        ("RETR", "file.txt"),
        ("STOR", "upload.bin"),
        ("PWD", ""),
        ("CWD", "/pub/data"),
        ("QUIT", ""),
        ("PASV", ""),
        ("TYPE", "I"),
    ];
    let (cmd, arg) = cmds[stable(pkt.no, cmds.len())];
    let arg_str = if arg.is_empty() {
        String::new()
    } else {
        format!(" {}", arg)
    };
    sections.push(TreeSection {
        title: "File Transfer Protocol (FTP)".into(),
        expanded: true,
        fields: vec![
            tf("Command:", cmd, FieldColor::Yellow),
            tf(
                "Argument:",
                if arg.is_empty() { "(none)" } else { arg },
                FieldColor::Cyan,
            ),
            tf(
                "Request:",
                &format!("{}{}\r\n", cmd, arg_str),
                FieldColor::Green,
            ),
        ],
    });
}

pub(super) fn telnet(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(
        (1024u16 + (pkt.no.wrapping_mul(67108859u64).wrapping_add(116u64) % 64512u64) as u16),
    );
    sections.push(TreeSection {
        title: format!(
            "Transmission Control Protocol, Src Port: {}, Dst Port: 23",
            sp
        ),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", "23", FieldColor::Yellow),
        ],
    });
    let cmds = [
        ("IAC DO", "Terminal Type (0x18)"),
        ("IAC WILL", "Terminal Speed (0x20)"),
        ("IAC SB", "Terminal Type IS xterm-256color"),
        ("Data", "login: "),
    ];
    let (cmd, detail) = cmds[stable(pkt.no, cmds.len())];
    sections.push(TreeSection {
        title: "Telnet Protocol".into(),
        expanded: true,
        fields: vec![
            tf("Command:", cmd, FieldColor::Yellow),
            tf("Option:", detail, FieldColor::Cyan),
            tf("Length:", &pkt.length.to_string(), FieldColor::Default),
        ],
    });
}
