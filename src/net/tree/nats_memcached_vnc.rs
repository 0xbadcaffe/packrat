use super::*;

pub(super) fn nats(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(
        (1024u16 + (pkt.no.wrapping_mul(2147483647u64).wrapping_add(151u64) % 64512u64) as u16),
    );
    sections.push(TreeSection {
        title: format!(
            "Transmission Control Protocol, Src Port: {}, Dst Port: 4222",
            sp
        ),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", "4222 (NATS)", FieldColor::Yellow),
        ],
    });
    let ops = [
        "INFO", "CONNECT", "PUB", "SUB", "UNSUB", "MSG", "PING", "PONG", "+OK", "-ERR",
    ];
    let op = ops[stable(pkt.no, ops.len())];
    let subjects = [
        "events.>",
        "orders.created",
        "users.login",
        "_INBOX.reply",
        "health.check",
    ];
    let subj = subjects[stable(pkt.no, subjects.len())];
    sections.push(TreeSection {
        title: format!("NATS Messaging — {}", op),
        expanded: true,
        fields: vec![
            tf("Operation:", op, FieldColor::Yellow),
            tf("Subject:", subj, FieldColor::Cyan),
            tf(
                "Payload Length:",
                &(0u16 + (pkt.no.wrapping_mul(1073741827u64).wrapping_add(152u64) % 513u64) as u16)
                    .to_string(),
                FieldColor::Default,
            ),
            tf("Version:", "2.x", FieldColor::Default),
        ],
    });
}

pub(super) fn memcached(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(
        (1024u16 + (pkt.no.wrapping_mul(536870923u64).wrapping_add(153u64) % 64512u64) as u16),
    );
    sections.push(TreeSection {
        title: format!(
            "Transmission Control Protocol, Src Port: {}, Dst Port: 11211",
            sp
        ),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", "11211 (Memcached)", FieldColor::Yellow),
        ],
    });
    let cmds = [
        "get",
        "set",
        "delete",
        "incr",
        "decr",
        "flush_all",
        "stats",
        "version",
    ];
    let cmd = cmds[stable(pkt.no, cmds.len())];
    let keys = [
        "session:abc123",
        "user:42:profile",
        "cache:homepage",
        "token:xyz789",
    ];
    let key = keys[stable(pkt.no, keys.len())];
    sections.push(TreeSection {
        title: format!("Memcached — {}", cmd),
        expanded: true,
        fields: vec![
            tf("Command:", cmd, FieldColor::Yellow),
            tf("Key:", key, FieldColor::Cyan),
            tf("Flags:", "0", FieldColor::Default),
            tf(
                "Exptime:",
                &(0u32 + (pkt.no.wrapping_mul(268435459u64).wrapping_add(154u64) % 3601u64) as u32)
                    .to_string(),
                FieldColor::Default,
            ),
            tf(
                "Bytes:",
                &(0u16 + (pkt.no.wrapping_mul(134217757u64).wrapping_add(155u64) % 4097u64) as u16)
                    .to_string(),
                FieldColor::Default,
            ),
        ],
    });
}

pub(super) fn vnc(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(
        (1024u16 + (pkt.no.wrapping_mul(67108859u64).wrapping_add(156u64) % 64512u64) as u16),
    );
    sections.push(TreeSection {
        title: format!(
            "Transmission Control Protocol, Src Port: {}, Dst Port: 5900",
            sp
        ),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", "5900 (VNC)", FieldColor::Yellow),
        ],
    });
    let msgs = [
        "ProtocolVersion 3.8",
        "SecurityType: VNC Authentication",
        "ServerInit",
        "FramebufferUpdateRequest",
        "KeyEvent",
        "PointerEvent",
        "FramebufferUpdate",
    ];
    let msg = msgs[stable(pkt.no, msgs.len())];
    sections.push(TreeSection {
        title: format!("Virtual Network Computing (VNC) — {}", msg),
        expanded: true,
        fields: vec![
            tf("Message:", msg, FieldColor::Yellow),
            tf("Desktop Width:", "1920", FieldColor::Cyan),
            tf("Desktop Height:", "1080", FieldColor::Cyan),
            tf(
                "Pixel Format:",
                "32 bits/pixel, BGR888",
                FieldColor::Default,
            ),
            tf("Name:", "Remote Desktop", FieldColor::Default),
        ],
    });
}
