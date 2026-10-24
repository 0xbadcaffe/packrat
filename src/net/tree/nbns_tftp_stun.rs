use super::*;

pub(super) fn nbns(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(137);
    sections.push(TreeSection {
        title: format!("User Datagram Protocol, Src Port: {}, Dst Port: 137", sp),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", "137 (NBNS)", FieldColor::Yellow),
        ],
    });
    let names = [
        "WORKSTATION01",
        "FILESERVER",
        "PRINTSERVER",
        "DOMAIN-CTRL",
        "WIN10-PC",
    ];
    let name = names[stable(pkt.no, names.len())];
    let types = [
        (0x0000u16, "General"),
        (0x0020, "Server"),
        (0x0000, "Workstation"),
        (0x001c, "Domain Controller"),
    ];
    let (nt, nt_name) = types[stable(pkt.no, types.len())];
    let tid: u16 = (pkt.no.wrapping_mul(536870923u64).wrapping_add(73u64) as u16);
    let is_query = (pkt.no & 1) == 0;
    sections.push(TreeSection {
        title: format!(
            "NetBIOS Name Service — {} {}",
            if is_query { "Query" } else { "Response" },
            name
        ),
        expanded: true,
        fields: vec![
            tf(
                "Transaction ID:",
                &format!("0x{:04x}", tid),
                FieldColor::Cyan,
            ),
            tf(
                "Flags:",
                if is_query {
                    "0x0110 (Query)"
                } else {
                    "0x8500 (Response)"
                },
                FieldColor::Yellow,
            ),
            tf("Name:", name, FieldColor::Green),
            tf(
                "Type:",
                &format!("0x{:04x} ({})", nt, nt_name),
                FieldColor::Default,
            ),
            tf(
                "IP:",
                &format!(
                    "192.168.1.{}",
                    (1u8 + (pkt.no.wrapping_mul(2246822519u64).wrapping_add(161u64) % 254u64)
                        as u8)
                ),
                FieldColor::Cyan,
            ),
        ],
    });
}

pub(super) fn tftp(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(
        (1024u16 + (pkt.no.wrapping_mul(3266489917u64).wrapping_add(162u64) % 64512u64) as u16),
    );
    sections.push(TreeSection {
        title: format!("User Datagram Protocol, Src Port: {}, Dst Port: 69", sp),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", "69 (TFTP)", FieldColor::Yellow),
        ],
    });
    let opcodes = [
        (1u16, "Read Request (RRQ)"),
        (2, "Write Request (WRQ)"),
        (3, "Data (DAT)"),
        (4, "Acknowledgment (ACK)"),
        (5, "Error (ERROR)"),
    ];
    let (op, op_name) = opcodes[stable(pkt.no, opcodes.len())];
    let files = [
        "pxelinux.0",
        "firmware.bin",
        "config.cfg",
        "initrd.img",
        "bootloader.img",
    ];
    let file = files[stable(pkt.no, files.len())];
    let block_field = if op <= 2 {
        tf("Filename:", file, FieldColor::Cyan)
    } else {
        tf(
            "Block:",
            &(1u16 + (pkt.no.wrapping_mul(668265263u64).wrapping_add(163u64) % 512u64) as u16)
                .to_string(),
            FieldColor::Cyan,
        )
    };
    sections.push(TreeSection {
        title: format!("Trivial File Transfer Protocol — {}", op_name),
        expanded: true,
        fields: vec![
            tf(
                "Opcode:",
                &format!("{} ({})", op, op_name),
                FieldColor::Yellow,
            ),
            block_field,
            tf("Mode:", "octet", FieldColor::Default),
        ],
    });
}

pub(super) fn stun(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(
        (1024u16 + (pkt.no.wrapping_mul(374761393u64).wrapping_add(164u64) % 64512u64) as u16),
    );
    sections.push(TreeSection {
        title: format!("User Datagram Protocol, Src Port: {}, Dst Port: 3478", sp),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", "3478 (STUN)", FieldColor::Yellow),
        ],
    });
    let types = [
        (0x0001u16, "Binding Request"),
        (0x0101, "Binding Success Response"),
        (0x0111, "Binding Error Response"),
        (0x0003, "Allocate Request"),
        (0x0103, "Allocate Response"),
    ];
    let (mt, mt_name) = types[stable(pkt.no, types.len())];
    let tid_hi: u64 = (pkt.no.wrapping_mul(268435459u64).wrapping_add(74u64) as u64);
    let tid_lo: u32 = (pkt.no.wrapping_mul(134217757u64).wrapping_add(75u64) as u32);
    sections.push(TreeSection {
        title: format!("Session Traversal Utilities for NAT (STUN) — {}", mt_name),
        expanded: true,
        fields: vec![
            tf(
                "Message Type:",
                &format!("0x{:04x} ({})", mt, mt_name),
                FieldColor::Yellow,
            ),
            tf(
                "Message Length:",
                &pkt.length.to_string(),
                FieldColor::Default,
            ),
            tf("Magic Cookie:", "0x2112a442", FieldColor::Default),
            tf(
                "Transaction ID:",
                &format!("0x{:016x}{:08x}", tid_hi, tid_lo),
                FieldColor::Cyan,
            ),
            tf(
                "XOR-MAPPED-ADDRESS:",
                &format!("{}:{}", pkt.src, sp),
                FieldColor::Green,
            ),
        ],
    });
}
