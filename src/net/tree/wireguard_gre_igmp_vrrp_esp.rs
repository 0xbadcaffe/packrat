use super::*;

pub(super) fn wireguard(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(
        (1024u16 + (pkt.no.wrapping_mul(2870177450u64).wrapping_add(125u64) % 64512u64) as u16),
    );
    sections.push(TreeSection {
        title: format!("User Datagram Protocol, Src Port: {}, Dst Port: 51820", sp),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", "51820", FieldColor::Yellow),
        ],
    });
    let types = [
        (1u8, "Handshake Initiation"),
        (2, "Handshake Response"),
        (3, "Cookie Reply"),
        (4, "Transport Data"),
    ];
    let (wt, wt_name) = types[stable(pkt.no, types.len())];
    let sender: u32 = (pkt.no.wrapping_mul(2654435761u64).wrapping_add(60u64) as u32);
    let mut fields = vec![
        tf(
            "Message Type:",
            &format!("{} ({})", wt, wt_name),
            FieldColor::Yellow,
        ),
        tf("Reserved:", "0x000000", FieldColor::Default),
    ];
    if wt == 4 {
        let receiver: u32 = (pkt.no.wrapping_mul(2246822519u64).wrapping_add(61u64) as u32);
        let counter: u64 = (pkt.no.wrapping_mul(3266489917u64).wrapping_add(62u64) as u64);
        fields.push(tf(
            "Receiver Index:",
            &format!("0x{:08x}", receiver),
            FieldColor::Cyan,
        ));
        fields.push(tf("Counter:", &counter.to_string(), FieldColor::Default));
        fields.push(tf(
            "Encrypted Payload:",
            &format!("[{} bytes]", pkt.length.saturating_sub(32)),
            FieldColor::Magenta,
        ));
    } else {
        fields.push(tf(
            "Sender Index:",
            &format!("0x{:08x}", sender),
            FieldColor::Cyan,
        ));
        fields.push(tf(
            "Ephemeral Key:",
            &format!(
                "0x{:064x}",
                pkt.no.wrapping_mul(2246822519u64).wrapping_add(21u64)
            ),
            FieldColor::Green,
        ));
        fields.push(tf("Encrypted Static:", "[32 bytes]", FieldColor::Default));
        fields.push(tf(
            "Encrypted Timestamp:",
            "[12 bytes]",
            FieldColor::Default,
        ));
        fields.push(tf(
            "MAC1:",
            &format!(
                "0x{:032x}",
                pkt.no.wrapping_mul(3266489917u64).wrapping_add(22u64)
            ),
            FieldColor::Default,
        ));
    }
    sections.push(TreeSection {
        title: format!("WireGuard — {}", wt_name),
        expanded: true,
        fields,
    });
}

pub(super) fn gre(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    sections.push(TreeSection {
        title: "Generic Routing Encapsulation (GRE)".into(),
        expanded: true,
        fields: vec![
            tf("Flags:", "0x0000", FieldColor::Default),
            tf("Version:", "0", FieldColor::Default),
            tf("Protocol Type:", "0x0800 (IPv4)", FieldColor::Yellow),
            tf(
                "Key:",
                &format!(
                    "0x{:08x}",
                    (pkt.no.wrapping_mul(668265263u64).wrapping_add(23u64) as u32)
                ),
                FieldColor::Cyan,
            ),
            tf(
                "Sequence Number:",
                &(pkt.no.wrapping_mul(374761393u64).wrapping_add(24u64) as u32).to_string(),
                FieldColor::Default,
            ),
        ],
    });
}

pub(super) fn igmp(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let group = format!(
        "239.{}.{}.{}",
        (1u8 + (pkt.no.wrapping_mul(1145919239u64).wrapping_add(126u64) % 2u64) as u8),
        (pkt.no.wrapping_mul(2870177450u64).wrapping_add(25u64) as u8),
        (1u8 + (pkt.no.wrapping_mul(3264354801u64).wrapping_add(127u64) % 254u64) as u8)
    );
    let types = [
        (0x11u8, "Membership Query"),
        (0x16, "Membership Report v2"),
        (0x17, "Leave Group"),
        (0x22, "Membership Report v3"),
    ];
    let (it, it_name) = types[stable(pkt.no, types.len())];
    sections.push(TreeSection {
        title: format!("Internet Group Management Protocol ({})", it_name),
        expanded: true,
        fields: vec![
            tf(
                "Type:",
                &format!("0x{:02x} ({})", it, it_name),
                FieldColor::Yellow,
            ),
            tf("Max Resp Time:", "10.0 sec", FieldColor::Default),
            tf(
                "Checksum:",
                &format!(
                    "0x{:04x}",
                    (pkt.no.wrapping_mul(1145919239u64).wrapping_add(26u64) as u16)
                ),
                FieldColor::Default,
            ),
            tf("Multicast Address:", &group, FieldColor::Cyan),
            tf("S Flag:", "0", FieldColor::Default),
            tf("QRV:", "2", FieldColor::Default),
        ],
    });
}

pub(super) fn vrrp(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let vrid: u8 =
        ((1u64 + (pkt.no.wrapping_mul(1452813781u64).wrapping_add(128u64) % 255u64)) as u8);
    let prio: u8 =
        ((1u64 + (pkt.no.wrapping_mul(987654323u64).wrapping_add(129u64) % 254u64)) as u8);
    let ips: u8 = ((1u64 + (pkt.no.wrapping_mul(4294967291u64).wrapping_add(130u64) % 3u64)) as u8);
    sections.push(TreeSection {
        title: format!("Virtual Router Redundancy Protocol (VRID={})", vrid),
        expanded: true,
        fields: vec![
            tf("Version:", "3", FieldColor::Cyan),
            tf("Type:", "1 (Advertisement)", FieldColor::Yellow),
            tf("Virtual Router ID:", &vrid.to_string(), FieldColor::Yellow),
            tf(
                "Priority:",
                &prio.to_string(),
                if prio == 255 {
                    FieldColor::Green
                } else {
                    FieldColor::Default
                },
            ),
            tf("Count IP Addrs:", &ips.to_string(), FieldColor::Default),
            tf("Adver Interval:", "100 centiseconds", FieldColor::Default),
            tf(
                "Checksum:",
                &format!(
                    "0x{:04x}",
                    (pkt.no.wrapping_mul(3264354801u64).wrapping_add(27u64) as u16)
                ),
                FieldColor::Default,
            ),
            tf(
                "Virtual IP:",
                &format!(
                    "10.0.0.{}",
                    (1u8 + (pkt.no.wrapping_mul(2147483647u64).wrapping_add(131u64) % 10u64) as u8)
                ),
                FieldColor::Cyan,
            ),
        ],
    });
}

pub(super) fn esp(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let spi: u32 = (pkt.no.wrapping_mul(668265263u64).wrapping_add(63u64) as u32);
    let seq: u32 = (pkt.no.wrapping_mul(374761393u64).wrapping_add(64u64) as u32);
    sections.push(TreeSection {
        title: "IPSec Encapsulating Security Payload (ESP)".into(),
        expanded: true,
        fields: vec![
            tf("SPI:", &format!("0x{:08x}", spi), FieldColor::Cyan),
            tf("Sequence Number:", &seq.to_string(), FieldColor::Default),
            tf(
                "Payload Data:",
                &format!("[{} bytes encrypted]", pkt.length.saturating_sub(8)),
                FieldColor::Magenta,
            ),
        ],
    });
}
