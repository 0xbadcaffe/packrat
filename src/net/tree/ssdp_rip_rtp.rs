use super::*;

pub(super) fn ssdp(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(
        (1024u16 + (pkt.no.wrapping_mul(2870177450u64).wrapping_add(165u64) % 64512u64) as u16),
    );
    sections.push(TreeSection {
        title: format!("User Datagram Protocol, Src Port: {}, Dst Port: 1900", sp),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", "1900 (SSDP)", FieldColor::Yellow),
        ],
    });
    let methods = [
        "M-SEARCH * HTTP/1.1",
        "NOTIFY * HTTP/1.1",
        "HTTP/1.1 200 OK",
    ];
    let m = methods[stable(pkt.no, methods.len())];
    let services = [
        "upnp:rootdevice",
        "urn:schemas-upnp-org:service:RenderingControl:1",
        "urn:schemas-upnp-org:device:MediaServer:1",
    ];
    let svc = services[stable(pkt.no, services.len())];
    sections.push(TreeSection {
        title: format!("Simple Service Discovery Protocol (SSDP) — {}", m),
        expanded: true,
        fields: vec![
            tf("Method:", m, FieldColor::Yellow),
            tf("Host:", "239.255.255.250:1900", FieldColor::Cyan),
            tf("ST/NT:", svc, FieldColor::Green),
            tf(
                "MX:",
                &(1u8 + (pkt.no.wrapping_mul(1145919239u64).wrapping_add(166u64) % 5u64) as u8)
                    .to_string(),
                FieldColor::Default,
            ),
            tf(
                "USN:",
                &format!(
                    "uuid:{:08x}-{:04x}-{:04x}-{:04x}-{:012x}::{}",
                    (pkt.no.wrapping_mul(16777259u64).wrapping_add(38u64) as u32),
                    (pkt.no.wrapping_mul(8388617u64).wrapping_add(39u64) as u16),
                    (pkt.no.wrapping_mul(2654435761u64).wrapping_add(40u64) as u16),
                    (pkt.no.wrapping_mul(2246822519u64).wrapping_add(41u64) as u16),
                    pkt.no.wrapping_mul(3266489917u64).wrapping_add(42u64) & 0xFFFFFFFFFFFF,
                    svc
                ),
                FieldColor::Default,
            ),
        ],
    });
}

pub(super) fn rip(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(520);
    sections.push(TreeSection {
        title: format!("User Datagram Protocol, Src Port: {}, Dst Port: 520", sp),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", "520 (RIP)", FieldColor::Yellow),
        ],
    });
    let cmds = [(1u8, "Request"), (2, "Response")];
    let (cmd, cmd_name) = cmds[stable(pkt.no, cmds.len())];
    let prefix = format!(
        "{}.0.0.0/8",
        (1u8 + (pkt.no.wrapping_mul(3264354801u64).wrapping_add(167u64) % 223u64) as u8)
    );
    let metric: u8 =
        ((1u64 + (pkt.no.wrapping_mul(1452813781u64).wrapping_add(168u64) % 15u64)) as u8);
    sections.push(TreeSection {
        title: format!("Routing Information Protocol v2 — {}", cmd_name),
        expanded: true,
        fields: vec![
            tf(
                "Command:",
                &format!("{} ({})", cmd, cmd_name),
                FieldColor::Yellow,
            ),
            tf("Version:", "2", FieldColor::Cyan),
            tf("Address Family:", "2 (IPv4)", FieldColor::Default),
            tf("Route Tag:", "0", FieldColor::Default),
            tf("Network:", &prefix, FieldColor::Green),
            tf("Subnet Mask:", "255.0.0.0", FieldColor::Default),
            tf("Next Hop:", &pkt.src, FieldColor::Cyan),
            tf("Metric:", &metric.to_string(), FieldColor::Yellow),
        ],
    });
}

pub(super) fn rtp(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(
        (10000u16 + (pkt.no.wrapping_mul(987654323u64).wrapping_add(169u64) % 10001u64) as u16),
    );
    let dp = pkt.dst_port.unwrap_or(
        (10000u16 + (pkt.no.wrapping_mul(4294967291u64).wrapping_add(170u64) % 10001u64) as u16),
    );
    sections.push(TreeSection {
        title: format!("User Datagram Protocol, Src Port: {}, Dst Port: {}", sp, dp),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", &dp.to_string(), FieldColor::Yellow),
        ],
    });
    let payload_types = [
        (0u8, "PCMU"),
        (3, "GSM"),
        (8, "PCMA"),
        (9, "G722"),
        (96, "H264"),
        (97, "H265"),
        (111, "OPUS"),
    ];
    let (pt, pt_name) = payload_types[stable(pkt.no, payload_types.len())];
    let ssrc: u32 = (pkt.no.wrapping_mul(67108859u64).wrapping_add(76u64) as u32);
    let seq: u16 = (pkt.no.wrapping_mul(33554467u64).wrapping_add(77u64) as u16);
    let rtp_ts: u32 = (pkt.no.wrapping_mul(16777259u64).wrapping_add(78u64) as u32);
    sections.push(TreeSection {
        title: format!("Real-Time Transport Protocol — {} (PT={})", pt_name, pt),
        expanded: true,
        fields: vec![
            tf("Version:", "2", FieldColor::Cyan),
            tf("Padding:", "0", FieldColor::Default),
            tf("Extension:", "0", FieldColor::Default),
            tf(
                "Payload Type:",
                &format!("{} ({})", pt, pt_name),
                FieldColor::Yellow,
            ),
            tf("Sequence Number:", &seq.to_string(), FieldColor::Default),
            tf("Timestamp:", &rtp_ts.to_string(), FieldColor::Default),
            tf("SSRC:", &format!("0x{:08x}", ssrc), FieldColor::Cyan),
        ],
    });
}
