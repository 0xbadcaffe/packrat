use super::*;

pub(super) fn ntp(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(
        (1024u16 + (pkt.no.wrapping_mul(2246822519u64).wrapping_add(81u64) % 64512u64) as u16),
    );
    sections.push(TreeSection {
        title: format!("User Datagram Protocol, Src Port: {}, Dst Port: 123", sp),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", "123", FieldColor::Yellow),
            tf("Length:", "48", FieldColor::Default),
        ],
    });
    let strata = [
        "1 (primary reference)",
        "2 (secondary reference)",
        "3 (tertiary reference)",
        "4",
    ];
    let stratum_idx = stable(pkt.no, strata.len());
    let stratum = strata[stratum_idx];
    let modes = ["3 (client)", "4 (server)", "5 (broadcast)"];
    let mode = modes[stable(pkt.no, modes.len())];
    let poll: u8 = ((6u64 + (pkt.no.wrapping_mul(3266489917u64).wrapping_add(82u64) % 5u64)) as u8);
    let precision: i8 =
        -(10i8 + (pkt.no.wrapping_mul(668265263u64).wrapping_add(83u64) % 11u64) as i8);
    let ref_ids = ["GPS\0", "PPS\0", "ACTS", "USNO"];
    let ref_id = if stratum_idx == 0 {
        ref_ids[stable(pkt.no, ref_ids.len())]
            .trim_end_matches('\0')
            .to_string()
    } else {
        format!(
            "{}.{}.{}.{}",
            (1u8 + (pkt.no.wrapping_mul(374761393u64).wrapping_add(84u64) % 254u64) as u8),
            (pkt.no.wrapping_mul(668265263u64).wrapping_add(3u64) as u8),
            (pkt.no.wrapping_mul(374761393u64).wrapping_add(4u64) as u8),
            (1u8 + (pkt.no.wrapping_mul(2870177450u64).wrapping_add(85u64) % 254u64) as u8)
        )
    };
    let base_ts: u64 = 3_915_000_000
        + (0u64 + (pkt.no.wrapping_mul(1145919239u64).wrapping_add(86u64) % 86401u64) as u64);
    sections.push(TreeSection {
        title: "Network Time Protocol (v4)".into(),
        expanded: true,
        fields: vec![
            tf("Leap Indicator:", "0 (no warning)", FieldColor::Default),
            tf("Version:", "4", FieldColor::Cyan),
            tf("Mode:", mode, FieldColor::Yellow),
            tf("Stratum:", stratum, FieldColor::Default),
            tf(
                "Poll Interval:",
                &format!("{} ({} sec)", poll, 1u32 << poll),
                FieldColor::Default,
            ),
            tf("Precision:", &format!("{}", precision), FieldColor::Default),
            tf(
                "Root Delay:",
                &format!(
                    "0.{:04} sec",
                    (0u32
                        + (pkt.no.wrapping_mul(3264354801u64).wrapping_add(87u64) % 5001u64)
                            as u32)
                ),
                FieldColor::Default,
            ),
            tf(
                "Root Dispersion:",
                &format!(
                    "0.{:04} sec",
                    (0u32
                        + (pkt.no.wrapping_mul(1452813781u64).wrapping_add(88u64) % 5001u64)
                            as u32)
                ),
                FieldColor::Default,
            ),
            tf("Reference ID:", &ref_id, FieldColor::Cyan),
            tf(
                "Reference Timestamp:",
                &format!(
                    "{}.{:06}",
                    base_ts,
                    (0u32
                        + (pkt.no.wrapping_mul(987654323u64).wrapping_add(89u64) % 1000000u64)
                            as u32)
                ),
                FieldColor::Default,
            ),
            tf(
                "Originate Timestamp:",
                &format!(
                    "{}.{:06}",
                    base_ts + 1,
                    (0u32
                        + (pkt.no.wrapping_mul(4294967291u64).wrapping_add(90u64) % 1000000u64)
                            as u32)
                ),
                FieldColor::Default,
            ),
            tf(
                "Receive Timestamp:",
                &format!(
                    "{}.{:06}",
                    base_ts + 1,
                    (0u32
                        + (pkt.no.wrapping_mul(2147483647u64).wrapping_add(91u64) % 1000000u64)
                            as u32)
                ),
                FieldColor::Default,
            ),
            tf(
                "Transmit Timestamp:",
                &format!(
                    "{}.{:06}",
                    base_ts + 1,
                    (0u32
                        + (pkt.no.wrapping_mul(1073741827u64).wrapping_add(92u64) % 1000000u64)
                            as u32)
                ),
                FieldColor::Green,
            ),
        ],
    });
}

pub(super) fn quic(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    sections.push(TreeSection {
        title: "QUIC (RFC 9000)".into(),
        expanded: true,
        fields: vec![
            tf("Version:", "1 (0x00000001)", FieldColor::Cyan),
            tf("Packet Type:", "Initial", FieldColor::Yellow),
            tf(
                "Destination CID:",
                &format!(
                    "0x{:016x}",
                    pkt.no.wrapping_mul(2870177450u64).wrapping_add(5u64)
                ),
                FieldColor::Green,
            ),
        ],
    });
}

pub(super) fn tcp(
    pkt: &Packet,
    raw: &[u8],
    tp_off: usize,
    sections: &mut Vec<TreeSection>,
    proto: &str,
) {
    let sp = pkt.src_port.unwrap_or(12345);
    let dp = pkt.dst_port.unwrap_or(80);
    // Read real TCP header fields from bytes
    let seq: u32 = u32_be(raw, tp_off + 4);
    let ack: u32 = u32_be(raw, tp_off + 8);
    let flags_byte = u8_at(raw, tp_off + 13);
    let win: u16 = u16_be(raw, tp_off + 14);
    let flags_str = fmt_tcp_flags(flags_byte);
    sections.push(TreeSection {
        title: format!(
            "Transmission Control Protocol, Src Port: {}, Dst Port: {}",
            sp, dp
        ),
        expanded: true,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", &dp.to_string(), FieldColor::Yellow),
            tf("Sequence Number:", &seq.to_string(), FieldColor::Default),
            tf("Acknowledgment:", &ack.to_string(), FieldColor::Default),
            tf(
                "Flags:",
                &format!("0x{:02x} ({})", flags_byte, flags_str),
                FieldColor::Magenta,
            ),
            tf("Window Size:", &win.to_string(), FieldColor::Default),
        ],
    });
    if proto == "HTTP" {
        let methods = ["GET", "POST", "PUT", "DELETE"];
        let paths = ["/api/users", "/index.html", "/static/app.js"];
        sections.push(TreeSection {
            title: "Hypertext Transfer Protocol".into(),
            expanded: true,
            fields: vec![
                tf(
                    "Method:",
                    methods[stable(pkt.no, methods.len())],
                    FieldColor::Green,
                ),
                tf("URI:", paths[stable(pkt.no, paths.len())], FieldColor::Cyan),
                tf("Version:", "HTTP/1.1", FieldColor::Default),
                tf("Host:", "api.example.com", FieldColor::Yellow),
            ],
        });
    }
    if matches!(proto, "TLS" | "HTTPS") {
        let hs = [
            "Client Hello (1)",
            "Server Hello (2)",
            "Certificate (11)",
            "Application Data (23)",
        ];
        let ciphers = ["TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"];
        sections.push(TreeSection {
            title: "Transport Layer Security".into(),
            expanded: true,
            fields: vec![
                tf("Version:", "TLS 1.3 (0x0304)", FieldColor::Cyan),
                tf(
                    "Handshake Type:",
                    hs[stable(pkt.no, hs.len())],
                    FieldColor::Yellow,
                ),
                tf(
                    "Cipher Suite:",
                    ciphers[stable(pkt.no, ciphers.len())],
                    FieldColor::Magenta,
                ),
            ],
        });
    }
}
