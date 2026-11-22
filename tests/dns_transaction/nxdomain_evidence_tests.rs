use super::{AnalysisCore, Packet, dns_packet};
use packrat_tui::net::parser::parse_ethernet;

#[test]
fn nxdomain_burst_counts_distinct_matched_names_and_keeps_packet_pairs() {
    let mut core = AnalysisCore::default();
    let make = |no: u64, id, name: &str, flags, vlan, opt_ext: Option<u8>| {
        let mut query = dns_packet(no, false, "10.0.0.5", "10.0.0.53", id, name);
        let mut reply = dns_packet(no + 1, true, "10.0.0.53", "10.0.0.5", id, name);
        query.timestamp = no as f64 / 100.0;
        reply.timestamp = (no + 1) as f64 / 100.0;
        query.vlan_id = Some(vlan);
        reply.vlan_id = Some(vlan);
        reply.info = "Summary contains NXDOMAIN".into();
        reply.bytes[44..46].copy_from_slice(&u16::to_be_bytes(flags));
        if let Some(extended) = opt_ext {
            reply.bytes[53] = 1; // ARCOUNT.
            reply
                .bytes
                .extend([0, 0, 41, 4, 0, extended, 0, 0, 0, 0, 0]);
            reply.length = reply.bytes.len() as u16;
            reply.bytes[16..18].copy_from_slice(&(reply.length - 14).to_be_bytes());
            reply.bytes[38..40].copy_from_slice(&(reply.length - 34).to_be_bytes());
        }
        [query, reply]
    };
    for i in 1..=20_u16 {
        for pair in [
            make(u64::from(i * 8), i, "Repeated.example", 0x8183, 20, None),
            make(
                u64::from(i * 8 + 2),
                i + 20,
                &format!("ok{i}.example"),
                0x8180,
                30,
                None,
            ),
            make(
                u64::from(i * 8 + 4),
                i + 40,
                &format!("trunc{i}.example"),
                0x8383,
                30,
                None,
            ),
            make(
                u64::from(i * 8 + 6),
                i + 60,
                &format!("edns{i}.example"),
                0x8183,
                30,
                Some(1),
            ),
        ] {
            for packet in &pair {
                core.analyze(packet);
            }
            core.analyze(&pair[1]); // Duplicate response.
        }
    }
    for i in 1..=19_u16 {
        for packet in make(
            200 + u64::from(2 * i),
            i + 100,
            &format!("miss{i}.example"),
            0x8183,
            10,
            None,
        ) {
            core.analyze(&packet);
        }
    }
    assert!(
        core.alert_center
            .items
            .iter()
            .all(|a| a.title != "DNS NXDOMAIN burst")
    );
    for packet in make(240, 120, "miss20.example", 0x8183, 10, Some(0)) {
        core.analyze(&packet);
    }
    let alert = core
        .alert_center
        .items
        .iter()
        .find(|a| a.title == "DNS NXDOMAIN burst")
        .unwrap();
    let mut evidence = alert.packet_refs.clone();
    evidence.sort_unstable();
    assert_eq!(evidence, (202..=241).collect::<Vec<_>>());
    assert_eq!(
        alert.provenance.as_ref().unwrap().rule_id,
        "dns.nxdomain_distinct_names"
    );
    assert_eq!(alert.severity, "MEDIUM");
    assert!(core.incidents.incidents.is_empty());
}

fn tcp_frame(no: u64, sequence: u32, flags: u8, reply: bool, data: &[u8]) -> Packet {
    let mut raw = dns_packet(no, reply, "", "", 0, "example.test").bytes;
    raw.resize(54, 0);
    raw[16..18].copy_from_slice(&((40 + data.len()) as u16).to_be_bytes());
    raw[23] = 6;
    let (source, destination) = if reply { (53, 5) } else { (5, 53) };
    raw[26..34].copy_from_slice(&[10, 0, 0, source, 10, 0, 0, destination]);
    raw[38..42].copy_from_slice(&sequence.to_be_bytes());
    raw[46] = 0x50;
    raw[47] = flags;
    raw.extend_from_slice(data);
    parse_ethernet(&raw, no, no as f64 / 10.0)
}

fn wire_message(id: u16, name: &str, reply: bool) -> Vec<u8> {
    let packet = dns_packet(0, reply, "", "", id, name);
    let body = &packet.bytes[42..];
    let mut wire = (body.len() as u16).to_be_bytes().to_vec();
    wire.extend_from_slice(body);
    if reply {
        wire[5] = 0x83;
    }
    wire
}

#[test]
fn nxdomain_burst_retains_bounded_query_and_reply_segments_for_every_name() {
    for (pieces, distinct, expect_alert) in [(2, true, true), (4, true, true), (2, false, false)] {
        let mut core = AnalysisCore::default();
        core.analyze(&tcp_frame(1, 100, 0x02, false, &[]));
        core.analyze(&tcp_frame(2, 500, 0x12, true, &[]));
        let mut sequence = [101, 501];
        let mut frame = 3;
        let mut expected = Vec::new();
        for id in 0..20 {
            let name = if distinct {
                format!("missing{id}.test")
            } else {
                "same.test".into()
            };
            for reply in [false, true] {
                let message = wire_message(id, &name, reply);
                let offset = usize::from(reply);
                for piece in 0..pieces {
                    let start = piece * 4;
                    let end = if piece + 1 == pieces {
                        message.len()
                    } else {
                        start + 4
                    };
                    let data = &message[start..end];
                    core.analyze(&tcp_frame(frame, sequence[offset], 0x18, reply, data));
                    sequence[offset] += data.len() as u32;
                    if piece < 2 || piece + 1 == pieces {
                        expected.push(frame);
                    }
                    frame += 1;
                }
            }
        }
        let mut alerts = core
            .alert_center
            .items
            .iter()
            .filter(|alert| alert.title == "DNS NXDOMAIN burst");
        if !expect_alert {
            assert!(alerts.next().is_none());
            continue;
        }
        let alert = alerts.next().expect("one distinct-name burst");
        assert!(alerts.next().is_none());
        let mut actual = alert.packet_refs.clone();
        actual.sort_unstable();
        assert_eq!(actual, expected, "segments per message: {pieces}");
        assert_eq!(
            alert
                .detail
                .contains("contributing frame references sampled"),
            pieces == 4
        );
    }
}
