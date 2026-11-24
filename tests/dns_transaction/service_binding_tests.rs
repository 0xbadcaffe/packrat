use super::{append_answer, dns_packet};
use packrat_tui::analysis::dns_transactions::{DnsFindingKind, DnsTransactionTracker};
use packrat_tui::net::packet::Packet;

#[path = "../support/ech_config.rs"]
mod ech_config;

fn packet(frame: u64, reply: bool, rr_type: u16) -> Packet {
    let (client, resolver) = ("192.0.2.5", "192.0.2.53");
    let (source, destination) = if reply {
        (resolver, client)
    } else {
        (client, resolver)
    };
    let mut packet = dns_packet(frame, reply, source, destination, 50, "service.test");
    let qtype = packet.bytes.len() - 4;
    packet.bytes[qtype..qtype + 2].copy_from_slice(&rr_type.to_be_bytes());
    packet
}

fn binding(priority: u16, target: &[u8], parameters: &[(u16, &[u8])]) -> Vec<u8> {
    let mut data = priority.to_be_bytes().to_vec();
    data.extend(target);
    for (key, value) in parameters {
        data.extend(key.to_be_bytes());
        data.extend(u16::try_from(value.len()).unwrap().to_be_bytes());
        data.extend(*value);
    }
    data
}

fn observe_replies(rr_type: u16, replies: &[(u32, Vec<u8>)]) -> Vec<Vec<DnsFindingKind>> {
    let mut tracker = DnsTransactionTracker::default();
    assert!(tracker.observe(&packet(1, false, rr_type)).is_empty());
    replies
        .iter()
        .enumerate()
        .map(|(index, (ttl, data))| {
            let mut reply = packet(index as u64 + 2, true, rr_type);
            append_answer(&mut reply, b"\xc0\x0c", rr_type, *ttl, data);
            tracker
                .observe(&reply)
                .into_iter()
                .map(|finding| {
                    assert_eq!(finding.related_packets, [1, 2]);
                    finding.kind
                })
                .collect()
        })
        .collect()
}

#[test]
fn https_service_mode_ignores_hint_order_but_detects_port_changes() {
    let first = binding(
        1,
        b"\x03cdn\x04test\0",
        &[
            (0, b"\0\x01"),
            (1, b"\x02h2\x02h3"),
            (2, b""),
            (3, b"\x01\xbb"),
            (4, &[192, 0, 2, 1, 192, 0, 2, 2]),
        ],
    );
    let mut reordered = binding(
        1,
        b"\x03CDN\x04TEST\0",
        &[
            (0, b"\0\x01"),
            (1, b"\x02h3\x02h2"),
            (2, b""),
            (3, b"\x01\xbb"),
            (4, &[192, 0, 2, 2, 192, 0, 2, 1]),
        ],
    );
    let equivalent = reordered.clone();
    let port = reordered.len() - 13;
    assert_eq!(reordered[port], 0xbb);
    reordered[port] = 0xbc;
    assert_eq!(
        observe_replies(65, &[(300, first), (299, equivalent), (299, reordered)]),
        [vec![], vec![], vec![DnsFindingKind::ChangedAnswerSet]]
    );
}

#[test]
fn svcb_alias_compares_targets_and_ignores_alias_parameters() {
    let first = binding(0, b"\x03cdn\x04test\0", &[]);
    let equivalent = binding(0, b"\x03CDN\x04TEST\0", &[(100, b"ignored")]);
    let changed = binding(0, b"\x03alt\x04test\0", &[]);
    assert_eq!(
        observe_replies(64, &[(300, first), (300, equivalent), (300, changed)]),
        [vec![], vec![], vec![DnsFindingKind::ChangedAnswerSet]]
    );
}

#[test]
fn malformed_or_unsupported_service_parameters_remain_wire_only() {
    let target = b"\x03cdn\x04test\0";
    let first = binding(1, target, &[(1, b"\x02h2")]);
    let mut truncated = binding(1, target, &[(4, &[192, 0, 2, 1])]);
    truncated.pop();
    for data in [
        binding(1, b"\xc0\x0c", &[]),
        binding(1, target, &[(1, b"\x02h2"), (1, b"\x02h3")]),
        binding(1, target, &[(3, b"\x01\xbb"), (1, b"\x02h2")]),
        binding(1, target, &[(0, b"\0\x03"), (1, b"\x02h2")]),
        binding(1, target, &[(1, b"\x03h2")]),
        binding(1, target, &[(1, b"\x00")]),
        binding(1, target, &[(2, b"")]),
        binding(1, target, &[(4, &[192, 0, 2])]),
        binding(1, target, &[(5, b"opaque ECH data")]),
        truncated,
    ] {
        assert_eq!(
            observe_replies(65, &[(300, first.clone()), (299, data)]),
            [vec![], vec![DnsFindingKind::ChangedReply]]
        );
    }
}

#[test]
fn https_ech_compares_the_exact_config_but_ignores_dns_encoding_changes() {
    let config = ech_config::fixture(1, b"ech.test", &[]);
    let changed = ech_config::fixture(2, b"ech.test", &[]);
    let target = b"\x03cdn\x04test\0";
    assert_eq!(
        observe_replies(
            65,
            &[
                (300, binding(1, target, &[(5, &config)])),
                (299, binding(1, b"\x03CDN\x04TEST\0", &[(5, &config)])),
                (299, binding(1, target, &[(5, &changed)])),
            ],
        ),
        [vec![], vec![], vec![DnsFindingKind::ChangedAnswerSet]]
    );
}

#[test]
fn https_ech_rejects_invalid_lengths_unknown_versions_and_unsupported_extensions() {
    let config = ech_config::fixture(1, b"ech.test", &[]);
    let target = b"\x03cdn\x04test\0";
    let baseline = binding(1, target, &[(5, &config)]);
    let mut incomplete = config.clone();
    incomplete.pop();
    let mut unknown = config.clone();
    unknown[3] = 0x0e;
    let mut wrong_list_length = config.clone();
    wrong_list_length[1] -= 1;
    for invalid in [
        incomplete,
        unknown,
        wrong_list_length,
        ech_config::fixture(1, b"192.0.2.5", &[]),
        ech_config::fixture(1, b"ech.test", &[(0x80ff, b"required")]),
        ech_config::fixture(1, b"ech.test", &[(0xff, b"one"), (0xff, b"two")]),
    ] {
        assert_eq!(
            observe_replies(
                65,
                &[
                    (300, baseline.clone()),
                    (299, binding(1, target, &[(5, &invalid)]))
                ]
            ),
            [vec![], vec![DnsFindingKind::ChangedReply]]
        );
    }
}
