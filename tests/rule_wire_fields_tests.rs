#[path = "support/packets.rs"]
mod packets;

use packrat_tui::{
    analysis::{display_filter::DisplayFilter, rules::{Action, CmpOp, Condition, Rule, RuleEngine}},
    net::{packet::Packet, parser::parse_ethernet},
};

fn matches_rule(packet: &Packet, field: &str, value: u64) -> bool {
    let mut rules = RuleEngine::default();
    rules.add_rule(Rule::new(
        "wire-field", "wire-field",
        Condition::Num { field: field.into(), op: CmpOp::Eq, value },
        vec![Action::Log { message: "wire field matched".into() }],
    ));
    rules.evaluate(packet);
    !rules.hits.is_empty()
}

fn matches_filter(packet: &Packet, expression: &str) -> bool {
    let mut filter = DisplayFilter::default();
    filter.set(expression);
    assert!(!filter.has_error(), "{expression}");
    filter.matches(packet, false, &[])
}

#[test]
fn ttl_rules_and_filters_follow_the_ipv4_header_through_vlan_tags() {
    let tcp = packets::tcp(1, 100, 0x10, &[]);
    for tags in [&[][..], &[0x8100_u16, 10][..], &[0x88a8, 20, 0x8100, 10][..]] {
        let mut frame = tcp.bytes[..12].to_vec();
        frame.extend(tags.iter().flat_map(|word| word.to_be_bytes()));
        frame.extend(&tcp.bytes[12..]);
        let packet = parse_ethernet(&frame, 1, 1.0);
        assert!(matches_rule(&packet, "ip.ttl", 64), "{tags:?}");
        assert!(matches_filter(&packet, "ip.ttl == 64"), "{tags:?}");
    }
}

#[test]
fn ttl_rules_and_filters_do_not_invent_a_value_for_non_ipv4_or_bad_headers() {
    let mut ipv6 = vec![0; 54];
    ipv6[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
    ipv6[14] = 0x60;
    ipv6[20] = 59;
    ipv6[21] = 64;
    ipv6[22] = 64;
    let ipv6 = parse_ethernet(&ipv6, 1, 1.0);
    assert!(!matches_rule(&ipv6, "ip.ttl", 64));
    assert!(!matches_filter(&ipv6, "ip.ttl == 64"));

    let mut raw = packets::tcp(1, 100, 0x10, &[]).bytes;
    raw[14] = 0x44;
    let malformed = parse_ethernet(&raw, 2, 2.0);
    assert!(!matches_rule(&malformed, "ip.ttl", 64));
    assert!(!matches_filter(&malformed, "ip.ttl == 64"));

    let tiny = parse_ethernet(&[], 3, 3.0);
    assert!(!matches_filter(&tiny, "ip.ttl == 0"));
}

#[test]
fn local_transport_port_rules_are_specific_to_the_wire_transport() {
    let tcp = packets::tcp(1, 100, 0x10, &[]);
    let mut raw = tcp.bytes.clone();
    raw.truncate(42);
    raw[16..18].copy_from_slice(&28_u16.to_be_bytes());
    raw[23] = 17;
    raw[38..40].copy_from_slice(&8_u16.to_be_bytes());
    let udp = parse_ethernet(&raw, 2, 2.0);
    assert!(matches_rule(&tcp, "tcp.dstport", 80));
    assert!(matches_rule(&tcp, "tcp.srcport", 40_000));
    assert!(!matches_rule(&tcp, "udp.dstport", 80));
    assert!(!matches_rule(&udp, "tcp.dstport", 80));
    assert!(!matches_rule(&udp, "tcp.srcport", 40_000));
    assert!(matches_rule(&udp, "udp.dstport", 80));
    assert!(matches_rule(&udp, "udp.srcport", 40_000));
    assert!(matches_rule(&udp, "port", 80));
}
