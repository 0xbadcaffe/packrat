use super::{SecurityEngine, ipv4_tcp_packet};
use rstest::rstest;
use std::net::Ipv4Addr;

fn handshake(flags: u8) -> super::Packet {
    let mut packet = ipv4_tcp_packet(1, 1, flags, b"");
    packet.bytes[22] = 64;
    packet.bytes[48..50].copy_from_slice(&29_200_u16.to_be_bytes());
    packet
}

#[test]
fn fingerprint_lookup_stays_bounded_and_evicts_the_oldest_observation() {
    let mut engine = SecurityEngine::new();
    let limit = 1_000;
    let mut packet = handshake(0x02);
    let address = |index| Ipv4Addr::from(0x0a01_0000_u32 + index);
    let mut observe = |engine: &mut SecurityEngine, index, frame| {
        let ip = address(index);
        packet.src = ip.to_string();
        packet.bytes[26..30].copy_from_slice(&ip.octets());
        packet.no = frame;
        packet.timestamp = frame as f64;
        engine.update(&packet);
    };
    for index in 1..=limit {
        observe(&mut engine, index, u64::from(index));
    }

    let first = address(1).to_string();
    let next = address(2).to_string();
    assert_eq!(engine.os_guess_for(&first), Some("Linux 3.x"));
    observe(&mut engine, limit + 1, u64::from(limit + 1));
    assert_eq!(engine.os_guess_for(&first), None);
    assert_eq!(engine.os_guesses[0].src_ip, next);
    assert_eq!(engine.os_guess_for(&address(limit + 1).to_string()), Some("Linux 3.x"));

    observe(&mut engine, 1, u64::from(limit + 2));
    assert_eq!(engine.os_guess_for(&first), Some("Linux 3.x"));
    assert_eq!(engine.os_guess_for(&next), None);
    assert_eq!(engine.summary().os_guesses, limit as usize);
    assert_eq!(engine.os_guesses.len(), limit as usize);

    engine.clear();
    assert!(engine.os_guesses.is_empty());
    assert_eq!(engine.os_guess_for(&first), None);
}

#[rstest]
#[case(0x02)]
#[case(0x12)]
fn fingerprint_reads_handshakes_with_vlan_tags_and_ipv4_options(#[case] flags: u8) {
    let mut packet = handshake(flags);
    packet.bytes[14] = 0x46;
    packet.bytes[16..18].copy_from_slice(&44_u16.to_be_bytes());
    packet.bytes.splice(34..34, [1, 1, 1, 0]);
    packet.bytes.splice(12..12, [0x88, 0xa8, 0, 10, 0x81, 0, 0, 20]);
    let mut engine = SecurityEngine::new();
    engine.update(&packet);
    assert_eq!(engine.os_guess_for(&packet.src), Some("Linux 3.x"));
    let guess = &engine.os_guesses[0];
    assert_eq!((guess.ttl, guess.window), (64, 29_200));
}

#[rstest]
#[case("ack")]
#[case("syn_rst")]
#[case("short")]
#[case("bad_offset")]
#[case("fragment")]
#[case("metadata_mismatch")]
fn fingerprint_ignores_unusable_wire_observations(#[case] defect: &str) {
    let mut packet = handshake(0x02);
    match defect {
        "ack" => packet.bytes[47] = 0x10,
        "syn_rst" => packet.bytes[47] = 0x06,
        "short" => { packet.bytes.pop(); }
        "bad_offset" => packet.bytes[46] = 0x40,
        "fragment" => packet.bytes[20] = 0x20,
        "metadata_mismatch" => packet.src = "203.0.113.10".into(),
        _ => unreachable!(),
    }
    let mut engine = SecurityEngine::new();
    engine.update(&packet);
    assert!(engine.os_guesses.is_empty());
}
