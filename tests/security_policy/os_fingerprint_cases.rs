use super::{SecurityEngine, ipv4_tcp_packet};
use std::net::Ipv4Addr;

#[test]
fn fingerprint_lookup_stays_bounded_and_evicts_the_oldest_observation() {
    let mut engine = SecurityEngine::new();
    let limit = 1_000;
    let mut packet = ipv4_tcp_packet(1, 1, 0x02, b"");
    packet.protocol = "TCP".into();
    packet.bytes[22] = 64;
    packet.bytes[48..50].copy_from_slice(&29_200_u16.to_be_bytes());
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
