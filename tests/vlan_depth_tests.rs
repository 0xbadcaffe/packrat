#[path = "support/packets.rs"]
mod packets;

use packrat_tui::net::parser::parse_ethernet;

fn stacked(depth: u16) -> Vec<u8> {
    let packet = packets::tcp(1, 100, 0x18, &[]);
    let mut bytes = packet.bytes[..12].to_vec();
    for tag in 1..=depth {
        bytes.extend(0x8100u16.to_be_bytes());
        bytes.extend(tag.to_be_bytes());
    }
    bytes.extend(&packet.bytes[12..]);
    bytes
}

#[test]
fn adversarial_tag_stacks_never_overflow_the_parser_counter() {
    for depth in 0..=300 {
        let bytes = stacked(depth);
        let packet = parse_ethernet(&bytes, 1, 1.0);
        assert_eq!(packet.bytes, bytes);
        if depth > 2 {
            assert_eq!(packet.protocol, "RAW");
            assert!(packet.info.contains("supported depth"));
            assert_eq!(packet.outer_vlan_id, Some(1));
            assert_eq!(packet.vlan_id, Some(2));
        } else {
            assert_ne!(packet.protocol, "RAW");
        }
    }
}

#[test]
fn truncated_stacked_frames_are_safe_at_every_prefix() {
    for depth in 1..=4 {
        let bytes = stacked(depth);
        for end in 0..bytes.len() {
            let packet = parse_ethernet(&bytes[..end], 1, 1.0);
            assert_eq!(packet.bytes, bytes[..end]);
        }
    }
}
