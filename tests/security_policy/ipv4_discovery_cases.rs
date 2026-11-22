use packrat_tui::{
    engine::AnalysisCore,
    net::{packet::Packet, parser::parse_ethernet},
};

pub(super) fn discovery_packet(no: u64, target: u8, protocol: u8, transport: &[u8]) -> Packet {
    let mut wire = super::ipv4_tcp_packet(no, 100, 0x18, &[]).bytes;
    wire.truncate(34);
    wire[16..18].copy_from_slice(&((20 + transport.len()) as u16).to_be_bytes());
    wire[22] = 64;
    wire[23] = protocol;
    wire[30..34].copy_from_slice(&[10, 0, 0, target]);
    wire.extend(transport);
    parse_ethernet(&wire, no, no as f64 / 100.0)
}

#[test]
fn ipv4_discovery_uses_complete_unfragmented_wire_payloads_and_ports() {
    const ICMP: &str = "ICMP address sweep";
    const UDP: &str = "Horizontal host scan";
    let mut core = AnalysisCore::default();
    let empty_udp = [0x9c, 0x40, 0x01, 0xbb, 0, 8, 0, 0];
    for target in 1..=12 {
        let no = u64::from(target);
        let mut reply = discovery_packet(no, target, 1, &[0, 0, 0, 0, 0, 0, 0, 0]);
        reply.info = "Echo request".into();
        core.analyze(&reply);
        let mut padding = discovery_packet(no + 20, target, 17, &empty_udp);
        padding.bytes[16..18].copy_from_slice(&20_u16.to_be_bytes());
        core.analyze(&padding);
        let mut fragment = discovery_packet(no + 40, target, 17, &empty_udp);
        fragment.bytes[20..22].copy_from_slice(&1_u16.to_be_bytes());
        core.analyze(&fragment);
    }
    assert!(
        core.alert_center
            .items
            .iter()
            .all(|alert| !matches!(alert.title.as_str(), ICMP | UDP))
    );

    for target in 1..=12 {
        let no = u64::from(target);
        let mut echo = discovery_packet(no + 60, target, 1, &[8, 0, 0, 0, 0, 0, 0, 0]);
        echo.info.clear();
        core.analyze(&echo);
    }
    for target in 1..=12 {
        let mut udp = discovery_packet(u64::from(target) + 80, target, 17, &empty_udp);
        udp.dst_port = Some(u16::from(target));
        core.analyze(&udp);
    }
    let echo = core
        .alert_center
        .items
        .iter()
        .find(|alert| alert.title == ICMP)
        .unwrap();
    assert_eq!(echo.packet_refs, (61..=72).collect::<Vec<_>>());
    let udp = core
        .alert_center
        .items
        .iter()
        .find(|alert| alert.title == UDP)
        .unwrap();
    assert_eq!(udp.packet_refs, (81..=92).collect::<Vec<_>>());
    assert!(udp.detail.contains("UDP port 443"));
}
