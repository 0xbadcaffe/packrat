use packrat_tui::engine::AnalysisCore;
use packrat_tui::net::{packet::Packet, parser::parse_ethernet};

const TITLE: &str = "ARP binding changed";

fn reply(frame: u64, time: f64, vlan: u16, host: u8) -> Packet {
    let sender = [2, 0, 0, 0, 0, host];
    let receiver = [2, 0, 0, 0, 0, 99];
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&receiver);
    bytes.extend_from_slice(&sender);
    bytes.extend_from_slice(&0x8100_u16.to_be_bytes());
    bytes.extend_from_slice(&vlan.to_be_bytes());
    bytes.extend_from_slice(&0x0806_u16.to_be_bytes());
    bytes.extend_from_slice(&[0, 1, 8, 0, 6, 4, 0, 2]);
    bytes.extend_from_slice(&sender);
    bytes.extend_from_slice(&[192, 0, 2, 1]);
    bytes.extend_from_slice(&receiver);
    bytes.extend_from_slice(&[192, 0, 2, 99]);
    parse_ethernet(&bytes, frame, time)
}

#[test]
fn arp_reply_changes_retain_both_frames_without_cross_vlan_matching() {
    let mut core = AnalysisCore::default();
    core.analyze(&reply(1, 1.0, 10, 1));
    core.analyze(&reply(2, 2.0, 10, 1));
    core.analyze(&reply(3, 3.0, 20, 2));
    assert!(
        core.alert_center
            .items
            .iter()
            .all(|alert| alert.title != TITLE)
    );

    core.analyze(&reply(4, 4.0, 10, 3));
    let finding = core
        .alert_center
        .items
        .iter()
        .find(|item| item.title == TITLE)
        .unwrap();
    assert_eq!(finding.packet_refs, [2, 4]);
    assert_eq!(finding.severity, "MEDIUM");
    assert!(
        finding
            .detail
            .contains("whether any host accepted the change is unknown")
    );
    assert_eq!(
        finding.provenance.as_ref().unwrap().rule_id,
        "arp.reply_binding_change"
    );
}

#[test]
fn arp_claim_history_ignores_requests_truncation_old_baselines_and_older_timestamps() {
    let mut core = AnalysisCore::default();
    core.analyze(&reply(1, 100.0, 10, 1));
    core.analyze(&reply(2, 99.0, 10, 2));
    let mut request = reply(3, 101.0, 10, 3);
    request.bytes[25] = 1;
    core.analyze(&request);
    let mut partial = reply(4, 102.0, 10, 4);
    partial.bytes.truncate(30);
    partial.length = 30;
    core.analyze(&partial);
    core.analyze(&reply(5, 500.0, 10, 5));
    assert!(
        core.alert_center
            .items
            .iter()
            .all(|alert| alert.title != TITLE)
    );
}
