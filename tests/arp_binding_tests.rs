use packrat_tui::engine::AnalysisCore;
#[path = "support/arp.rs"]
mod arp;
use arp::reply;

const TITLE: &str = "ARP binding changed";
const SOURCE_MISMATCH: &str = "ARP reply sender differs from Ethernet source";

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

#[test]
fn arp_source_mismatch_is_distinct_from_binding_changes_and_vrrp() {
    let mut core = AnalysisCore::default();
    core.analyze(&reply(1, 1.0, 10, 1));
    let mut vrrp = reply(2, 2.0, 20, 1);
    vrrp.bytes[26..32].copy_from_slice(&[0, 0, 0x5e, 0, 1, 7]);
    core.analyze(&vrrp);
    let mut mismatch = reply(3, 3.0, 10, 1);
    mismatch.bytes[11] = 0x25;
    core.analyze(&mismatch);

    let mut invalid = mismatch.clone();
    invalid.no = 4;
    invalid.bytes[6] |= 1;
    core.analyze(&invalid);
    let mut truncated = mismatch.clone();
    truncated.no = 5;
    truncated.bytes.truncate(33);
    core.analyze(&truncated);

    let findings: Vec<_> = core.alert_center.items.iter()
        .filter(|alert| alert.title == SOURCE_MISMATCH).collect();
    assert_eq!(findings.len(), 1);
    let alert = findings[0];
    assert_eq!(alert.severity, "LOW");
    assert_eq!(alert.packet_refs, [3]);
    assert!(alert.detail.contains("02:00:00:00:00:25"));
    assert!(alert.detail.contains("02:00:00:00:00:01"));
    assert_eq!(alert.provenance.as_ref().unwrap().rule_id, "arp.reply_source_mismatch");
    assert!(core.alert_center.items.iter().all(|alert| alert.title != TITLE));
    assert!(core.incidents.incidents.is_empty());
}

#[test]
fn alternating_arp_claims_require_three_scoped_ordered_frames() {
    let by_rule = |core: &AnalysisCore| {
        core.alert_center.items.iter().position(|alert| {
            alert.provenance.as_ref().is_some_and(|rule| rule.rule_id == "arp.alternating_claims")
        })
    };
    for samples in [
        [(1, 1.0, 10, 1), (2, 2.0, 10, 2), (3, 3.0, 10, 2)], // One change.
        [(1, 1.0, 10, 1), (2, 2.0, 20, 2), (3, 3.0, 10, 1)], // Different VLAN.
        [(1, 1.0, 10, 1), (2, 2.0, 10, 2), (3, 1.5, 10, 1)], // Reordered.
        [(1, 1.0, 10, 1), (2, 2.0, 10, 2), (3, 2.0, 10, 1)], // Tied timestamp.
        [(1, 1.0, 10, 1), (2, 2.0, 10, 2), (1, 3.0, 10, 1)], // Duplicate frame identity.
        [(1, 1.0, 10, 1), (2, 2.0, 10, 2), (3, 32.0, 10, 1)], // Too far apart.
    ] {
        let mut core = AnalysisCore::default();
        for (no, time, vlan, host) in samples {
            core.analyze(&reply(no, time, vlan, host));
        }
        assert!(by_rule(&core).is_none(), "{samples:?}");
    }

    let mut core = AnalysisCore::default();
    for (no, host) in [(1, 1), (2, 2), (3, 1)] {
        core.analyze(&reply(no, no as f64, 10, host));
    }
    let index = by_rule(&core).unwrap();
    let alert = &core.alert_center.items[index];
    assert_eq!(alert.packet_refs, [1, 2, 3]);
    assert_eq!(alert.severity, "MEDIUM");
    assert_eq!(alert.hit_count, 1);
    assert!(alert.detail.contains("failover, duplicate addressing, and spoofing are possible"));
    core.analyze(&reply(4, 4.0, 10, 2));
    let alert = &core.alert_center.items[index];
    assert_eq!(alert.hit_count, 2);
    assert_eq!(alert.packet_refs, [1, 2, 3, 4]);
    assert!(core.incidents.incidents.is_empty());
}
