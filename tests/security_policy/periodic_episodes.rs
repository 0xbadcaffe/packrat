use packrat_tui::{analysis::alert_center::AlertDisposition, engine::AnalysisCore};

use super::periodic_datagram;

#[test]
fn periodic_samples_use_one_tag_path_even_when_global_cadence_is_regular() {
    const TITLE: &str = "Periodic fixed-size traffic";
    let mut core = AnalysisCore::default();
    for (index, (time, provider)) in [
        (0., false), (10., true), (20., false), (30., true), (40., false), (50., true),
        (60., false), (80., false), (100., false), (120., false),
    ].into_iter().enumerate() {
        let frame = index as u64 + 1;
        let mut raw = periodic_datagram(frame, time, 120, 50_000, false).bytes;
        let tpid = if provider { 0x88a8_u16 } else { 0x8100_u16 };
        let tci = if frame % 2 == 0 { 0xb014_u16 } else { 20_u16 };
        raw.splice(12..12, [tpid, tci].into_iter().flat_map(u16::to_be_bytes));
        core.analyze(&packrat_tui::net::parser::parse_ethernet(&raw, frame, time));
        if frame < 10 {
            assert!(core.alert_center.items.iter().all(|alert| alert.title != TITLE));
        }
    }
    let alert = core.alert_center.items.iter().find(|alert| alert.title == TITLE).unwrap();
    assert_eq!(alert.packet_refs, [1, 3, 5, 7, 8, 9, 10]);
}

#[rstest::rstest]
#[case(42, 50000)]
#[case(120, 0)]
fn periodic_udp_requires_payload_and_nonzero_ports(#[case] size: usize, #[case] port: u16) {
    let mut core = AnalysisCore::default();
    for frame in 1..=7 {
        core.analyze(&periodic_datagram(frame, frame as f64 * 10.0, size, port, false));
    }
    assert!(!core.alert_center.items.iter().any(|alert| alert.title == "Periodic fixed-size traffic"));

    for frame in 8..=14 {
        core.analyze(&periodic_datagram(frame, frame as f64 * 10.0, 120, 50000, false));
    }
    let alerts: Vec<_> = core.alert_center.items.iter()
        .filter(|alert| alert.title == "Periodic fixed-size traffic").collect();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].packet_refs, (8..=14).collect::<Vec<_>>());
}

#[test]
fn reverse_traffic_does_not_hide_a_new_periodic_episode() {
    let mut core = AnalysisCore::default();
    let forward = |frame, time| periodic_datagram(frame, time, 120, 50000, false);
    for index in 0..7 {
        core.analyze(&forward(index + 1, index as f64 * 10.0));
    }
    let first = &core.alert_center.items[0];
    let (id, scope) = (first.id, first.capture_id.clone());
    assert!(core.alert_center.set_disposition(id, scope.as_deref(), AlertDisposition::Benign));

    for (frame, time) in [(8, 1_000.0), (9, 2_750.0), (10, 3_650.0)] {
        core.analyze(&periodic_datagram(frame, time, 100, 50000, true));
    }
    core.analyze(&forward(11, 3_670.0));
    core.analyze(&forward(12, 3_640.0)); // A late frame from before the new episode.
    for index in 0..6 {
        core.analyze(&forward(index + 13, 3_680.0 + index as f64 * 10.0));
    }
    let alerts = &core.alert_center.items;
    assert_eq!(alerts.len(), 2);
    assert_eq!(alerts[0].disposition, AlertDisposition::Benign);
    assert_eq!(alerts[0].packet_refs, [1, 2, 3, 4, 5, 6, 7]);
    assert_eq!(alerts[1].disposition, AlertDisposition::New);
    assert_eq!(alerts[1].packet_refs, [11, 13, 14, 15, 16, 17, 18]);
}

#[test]
fn a_periodic_burst_after_idle_expiry_keeps_its_own_evidence_and_review_state() {
    let mut core = AnalysisCore::default();
    let make = |frame, time| periodic_datagram(frame, time, 120, 50000, false);
    for index in 0..7 {
        core.analyze(&make(index + 1, index as f64 * 10.0));
    }
    let first = &core.alert_center.items[0];
    let (first_id, scope) = (first.id, first.capture_id.clone());
    assert!(core.alert_center.set_disposition(first_id, scope.as_deref(), AlertDisposition::Benign));
    for index in 0..7 {
        core.analyze(&make(index + 8, 70.0 + index as f64 * 10.0));
    }
    assert_eq!(core.alert_center.items.len(), 1);
    for index in 0..6 {
        core.analyze(&make(index + 15, 3731.0 + index as f64 * 10.0));
    }
    assert_eq!(core.alert_center.items.len(), 1);
    core.analyze(&make(21, 3791.0));

    let alerts = &core.alert_center.items;
    assert_eq!(alerts.len(), 2);
    assert_eq!(alerts[0].id, first_id);
    assert_eq!(alerts[0].disposition, AlertDisposition::Benign);
    assert_eq!(alerts[0].packet_refs, (1..=7).collect::<Vec<_>>());
    assert_eq!(alerts[1].disposition, AlertDisposition::New);
    assert_eq!(alerts[1].packet_refs, (15..=21).collect::<Vec<_>>());
    assert_eq!(alerts[1].severity, "MEDIUM");
    assert_ne!(alerts[1].correlation_key, alerts[0].correlation_key);
    assert!(alerts[1].detail.contains("Timing alone does not establish command-and-control"));
}

#[rstest::rstest]
#[case(450)]
#[case(120)]
fn irregular_same_direction_traffic_cannot_keep_a_periodic_episode_open(#[case] size: usize) {
    let mut core = AnalysisCore::default();
    let periodic = |frame, time| periodic_datagram(frame, time, 120, 50000, false);
    for index in 0..7 {
        core.analyze(&periodic(index + 1, index as f64 * 10.0));
    }
    assert_eq!(core.alert_center.items.len(), 1);
    for (frame, time) in [(8, 1_000.0), (9, 2_750.0), (10, 3_650.0)] {
        core.analyze(&periodic_datagram(frame, time, size, 50000, false));
    }
    assert_eq!(core.alert_center.items.len(), 1);
    for index in 0..7 {
        core.analyze(&periodic(index + 11, 3_661.0 + index as f64 * 10.0));
    }
    let alerts = &core.alert_center.items;
    assert_eq!(alerts.len(), 2);
    assert_eq!(alerts[1].severity, "MEDIUM");
    assert_eq!(alerts[1].packet_refs, [11, 12, 13, 14, 15, 16, 17]);
}
