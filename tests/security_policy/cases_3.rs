use super::*;
use packrat_tui::engine::AnalysisCore;
use packrat_tui::net::parser::parse_ethernet;

#[test]
fn syn_spike_evidence_excludes_retransmissions_and_other_vlan_scopes() {
    let mut core = AnalysisCore::default();
    for no in 1..=140 {
        let mut packet = tcp_probe(no, [10, 0, 0, 5], 443, 0x02, no as f64 / 1000.0);
        packet.bytes[38..42].copy_from_slice(&42_u32.to_be_bytes());
        packet.vlan_id = Some(10);
        core.analyze(&packet);
    }
    assert!(!core.alert_center.items.iter().any(|alert| alert.title == "SYN arrival spike"));

    for no in 141..=200 {
        let mut packet = tcp_probe(no, [10, 0, 0, 5], 443, 0x02, no as f64 / 1000.0);
        packet.vlan_id = Some(10);
        core.analyze(&packet);
        packet.vlan_id = Some(20);
        packet.no += 1000;
        core.analyze(&packet);
    }
    assert!(!core.alert_center.items.iter().any(|alert| alert.title == "SYN arrival spike"));

    for no in 201..=239 {
        let mut packet = tcp_probe(no, [10, 0, 0, 5], 443, 0x02, no as f64 / 1000.0);
        packet.vlan_id = Some(10);
        core.analyze(&packet);
    }
    let spikes: Vec<_> = core.alert_center.items.iter()
        .filter(|alert| alert.title == "SYN arrival spike").collect();
    assert_eq!(spikes.len(), 1);
    assert_eq!(spikes[0].packet_refs, std::iter::once(1).chain(141..=239).collect::<Vec<_>>());
    assert_eq!(spikes[0].provenance.as_ref().unwrap().rule_id, "tcp.syn_arrival_spike");
    assert_eq!(spikes[0].severity, "HIGH");
    assert!(spikes[0].detail.contains("service impact is unverified"));
    assert!(core.incidents.incidents.is_empty());
}

fn ipv6_frame(target: u16, next_header: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 54];
    bytes[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
    bytes[14] = 0x60;
    bytes[18..20].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    bytes[20] = next_header;
    bytes[21] = 64;
    bytes[22..38].copy_from_slice(&"2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
    bytes[38..54].copy_from_slice(&"2001:db8:1::".parse::<std::net::Ipv6Addr>().unwrap().octets());
    bytes[52..54].copy_from_slice(&target.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn analyze_ipv6(core: &mut AnalysisCore, no: u64, bytes: &[u8]) {
    core.analyze(&parse_ethernet(bytes, no, no as f64 / 1000.0));
}

#[rstest]
#[case(false)]
#[case(true)]
fn ssh_burst_counts_unique_connection_starts_and_keeps_scopes_separate(#[case] ipv6: bool) {
    let mut core = AnalysisCore::default();
    let make_packet = |no: u64, sequence: u32, flags: u8, vlan: u16| {
        let mut packet = if ipv6 {
            let mut tcp = [0; 20];
            tcp[..2].copy_from_slice(&50000_u16.to_be_bytes());
            tcp[2..4].copy_from_slice(&22_u16.to_be_bytes());
            tcp[4..8].copy_from_slice(&sequence.to_be_bytes());
            tcp[12] = 0x50;
            tcp[13] = flags;
            parse_ethernet(&ipv6_frame(5, 6, &tcp), no, no as f64 / 100.0)
        } else {
            let mut packet = tcp_probe(no, [10, 0, 0, 5], 22, flags, no as f64 / 100.0);
            packet.bytes[38..42].copy_from_slice(&sequence.to_be_bytes());
            packet
        };
        packet.vlan_id = Some(vlan);
        packet
    };
    for no in 1..=5 {
        core.analyze(&make_packet(no, no as u32, 0x18, 10));
        core.analyze(&make_packet(no + 5, no as u32, 0x12, 10));
        core.analyze(&make_packet(no + 10, 100, 0x02, 10));
    }
    for no in 16..=23 {
        core.analyze(&make_packet(no, no as u32, 0x02, if no % 2 == 0 { 20 } else { 30 }));
    }
    assert!(core.alert_center.items.iter().all(|a| a.source != "AUTH"));

    core.analyze(&make_packet(24, 24, 0x02, 20));
    core.analyze(&make_packet(25, 25, 0x02, 30));
    let alerts: Vec<_> = core.alert_center.items.iter().filter(|a| a.source == "AUTH").collect();
    assert_eq!(alerts.len(), 2);
    for (ending, refs) in [(24, [16, 18, 20, 22, 24]), (25, [17, 19, 21, 23, 25])] {
        let alert = alerts.iter().find(|a| a.last_packet == ending).unwrap();
        assert_eq!(alert.title, "SSH connection-start burst");
        assert_eq!(alert.severity, "MEDIUM");
        assert_eq!(alert.packet_refs, refs);
        assert_eq!(alert.provenance.as_ref().unwrap().rule_id, "ssh.connection_start_burst");
        assert!(alert.detail.contains("authentication outcome not observable"));
    }
    assert!(core.incidents.incidents.is_empty());
}

#[test]
fn ipv6_tcp_scan_counts_only_complete_initial_syns_through_extensions() {
    let mut core = AnalysisCore::default();
    let mut tcp = [0; 24];
    tcp[..2].copy_from_slice(&40000_u16.to_be_bytes());
    tcp[2..4].copy_from_slice(&443_u16.to_be_bytes());
    tcp[12] = 0x50;
    for target in 1..=12 {
        let no = u64::from(target);
        tcp[13] = 0x12;
        analyze_ipv6(&mut core, no, &ipv6_frame(target, 6, &tcp));
        tcp[13] = 0x02;
        let mut fragment = vec![6, 0, 0, 1, 0, 0, 0, 1];
        fragment.extend_from_slice(&tcp);
        analyze_ipv6(&mut core, no + 12, &ipv6_frame(target, 44, &fragment));
        let mut truncated = ipv6_frame(target, 6, &tcp);
        truncated.pop();
        analyze_ipv6(&mut core, no + 24, &truncated);
    }
    assert!(!core.alert_center.items.iter().any(|a| a.title == "Horizontal host scan"));

    let mut options = vec![6, 0, 0, 0, 0, 0, 0, 0];
    options.extend_from_slice(&tcp);
    for target in 1..=12 {
        analyze_ipv6(&mut core, u64::from(target) + 36, &ipv6_frame(target, 60, &options));
    }
    let alert = core.alert_center.items.iter().find(|a| a.title == "Horizontal host scan").unwrap();
    assert_eq!(alert.packet_refs, (37..=48).collect::<Vec<_>>());
    assert_eq!(alert.provenance.as_ref().unwrap().revision, 3);
}

#[rstest]
#[case(17, [0x9c, 0x40, 0x01, 0xbb, 0, 7, 0, 0], [0x9c, 0x40, 0x01, 0xbb, 0, 8, 0, 0], "Horizontal host scan", "scan.horizontal")]
#[case(58, [129, 0, 0, 0, 0, 0, 0, 0], [128, 0, 0, 0, 0, 0, 0, 0], "ICMP address sweep", "icmp.address_sweep")]
fn ipv6_udp_and_echo_sweeps_keep_only_distinct_matching_evidence(
    #[case] next_header: u8,
    #[case] ignored: [u8; 8],
    #[case] counted: [u8; 8],
    #[case] title: &str,
    #[case] rule_id: &str,
) {
    let mut core = AnalysisCore::default();
    for no in 1..=12 {
        analyze_ipv6(&mut core, no, &ipv6_frame(no as u16, next_header, &ignored));
        analyze_ipv6(&mut core, no + 12, &ipv6_frame(1, next_header, &counted));
    }
    assert!(!core.alert_center.items.iter().any(|a| a.title == title));

    for target in 2..=12 {
        analyze_ipv6(&mut core, u64::from(target) + 23, &ipv6_frame(target, next_header, &counted));
    }
    let alert = core.alert_center.items.iter().find(|a| a.title == title).unwrap();
    assert_eq!(alert.packet_refs, (24..=35).collect::<Vec<_>>());
    assert_eq!(alert.provenance.as_ref().unwrap().rule_id, rule_id);
}
