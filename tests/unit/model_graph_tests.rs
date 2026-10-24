use super::*;
use crate::model::evidence::PacketRef;

#[test]
fn graph_evidence_is_bounded_and_keeps_first_and_latest_packets() {
    let mut evidence = Vec::new();
    for packet_no in 1..=MAX_GRAPH_EVIDENCE as u64 + 100 {
        add_evidence_bounded(
            &mut evidence,
            GraphEvidenceRef::Packet(PacketRef(packet_no)),
        );
    }
    assert_eq!(evidence.len(), MAX_GRAPH_EVIDENCE);
    assert_eq!(evidence.first(), Some(&GraphEvidenceRef::Packet(PacketRef(1))));
    assert_eq!(
        evidence.last(),
        Some(&GraphEvidenceRef::Packet(PacketRef(MAX_GRAPH_EVIDENCE as u64 + 100))),
    );

    let before = evidence.len();
    add_evidence_bounded(
        &mut evidence,
        GraphEvidenceRef::Packet(PacketRef(MAX_GRAPH_EVIDENCE as u64 + 100)),
    );
    assert_eq!(evidence.len(), before);
}
