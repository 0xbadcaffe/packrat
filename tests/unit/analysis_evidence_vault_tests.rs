use super::*;
use crate::analysis::incident::{IncidentSource, IncidentStatus};
use crate::model::evidence::Severity;
use crate::net::packet::Packet;

fn incident() -> Incident {
    Incident {
        id: 9,
        source: IncidentSource::IndustrySignature,
        detector: "test detector".into(),
        summary: "test summary".into(),
        severity: Severity::Critical,
        attacker: "203.0.113.9".into(),
        target: "10.0.0.9".into(),
        first_packet: 1,
        last_packet: 1,
        first_seen: 1.0,
        last_seen: 1.0,
        status: IncidentStatus::PendingReview,
        reviewed: false,
        packet_history: vec![Packet { capture: None,
            no: 1,
            timestamp: 1.0,
            src: "203.0.113.9".into(),
            dst: "10.0.0.9".into(),
            protocol: "TCP".into(),
            length: 4,
            info: "test".into(),
            src_port: Some(4444),
            dst_port: Some(443),
            vlan_id: None,
            vlan_pcp: None,
            vlan_dei: None,
            outer_vlan_id: None,
            bytes: vec![1, 2, 3, 4],
        }],
    }
}

#[test]
fn freezes_pcap_metadata_and_ndjson_once() {
    let directory = std::env::temp_dir().join(format!("packrat-vault-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    let mut vault = EvidenceVault::new(&directory);
    let incident = incident();
    let first = vault.freeze(&incident).unwrap().unwrap().clone();
    assert!(first.pcap_path.exists());
    assert!(first.metadata_path.exists());
    assert!(first.ndjson_path.exists());
    assert_eq!(first.pcap_path.extension().unwrap(), "pcapng");
    let packets = crate::pcap_replay::read_pcap(&first.pcap_path).unwrap();
    assert_eq!(packets[0].bytes, incident.packet_history[0].bytes);
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        for path in [&first.pcap_path, &first.metadata_path, &first.ndjson_path] {
            assert_eq!(std::fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }
    assert!(vault.freeze(&incident).unwrap().is_none());
    let ndjson = std::fs::read_to_string(first.ndjson_path).unwrap();
    assert_eq!(ndjson.lines().count(), 2);
    let _ = std::fs::remove_dir_all(directory);
}
