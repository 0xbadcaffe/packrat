//! Automatic evidence preservation for critical incidents.

use std::collections::HashSet;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use crate::analysis::incident::Incident;
use crate::export::PcapWriter;

#[derive(Debug, Clone)]
pub struct EvidenceExport {
    pub incident_id: u64,
    pub pcap_path: PathBuf,
    pub metadata_path: PathBuf,
    pub ndjson_path: PathBuf,
    pub packet_count: usize,
}

#[derive(Debug)]
pub struct EvidenceVault {
    pub enabled: bool,
    pub directory: PathBuf,
    pub exports: Vec<EvidenceExport>,
    frozen_incidents: HashSet<u64>,
}

impl Default for EvidenceVault {
    fn default() -> Self {
        let directory = dirs_next::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("packrat")
            .join("evidence");
        Self::new(directory)
    }
}

impl EvidenceVault {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            enabled: true,
            directory: directory.into(),
            exports: Vec::new(),
            frozen_incidents: HashSet::new(),
        }
    }

    /// Persist an incident once. Repeated signature hits update the in-memory
    /// incident but do not create duplicate evidence sets.
    pub fn freeze(&mut self, incident: &Incident) -> Result<Option<&EvidenceExport>, String> {
        if !self.enabled || self.frozen_incidents.contains(&incident.id) {
            return Ok(None);
        }
        std::fs::create_dir_all(&self.directory)
            .map_err(|error| format!("create evidence directory: {error}"))?;

        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let base = format!("incident-{}-{stamp}", incident.id);
        let pcap_path = self.directory.join(format!("{base}.pcap"));
        let metadata_path = self.directory.join(format!("{base}.json"));
        let ndjson_path = self.directory.join(format!("{base}.ndjson"));

        write_pcap(&pcap_path, incident)?;
        write_metadata(&metadata_path, incident)?;
        write_ndjson(&ndjson_path, incident)?;

        self.frozen_incidents.insert(incident.id);
        self.exports.push(EvidenceExport {
            incident_id: incident.id,
            pcap_path,
            metadata_path,
            ndjson_path,
            packet_count: incident.packet_history.len(),
        });
        Ok(self.exports.last())
    }

    pub fn clear_session(&mut self) {
        self.exports.clear();
        self.frozen_incidents.clear();
    }
}

fn write_pcap(path: &Path, incident: &Incident) -> Result<(), String> {
    let mut writer = PcapWriter::new(path).map_err(|error| format!("create PCAP: {error}"))?;
    for packet in &incident.packet_history {
        writer.write_packet(packet).map_err(|error| format!("write PCAP: {error}"))?;
    }
    writer.flush().map_err(|error| format!("flush PCAP: {error}"))
}

#[derive(serde::Serialize)]
struct IncidentMetadata<'a> {
    schema: &'static str,
    incident_id: u64,
    source: String,
    detector: &'a str,
    summary: &'a str,
    severity: String,
    attacker: &'a str,
    target: &'a str,
    first_packet: u64,
    last_packet: u64,
    first_seen: f64,
    last_seen: f64,
    packet_count: usize,
}

fn metadata(incident: &Incident) -> IncidentMetadata<'_> {
    IncidentMetadata {
        schema: "packrat.evidence.v1",
        incident_id: incident.id,
        source: incident.source.to_string(),
        detector: &incident.detector,
        summary: &incident.summary,
        severity: incident.severity.to_string(),
        attacker: &incident.attacker,
        target: &incident.target,
        first_packet: incident.first_packet,
        last_packet: incident.last_packet,
        first_seen: incident.first_seen,
        last_seen: incident.last_seen,
        packet_count: incident.packet_history.len(),
    }
}

fn write_metadata(path: &Path, incident: &Incident) -> Result<(), String> {
    let json = serde_json::to_string_pretty(&metadata(incident))
        .map_err(|error| format!("serialize metadata: {error}"))?;
    std::fs::write(path, json).map_err(|error| format!("write metadata: {error}"))
}

#[derive(serde::Serialize)]
struct PacketRecord<'a> {
    record: &'static str,
    incident_id: u64,
    packet_no: u64,
    timestamp: f64,
    source: &'a str,
    target: &'a str,
    protocol: &'a str,
    source_port: Option<u16>,
    target_port: Option<u16>,
    length: u16,
    vlan_id: Option<u16>,
    outer_vlan_id: Option<u16>,
    info: &'a str,
}

fn write_ndjson(path: &Path, incident: &Incident) -> Result<(), String> {
    let file = File::create(path).map_err(|error| format!("create NDJSON: {error}"))?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer(&mut writer, &metadata(incident))
        .map_err(|error| format!("serialize NDJSON metadata: {error}"))?;
    writer.write_all(b"\n").map_err(|error| format!("write NDJSON: {error}"))?;
    for packet in &incident.packet_history {
        let record = PacketRecord {
            record: "packet",
            incident_id: incident.id,
            packet_no: packet.no,
            timestamp: packet.timestamp,
            source: &packet.src,
            target: &packet.dst,
            protocol: &packet.protocol,
            source_port: packet.src_port,
            target_port: packet.dst_port,
            length: packet.length,
            vlan_id: packet.vlan_id,
            outer_vlan_id: packet.outer_vlan_id,
            info: &packet.info,
        };
        serde_json::to_writer(&mut writer, &record)
            .map_err(|error| format!("serialize NDJSON packet: {error}"))?;
        writer.write_all(b"\n").map_err(|error| format!("write NDJSON: {error}"))?;
    }
    writer.flush().map_err(|error| format!("flush NDJSON: {error}"))
}

#[cfg(test)]
mod tests {
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
            packet_history: vec![Packet {
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
        assert!(vault.freeze(&incident).unwrap().is_none());
        let ndjson = std::fs::read_to_string(first.ndjson_path).unwrap();
        assert_eq!(ndjson.lines().count(), 2);
        let _ = std::fs::remove_dir_all(directory);
    }
}
