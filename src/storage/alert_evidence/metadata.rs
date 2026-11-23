use std::{collections::BTreeMap, net::{IpAddr, SocketAddr}};

use anyhow::Result;
use serde::Serialize;

use crate::analysis::packet_fields::{CapturedVlanTag, MAX_EVIDENCE_VLAN_TAGS, captured_transport_header};
use crate::net::packet::Packet;

use super::{
    AlertLogs, FrameStatus, PacketArchive, evidence_frame_set_sha256, frame_status, latest_alert_in_logs,
    scoped_frames,
};

#[derive(Serialize)]
pub struct AlertPacketMetadata {
    record_type: &'static str,
    session_id: String,
    capture_id: String,
    alert_id: u64,
    evidence_frame_set_sha256: String,
    #[serde(skip)]
    trigger_frame_number: Option<u64>,
    frames: Vec<FrameMetadata>,
}

#[derive(Serialize)]
struct FrameMetadata {
    frame_number: u64,
    status: FrameStatus,
    packet: Option<PacketMetadata>,
}

#[derive(Serialize)]
struct PacketMetadata {
    timestamp: Option<f64>,
    recorded_source: Option<IpAddr>,
    recorded_destination: Option<IpAddr>,
    captured_length: Option<u32>,
    wire_length: Option<u32>,
    link_type: Option<u32>,
    section_id: Option<u32>,
    interface_id: Option<u32>,
    transport: Option<TransportHeader>,
    #[serde(skip)]
    flow: Option<FlowKey>,
}

#[derive(Serialize)]
struct TransportHeader {
    protocol: &'static str,
    source_port: u16,
    destination_port: u16,
    tcp_flags: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
struct FlowKey {
    section_id: u32,
    interface_id: u32,
    outer_vlan_id: Option<u16>,
    vlan_id: Option<u16>,
    vlan_stack: Vec<CapturedVlanTag>,
    protocol: &'static str,
    source: SocketAddr,
    destination: SocketAddr,
}

#[derive(Default, Serialize)]
struct FlowCounts {
    evidence_frames: usize,
    contains_trigger_frame: bool,
    initial_syn_frames: usize,
    syn_ack_frames: usize,
    reset_frames: usize,
    first_seen: Option<f64>,
    last_seen: Option<f64>,
}

#[derive(Serialize)]
struct DirectionalFlow {
    #[serde(flatten)]
    key: FlowKey,
    #[serde(flatten)]
    counts: FlowCounts,
    reverse_evidence_frames: usize,
}

#[derive(Serialize)]
struct TriggerFrame {
    frame_number: u64,
    status: FrameStatus,
    transport_header_observed: bool,
}

#[derive(Serialize)]
pub struct AlertFlowSummary {
    record_type: &'static str,
    session_id: String,
    capture_id: String,
    alert_id: u64,
    evidence_frame_set_sha256: String,
    referenced_frames: usize,
    missing_frames: usize,
    unreadable_frames: usize,
    truncated_frames: usize,
    length_unknown_frames: usize,
    retained_frames_without_flow: usize,
    max_vlan_tags: usize,
    trigger_frame: Option<TriggerFrame>,
    directional_flows: Vec<DirectionalFlow>,
    limitation: &'static str,
}

impl PacketMetadata {
    fn new(packet: &Packet) -> Self {
        let capture = packet.capture.as_ref();
        let wire = captured_transport_header(packet);
        let transport = wire.as_ref().map(|wire| TransportHeader {
            protocol: if wire.protocol == 6 { "tcp" } else { "udp" },
            source_port: wire.source.port(),
            destination_port: wire.destination.port(),
            tcp_flags: wire.tcp_flags,
        });
        let flow = capture.zip(wire).zip(transport.as_ref()).map(|((capture, wire), transport)| {
            FlowKey {
                section_id: capture.section_id, interface_id: capture.interface_id,
                outer_vlan_id: wire.vlan_stack.first().filter(|_| wire.vlan_stack.len() > 1).map(|tag| tag.vid),
                vlan_id: wire.vlan_stack.last().map(|tag| tag.vid),
                vlan_stack: wire.vlan_stack, protocol: transport.protocol,
                source: wire.source, destination: wire.destination,
            }
        });
        Self {
            timestamp: packet.timestamp.is_finite().then_some(packet.timestamp),
            recorded_source: packet.src.parse().ok(),
            recorded_destination: packet.dst.parse().ok(),
            captured_length: capture.map(|value| value.captured_length),
            wire_length: capture.map(|value| value.wire_length),
            link_type: capture.map(|value| value.link_type),
            section_id: capture.map(|value| value.section_id),
            interface_id: capture.map(|value| value.interface_id),
            transport,
            flow,
        }
    }
}

pub fn alert_flow_summary(
    archive: &mut PacketArchive, logs: AlertLogs<'_>, session_id: &str, capture_id: &str, alert_id: u64,
) -> Result<AlertFlowSummary> {
    let metadata = alert_packet_metadata(archive, logs, session_id, capture_id, alert_id)?;
    let mut result = AlertFlowSummary {
        record_type: "alert_flow_summary", session_id: metadata.session_id, capture_id: metadata.capture_id,
        alert_id: metadata.alert_id, evidence_frame_set_sha256: metadata.evidence_frame_set_sha256,
        referenced_frames: metadata.frames.len(), missing_frames: 0, unreadable_frames: 0,
        truncated_frames: 0, length_unknown_frames: 0, retained_frames_without_flow: 0,
        max_vlan_tags: MAX_EVIDENCE_VLAN_TAGS,
        trigger_frame: None,
        directional_flows: Vec::new(),
        limitation: "Only cited evidence is summarized; unseen reverse traffic and endpoint outcomes are unknown. Frames beyond the VLAN depth limit have no flow summary.",
    };
    let mut flows = BTreeMap::<FlowKey, FlowCounts>::new();
    for frame in metadata.frames {
        let is_trigger = metadata.trigger_frame_number == Some(frame.frame_number);
        if is_trigger {
            result.trigger_frame = Some(TriggerFrame {
                frame_number: frame.frame_number,
                status: frame.status,
                transport_header_observed: frame.packet.as_ref().is_some_and(|packet| packet.flow.is_some()),
            });
        }
        match frame.status {
            FrameStatus::Missing => result.missing_frames += 1,
            FrameStatus::Unreadable => result.unreadable_frames += 1,
            FrameStatus::Truncated => result.truncated_frames += 1,
            FrameStatus::LengthUnknown => result.length_unknown_frames += 1,
            FrameStatus::Complete => {}
        }
        let Some(packet) = frame.packet else { continue };
        let Some(flow) = packet.flow else { result.retained_frames_without_flow += 1; continue };
        let counts = flows.entry(flow).or_default();
        counts.evidence_frames += 1;
        counts.contains_trigger_frame |= is_trigger;
        if let Some(flags) = packet.transport.and_then(|header| header.tcp_flags) {
            counts.initial_syn_frames += usize::from(flags & 0x17 == 0x02);
            counts.syn_ack_frames += usize::from(flags & 0x17 == 0x12);
            counts.reset_frames += usize::from(flags & 0x04 != 0);
        }
        if let Some(time) = packet.timestamp {
            counts.first_seen = Some(counts.first_seen.map_or(time, |prior| prior.min(time)));
            counts.last_seen = Some(counts.last_seen.map_or(time, |prior| prior.max(time)));
        }
    }
    let counts: BTreeMap<_, _> = flows.iter().map(|(key, value)| (key.clone(), value.evidence_frames)).collect();
    result.directional_flows = flows.into_iter().map(|(key, counts_for_flow)| {
        let reverse = FlowKey { source: key.destination, destination: key.source, ..key.clone() };
        let reverse_evidence_frames = if reverse != key { counts.get(&reverse).copied().unwrap_or(0) } else { 0 };
        DirectionalFlow { key, counts: counts_for_flow, reverse_evidence_frames }
    }).collect();
    Ok(result)
}

pub fn alert_packet_metadata(
    archive: &mut PacketArchive,
    logs: AlertLogs<'_>,
    session_id: &str,
    capture_id: &str,
    alert_id: u64,
) -> Result<AlertPacketMetadata> {
    let alert = latest_alert_in_logs(logs, session_id, alert_id, Some(capture_id))?;
    let (capture_id, frames) = scoped_frames(&alert)?;
    Ok(AlertPacketMetadata {
        record_type: "alert_packet_metadata",
        session_id: session_id.to_owned(),
        capture_id: capture_id.to_owned(),
        alert_id,
        evidence_frame_set_sha256: evidence_frame_set_sha256(&frames),
        trigger_frame_number: (alert.packet_no > 0).then_some(alert.packet_no),
        frames: frames
            .into_iter()
            .map(|frame_number| {
                let (status, packet) = match archive.packet_for_capture(capture_id, frame_number) {
                    Ok(Some(packet)) => {
                        let status = frame_status(&packet);
                        let metadata = (status != FrameStatus::Unreadable)
                            .then(|| PacketMetadata::new(&packet));
                        (status, metadata)
                    }
                    Ok(None) => (FrameStatus::Missing, None),
                    Err(_) => (FrameStatus::Unreadable, None),
                };
                FrameMetadata { frame_number, status, packet }
            })
            .collect(),
    })
}
