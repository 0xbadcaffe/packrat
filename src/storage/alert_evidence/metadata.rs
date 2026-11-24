use std::{collections::BTreeMap, net::{IpAddr, SocketAddr}};

use anyhow::Result;
use serde::Serialize;

use crate::analysis::alert_center::{AlertFlow, AlertTransport};
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
    #[serde(skip)]
    recorded_trigger_flow: Option<AlertFlow>,
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
    declared_payload_length: usize,
    captured_payload_length: usize,
    #[serde(skip)]
    tcp_sequence_pair: Option<(u32, u32)>,
}

#[derive(Clone, Copy)]
struct SynSegment {
    frame: u64,
    sequence: u32,
    payload_len: u32,
}

impl SynSegment {
    fn acknowledges_syn(self, acknowledgment: u32) -> bool {
        acknowledgment.wrapping_sub(self.sequence.wrapping_add(1)) <= self.payload_len
    }
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

impl FlowKey {
    fn reversed(&self) -> Self {
        Self { source: self.destination, destination: self.source, ..self.clone() }
    }
}

#[derive(Default, Serialize)]
struct FlowCounts {
    evidence_frames: usize,
    cited_declared_payload_bytes: usize,
    cited_captured_payload_bytes: usize,
    frames: Vec<FlowFrameRef>,
    contains_trigger_frame: bool,
    initial_syn_frames: usize,
    syn_ack_frames: usize,
    reset_frames: usize,
    first_seen: Option<f64>,
    last_seen: Option<f64>,
    #[serde(skip)]
    initial_syns: Vec<SynSegment>,
    #[serde(skip)]
    syn_acks: Vec<(SynSegment, u32)>,
    #[serde(skip)]
    acks: Vec<(u64, u32, u32)>,
    #[serde(skip)]
    resets: Vec<u64>,
}

#[derive(Serialize)]
struct FlowFrameRef {
    frame_number: u64,
    status: FrameStatus,
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
struct SynAckMatch {
    syn_ack_frame: u64,
    prior_syn_candidates: usize,
    latest_candidate_syn_frame: u64,
    later_ack_candidates: usize,
    earliest_candidate_ack_frame: Option<u64>,
}

#[derive(Serialize)]
struct TriggerFrame {
    frame_number: u64,
    status: FrameStatus,
    transport_header_observed: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum TriggerTupleStatus {
    NotRecorded,
    TriggerHeaderUnavailable,
    MatchesWire,
    DiffersFromWire,
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
    trigger_tuple_status: TriggerTupleStatus,
    directional_flows: Vec<DirectionalFlow>,
    tcp_syn_ack_matches: Vec<SynAckMatch>,
    unassigned_frames: Vec<FlowFrameRef>,
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
            declared_payload_length: wire.declared_payload_length,
            captured_payload_length: wire.captured_payload_length,
            tcp_sequence_pair: wire.tcp_sequence_pair,
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
        trigger_tuple_status: if metadata.recorded_trigger_flow.is_some() {
            TriggerTupleStatus::TriggerHeaderUnavailable
        } else {
            TriggerTupleStatus::NotRecorded
        },
        directional_flows: Vec::new(),
        tcp_syn_ack_matches: Vec::new(),
        unassigned_frames: Vec::new(),
        limitation: "Only cited evidence is summarized; unseen reverse traffic and endpoint outcomes are unknown. Payload sums count cited frame bytes, including possible retransmissions, not unique transfer bytes. Declared lengths can include uncaptured payload. TCP handshake candidates account for declared SYN payload, but sequence matches do not establish endpoint acceptance or a specific retransmission. Earlier SYN candidates do not cross a cited reset or a different initial SYN in the same direction. Later ACK candidates do not cross a cited reset or another SYN. Fragmented datagrams and frames beyond the VLAN depth limit have no flow summary.",
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
        let reference = FlowFrameRef { frame_number: frame.frame_number, status: frame.status };
        let Some(packet) = frame.packet else {
            result.unassigned_frames.push(reference);
            continue;
        };
        let Some((flow, header)) = packet.flow.zip(packet.transport) else {
            result.retained_frames_without_flow += 1;
            result.unassigned_frames.push(reference);
            continue;
        };
        if is_trigger && let Some(saved) = metadata.recorded_trigger_flow {
            let protocol = match saved.transport {
                AlertTransport::Tcp => "tcp",
                AlertTransport::Udp => "udp",
            };
            result.trigger_tuple_status = if protocol == flow.protocol && saved.source == flow.source
                && saved.destination == flow.destination
            {
                TriggerTupleStatus::MatchesWire
            } else {
                TriggerTupleStatus::DiffersFromWire
            };
        }
        let counts = flows.entry(flow).or_default();
        counts.frames.push(reference);
        counts.evidence_frames = counts.frames.len();
        counts.contains_trigger_frame |= is_trigger;
        counts.cited_declared_payload_bytes += header.declared_payload_length;
        counts.cited_captured_payload_bytes += header.captured_payload_length;
        if let (Some(flags), Some((sequence, acknowledgment))) = (header.tcp_flags, header.tcp_sequence_pair) {
            let syn = u32::try_from(header.declared_payload_length).ok().map(|payload_len| {
                SynSegment { frame: frame.frame_number, sequence, payload_len }
            });
            match flags & 0x17 {
                0x02 => counts.initial_syns.extend(syn),
                0x12 => counts.syn_acks.extend(syn.map(|segment| (segment, acknowledgment))),
                0x10 => counts.acks.push((frame.frame_number, sequence, acknowledgment)),
                _ => {}
            }
            counts.initial_syn_frames = counts.initial_syns.len();
            counts.syn_ack_frames = counts.syn_acks.len();
            if flags & 0x04 != 0 {
                counts.resets.push(frame.frame_number);
                counts.reset_frames = counts.resets.len();
            }
        }
        if let Some(time) = packet.timestamp {
            counts.first_seen = Some(counts.first_seen.map_or(time, |prior| prior.min(time)));
            counts.last_seen = Some(counts.last_seen.map_or(time, |prior| prior.max(time)));
        }
    }
    result.tcp_syn_ack_matches = syn_ack_matches(&flows);
    let counts: BTreeMap<_, _> = flows.iter().map(|(key, value)| (key.clone(), value.evidence_frames)).collect();
    result.directional_flows = flows.into_iter().map(|(key, counts_for_flow)| {
        let reverse = key.reversed();
        let reverse_evidence_frames = if reverse != key { counts.get(&reverse).copied().unwrap_or(0) } else { 0 };
        DirectionalFlow { key, counts: counts_for_flow, reverse_evidence_frames }
    }).collect();
    Ok(result)
}

fn syn_ack_matches(flows: &BTreeMap<FlowKey, FlowCounts>) -> Vec<SynAckMatch> {
    let mut matches = Vec::new();
    for (key, response) in flows {
        if response.syn_acks.is_empty() || key.source == key.destination {
            continue;
        }
        let Some(request) = flows.get(&key.reversed()) else { continue; };
        for &(server, acknowledgment) in &response.syn_acks {
            let syn_ack_frame = server.frame;
            let reset = request.resets.iter().chain(&response.resets).copied()
                .filter(|&frame| frame < syn_ack_frame)
                .max().unwrap_or(0);
            let Some(latest_syn) = request.initial_syns.iter().rev()
                .find(|syn| reset < syn.frame && syn.frame < syn_ack_frame)
            else { continue };
            let boundary = request.initial_syns.iter().rev()
                .find(|syn| reset < syn.frame && syn.frame < latest_syn.frame && syn.sequence != latest_syn.sequence)
                .map_or(reset, |syn| syn.frame);
            let (prior_syn_candidates, latest_candidate_syn_frame) = request.initial_syns.iter()
                .filter(|syn| boundary < syn.frame && syn.frame < syn_ack_frame
                    && syn.sequence == latest_syn.sequence && syn.acknowledges_syn(acknowledgment))
                .fold((0, 0_u64), |(count, latest), syn| (count + 1, latest.max(syn.frame)));
            if prior_syn_candidates > 0 {
                let (later_ack_candidates, earliest_candidate_ack_frame) = later_ack_candidates(
                    request, response, latest_syn.frame, acknowledgment, server,
                );
                matches.push(SynAckMatch {
                    syn_ack_frame, prior_syn_candidates, latest_candidate_syn_frame,
                    later_ack_candidates, earliest_candidate_ack_frame,
                });
            }
        }
    }
    matches.sort_unstable_by_key(|correlation| correlation.syn_ack_frame);
    matches
}

fn later_ack_candidates(
    request: &FlowCounts, response: &FlowCounts, syn_frame: u64, expected_seq: u32, server: SynSegment,
) -> (usize, Option<u64>) {
    let boundary = request.resets.iter().chain(&response.resets).copied()
        .chain(request.initial_syns.iter().chain(&response.initial_syns).map(|syn| syn.frame))
        .filter(|&frame| frame > syn_frame)
        .min();
    if boundary.is_some_and(|frame| frame < server.frame) {
        return (0, None);
    }
    let candidates = request.acks.iter().filter(|&&(frame, seq, ack)| {
        frame > server.frame && boundary.is_none_or(|end| frame < end)
            && seq == expected_seq && server.acknowledges_syn(ack)
    });
    candidates.fold((0, None), |(count, first), &(frame, _, _)| {
        (count + 1, Some(first.map_or(frame, |earliest: u64| earliest.min(frame))))
    })
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
        recorded_trigger_flow: alert.flow,
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
