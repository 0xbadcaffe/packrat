use std::net::IpAddr;

use anyhow::Result;
use serde::Serialize;

use crate::analysis::packet_fields::captured_transport_header;
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
}

#[derive(Serialize)]
struct TransportHeader {
    protocol: &'static str,
    source_port: u16,
    destination_port: u16,
    tcp_flags: Option<u8>,
}

impl PacketMetadata {
    fn new(packet: &Packet) -> Self {
        let capture = packet.capture.as_ref();
        let transport = captured_transport_header(packet).map(
            |(protocol, source_port, destination_port, tcp_flags)| TransportHeader {
                protocol: if protocol == 6 { "tcp" } else { "udp" },
                source_port,
                destination_port,
                tcp_flags,
            },
        );
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
        }
    }
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
