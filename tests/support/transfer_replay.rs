use packrat_tui::{
    export::pcapng::PcapNgWriter,
    net::{
        packet::{CaptureMetadata, CaptureTimestamp, TimestampResolution},
        parser::parse_ethernet,
    },
};
use std::path::Path;

pub fn write_fixture(path: &Path, frames: u64, varied_bytes: bool, split_interface: bool) {
    let mut capture = PcapNgWriter::create(path).unwrap();
    let payload: Vec<u8> = (0..60_000)
        .map(|index| {
            if varied_bytes {
                (index * 73 % 256) as u8
            } else {
                0
            }
        })
        .collect();
    let mut bytes = vec![0_u8; 42];
    bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    bytes[14] = 0x45;
    bytes[16..18].copy_from_slice(&((28 + payload.len()) as u16).to_be_bytes());
    bytes[22] = 64;
    bytes[23] = 17;
    bytes[26..30].copy_from_slice(&[10, 0, 0, 5]);
    bytes[30..34].copy_from_slice(&[198, 51, 100, 10]);
    bytes[34..36].copy_from_slice(&40_000_u16.to_be_bytes());
    bytes[36..38].copy_from_slice(&45_001_u16.to_be_bytes());
    bytes[38..40].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    bytes.extend_from_slice(&payload);
    let len = bytes.len() as u32;

    for frame in 1..=frames {
        let mut packet = parse_ethernet(&bytes, frame, frame as f64 / 10.0);
        packet.capture = Some(CaptureMetadata {
            timestamp: Some(CaptureTimestamp {
                ticks: frame,
                resolution: TimestampResolution::Decimal(1),
                offset_seconds: 0,
            }),
            captured_length: len,
            wire_length: len,
            link_type: 1,
            section_id: 0,
            interface_id: if split_interface {
                (frame % 2) as u32
            } else {
                0
            },
            interface_name: None,
            comments: vec![],
        });
        capture.write_packet(&packet).unwrap();
    }
    capture.flush().unwrap();
}
