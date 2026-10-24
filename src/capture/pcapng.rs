//! Bounded PCAPNG ingestion with explicit interface and clock provenance.

use crate::net::packet::{CaptureMetadata, CaptureTimestamp, Packet, TimestampResolution};
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{Block, OptionCode, PcapBlockOwned, PcapError, PcapNGReader};
use std::io::Read;

const MAX_BLOCK: usize = 2 * 1024 * 1024;

struct Interface {
    link_type: u32,
    snapshot_length: u32,
    name: Option<String>,
    resolution: TimestampResolution,
    offset: i64,
}

fn packet(data: &[u8], no: u64, metadata: CaptureMetadata) -> Packet {
    let timestamp = metadata.timestamp.map_or(0.0, CaptureTimestamp::seconds);
    let mut packet = if metadata.link_type == 1 {
        crate::net::parser::parse_ethernet(data, no, timestamp)
    } else {
        let mut packet = crate::net::parser::parse_ethernet(&[], no, timestamp);
        packet.bytes = data.to_vec();
        packet.length = data.len().min(u16::MAX as usize) as u16;
        packet.info = format!("Undecoded capture link type {}", metadata.link_type);
        packet
    };
    packet.capture = Some(metadata);
    packet
}

pub fn stream(
    reader: impl Read,
    mut consume: impl FnMut(Packet) -> Result<(), String>,
) -> Result<u64, String> {
    let mut reader = PcapNGReader::new(MAX_BLOCK, reader)
        .map_err(|error| format!("Invalid PCAPNG header: {error:?}"))?;
    let mut interfaces: Vec<Interface> = Vec::new();
    let mut section = None::<u32>;
    let mut big_endian = false;
    let mut count = 0u64;
    loop {
        match reader.next() {
            Ok((consumed, block)) => {
                match block {
                    PcapBlockOwned::NG(Block::SectionHeader(header)) => {
                        if header.major_version != 1 || header.minor_version != 0 {
                            return Err("Unsupported PCAPNG section version".into());
                        }
                        section = Some(match section {
                            None => 0,
                            Some(value) => {
                                value.checked_add(1).ok_or("Too many PCAPNG sections")?
                            }
                        });
                        big_endian = header.big_endian();
                        interfaces.clear();
                    }
                    PcapBlockOwned::NG(Block::InterfaceDescription(interface)) => {
                        if interfaces.len() >= 4096 {
                            return Err("Too many PCAPNG interfaces".into());
                        }
                        let resolution = interface
                            .if_tsresol()
                            .transpose()
                            .map_err(|error| error.to_string())?
                            .unwrap_or(6);
                        let mut offset = 0;
                        if let Some(option) = interface
                            .options
                            .iter()
                            .find(|option| option.code == OptionCode::IfTsoffset)
                        {
                            let bytes: [u8; 8] = option
                                .as_bytes()
                                .map_err(|error| error.to_string())?
                                .try_into()
                                .map_err(|_| "Invalid PCAPNG clock offset")?;
                            offset = if big_endian {
                                i64::from_be_bytes(bytes)
                            } else {
                                i64::from_le_bytes(bytes)
                            };
                        }
                        let name = interface
                            .if_name()
                            .transpose()
                            .map_err(|error| error.to_string())?
                            .map(str::to_string);
                        if name.as_ref().is_some_and(|name| name.len() > 4096) {
                            return Err("PCAPNG interface name exceeds limit".into());
                        }
                        interfaces.push(Interface {
                            link_type: interface.linktype.0 as u32,
                            snapshot_length: interface.snaplen,
                            name,
                            resolution: if resolution & 0x80 != 0 {
                                TimestampResolution::Binary(resolution & 0x7f)
                            } else {
                                TimestampResolution::Decimal(resolution)
                            },
                            offset,
                        });
                    }
                    PcapBlockOwned::NG(Block::EnhancedPacket(block)) => {
                        let interface = interfaces
                            .get(block.if_id as usize)
                            .ok_or("PCAPNG packet references an unknown interface")?;
                        if block.caplen > block.origlen
                            || block.caplen > 1_048_576
                            || (interface.snapshot_length != 0
                                && block.caplen > interface.snapshot_length)
                        {
                            return Err("Invalid PCAPNG packet length".into());
                        }
                        let data = block
                            .data
                            .get(..block.caplen as usize)
                            .ok_or("Truncated PCAPNG packet")?;
                        let mut comments = Vec::new();
                        for option in block
                            .options
                            .iter()
                            .filter(|option| option.code == OptionCode::Comment)
                        {
                            let comment = option.as_str().map_err(|error| error.to_string())?;
                            if comments.len() >= 16 || comment.len() > 4096 {
                                return Err("PCAPNG comments exceed limits".into());
                            }
                            comments.push(comment.to_string());
                        }
                        count = count.checked_add(1).ok_or("Too many capture packets")?;
                        consume(packet(
                            data,
                            count,
                            CaptureMetadata {
                                timestamp: Some(CaptureTimestamp {
                                    ticks: (u64::from(block.ts_high) << 32)
                                        | u64::from(block.ts_low),
                                    resolution: interface.resolution,
                                    offset_seconds: interface.offset,
                                }),
                                captured_length: block.caplen,
                                wire_length: block.origlen,
                                link_type: interface.link_type,
                                interface_id: block.if_id,
                                section_id: section.ok_or("Missing PCAPNG section")?,
                                interface_name: interface.name.clone(),
                                comments,
                            },
                        ))?;
                    }
                    PcapBlockOwned::NG(Block::SimplePacket(block)) => {
                        let interface = interfaces
                            .first()
                            .ok_or("PCAPNG simple packet has no interface")?;
                        let length = if interface.snapshot_length == 0 {
                            block.origlen
                        } else {
                            block.origlen.min(interface.snapshot_length)
                        };
                        if length > 1_048_576 || block.data.len() != ((length as usize + 3) & !3) {
                            return Err("Invalid PCAPNG simple packet length".into());
                        }
                        let data = block
                            .data
                            .get(..length as usize)
                            .ok_or("Truncated PCAPNG simple packet")?;
                        count = count.checked_add(1).ok_or("Too many capture packets")?;
                        consume(packet(
                            data,
                            count,
                            CaptureMetadata {
                                timestamp: None,
                                captured_length: length,
                                wire_length: block.origlen,
                                link_type: interface.link_type,
                                interface_id: 0,
                                section_id: section.ok_or("Missing PCAPNG section")?,
                                interface_name: interface.name.clone(),
                                comments: Vec::new(),
                            },
                        ))?;
                    }
                    PcapBlockOwned::NG(_) => {}
                    _ => return Err("Unexpected classic packet in PCAPNG stream".into()),
                }
                reader.consume(consumed);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                let previous = reader.data().len();
                reader
                    .refill()
                    .map_err(|error| format!("Read PCAPNG: {error:?}"))?;
                if reader.data().len() == previous && !reader.reader_exhausted() {
                    return Err("PCAPNG reader made no progress".into());
                }
            }
            Err(error) => return Err(format!("Invalid or truncated PCAPNG block: {error:?}")),
        }
    }
    if count == 0 {
        Err("No packets found in PCAPNG".into())
    } else {
        Ok(count)
    }
}
