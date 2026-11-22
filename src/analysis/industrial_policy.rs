//! Passive policy checks for state-changing industrial protocol operations.

use crate::net::packet::Packet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndustrialFinding {
    pub protocol: &'static str,
    pub operation: &'static str,
    pub critical: bool,
}

impl IndustrialFinding {
    pub fn detail(&self, packet: &Packet) -> String {
        format!("{} {} from {} to {}", self.protocol, self.operation, packet.src, packet.dst)
    }
}

pub fn inspect(packet: &Packet) -> Option<IndustrialFinding> {
    // Decoded ports nominate candidates; the wire ports and transport decide.
    if ![packet.src_port, packet.dst_port].into_iter().flatten()
        .any(|port| matches!(port, 102 | 502 | 20_000 | 47_808))
    {
        return None;
    }
    let (protocol, ports, payload) = transport_payload(packet)?;
    if protocol == 6 && ports.contains(&502) {
        return if ports[1] == 502 && ports[0] != 502 {
            inspect_modbus(payload)
        } else {
            None
        };
    }
    if ports.contains(&20_000) {
        return inspect_dnp3(payload);
    }
    if protocol == 6 && ports.contains(&102) {
        return inspect_s7(payload);
    }
    if protocol == 17 && ports.contains(&47_808) {
        return inspect_bacnet(payload);
    }
    None
}

fn inspect_modbus(mut payload: &[u8]) -> Option<IndustrialFinding> {
    while !payload.is_empty() {
        let length = usize::from(read_u16(payload, 4)?);
        // The MBAP length covers the unit identifier and the bounded PDU.
        if !(2..=254).contains(&length) || read_u16(payload, 2)? != 0 {
            return None;
        }
        let message = payload.get(..6 + length)?;
        if let Some(operation) = modbus_operation(message[7]) {
            return Some(IndustrialFinding { protocol: "Modbus/TCP", operation, critical: false });
        }
        payload = &payload[message.len()..];
    }
    None
}

fn modbus_operation(code: u8) -> Option<&'static str> {
    Some(match code {
        5 => "write single coil",
        6 => "write single register",
        8 => "diagnostics",
        15 => "write multiple coils",
        16 => "write multiple registers",
        21 => "write file record",
        22 => "mask write register",
        23 => "read/write multiple registers",
        _ => return None,
    })
}

fn inspect_dnp3(payload: &[u8]) -> Option<IndustrialFinding> {
    if payload.len() < 13 || payload[..2] != [0x05, 0x64] {
        return None;
    }
    let (operation, critical) = match payload[12] {
        0x02 => ("write", false),
        0x03 => ("select", false),
        0x04 => ("operate", true),
        0x05 => ("direct operate", true),
        0x06 => ("direct operate without response", true),
        0x0d => ("cold restart", true),
        0x0e => ("warm restart", true),
        _ => return None,
    };
    Some(IndustrialFinding { protocol: "DNP3", operation, critical })
}

fn inspect_s7(payload: &[u8]) -> Option<IndustrialFinding> {
    if payload.len() < 18 || payload[0] != 0x03 || payload[1] != 0x00 || payload[7] != 0x32 {
        return None;
    }
    let (operation, critical) = match payload[17] {
        0x05 => ("write variable", false),
        0x28 => ("PLC control", true),
        0x29 => ("PLC stop", true),
        _ => return None,
    };
    Some(IndustrialFinding { protocol: "S7comm", operation, critical })
}

fn inspect_bacnet(payload: &[u8]) -> Option<IndustrialFinding> {
    if payload.len() < 10 || payload[0] != 0x81 || payload[4] != 0x01 {
        return None;
    }
    let npdu_control = payload[5];
    if npdu_control & 0xa8 != 0 {
        return None;
    }
    let apdu = &payload[6..];
    if apdu[0] >> 4 != 0 || apdu.len() < 4 {
        return None;
    }
    let (operation, critical) = match apdu[3] {
        15 => ("WriteProperty", false),
        16 => ("WritePropertyMultiple", false),
        17 => ("DeviceCommunicationControl", true),
        20 => ("ReinitializeDevice", true),
        _ => return None,
    };
    Some(IndustrialFinding { protocol: "BACnet/IP", operation, critical })
}

fn transport_payload(packet: &Packet) -> Option<(u8, [u16; 2], &[u8])> {
    if packet.capture.as_ref().is_some_and(|meta| !crate::net::parser::supports_capture_link_type(meta.link_type)) {
        return None;
    }
    let raw = &packet.bytes;
    if raw.len() < 14 {
        return None;
    }
    let mut ether_type_offset = 12usize;
    let ip_offset = loop {
        let ether_type = u16::from_be_bytes([
            *raw.get(ether_type_offset)?,
            *raw.get(ether_type_offset + 1)?,
        ]);
        if matches!(ether_type, 0x8100 | 0x88a8) {
            ether_type_offset += 4;
            continue;
        }
        if ether_type != 0x0800 {
            return None;
        }
        break ether_type_offset + 2;
    };
    if raw.len() < ip_offset + 20 || raw[ip_offset] >> 4 != 4 {
        return None;
    }
    let ip_header_len = usize::from(raw[ip_offset] & 0x0f) * 4;
    if ip_header_len < 20 || read_u16(raw, ip_offset + 6)? & 0x3fff != 0 {
        return None;
    }
    let transport_offset = ip_offset + ip_header_len;
    let packet_end = ip_offset + usize::from(read_u16(raw, ip_offset + 2)?);
    let transport = raw.get(transport_offset..packet_end)?;
    let protocol = raw[ip_offset + 9];
    let payload = match protocol {
        6 => {
            let tcp_header_len = usize::from(*transport.get(12)? >> 4) * 4;
            if tcp_header_len < 20 { return None; }
            transport.get(tcp_header_len..)?
        }
        17 => transport.get(8..usize::from(read_u16(transport, 4)?))?,
        _ => return None,
    };
    let ports = [read_u16(transport, 0)?, read_u16(transport, 2)?];
    Some((protocol, ports, payload))
}

fn read_u16(bytes: &[u8], start: usize) -> Option<u16> {
    Some(u16::from_be_bytes(bytes.get(start..start + 2)?.try_into().ok()?))
}
