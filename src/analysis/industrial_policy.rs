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
    let payload = transport_payload(packet)?;
    let source_port = packet.src_port.unwrap_or(0);
    let destination_port = packet.dst_port.unwrap_or(0);

    if source_port == 502 || destination_port == 502 || packet.protocol.eq_ignore_ascii_case("Modbus") {
        return inspect_modbus(payload);
    }
    if source_port == 20_000 || destination_port == 20_000 || packet.protocol.eq_ignore_ascii_case("DNP3") {
        return inspect_dnp3(payload);
    }
    if source_port == 102 || destination_port == 102 || packet.protocol.eq_ignore_ascii_case("S7comm") {
        return inspect_s7(payload);
    }
    if source_port == 47_808 || destination_port == 47_808 || packet.protocol.eq_ignore_ascii_case("BACnet") {
        return inspect_bacnet(payload);
    }
    None
}

fn inspect_modbus(payload: &[u8]) -> Option<IndustrialFinding> {
    if payload.len() < 8 || payload[2..4] != [0, 0] {
        return None;
    }
    let operation = match payload[7] {
        5 => "write single coil",
        6 => "write single register",
        8 => "diagnostics",
        15 => "write multiple coils",
        16 => "write multiple registers",
        21 => "write file record",
        22 => "mask write register",
        23 => "read/write multiple registers",
        _ => return None,
    };
    Some(IndustrialFinding { protocol: "Modbus/TCP", operation, critical: false })
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

fn transport_payload(packet: &Packet) -> Option<&[u8]> {
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
    let transport_offset = ip_offset + ip_header_len;
    let packet_end = (ip_offset + usize::from(u16::from_be_bytes([raw[ip_offset + 2], raw[ip_offset + 3]])))
        .min(raw.len());
    match raw[ip_offset + 9] {
        6 => {
            let tcp_header_len = usize::from(*raw.get(transport_offset + 12)? >> 4) * 4;
            raw.get((transport_offset + tcp_header_len)..packet_end)
        }
        17 => raw.get((transport_offset + 8)..packet_end),
        _ => None,
    }
}
