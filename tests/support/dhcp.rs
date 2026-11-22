use packrat_tui::net::{packet::Packet, parser::parse_ethernet};

pub fn dhcp_packet(
    no: u64,
    message_type: u8,
    source_mac: [u8; 6],
    client_mac: [u8; 6],
    server_id: Option<[u8; 4]>,
) -> Packet {
    let server_message = matches!(message_type, 2 | 5);
    let mut bootp = vec![0_u8; 240];
    bootp[0] = if server_message { 2 } else { 1 };
    bootp[1] = 1;
    bootp[2] = 6;
    bootp[28..34].copy_from_slice(&client_mac);
    bootp[236..240].copy_from_slice(&[99, 130, 83, 99]);
    bootp.extend_from_slice(&[53, 1, message_type]);
    if let Some(server) = server_id {
        bootp.extend_from_slice(&[54, 4]);
        bootp.extend_from_slice(&server);
    }
    bootp.push(255);

    let udp_len = 8 + bootp.len();
    let mut bytes = vec![0_u8; 14 + 20 + 8];
    bytes[..6].copy_from_slice(&[0xff; 6]);
    bytes[6..12].copy_from_slice(&source_mac);
    bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    bytes[14] = 0x45;
    bytes[16..18].copy_from_slice(&((20 + udp_len) as u16).to_be_bytes());
    bytes[23] = 17;
    bytes[26..30].copy_from_slice(if server_message {
        &[10, 0, 0, 1]
    } else {
        &[0, 0, 0, 0]
    });
    bytes[30..34].copy_from_slice(&[255, 255, 255, 255]);
    let (source_port, destination_port) = if server_message {
        (67_u16, 68_u16)
    } else {
        (68, 67)
    };
    bytes[34..36].copy_from_slice(&source_port.to_be_bytes());
    bytes[36..38].copy_from_slice(&destination_port.to_be_bytes());
    bytes[38..40].copy_from_slice(&(udp_len as u16).to_be_bytes());
    bytes.extend_from_slice(&bootp);
    parse_ethernet(&bytes, no, no as f64 / 100.0)
}
