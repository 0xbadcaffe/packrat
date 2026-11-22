use super::*;
use packrat_tui::{engine::AnalysisCore, net::parser::parse_ethernet};

#[test]
fn anonymous_smb_requires_a_successful_server_session_setup() {
    const TITLE: &str = "SMB2 anonymous session accepted";
    let mut valid = vec![0_u8; 76];
    valid[3] = 72;
    let message = &mut valid[4..];
    message[..6].copy_from_slice(b"\xfeSMB\x40\0");
    message[12] = 1; // SESSION_SETUP.
    message[16] = 1; // Server to client.
    message[40] = 3; // Session ID.
    message[64] = 9; // Response structure size.
    message[66] = 2; // Anonymous session.

    let make = |no, payload: &[u8], client_to_server| {
        let mut frame = ipv4_tcp_packet(no, no as u32 * 1000, 0x18, payload).bytes;
        let (src, dst) = if client_to_server { (50000_u16, 445_u16) } else { (445, 50000) };
        frame[34..36].copy_from_slice(&src.to_be_bytes());
        frame[36..38].copy_from_slice(&dst.to_be_bytes());
        parse_ethernet(&frame, no, no as f64)
    };

    let mut core = AnalysisCore::default();
    core.analyze(&make(1, b"NTLMSSP\0\0\0\0\0\0\0\0", true));
    core.analyze(&make(2, &valid, true));
    for (index, offset, value) in [
        (3, 12, 0x16), // STATUS_MORE_PROCESSING_REQUIRED (set other bytes below).
        (4, 16, 5),    // Not SESSION_SETUP.
        (5, 20, 0),    // Client-direction message.
        (6, 44, 0),    // No established session ID.
        (7, 68, 8),    // Wrong response structure size.
        (8, 70, 1),    // Guest is distinct from anonymous.
        (9, 72, 1),    // Security buffer overlaps the header.
        (10, 74, 1),   // Declared security buffer is missing.
    ] {
        let mut sample = valid.clone();
        sample[offset] = value;
        if index == 3 {
            sample[12..16].copy_from_slice(&0xc000_0016_u32.to_le_bytes());
        }
        core.analyze(&make(index, &sample, false));
    }
    core.analyze(&make(11, &valid[..valid.len() - 1], false));
    assert!(core.alert_center.items.iter().all(|item| item.title != TITLE && item.title != "SMB Null Session"));

    core.analyze(&make(12, &valid, false));
    let alert = core.alert_center.items.iter().find(|item| item.title == TITLE).unwrap();
    assert_eq!(alert.packet_refs, [12]);
    assert_eq!(alert.severity, "MEDIUM");
    assert_eq!(alert.provenance.as_ref().unwrap().rule_id, "smb2.anonymous_session_accepted");
    assert!(alert.detail.contains("subsequent share access was not verified"));
}
