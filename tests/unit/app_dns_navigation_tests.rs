use super::*;
use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};

fn dns_frame(no: u64, resolver: [u8; 4], reply: bool) -> Packet {
    let mut raw = vec![0; 42];
    raw[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    raw[14] = 0x45;
    raw[23] = 17;
    let client = [10, 0, 0, 5];
    let (src, dst, source_port, destination_port) = if reply {
        (resolver, client, 53_u16, 50_000_u16)
    } else {
        (client, resolver, 50_000, 53)
    };
    raw[26..30].copy_from_slice(&src);
    raw[30..34].copy_from_slice(&dst);
    raw[34..36].copy_from_slice(&source_port.to_be_bytes());
    raw[36..38].copy_from_slice(&destination_port.to_be_bytes());
    raw.extend([0, 42, if reply { 0x81 } else { 0x01 }, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    raw.extend_from_slice(b"\x07example\x04test\0\0\x01\0\x01");
    let length = raw.len() as u16;
    raw[16..18].copy_from_slice(&(length - 14).to_be_bytes());
    raw[38..40].copy_from_slice(&(length - 34).to_be_bytes());
    crate::net::parser::parse_ethernet(&raw, no, no as f64)
}

fn advance(app: &mut App) {
    crate::event::handle(app, Event::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)));
}

#[test]
fn enter_in_dns_transactions_cycles_only_available_exchange_evidence() {
    let mut app = App::new_for_test();
    app.active_tab = Tab::Investigate;
    app.investigation_view = InvestigationView::Transactions;
    let query = dns_frame(1, [10, 0, 0, 53], false);
    let absent = dns_frame(2, [10, 0, 0, 53], true);
    let alternate = dns_frame(3, [10, 0, 0, 54], true);
    {
        let mut core = app.core.edit();
        for packet in [&query, &absent, &alternate] {
            core.analyze(packet);
        }
    }
    app.worklist.pin_packet(&dns_frame(99, [10, 0, 0, 55], false)).unwrap();
    app.worklist.pin_packet(&query).unwrap();
    app.packets.push_back(alternate);
    advance(&mut app);
    assert_eq!(app.worklist.active_packet_no(), Some(3));
    assert!(app.status_msg.as_deref().unwrap().contains("skipped 1 unavailable"));
    advance(&mut app);
    assert_eq!(app.worklist.active_packet_no(), Some(1));
    assert_eq!(app.investigation_view, InvestigationView::Transactions);
    assert!(app.worklist.retained_packet(2).is_none());
}

#[test]
fn dns_transaction_navigation_recovers_a_frame_from_the_current_archive() {
    let directory = tempfile::tempdir().unwrap();
    let mut app = App::new_for_test();
    app.set_packet_archive(crate::storage::packet_archive::ArchiveWorker::open(directory.path()).unwrap()).unwrap();
    let query = dns_frame(1, [10, 0, 0, 53], false);
    let reply = dns_frame(2, [10, 0, 0, 53], true);
    app.inject_packet(query.clone());
    app.inject_packet(reply.clone());
    app.packet_archive.as_mut().unwrap().finish().unwrap();
    app.packets.clear();
    app.worklist.pin_packet(&query).unwrap();
    app.active_tab = Tab::Investigate;
    app.investigation_view = InvestigationView::Transactions;
    advance(&mut app);
    assert_eq!(app.worklist.active_packet_no(), Some(2));
    assert_eq!(app.worklist.retained_packet(2).unwrap().bytes, reply.bytes);
    assert!(app.packets.is_empty());
}
