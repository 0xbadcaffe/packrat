#![cfg(all(unix, feature = "terminal-ui"))]
#[path = "support/http3.rs"]
mod support;
use packrat_tui::analysis::transactions::http3::Http3Sender::Client;
use packrat_tui::{
    app::{App, InvestigationView},
    ui,
};
use ratatui::{Terminal, backend::TestBackend};
use std::time::{Duration, Instant};
use support::*;

fn drain(app: &mut App) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        app.poll_analysis();
        if app.analysis_idle() {
            break;
        }
        assert!(Instant::now() < deadline, "{:?}", app.status_msg);
        std::thread::yield_now();
    }
}

#[test]
fn authenticated_http3_headers_render_from_the_selected_packet_snapshot() {
    let directory = tempfile::tempdir().unwrap();
    let program = helper(
        directory.path(),
        &serde_json::json!({"ok":true, "http3":batch(vec![header_event(Client, 0, request()), finished(Client, 10)])}),
    );
    let mut app = App::new_for_test();
    app.configure_core(move |core| core.quic_scope.decode_helper_path = Some(program));
    app.start_background_analysis().unwrap();
    app.inject_packet(quic_packet(1));
    drain(&mut app);
    app.open_selected_packet_investigation();
    app.investigation_view = InvestigationView::Transactions;
    app.poll_analysis();
    drain(&mut app);
    let snapshot = app.transaction_http3_inspection().unwrap().clone();
    assert_eq!(snapshot.packet_no, 1);
    let mut terminal = Terminal::new(TestBackend::new(180, 60)).unwrap();
    let view = app.try_view().unwrap().unwrap();
    terminal.draw(|frame| ui::draw_view(frame, &view)).unwrap();
    let text: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    for expected in [
        "HTTP/3 Transactions",
        "Request stream #0",
        ":method: GET",
        ":path: /inspect",
        "Complete",
    ] {
        assert!(text.contains(expected), "{text}");
    }
    drop(view);
    app.inject_packet(quic_packet(2));
    drain(&mut app);
    app.worklist.items.clear();
    app.worklist.active = None;
    app.selected = Some(1);
    assert!(app.transaction_http3_inspection().is_none());
    app.poll_analysis();
    drain(&mut app);
    assert_eq!(app.transaction_http3_inspection().unwrap().packet_no, 2);
    assert_eq!(snapshot.packet_no, 1);
    app.stop_background_analysis().unwrap();
}

#[test]
fn no_http3_decoder_produces_no_plaintext_claims_even_on_small_terminals() {
    let mut app = App::new_for_test();
    app.inject_packet(quic_packet(1));
    app.open_selected_packet_investigation();
    app.investigation_view = InvestigationView::Transactions;
    for (width, height) in [(1, 1), (30, 8), (120, 30)] {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| ui::draw(frame, &app)).unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect();
        assert!(!text.contains(":method:"));
    }
}

#[test]
fn malformed_helper_header_names_cannot_emit_terminal_control_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let mut fields = request();
    fields.push(packrat_tui::analysis::transactions::HttpHeader {
        name: "bad\u{1b}[2J".into(),
        value: vec![0x1b, b'[', b'm'],
    });
    let program = helper(
        directory.path(),
        &serde_json::json!({"ok":true, "http3":batch(vec![header_event(Client, 0, fields), finished(Client, 10)])}),
    );
    let mut app = App::new_for_test();
    app.configure_core(move |core| core.quic_scope.decode_helper_path = Some(program));
    app.inject_packet(quic_packet(1));
    app.open_selected_packet_investigation();
    app.investigation_view = InvestigationView::Transactions;
    let mut terminal = Terminal::new(TestBackend::new(180, 60)).unwrap();
    terminal.draw(|frame| ui::draw(frame, &app)).unwrap();
    let text: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(!text.contains('\u{1b}'));
    assert!(text.contains("Ambiguous"));
    assert!(text.contains("bad.[2J"));
}

#[test]
fn decoded_quic_frame_details_cannot_emit_terminal_controls() {
    let directory = tempfile::tempdir().unwrap();
    let program = helper(
        directory.path(),
        &serde_json::json!({"ok":true, "frames":[{"frame_type":"data\u{1b}", "detail":"peer\u{1b}[2J"}]}),
    );
    let mut app = App::new_for_test();
    app.configure_core(move |core| core.quic_scope.decode_helper_path = Some(program));
    app.inject_packet(quic_packet(1));
    app.open_selected_packet_investigation();
    app.investigation_view = InvestigationView::Encrypted;
    let mut terminal = Terminal::new(TestBackend::new(180, 60)).unwrap();
    terminal.draw(|frame| ui::draw(frame, &app)).unwrap();
    let text: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(!text.contains('\u{1b}'));
    assert!(text.contains("peer.[2J"));
}
