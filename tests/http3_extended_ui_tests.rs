#![cfg(all(unix, feature = "terminal-ui"))]
#[path = "support/http3_control.rs"]
mod control;
#[path = "support/http3_push.rs"]
mod push_fixture;
#[path = "support/http3.rs"]
mod support;
use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use packrat_tui::analysis::transactions::http3::*;
use packrat_tui::{
    app::{App, InvestigationView},
    event, ui,
};
use ratatui::{Terminal, backend::TestBackend};
use std::time::{Duration, Instant};
use support::*;

fn app(events: Vec<Http3Event>) -> (tempfile::TempDir, App) {
    let directory = tempfile::tempdir().unwrap();
    let program = helper(
        directory.path(),
        &serde_json::json!({"ok":true, "http3":batch(events)}),
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
    (directory, app)
}
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
fn screen(app: &App, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    let view = app.try_view().unwrap().unwrap();
    terminal.draw(|frame| ui::draw_view(frame, &view)).unwrap();
    terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect()
}

#[test]
fn control_and_push_evidence_share_the_existing_keyboard_transaction_context() {
    let (_directory, mut app) = app(push_fixture::exchange());
    let text = screen(&app, 180, 80);
    for expected in [
        "Pushes: 1",
        "Control streams: 1",
        "Control stream #2 Client",
        "MAX_PUSH_ID: Some(0)",
        "Push #0 [Complete]",
        "Promise :path: /inspect",
        "Push response stream #7",
        "DATA @12: ok",
    ] {
        assert!(text.contains(expected), "Missing {expected}: {text}");
    }
    for _ in 0..3 {
        event::handle(
            &mut app,
            Event::Key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE)),
        );
    }
    assert_eq!(app.investigation_scroll, 3);
    assert_eq!(app.active_investigation_packet().unwrap().no, 1);
    for (width, height) in [(1, 1), (30, 8), (80, 24)] {
        screen(&app, width, height);
    }
    app.stop_background_analysis().unwrap();
}

#[test]
fn missing_prefixes_remain_visible_without_guessing_a_push_stream_identity() {
    let mut events = push_fixture::credit(0);
    events.push(push_fixture::promise(0, 0, 0));
    events.extend(push_fixture::response(7, 0, b"ok").into_iter().skip(1));
    let (_directory, mut app) = app(events);
    let text = screen(&app, 180, 80);
    assert!(text.contains("Unclassified unidirectional streams: [7]"));
    assert!(text.contains("Push #0 [Incomplete]"));
    assert!(!text.contains("Push response stream #7"));
    app.stop_background_analysis().unwrap();
}

#[test]
fn malicious_promise_field_names_are_escaped_in_the_push_view() {
    let mut events = push_fixture::exchange();
    for event in &mut events {
        if let Http3EventKind::PushPromise { headers, .. } = &mut event.event {
            headers.extend(support::headers(&[("bad\u{1b}[2J", "value")]));
        }
    }
    let (_directory, mut app) = app(events);
    let text = screen(&app, 180, 80);
    assert!(!text.contains('\u{1b}'));
    assert!(text.contains("Push #0 [Ambiguous]"));
    assert!(text.contains("Promise bad.[2J: value"));
    app.stop_background_analysis().unwrap();
}
