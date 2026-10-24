#![cfg(feature = "terminal-ui")]

#[path = "support/http2.rs"]
mod http2;
#[path = "support/http.rs"]
mod support;

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use packrat_tui::analysis::stream::StreamKey;
use packrat_tui::{
    app::{App, InvestigationItem, InvestigationView},
    event,
    tabs::Tab,
    ui,
};
use ratatui::{Terminal, backend::TestBackend};

fn screen(app: &App, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|frame| ui::draw(frame, app)).unwrap();
    let buffer = terminal.backend().buffer();
    (0..height)
        .map(|y| {
            (0..width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn key(app: &mut App, code: KeyCode) {
    event::handle(app, Event::Key(KeyEvent::new(code, KeyModifiers::NONE)));
}

fn app() -> App {
    let mut app = App::new_for_test();
    app.inject_packet(support::tcp(
        1,
        100,
        0x18,
        b"GET /inspect HTTP/1.1\r\nHost: example\r\n\r\n",
        false,
    ));
    app.inject_packet(support::tcp(
        2,
        500,
        0x18,
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        true,
    ));
    app.worklist.items = vec![InvestigationItem::Packet(1)];
    app.worklist.active = Some(0);
    app.active_tab = Tab::Investigate;
    app.investigation_view = InvestigationView::Transactions;
    app
}

#[test]
fn transaction_view_displays_exchange_without_changing_packet_selection() {
    let mut app = app();
    let text = screen(&app, 140, 40);
    for expected in [
        "Exchange #1",
        "GET /inspect",
        "HTTP 200",
        "Host: example",
        "Packets [1]",
        "Body: ok",
    ] {
        assert!(text.contains(expected), "Missing {expected}: {text}");
    }
    key(&mut app, KeyCode::Char('['));
    assert_eq!(app.investigation_view, InvestigationView::Notes);
    key(&mut app, KeyCode::Char(']'));
    assert_eq!(app.investigation_view, InvestigationView::Transactions);
    assert_eq!(app.active_investigation_packet().unwrap().no, 1);
    key(&mut app, KeyCode::Char('j'));
    assert_eq!(app.investigation_scroll, 1);
    key(&mut app, KeyCode::Char('l'));
    assert_eq!(app.active_tab, Tab::Packets);
}

#[test]
fn a_pinned_stream_has_transactions_without_a_packet_selection() {
    let mut app = app();
    let id = StreamKey::from_packet(app.active_investigation_packet().unwrap())
        .unwrap()
        .id();
    app.worklist.items = vec![InvestigationItem::Stream(id)];
    assert!(app.active_investigation_packet().is_none());
    assert!(screen(&app, 140, 40).contains("GET /inspect"));
    key(&mut app, KeyCode::Char('s'));
    assert!(app.stream_overlay.is_some());
}

#[test]
fn transaction_screen_handles_tiny_and_short_terminals() {
    let app = app();
    for (width, height) in [(1, 1), (20, 6), (40, 12), (80, 24)] {
        screen(&app, width, height);
    }
}

#[test]
fn all_investigation_views_have_stable_index_round_trips() {
    for index in 0..InvestigationView::COUNT {
        assert_eq!(InvestigationView::from_index(index).index(), index);
    }
}

#[test]
fn multiplexed_exchange_headers_render_in_the_same_investigation_context() {
    let mut app = App::new_for_test();
    let stream = http2::stream(
        &http2::frame(1, 5, 1, &http2::request(b"/h2")),
        &http2::frame(1, 5, 1, &[0x88]),
    );
    app.inject_packet(support::tcp(1, 100, 0x18, &stream.client_data, false));
    app.inject_packet(support::tcp(2, 500, 0x18, &stream.server_data, true));
    app.worklist.items = vec![InvestigationItem::Packet(1)];
    app.worklist.active = Some(0);
    app.active_tab = Tab::Investigate;
    app.investigation_view = InvestigationView::Transactions;
    let text = screen(&app, 140, 40);
    for label in [
        "HTTP/2",
        "Stream #1",
        ":method: GET",
        ":path: /h2",
        ":status: 200",
    ] {
        assert!(text.contains(label), "{text}");
    }
}
