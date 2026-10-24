#![cfg(feature = "terminal-ui")]
#[path = "support/packets.rs"]
mod packets;

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use packrat_tui::{
    app::App,
    engine::{
        AnalysisCore,
        worker::{AnalysisWorker, WorkerEvent, WorkerLimits},
    },
    event, ui,
};
use ratatui::{Terminal, backend::TestBackend};
use std::time::{Duration, Instant};

#[test]
fn frame_view_stays_consistent_until_rendering_releases_it() {
    let mut app = App::new_for_test();
    let mut worker =
        AnalysisWorker::spawn(AnalysisCore::default(), WorkerLimits::default()).unwrap();
    app.core = worker.read_core();
    let view = app.try_view().unwrap().unwrap();
    worker
        .try_packet(packets::tcp(1, 100, 0x18, b"GET / HTTP/1.1\r\n\r\n"), false)
        .unwrap();
    assert!(view.core.streams.is_empty());
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    terminal.draw(|frame| ui::draw_view(frame, &view)).unwrap();
    assert!(worker.try_event().unwrap().is_none());
    assert!(
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .any(|cell| cell.symbol() == "T")
    );
    drop(view);
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(WorkerEvent::Packet { packet_no: 1, .. }) = worker.try_event().unwrap() {
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
    worker.finish_shared(|_| ()).unwrap();
    assert_eq!(app.try_view().unwrap().unwrap().core.streams.len(), 1);
}

#[test]
fn busy_analysis_leaves_settings_and_workspace_keys_responsive() {
    let mut app = App::new_for_test();
    let worker = AnalysisWorker::spawn(AnalysisCore::default(), WorkerLimits::default()).unwrap();
    app.core = worker.read_core();
    let (start, started) = std::sync::mpsc::channel();
    let (release, wait) = std::sync::mpsc::channel();
    worker
        .try_update(1, move |_| {
            start.send(()).unwrap();
            wait.recv().unwrap();
            Ok(())
        })
        .unwrap();
    started.recv_timeout(Duration::from_secs(3)).unwrap();
    let began = Instant::now();
    assert!(app.try_view().unwrap().is_none());
    event::handle(
        &mut app,
        Event::Key(KeyEvent::new(KeyCode::Char(','), KeyModifiers::NONE)),
    );
    assert!(app.settings_open);
    assert!(began.elapsed() < Duration::from_millis(100));
    release.send(()).unwrap();
    worker.finish_shared(|_| ()).unwrap();
}
