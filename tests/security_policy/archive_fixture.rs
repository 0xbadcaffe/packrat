use packrat_tui::app::App;
use packrat_tui::engine::worker::WorkerLimits;
use packrat_tui::net::parser::parse_ethernet;
use packrat_tui::storage::packet_archive::{ArchiveLimits, ArchiveWorker};
use std::path::Path;
use std::time::{Duration, Instant};

pub(super) fn start(path: &Path, rules: Vec<String>) -> App {
    let mut app = App::new_for_test();
    let archive = ArchiveWorker::open_alert_evidence(path, ArchiveLimits::default()).unwrap();
    app.set_packet_archive_with_rules(archive, rules).unwrap();
    app.start_background_analysis().unwrap();
    app
}

pub(super) fn drain(app: &mut App) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !app.analysis_idle() {
        app.poll_analysis();
        assert!(Instant::now() < deadline, "analysis did not drain");
        std::thread::yield_now();
    }
}

pub(super) fn roll_history(app: &mut App, first: u64) -> u64 {
    drain(app);
    let trigger = first + WorkerLimits::default().history_packets as u64 + 1;
    for frame in first..trigger {
        app.inject_packet(parse_ethernet(&[0; 14], frame, 6.0));
        drain(app);
    }
    app.packets.clear();
    trigger
}

pub(super) fn finish(app: &mut App) {
    drain(app);
    app.stop_background_analysis().unwrap();
    app.packet_archive.as_mut().unwrap().finish().unwrap();
}
