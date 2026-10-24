use packrat_tui::capture::dispatch::DispatchBudget;
use std::num::NonZeroUsize;
use std::time::Duration;
use tokio::sync::mpsc;

#[test]
fn sustained_input_is_bounded_ordered_and_never_dropped() {
    let (sender, mut receiver) = mpsc::channel(1000);
    for number in 0..1000 {
        sender.try_send(number).unwrap();
    }
    let budget = DispatchBudget::new(NonZeroUsize::new(17).unwrap(), Duration::from_secs(10));
    let mut output = Vec::new();
    assert_eq!(
        budget.drain(&mut receiver, |packet| output.push(packet)),
        17
    );
    assert_eq!(receiver.len(), 983);
    while !receiver.is_empty() {
        assert!(budget.drain(&mut receiver, |packet| output.push(packet)) <= 17);
    }
    assert_eq!(output, (0..1000).collect::<Vec<_>>());
}

#[test]
fn zero_time_budget_keeps_every_queued_packet() {
    let (sender, mut receiver) = mpsc::channel(1);
    sender.try_send(42).unwrap();
    let budget = DispatchBudget::new(NonZeroUsize::new(1).unwrap(), Duration::ZERO);
    assert_eq!(
        budget.drain(&mut receiver, |_| panic!("callback must not run")),
        0
    );
    assert_eq!(receiver.try_recv().unwrap(), 42);
}

#[test]
fn slow_consumer_yields_after_its_current_packet() {
    let (sender, mut receiver) = mpsc::channel(10);
    for number in 0..10 {
        sender.try_send(number).unwrap();
    }
    let budget = DispatchBudget::new(NonZeroUsize::new(10).unwrap(), Duration::from_millis(1));
    let count = budget.drain(&mut receiver, |_| {
        std::thread::sleep(Duration::from_millis(2))
    });
    assert!(count <= 1);
    assert_eq!(receiver.len(), 10 - count);
}

#[test]
fn disconnected_and_empty_queues_return_without_waiting() {
    let (sender, mut receiver) = mpsc::channel::<u8>(1);
    assert_eq!(
        DispatchBudget::default().drain(&mut receiver, |_| unreachable!()),
        0
    );
    drop(sender);
    assert_eq!(
        DispatchBudget::default().drain(&mut receiver, |_| unreachable!()),
        0
    );
}
#[test]
fn downstream_pressure_leaves_unread_packets_in_the_capture_channel() {
    let (sender, mut receiver) = tokio::sync::mpsc::channel(8);
    for index in 0..4 {
        sender.try_send(index).unwrap();
    }
    let mut pending = None;
    let count = packrat_tui::capture::dispatch::DispatchBudget::default().drain_while(
        &mut receiver,
        |item| {
            pending = Some(item);
            false
        },
    );
    assert_eq!(count, 1);
    assert_eq!(pending, Some(0));
    assert_eq!(receiver.len(), 3);
    assert_eq!(receiver.try_recv().unwrap(), 1);
}
