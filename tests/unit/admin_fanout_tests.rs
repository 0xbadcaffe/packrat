use super::*;

#[test]
fn administrative_reply_pairs_require_a_timely_preceding_frame() {
    let mut pending = PendingSyn::new(SynSample { at: 1.0, frame: 10 });
    pending.retry(SynSample { at: 10.0, frame: 20 });
    assert_eq!(pending.matched_frame(16.0, 21), Some(10));
    assert_eq!(pending.matched_frame(17.0, 21), Some(20));
    assert_eq!(pending.matched_frame(17.0, 20), None);
    assert_eq!(pending.matched_frame(1.0, 9), None);
    assert_eq!(pending.matched_frame(1.0, 11), Some(10));
    assert_eq!(pending.matched_frame(26.0, 21), None);

    pending.retry(SynSample { at: 26.0, frame: 22 });
    pending.retry(SynSample { at: 27.0, frame: 19 });
    pending.retry(SynSample { at: 24.0, frame: 23 });
    assert_eq!(pending.matched_frame(25.0, 24), None);
    assert_eq!(pending.matched_frame(26.0, 24), Some(22));
}

fn pending_key() -> SynKey {
    SynKey {
        scope: (None, None, None),
        client: ("10.0.0.1".into(), 40000),
        server: ("10.0.0.2".into(), 445),
    }
}

fn remember(state: &mut AdminFanout, sequence: u32, payload_length: u32, at: f64, frame: u64) -> bool {
    state.remember_syn(pending_key(), TcpSignal {
        flags: INITIAL_SYN, sequence, acknowledgement: 0, payload_length,
        source_port: 40000, destination_port: 445, complete: true,
    }, SynSample { at, frame })
}

#[test]
fn syn_ack_requires_a_unique_timely_attempt_and_can_acknowledge_observed_payload() {
    let mut state = AdminFanout::default();
    assert!(remember(&mut state, u32::MAX, 3, 1.0, 1));
    assert!(remember(&mut state, 1, 0, 2.0, 2));
    let key = pending_key();
    let reply = crate::net::parser::parse_ethernet(&[], 3, 3.0);

    assert_eq!(state.take_unique_syn(&key, &reply, 4), None);
    assert_eq!(state.take_unique_syn(&key, &reply, 2), None);
    assert_eq!(state.pending_count, 2);
    assert_eq!(state.take_unique_syn(&key, &reply, 3), Some(1));
    let later_reply = crate::net::parser::parse_ethernet(&[], 4, 4.0);
    assert_eq!(state.take_unique_syn(&key, &later_reply, 2), Some(2));
    assert!(state.pending.is_empty());
    assert_eq!(state.pending_count, 0);
}

#[test]
fn global_capacity_does_not_overstate_attribution_after_an_untracked_tuple() {
    let mut state = AdminFanout::default();
    let syn = TcpSignal {
        flags: INITIAL_SYN, sequence: 100, acknowledgement: 0, payload_length: 0,
        source_port: 40000, destination_port: 445, complete: true,
    };
    for offset in 0..=MAX_PENDING {
        let mut key = pending_key();
        key.client.1 += offset as u16;
        assert_eq!(state.remember_syn(key, syn, SynSample { at: 1.0, frame: offset as u64 + 1 }),
            offset < MAX_PENDING);
    }
    assert_eq!(state.pending_count, MAX_PENDING);
    let reply = crate::net::parser::parse_ethernet(&[], 3000, 2.0);
    assert_eq!(state.take_unique_syn(&pending_key(), &reply, 101), None);

    assert!(state.remember_syn(pending_key(), syn, SynSample { at: 17.0, frame: 3001 }));
    let reply = crate::net::parser::parse_ethernet(&[], 3002, 18.0);
    assert_eq!(state.take_unique_syn(&pending_key(), &reply, 101), Some(3001));
}

#[test]
fn overflowed_tuple_does_not_claim_unique_attribution_until_attempts_expire() {
    let mut state = AdminFanout::default();
    for index in 0..MAX_PENDING_PER_TUPLE {
        assert!(remember(&mut state, index as u32, 0, 1.0, index as u64 + 1));
    }
    assert!(!remember(&mut state, 100, 0, 2.0, 20));
    let reply = crate::net::parser::parse_ethernet(&[], 21, 3.0);
    assert_eq!(state.take_unique_syn(&pending_key(), &reply, 1), None);
    assert_eq!(state.pending_count, MAX_PENDING_PER_TUPLE);
    assert!(remember(&mut state, 100, 0, 18.0, 22));
    let reply = crate::net::parser::parse_ethernet(&[], 23, 19.0);
    assert_eq!(state.take_unique_syn(&pending_key(), &reply, 101), Some(22));
    assert_eq!(state.pending_count, 0);
}
