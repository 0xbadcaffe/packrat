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
        scope: ((None, None, None), [0; 2]),
        client: ("10.0.0.1".into(), 40000),
        server: ("10.0.0.2".into(), 445),
    }
}

#[test]
fn administrative_reply_must_have_the_same_vlan_tag_order_but_can_change_priority() {
    let packet = |no, reverse, tpids: [u16; 2], tci: u16| {
        let mut raw = [0u8; 62];
        for (index, tpid) in tpids.into_iter().enumerate() {
            let offset = 12 + index * 4;
            raw[offset..offset + 2].copy_from_slice(&tpid.to_be_bytes());
            raw[offset + 2..offset + 4].copy_from_slice(&tci.to_be_bytes());
        }
        raw[20..22].copy_from_slice(&0x0800_u16.to_be_bytes());
        raw[22] = 0x45;
        raw[24..26].copy_from_slice(&40_u16.to_be_bytes());
        raw[31] = 6;
        let (source, destination) = if reverse { (2, 1) } else { (1, 2) };
        raw[34..38].copy_from_slice(&[10, 0, 0, source]);
        raw[38..42].copy_from_slice(&[10, 0, 0, destination]);
        crate::net::parser::parse_ethernet(&raw, no, no as f64)
    };
    let syn = TcpSignal { flags: INITIAL_SYN, source_port: 40000, destination_port: 445,
        sequence: 100, acknowledgement: 0, payload_length: 0, complete: true };
    let ack = TcpSignal { flags: SYN_ACK, source_port: 445, destination_port: 40000,
        acknowledgement: 101, ..syn };
    let mut state = AdminFanout::default();
    state.observe(&packet(1, false, [0x88a8, 0x8100], 20), syn, None);
    state.observe(&packet(2, true, [0x8100, 0x88a8], 20), ack, None);
    assert_eq!(state.pending_count, 1);
    assert!(state.responders.is_empty());
    state.observe(&packet(3, true, [0x88a8, 0x8100], 0xb014), ack, None);
    assert_eq!(state.pending_count, 0);
    let targets = &state.responders.values().next().unwrap().targets;
    assert_eq!(targets["10.0.0.2"].1, [1, 3]);
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
