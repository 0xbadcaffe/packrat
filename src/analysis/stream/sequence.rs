const MAX_STREAM_BYTES: usize = 1_000_000;
const MAX_PENDING_SEGMENTS: usize = 1_024;
const MAX_PENDING_BYTES: usize = 2_000_000;

#[derive(Debug, Clone)]
pub(super) struct PendingTcpSegment {
    pub(super) sequence: u32,
    pub(super) payload: Vec<u8>,
    pub(super) fin: bool,
    pub(super) timestamp: f64,
}

pub(super) fn sequence_delta(sequence: u32, expected: u32) -> i32 {
    sequence.wrapping_sub(expected) as i32
}

pub(super) fn buffer_pending(pending: &mut Vec<PendingTcpSegment>, segment: PendingTcpSegment) {
    if pending.iter().any(|existing| {
        existing.sequence == segment.sequence
            && existing.payload == segment.payload
            && existing.fin == segment.fin
    }) {
        return;
    }
    let pending_bytes: usize = pending.iter().map(|segment| segment.payload.len()).sum();
    if pending.len() >= MAX_PENDING_SEGMENTS
        || pending_bytes.saturating_add(segment.payload.len()) > MAX_PENDING_BYTES
    {
        return;
    }
    pending.push(segment);
}

pub(super) fn consume_contiguous(
    data: &mut Vec<u8>,
    next_sequence: &mut Option<u32>,
    pending: &mut Vec<PendingTcpSegment>,
    first: PendingTcpSegment,
) -> (Vec<(usize, usize, f64)>, bool) {
    let mut emitted = Vec::new();
    let mut fin_consumed = consume_one(data, next_sequence, first, &mut emitted);

    loop {
        let expected = match *next_sequence {
            Some(expected) => expected,
            None => break,
        };
        pending.retain(|segment| {
            let payload_end = segment.sequence.wrapping_add(segment.payload.len() as u32);
            sequence_delta(payload_end, expected) > 0 || (segment.fin && payload_end == expected)
        });
        let Some(index) = pending.iter().position(|segment| {
            let start_delta = sequence_delta(segment.sequence, expected);
            let payload_end = segment.sequence.wrapping_add(segment.payload.len() as u32);
            let end_delta = sequence_delta(payload_end, expected);
            start_delta <= 0 && (end_delta > 0 || (segment.fin && end_delta == 0))
        }) else {
            break;
        };
        let segment = pending.remove(index);
        fin_consumed |= consume_one(data, next_sequence, segment, &mut emitted);
    }
    (emitted, fin_consumed)
}

pub(super) fn consume_one(
    data: &mut Vec<u8>,
    next_sequence: &mut Option<u32>,
    segment: PendingTcpSegment,
    emitted: &mut Vec<(usize, usize, f64)>,
) -> bool {
    let expected = next_sequence.unwrap_or(segment.sequence);
    let behind = sequence_delta(expected, segment.sequence).max(0) as usize;
    let unseen = segment.payload.get(behind..).unwrap_or_default();
    if !unseen.is_empty() {
        let offset = data.len();
        let captured = unseen
            .len()
            .min(MAX_STREAM_BYTES.saturating_sub(data.len()));
        data.extend_from_slice(&unseen[..captured]);
        if captured > 0 {
            emitted.push((offset, captured, segment.timestamp));
        }
        *next_sequence = Some(expected.wrapping_add(unseen.len() as u32));
    }
    let payload_end = segment.sequence.wrapping_add(segment.payload.len() as u32);
    if segment.fin && next_sequence == &Some(payload_end) {
        *next_sequence = Some(payload_end.wrapping_add(1));
        true
    } else {
        false
    }
}
