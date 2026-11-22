use super::ReassembledStream;

const MAX_MESSAGES_PER_OBSERVATION: usize = 128;

pub(crate) enum DnsTcpObservation {
    Unanchored,
    Anchored {
        source: u16,
        destination: u16,
        records: Vec<DnsTcpRecord>,
    },
}

pub(crate) struct DnsTcpRecord {
    pub(crate) bytes: Vec<u8>,
    pub(crate) frames: Vec<u64>,
}

pub(super) fn observe(
    stream: &mut ReassembledStream,
    from_a: bool,
    source: u16,
    destination: u16,
) -> DnsTcpObservation {
    let (syn, data) = if from_a {
        (stream.client_initial_syn, &stream.client_data)
    } else {
        (stream.server_initial_syn, &stream.server_data)
    };
    if syn.is_none() || stream.midstream {
        return DnsTcpObservation::Unanchored;
    }
    let mut records = Vec::new();
    if !stream.epoch_ambiguous
        && !stream.reset
        && !stream.truncated
        && stream.dropped_segments == 0
        && !stream.provenance_truncated
    {
        let direction = usize::from(from_a);
        let mut cursor = stream.dns_offsets[direction];
        for _ in 0..MAX_MESSAGES_PER_OBSERVATION {
            let Some(start) = cursor else { break };
            let Some(prefix) = data.get(start..).and_then(|bytes| bytes.first_chunk::<2>()) else {
                break;
            };
            let length = usize::from(u16::from_be_bytes(*prefix));
            if length < 12 {
                cursor = None;
                break;
            }
            let end = start + 2 + length;
            let Some(bytes) = data.get(start + 2..end) else {
                break;
            };
            cursor = Some(end);
            let frames = stream.packet_numbers(from_a, start, end);
            if !frames.is_empty()
                && frames.len() < crate::analysis::alert_center::MAX_ALERT_PACKET_REFS
            {
                records.push(DnsTcpRecord {
                    bytes: bytes.to_vec(),
                    frames,
                });
            }
        }
        stream.dns_offsets[direction] = cursor;
    }
    DnsTcpObservation::Anchored {
        source,
        destination,
        records,
    }
}
