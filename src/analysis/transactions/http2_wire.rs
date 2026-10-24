use super::{Direction, ReassembledStream};

pub(super) const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
pub(super) const MAX_FRAMES: usize = 4096;

pub(super) struct Frame<'a> {
    pub kind: u8,
    pub flags: u8,
    pub stream_id: u32,
    pub payload: &'a [u8],
    pub payload_offset: usize,
    pub direction: Direction,
    pub packets: Vec<u64>,
}

pub(super) fn frames<'a>(
    stream: &'a ReassembledStream,
    direction: Direction,
    start: usize,
    limitations: &mut Vec<String>,
) -> Vec<Frame<'a>> {
    let data = direction.bytes(stream);
    let mut offset = start;
    let mut result = Vec::new();
    while offset < data.len() && result.len() < MAX_FRAMES {
        let Some(header) = data.get(offset..offset.saturating_add(9)) else {
            limitations.push(format!("{direction:?}: incomplete HTTP/2 frame header"));
            break;
        };
        let length =
            (usize::from(header[0]) << 16) | (usize::from(header[1]) << 8) | usize::from(header[2]);
        let payload_offset = offset + 9;
        let end = payload_offset + length;
        let Some(payload) = data.get(payload_offset..end) else {
            limitations.push(format!("{direction:?}: incomplete HTTP/2 frame payload"));
            break;
        };
        result.push(Frame {
            kind: header[3],
            flags: header[4],
            stream_id: u32::from_be_bytes(header[5..9].try_into().unwrap()) & 0x7fff_ffff,
            payload,
            payload_offset,
            direction,
            packets: stream.packet_numbers(direction.from_a(), offset, end),
        });
        offset = end;
    }
    if offset < data.len() && result.len() == MAX_FRAMES {
        limitations.push("HTTP/2 frame retention limit reached".into());
    }
    result
}

pub(super) fn unpad<'a>(frame: &Frame<'a>) -> Result<(&'a [u8], usize), &'static str> {
    if frame.flags & 0x08 == 0 {
        return Ok((frame.payload, frame.payload_offset));
    }
    let padding = usize::from(*frame.payload.first().ok_or("Missing HTTP/2 pad length")?);
    let end = frame
        .payload
        .len()
        .checked_sub(padding)
        .filter(|end| *end >= 1)
        .ok_or("HTTP/2 padding exceeds payload")?;
    Ok((&frame.payload[1..end], frame.payload_offset + 1))
}
