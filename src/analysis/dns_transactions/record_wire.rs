use super::{DnsMessage, parse_name};

const MAX_RECORDS: usize = 128;
const MAX_MESSAGE_BYTES: usize = 4096;

#[derive(Default)]
pub(super) struct RecordSummary {
    pub(super) rcode: u16,
    pub(super) answer_txt_bytes: usize,
}

pub(super) fn summarize_response(message: &DnsMessage<'_>, count_txt: bool) -> Option<RecordSummary> {
    let bytes = message.bytes;
    if !message.response || bytes.len() > MAX_MESSAGE_BYTES
        || bytes[2] & 0x7a != 0 || bytes[4..6] != [0, 1]
    {
        return None;
    }
    let word = |at: usize| u16::from_be_bytes([bytes[at], bytes[at + 1]]) as usize;
    let answers = word(6);
    let additional_start = answers + word(8);
    let count = additional_start + word(10);
    if count > MAX_RECORDS {
        return None;
    }
    let mut summary = RecordSummary { rcode: u16::from(bytes[3] & 0x0f), ..Default::default() };
    let mut saw_opt = false;
    let mut offset = message.answer_offset;
    for record in 0..count {
        let (owner, fields) = parse_name(bytes, offset)?;
        let header = bytes.get(fields..fields + 10)?;
        let start = fields + 10;
        offset = start + u16::from_be_bytes([header[8], header[9]]) as usize;
        let data = bytes.get(start..offset)?;
        if header[..2] == [0, 41] {
            if record < additional_start || !owner.is_empty() || saw_opt {
                return None;
            }
            saw_opt = true;
            summary.rcode |= u16::from(header[4]) << 4;
        } else if count_txt && record < answers && header[..4] == [0, 16, 0, 1] {
            summary.answer_txt_bytes += txt_character_bytes(data)?;
        }
    }
    (offset == bytes.len()).then_some(summary)
}

pub(super) fn txt_character_bytes(mut data: &[u8]) -> Option<usize> {
    if data.is_empty() {
        return None;
    }
    let mut total = 0;
    while let Some((&size, content)) = data.split_first() {
        let size = usize::from(size);
        data = content.get(size..)?;
        total += size;
    }
    Some(total)
}
