use sha2::{Digest, Sha256};

use super::{DnsMessage, parse_name, record_wire};

#[path = "service_binding.rs"]
mod service_binding;

const MAX_ANSWERS: usize = 64;
#[derive(Debug)]
pub(super) struct AnswerFingerprint {
    pub(super) rcode: u16,
    pub(super) digest: Option<[u8; 32]>,
}

impl AnswerFingerprint {
    pub(super) fn same_answers(&self, other: &Self) -> bool {
        self.rcode == other.rcode && self.digest.is_some() && self.digest == other.digest
    }
}

pub(super) fn answer_fingerprint(message: &DnsMessage<'_>) -> Option<AnswerFingerprint> {
    let rcode = record_wire::summarize_response(message, false)?.rcode;
    Some(AnswerFingerprint { rcode, digest: answer_digest(message) })
}

fn answer_digest(message: &DnsMessage<'_>) -> Option<[u8; 32]> {
    let bytes = message.bytes;
    let mut offset = message.answer_offset;
    let count = usize::from(word(bytes, 6)?);
    if count > MAX_ANSWERS {
        return None;
    }
    let mut answers = Vec::with_capacity(count);
    for _ in 0..count {
        let (owner, fields) = parse_name(bytes, offset)?;
        let rr_type = word(bytes, fields)?;
        let class = word(bytes, fields + 2)?;
        let start = fields + 10;
        let end = start + usize::from(word(bytes, fields + 8)?);
        let data = bytes.get(start..end)?;
        if class != 1 {
            return None;
        }
        let canonical = match rr_type {
            1 if data.len() == 4 => data.to_vec(),   // A
            28 if data.len() == 16 => data.to_vec(), // AAAA
            2 | 5 | 12 | 39 => name_rdata(bytes, start, end, 0)?,
            6 => soa_rdata(bytes, start, end)?,
            15 => name_rdata(bytes, start, end, 2)?, // MX
            33 => name_rdata(bytes, start, end, 6)?, // SRV
            16 if record_wire::txt_character_bytes(data).is_some() => data.to_vec(),
            64 | 65 => service_binding::canonical(data)?,
            _ => return None,
        };
        answers.push((owner, rr_type, class, canonical));
        offset = end;
    }
    answers.sort_unstable();
    answers.dedup();

    let mut hash = Sha256::new();
    for (owner, rr_type, class, rdata) in answers {
        hash.update((owner.len() as u32).to_be_bytes());
        hash.update(owner.as_bytes());
        hash.update(rr_type.to_be_bytes());
        hash.update(class.to_be_bytes());
        hash.update((rdata.len() as u32).to_be_bytes());
        hash.update(rdata);
    }
    Some(hash.finalize().into())
}

fn name_rdata(bytes: &[u8], start: usize, end: usize, prefix_len: usize) -> Option<Vec<u8>> {
    let name_start = start + prefix_len;
    if name_start >= end {
        return None;
    }
    let (name, consumed) = parse_name(bytes, name_start)?;
    if consumed != end {
        return None;
    }
    let mut result = bytes.get(start..name_start)?.to_vec();
    result.extend(name.as_bytes());
    Some(result)
}

fn soa_rdata(bytes: &[u8], start: usize, end: usize) -> Option<Vec<u8>> {
    let numeric_start = end.checked_sub(20)?;
    let (primary, mailbox_start) = parse_name(bytes, start)?;
    if mailbox_start >= numeric_start {
        return None;
    }
    let (mailbox, consumed) = parse_name(bytes, mailbox_start)?;
    if consumed != numeric_start {
        return None;
    }
    let mut result = (primary.len() as u32).to_be_bytes().to_vec();
    result.extend(primary.as_bytes());
    result.extend(mailbox.as_bytes());
    result.extend(bytes.get(numeric_start..end)?);
    Some(result)
}

fn word(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(bytes.get(offset..offset + 2)?.try_into().ok()?))
}
