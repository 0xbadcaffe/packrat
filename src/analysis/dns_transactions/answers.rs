use sha2::{Digest, Sha256};

use super::{parse_name, record_wire::txt_character_bytes};

const MAX_ANSWERS: usize = 64;
const MAX_MESSAGE_BYTES: usize = 4096;

pub(super) fn answer_fingerprint(bytes: &[u8], mut offset: usize) -> Option<[u8; 32]> {
    if bytes.len() > MAX_MESSAGE_BYTES || bytes.get(2)? & 0x02 != 0 || word(bytes, 4)? != 1 {
        return None;
    }
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
            15 => name_rdata(bytes, start, end, 2)?, // MX
            33 => name_rdata(bytes, start, end, 6)?, // SRV
            16 if txt_character_bytes(data).is_some() => data.to_vec(),
            _ => return None,
        };
        answers.push((owner, rr_type, class, canonical));
        offset = end;
    }
    answers.sort_unstable();
    answers.dedup();

    let mut hash = Sha256::new();
    hash.update([bytes[3] & 0x0f]); // Base response code.
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

fn word(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(bytes.get(offset..offset + 2)?.try_into().ok()?))
}
