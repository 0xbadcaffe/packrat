#[path = "ech_config.rs"]
mod ech_config;

// RFC 9460: an uncompressed target followed by ordered SvcParam TLVs.
pub(super) fn canonical(data: &[u8]) -> Option<Vec<u8>> {
    let priority = data.get(..2)?;
    let alias = priority == [0, 0];
    let mut offset = 2;
    loop {
        let length = usize::from(*data.get(offset)?);
        offset += length + 1;
        if length > 63 || offset - 2 > 255 || offset > data.len() {
            return None;
        }
        if length == 0 {
            break;
        }
    }
    let mut out = data[..offset].to_vec();
    out[2..].make_ascii_lowercase();
    let mut keys = Vec::new();
    let mut mandatory = Vec::new();
    let mut rest = &data[offset..];
    while !rest.is_empty() {
        let key = word(rest)?;
        if key == u16::MAX || keys.last().is_some_and(|prior| *prior >= key) {
            return None;
        }
        let length = usize::from(word(rest.get(2..)?)?);
        let (value, next) = rest.get(4..)?.split_at_checked(length)?;
        rest = next;
        keys.push(key);
        if alias {
            continue;
        }
        let canonical = match key {
            0 if !value.is_empty() && value.len() % 2 == 0 => {
                mandatory = value
                    .chunks_exact(2)
                    .map(|entry| u16::from_be_bytes([entry[0], entry[1]]))
                    .collect();
                if mandatory[0] == 0 || !mandatory.windows(2).all(|pair| pair[0] < pair[1]) {
                    return None;
                }
                value.to_vec()
            }
            1 => alpn_set(value)?,
            2 if value.is_empty() && keys.binary_search(&1).is_ok() => Vec::new(),
            3 if value.len() == 2 => value.to_vec(),
            4 => address_set(value, 4)?,
            5 if ech_config::valid_list(value) => value.to_vec(),
            6 => address_set(value, 16)?,
            _ => return None,
        };
        out.extend(key.to_be_bytes());
        out.extend(u16::try_from(canonical.len()).ok()?.to_be_bytes());
        out.extend(canonical);
    }
    mandatory
        .iter()
        .all(|key| keys.binary_search(key).is_ok())
        .then_some(out)
}

fn alpn_set(mut value: &[u8]) -> Option<Vec<u8>> {
    let mut protocols = Vec::new();
    while let Some((&length, payload)) = value.split_first() {
        if length == 0 {
            return None;
        }
        let (protocol, rest) = payload.split_at_checked(usize::from(length))?;
        protocols.push(protocol);
        value = rest;
    }
    if protocols.is_empty() {
        return None;
    }
    protocols.sort_unstable();
    protocols.dedup();
    let mut stable = Vec::new();
    for protocol in protocols {
        stable.push(u8::try_from(protocol.len()).ok()?);
        stable.extend(protocol);
    }
    Some(stable)
}

fn address_set(value: &[u8], width: usize) -> Option<Vec<u8>> {
    if value.is_empty() || value.len() % width != 0 {
        return None;
    }
    let mut addresses: Vec<_> = value.chunks_exact(width).collect();
    addresses.sort_unstable();
    addresses.dedup();
    Some(addresses.concat())
}

fn word(value: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes(value.get(..2)?.try_into().ok()?))
}
