use std::collections::HashSet;

pub(super) fn valid_list(value: &[u8]) -> bool {
    parse_list(value).is_some()
}

fn parse_list(value: &[u8]) -> Option<()> {
    // RFCs 9848 and 9849: validate framing but keep the serialized config
    // unchanged because HPKE binds to those bytes.
    let (mut configs, trailing) = vector16(value)?;
    if !trailing.is_empty() || configs.is_empty() {
        return None;
    }
    while !configs.is_empty() {
        let (version, body) = configs.split_at_checked(2)?;
        if version != [0xfe, 0x0d] {
            return None;
        }
        let (config, rest) = vector16(body)?;
        parse_config(config)?;
        configs = rest;
    }
    Some(())
}

fn parse_config(config: &[u8]) -> Option<()> {
    let (public_key, rest) = vector16(config.get(3..)?)?;
    let (suites, rest) = vector16(rest)?;
    if public_key.is_empty() || suites.is_empty() || suites.len() % 4 != 0 {
        return None;
    }
    let name_len = usize::from(*rest.get(1)?);
    let (name, rest) = rest.get(2..)?.split_at_checked(name_len)?;
    if !valid_public_name(name) {
        return None;
    }
    let (mut extensions, trailing) = vector16(rest)?;
    if !trailing.is_empty() {
        return None;
    }
    let mut seen = HashSet::new();
    while !extensions.is_empty() {
        let (extension, data) = extensions.split_at_checked(2)?;
        let kind = u16::from_be_bytes(extension.try_into().ok()?);
        if kind & 0x8000 != 0 || !seen.insert(kind) {
            return None;
        }
        let (_, rest) = vector16(data)?;
        extensions = rest;
    }
    Some(())
}

fn valid_public_name(name: &[u8]) -> bool {
    name.len() <= 253
        && name
            .rsplit(|&byte| byte == b'.')
            .next()
            .is_some_and(|last| last.iter().any(u8::is_ascii_alphabetic))
        && name.split(|&byte| byte == b'.').all(|label| {
            (1..=63).contains(&label.len())
                && label.first().is_some_and(u8::is_ascii_alphanumeric)
                && label.last().is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        })
}

fn vector16(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (length, body) = bytes.split_at_checked(2)?;
    body.split_at_checked(usize::from(u16::from_be_bytes(length.try_into().ok()?)))
}
