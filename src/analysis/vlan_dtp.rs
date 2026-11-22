const DTP_SNAP: [u8; 8] = [0xaa, 0xaa, 3, 0, 0, 0x0c, 0x20, 4];

pub(super) fn parse_dtp_negotiation(raw: &[u8]) -> Option<()> {
    let mut length_at = 12;
    let length = loop {
        let field = u16::from_be_bytes(raw.get(length_at..length_at + 2)?.try_into().ok()?);
        if !matches!(field, 0x8100 | 0x88a8) {
            break usize::from(field);
        }
        length_at += 4;
    };
    if length > 1500 {
        return None;
    }
    let start = length_at + 2;
    let body = raw.get(start..start + length)?;
    let mut tlvs = body.strip_prefix(&DTP_SNAP)?.strip_prefix(&[1])?;
    let mut has_status = false;
    while !tlvs.is_empty() {
        let (kind, size) = match tlvs.get(..4)? {
            [a, b, c, d] => (u16::from_be_bytes([*a, *b]), usize::from(u16::from_be_bytes([*c, *d]))),
            _ => return None,
        };
        if size <= 4 {
            return None;
        }
        let value_len = tlvs.get(4..size)?.len();
        match kind {
            1 if value_len > 33 => return None,
            2 | 3 if value_len != 1 => return None,
            4 if value_len != 6 => return None,
            2 => has_status = true,
            _ => {}
        }
        tlvs = tlvs.get(size..)?;
    }
    has_status.then_some(())
}
