fn session_setup(payload: &[u8], response: bool) -> Option<&[u8]> {
    let prefix = payload.first_chunk::<4>()?;
    let length = u32::from_be_bytes(*prefix) as usize;
    if prefix[0] != 0 || length < 64 {
        return None;
    }
    let message = payload.get(4..4 + length)?;
    (message[..6] == *b"\xfeSMB\x40\x00"
        && message[12..14] == 1_u16.to_le_bytes()
        && (message[16] & 1 != 0) == response
        && message[20..24] == [0; 4]).then_some(message)
}

pub(super) fn is_smb2_logon_failure(payload: &[u8]) -> bool {
    let Some(message) = session_setup(payload, true).filter(|message| message.len() >= 72) else {
        return false;
    };
    let error_data_bytes = u32::from_le_bytes(message[68..72].try_into().unwrap()) as usize;
    message[8..12] == 0xc000_006d_u32.to_le_bytes()
        && message[64..66] == 9_u16.to_le_bytes()
        && error_data_bytes <= message.len() - 72
}

pub(super) fn has_ntlm_authenticate(payload: &[u8]) -> bool {
    let Some(message) = session_setup(payload, false).filter(|message| message.len() >= 88) else {
        return false;
    };
    if message[64..66] != 25_u16.to_le_bytes() {
        return false;
    }
    let offset = u16::from_le_bytes([message[76], message[77]]) as usize;
    let length = u16::from_le_bytes([message[78], message[79]]) as usize;
    if offset < 88 || length < 64 {
        return false;
    }
    let Some(buffer) = message.get(offset..offset + length) else { return false };
    // The marker must be inside the declared security buffer, not arbitrary SMB data.
    buffer.windows(12).enumerate().any(|(start, marker)| {
        marker == b"NTLMSSP\0\x03\0\0\0" && authenticate_fields_fit(&buffer[start..])
    })
}

fn authenticate_fields_fit(message: &[u8]) -> bool {
    let Some(fields) = message.get(12..60) else { return false };
    message.len() >= 64 && fields.chunks_exact(8).all(|field| {
        let length = u16::from_le_bytes([field[0], field[1]]) as usize;
        let offset = u32::from_le_bytes(field[4..8].try_into().unwrap()) as usize;
        length == 0 || (offset >= 64 && offset.checked_add(length).is_some_and(|end| end <= message.len()))
    })
}
