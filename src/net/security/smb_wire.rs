fn direct_tcp_message(payload: &[u8]) -> Option<&[u8]> {
    let prefix = payload.first_chunk::<4>()?;
    if prefix[0] != 0 {
        return None;
    }
    let length = u32::from_be_bytes(*prefix) as usize;
    payload.get(4..4 + length)
}

fn session_setup(payload: &[u8], response: bool) -> Option<&[u8]> {
    let message = direct_tcp_message(payload).filter(|message| message.len() >= 64)?;
    (message[..6] == *b"\xfeSMB\x40\x00"
        && message[12..14] == 1_u16.to_le_bytes()
        && (message[16] & 1 != 0) == response
        && message[20..24] == [0; 4]).then_some(message)
}

pub(super) fn is_successful_legacy_reply(payload: &[u8]) -> bool {
    let Some(message) = direct_tcp_message(payload).filter(|message| message.len() >= 35) else {
        return false;
    };
    if !message.starts_with(b"\xffSMB")
        || message[4] == 0x72 // Dialect negotiation alone does not establish SMBv1 use.
        || message[5..9] != [0; 4]
        || message[9] & 0x80 == 0
    {
        return false;
    }
    let count_offset = 33 + usize::from(message[32]) * 2;
    let Some(count) = message.get(count_offset..count_offset + 2) else { return false };
    let size = usize::from(u16::from_le_bytes([count[0], count[1]]));
    count_offset + 2 + size == message.len()
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
