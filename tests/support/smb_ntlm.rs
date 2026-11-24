pub(super) fn smb2_ntlm_request(message_type: u8) -> Vec<u8> {
    let mut request = vec![0; 4 + 88 + 64];
    request[3] = 88 + 64;
    let message = &mut request[4..];
    message[..6].copy_from_slice(b"\xfeSMB\x40\x00");
    message[12] = 1;
    message[64] = 25;
    message[76] = 88;
    message[78] = 64;
    message[88..96].copy_from_slice(b"NTLMSSP\0");
    message[96] = message_type;
    request
}
