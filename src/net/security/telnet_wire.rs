const IAC: u8 = 255;

pub(super) fn authentication_prompt(payload: &[u8]) -> Option<&'static str> {
    if payload.is_empty() || payload.len() > 4096 {
        return None;
    }
    let mut input = payload.iter().copied();
    let mut line = [0_u8; 80];
    let mut len = 0;
    while let Some(byte) = input.next() {
        match byte {
            IAC => match input.next()? {
                // DO, DONT, WILL, WONT have a one-byte option.
                251..=254 => { input.next()?; }
                250 => {
                    input.next()?; // Subnegotiation option.
                    loop {
                        if input.next()? == IAC {
                            match input.next()? {
                                240 => break, // End of subnegotiation.
                                IAC => {}
                                _ => return None,
                            }
                        }
                    }
                }
                241..=249 => {}
                _ => return None,
            },
            b'\r' => {
                if !matches!(input.next()?, b'\n' | 0) {
                    return None;
                }
                len = 0;
            }
            b'\n' => len = 0,
            b'\t' | b' '..=b'~' => {
                if let Some(slot) = line.get_mut(len) {
                    *slot = byte;
                }
                len += 1;
            }
            _ => return None,
        }
    }
    let text = std::str::from_utf8(line.get(..len)?).ok()?.trim_matches([' ', '\t']);
    if text.eq_ignore_ascii_case("password:") {
        Some("password")
    } else if text.eq_ignore_ascii_case("login:")
        || text.rsplit_once(' ').is_some_and(|(host, prompt)| {
            prompt.eq_ignore_ascii_case("login:")
                && !host.is_empty()
                && !host.eq_ignore_ascii_case("last")
                && host.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        })
    {
        Some("login")
    } else {
        None
    }
}
