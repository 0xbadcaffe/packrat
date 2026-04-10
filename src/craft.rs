/// Packet crafting state — lets users build and inject custom packets.
use crate::net::packet::Packet;

#[derive(Debug, Clone)]
pub struct CraftField {
    pub label: &'static str,
    pub value: String,
    pub hint:  &'static str,
}

impl CraftField {
    fn new(label: &'static str, default: &str, hint: &'static str) -> Self {
        Self { label, value: default.to_string(), hint }
    }
}

pub struct CraftState {
    pub fields:   Vec<CraftField>,
    pub focused:  usize,   // which field is currently focused
    pub editing:  bool,    // typing into the focused field
    pub result:   Option<Result<String, String>>,  // last inject result
}

impl Default for CraftState {
    fn default() -> Self {
        Self {
            fields: vec![
                CraftField::new("Protocol",    "ICMP",        "TCP UDP ICMP DNS HTTP TLS ARP..."),
                CraftField::new("Src IP",      "192.168.1.1", "x.x.x.x"),
                CraftField::new("Dst IP",      "8.8.8.8",     "x.x.x.x"),
                CraftField::new("Src Port",    "",            "leave blank for non-TCP/UDP"),
                CraftField::new("Dst Port",    "",            "leave blank for non-TCP/UDP"),
                CraftField::new("TTL",         "64",          "1–255"),
                CraftField::new("Info",        "",            "human-readable summary"),
                CraftField::new("Payload (hex)","",           "e.g. deadbeef  (leave blank for zeros)"),
            ],
            focused: 0,
            editing: false,
            result:  None,
        }
    }
}

impl CraftState {
    pub fn focus_next(&mut self) {
        self.editing = false;
        self.focused = (self.focused + 1) % self.fields.len();
    }

    pub fn focus_prev(&mut self) {
        self.editing = false;
        if self.focused == 0 {
            self.focused = self.fields.len() - 1;
        } else {
            self.focused -= 1;
        }
    }

    pub fn toggle_edit(&mut self) {
        self.editing = !self.editing;
    }

    pub fn start_edit(&mut self) {
        self.editing = true;
    }

    pub fn stop_edit(&mut self) {
        self.editing = false;
    }

    pub fn push_char(&mut self, c: char) {
        if self.editing {
            self.fields[self.focused].value.push(c);
        }
    }

    pub fn pop_char(&mut self) {
        if self.editing {
            self.fields[self.focused].value.pop();
        }
    }

    /// Build a Packet from the current field values.
    pub fn build_packet(&self, counter: u64) -> Result<Packet, String> {
        let proto = self.fields[0].value.trim().to_uppercase();
        let src   = self.fields[1].value.trim().to_string();
        let dst   = self.fields[2].value.trim().to_string();
        let sport = parse_port(&self.fields[3].value);
        let dport = parse_port(&self.fields[4].value);
        let ttl   = self.fields[5].value.trim().parse::<u8>().unwrap_or(64);
        let info  = if self.fields[6].value.trim().is_empty() {
            format!("Crafted {} → {}", src, dst)
        } else {
            self.fields[6].value.trim().to_string()
        };
        let payload_hex = self.fields[7].value.trim().replace(' ', "");

        if src.is_empty() || dst.is_empty() {
            return Err("Src IP and Dst IP are required".into());
        }

        // Build a minimal Ethernet+IP+transport byte buffer
        let payload: Vec<u8> = if payload_hex.is_empty() {
            vec![0u8; 16]
        } else {
            hex_decode(&payload_hex).map_err(|e| format!("Payload hex: {}", e))?
        };

        let mut bytes = vec![0u8; 54 + payload.len()];
        // Ethernet: dst MAC 0-5, src MAC 6-11, EtherType 12-13
        bytes[12] = 0x08; bytes[13] = 0x00; // IPv4
        // IPv4: version+IHL, DSCP, total length, TTL, protocol
        bytes[14] = 0x45; // version 4, IHL 5
        let total_len = (20u16 + payload.len() as u16).to_be_bytes();
        bytes[16] = total_len[0]; bytes[17] = total_len[1];
        bytes[22] = ttl;
        let proto_byte = match proto.as_str() {
            "TCP" | "HTTP" | "HTTPS" | "TLS" | "FTP" | "SSH" | "SMTP" => 6,
            "UDP" | "DNS" | "NTP" | "DHCP" | "QUIC"                   => 17,
            "ICMP"                                                      => 1,
            _                                                           => 6,
        };
        bytes[23] = proto_byte;
        // src IP
        if let Ok(octets) = parse_ip(&src) {
            bytes[26..30].copy_from_slice(&octets);
        }
        // dst IP
        if let Ok(octets) = parse_ip(&dst) {
            bytes[30..34].copy_from_slice(&octets);
        }
        // transport ports (TCP/UDP at offset 34)
        if let Some(sp) = sport {
            let b = sp.to_be_bytes();
            bytes[34] = b[0]; bytes[35] = b[1];
        }
        if let Some(dp) = dport {
            let b = dp.to_be_bytes();
            bytes[36] = b[0]; bytes[37] = b[1];
        }
        // payload after transport header (TCP/UDP header minimum 8 bytes → offset 42)
        if payload.len() > 0 {
            let start = 42.min(bytes.len());
            let end = (start + payload.len()).min(bytes.len());
            let copy_len = end - start;
            bytes[start..end].copy_from_slice(&payload[..copy_len]);
        }

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        Ok(Packet {
            no:        counter,
            timestamp: ts,
            src,
            dst,
            protocol:  proto.clone(),
            length:    bytes.len() as u16,
            info,
            bytes,
            src_port:  sport,
            dst_port:  dport,
            vlan_id:   None,
        })
    }
}

fn parse_port(s: &str) -> Option<u16> {
    s.trim().parse::<u16>().ok()
}

fn parse_ip(s: &str) -> Result<[u8; 4], String> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return Err(format!("invalid IP: {}", s));
    }
    let mut out = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        out[i] = p.parse::<u8>().map_err(|_| format!("invalid IP octet: {}", p))?;
    }
    Ok(out)
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("hex string must have even length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i+2], 16)
            .map_err(|_| format!("invalid hex byte: {}", &s[i..i+2])))
        .collect()
}
