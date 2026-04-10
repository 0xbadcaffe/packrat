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

// Field indices — keep in sync with Default impl and build_packet()
pub const F_PROTO:   usize = 0;
pub const F_SRC:     usize = 1;
pub const F_DST:     usize = 2;
pub const F_SPORT:   usize = 3;
pub const F_DPORT:   usize = 4;
pub const F_TTL:     usize = 5;
pub const F_IP_FL:   usize = 6;  // IPv4 flags (DF / MF)
pub const F_L4_FL:   usize = 7;  // L4 flags: TCP flags, ICMP type:code, UDP checksum override
pub const F_INFO:    usize = 8;
pub const F_PAYLOAD: usize = 9;

pub struct CraftState {
    pub fields:  Vec<CraftField>,
    pub focused: usize,
    pub editing: bool,
    pub result:  Option<Result<String, String>>,
    /// Flood mode — when true, inject one packet per tick at `flood_rate` pps.
    pub flooding: bool,
    /// Target packets-per-second for flood mode (1–10000).
    pub flood_rate: u32,
    /// Fractional tick accumulator for sub-tick rates.
    pub flood_accum: f64,
    /// Running count of packets sent in current flood session.
    pub flood_sent: u64,
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
                CraftField::new("IP Flags",    "",            "DF  MF  DF+MF  or 0x40=DF 0x20=MF  (leave blank = none)"),
                CraftField::new("L4 Flags",    "",            "TCP: SYN ACK FIN RST PSH URG ECE CWR  / ICMP: type:code (8:0=ping)  / or 0x.. hex"),
                CraftField::new("Info",        "",            "human-readable summary (auto-generated if blank)"),
                CraftField::new("Payload (hex)","",           "e.g. deadbeef  (leave blank for zeros)"),
            ],
            focused: 0,
            editing: false,
            result:  None,
            flooding: false,
            flood_rate: 10,
            flood_accum: 0.0,
            flood_sent: 0,
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

    pub fn start_edit(&mut self) { self.editing = true; }
    pub fn stop_edit(&mut self)  { self.editing = false; }

    pub fn push_char(&mut self, c: char) {
        if self.editing { self.fields[self.focused].value.push(c); }
    }

    pub fn pop_char(&mut self) {
        if self.editing { self.fields[self.focused].value.pop(); }
    }

    pub fn flood_rate_up(&mut self) {
        self.flood_rate = match self.flood_rate {
            r if r < 10   => r + 1,
            r if r < 100  => r + 10,
            r if r < 1000 => r + 100,
            r             => (r + 1000).min(10_000),
        };
    }

    pub fn flood_rate_down(&mut self) {
        self.flood_rate = match self.flood_rate {
            r if r <= 1    => 1,
            r if r <= 10   => r - 1,
            r if r <= 100  => r - 10,
            r if r <= 1000 => r - 100,
            r              => r - 1000,
        };
    }

    /// Called each app tick (100 ms). Returns how many packets to inject this tick.
    pub fn flood_tick(&mut self) -> u32 {
        if !self.flooding { return 0; }
        // flood_rate pps, tick = 100 ms → expected packets per tick = flood_rate / 10
        let per_tick = self.flood_rate as f64 / 10.0;
        self.flood_accum += per_tick;
        let n = self.flood_accum.floor() as u32;
        self.flood_accum -= n as f64;
        n
    }

    /// Build a Packet from the current field values.
    pub fn build_packet(&self, counter: u64) -> Result<Packet, String> {
        let proto   = self.fields[F_PROTO].value.trim().to_uppercase();
        let src     = self.fields[F_SRC].value.trim().to_string();
        let dst     = self.fields[F_DST].value.trim().to_string();
        let sport   = parse_port(&self.fields[F_SPORT].value);
        let dport   = parse_port(&self.fields[F_DPORT].value);
        let ttl     = self.fields[F_TTL].value.trim().parse::<u8>().unwrap_or(64);
        let ip_flags = parse_ip_flags(self.fields[F_IP_FL].value.trim());
        let l4_flags = self.fields[F_L4_FL].value.trim();
        let info    = if self.fields[F_INFO].value.trim().is_empty() {
            format!("Crafted {} → {}", src, dst)
        } else {
            self.fields[F_INFO].value.trim().to_string()
        };
        let payload_hex = self.fields[F_PAYLOAD].value.trim().replace(' ', "");

        if src.is_empty() || dst.is_empty() {
            return Err("Src IP and Dst IP are required".into());
        }

        let payload: Vec<u8> = if payload_hex.is_empty() {
            vec![0u8; 16]
        } else {
            hex_decode(&payload_hex).map_err(|e| format!("Payload hex: {}", e))?
        };

        let mut bytes = vec![0u8; 54 + payload.len()];

        // ── Ethernet (bytes 0–13) ────────────────────────────────────────────
        bytes[12] = 0x08; bytes[13] = 0x00; // EtherType = IPv4

        // ── IPv4 (bytes 14–33) ───────────────────────────────────────────────
        bytes[14] = 0x45; // version=4, IHL=5
        let total_len = (20u16 + payload.len() as u16).to_be_bytes();
        bytes[16] = total_len[0]; bytes[17] = total_len[1];
        // IPv4 flags field: bits 15-13 of the 16-bit flags+frag-offset at offset 6 in IP hdr
        // byte[20] = upper byte of that field; DF=bit14=0x40, MF=bit13=0x20
        bytes[20] = ip_flags;
        bytes[22] = ttl;

        let proto_byte: u8 = match proto.as_str() {
            "TCP" | "HTTP" | "HTTPS" | "TLS" | "FTP" | "SSH" | "SMTP" => 6,
            "UDP" | "DNS"  | "NTP"   | "DHCP" | "QUIC"                => 17,
            "ICMP"                                                      => 1,
            "ARP"                                                       => { bytes[12] = 0x08; bytes[13] = 0x06; 0 }
            _                                                           => 6,
        };
        bytes[23] = proto_byte;

        if let Ok(octets) = parse_ip(&src) { bytes[26..30].copy_from_slice(&octets); }
        if let Ok(octets) = parse_ip(&dst) { bytes[30..34].copy_from_slice(&octets); }

        // ── Layer-4 header (bytes 34+) ────────────────────────────────────────
        match proto_byte {
            6 => {
                // TCP — ports at 34-37, flags at 47 (TCP hdr offset 13)
                if let Some(sp) = sport { let b = sp.to_be_bytes(); bytes[34]=b[0]; bytes[35]=b[1]; }
                if let Some(dp) = dport { let b = dp.to_be_bytes(); bytes[36]=b[0]; bytes[37]=b[1]; }
                // TCP data offset = 5 (20 bytes) at byte 46
                bytes[46] = 0x50;
                bytes[47] = parse_tcp_flags(l4_flags);
            }
            17 => {
                // UDP — ports at 34-37, length at 38-39
                if let Some(sp) = sport { let b = sp.to_be_bytes(); bytes[34]=b[0]; bytes[35]=b[1]; }
                if let Some(dp) = dport { let b = dp.to_be_bytes(); bytes[36]=b[0]; bytes[37]=b[1]; }
                let udp_len = (8u16 + payload.len() as u16).to_be_bytes();
                bytes[38] = udp_len[0]; bytes[39] = udp_len[1];
                // UDP has no flags field, but allow raw hex override of checksum bytes 40-41
                if !l4_flags.is_empty() {
                    if let Some(v) = parse_raw_u16(l4_flags) {
                        let b = v.to_be_bytes();
                        bytes[40] = b[0]; bytes[41] = b[1];
                    }
                }
            }
            1 => {
                // ICMP — type at 34, code at 35, checksum at 36-37
                let (itype, icode) = parse_icmp_type_code(l4_flags);
                bytes[34] = itype;
                bytes[35] = icode;
                // ICMP identifier at 38-39, sequence at 40-41 (echo)
                bytes[38] = 0x00; bytes[39] = 0x01;
                bytes[40] = 0x00; bytes[41] = 0x01;
            }
            _ => {}
        }

        // Copy payload after transport header (offset 42 for TCP/UDP, 38 for ICMP body)
        let payload_start = if proto_byte == 1 { 42 } else { 42 }.min(bytes.len());
        let payload_end = (payload_start + payload.len()).min(bytes.len());
        let copy_len = payload_end - payload_start;
        bytes[payload_start..payload_end].copy_from_slice(&payload[..copy_len]);

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        Ok(Packet {
            no:       counter,
            timestamp: ts,
            src,
            dst,
            protocol: proto.clone(),
            length:   bytes.len() as u16,
            info,
            bytes,
            src_port: sport,
            dst_port: dport,
            vlan_id:  None,
        })
    }

    /// Return the decoded IP flags and L4 flags bytes for the current field values,
    /// for use in the UI summary panel.
    pub fn decoded_flags(&self) -> (u8, u8) {
        let ip = parse_ip_flags(self.fields[F_IP_FL].value.trim());
        let proto = self.fields[F_PROTO].value.trim().to_uppercase();
        let l4_raw = self.fields[F_L4_FL].value.trim();
        let l4 = match proto.as_str() {
            "TCP" | "HTTP" | "HTTPS" | "TLS" | "FTP" | "SSH" | "SMTP" => parse_tcp_flags(l4_raw),
            _ => 0,
        };
        (ip, l4)
    }
}

// ─── Parsers ──────────────────────────────────────────────────────────────────

fn parse_port(s: &str) -> Option<u16> {
    s.trim().parse::<u16>().ok()
}

fn parse_ip(s: &str) -> Result<[u8; 4], String> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 { return Err(format!("invalid IP: {}", s)); }
    let mut out = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        out[i] = p.parse::<u8>().map_err(|_| format!("invalid IP octet: {}", p))?;
    }
    Ok(out)
}

/// Parse IPv4 flags field (upper byte of the 16-bit flags+frag-offset).
/// DF = bit 6 of byte = 0x40, MF = bit 5 = 0x20.
pub fn parse_ip_flags(s: &str) -> u8 {
    if s.is_empty() { return 0; }
    // hex literal
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u8::from_str_radix(hex, 16).unwrap_or(0);
    }
    // decimal
    if s.chars().all(|c| c.is_ascii_digit()) {
        return s.parse::<u8>().unwrap_or(0);
    }
    // symbolic: DF, MF, DF+MF
    let mut flags: u8 = 0;
    for tok in s.split('+') {
        flags |= match tok.trim().to_uppercase().as_str() {
            "DF" => 0x40,
            "MF" => 0x20,
            _    => 0,
        };
    }
    flags
}

/// Parse TCP flags byte from symbolic or hex input.
pub fn parse_tcp_flags(s: &str) -> u8 {
    if s.is_empty() { return 0x02; } // default SYN
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u8::from_str_radix(hex, 16).unwrap_or(0x02);
    }
    if s.chars().all(|c| c.is_ascii_digit()) {
        return s.parse::<u8>().unwrap_or(0x02);
    }
    let mut flags: u8 = 0;
    for tok in s.split('+') {
        flags |= match tok.trim().to_uppercase().as_str() {
            "FIN" => 0x01,
            "SYN" => 0x02,
            "RST" => 0x04,
            "PSH" => 0x08,
            "ACK" => 0x10,
            "URG" => 0x20,
            "ECE" => 0x40,
            "CWR" => 0x80,
            _     => 0,
        };
    }
    if flags == 0 { 0x02 } else { flags }
}

/// Parse ICMP type:code from strings like "8:0", "8", "echo-request", "echo-reply".
pub fn parse_icmp_type_code(s: &str) -> (u8, u8) {
    if s.is_empty() { return (8, 0); } // default echo-request
    match s.to_lowercase().as_str() {
        "echo-request" | "echo" | "ping" => return (8, 0),
        "echo-reply"                      => return (0, 0),
        "dest-unreachable" | "unreach"   => return (3, 0),
        "time-exceeded"    | "ttl"       => return (11, 0),
        "redirect"                        => return (5, 0),
        "timestamp"                       => return (13, 0),
        "timestamp-reply"                 => return (14, 0),
        _ => {}
    }
    // hex literal like "0x0800" → type=0x08, code=0x00
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        if hex.len() >= 4 {
            let t = u8::from_str_radix(&hex[..2], 16).unwrap_or(8);
            let c = u8::from_str_radix(&hex[2..4], 16).unwrap_or(0);
            return (t, c);
        }
    }
    // "type:code" or just "type"
    if let Some((t, c)) = s.split_once(':') {
        let t = t.trim().parse::<u8>().unwrap_or(8);
        let c = c.trim().parse::<u8>().unwrap_or(0);
        return (t, c);
    }
    let t = s.trim().parse::<u8>().unwrap_or(8);
    (t, 0)
}

/// Parse a raw u16 from decimal or hex (for UDP checksum override).
fn parse_raw_u16(s: &str) -> Option<u16> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u16::from_str_radix(hex, 16).ok();
    }
    s.parse::<u16>().ok()
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
