use crate::net::packet::Packet;
use crate::net::parser::parse_ethernet;
/// PCAP file replay — load a .pcap and feed packets into the capture pipeline.
use std::path::PathBuf;

pub struct ReplayState {
    pub path: String, // editable input
    pub speed: f64,   // replay speed multiplier (1.0 = real-time, 0 = instant)
    pub packets: Vec<Packet>,
    pub current: usize,
    pub running: bool,
    pub complete: bool,
    pub error: Option<String>,
    pub total: usize,
    /// Accumulated fractional ticks for sub-1-packet/tick speeds
    tick_accum: f64,
}

impl Default for ReplayState {
    fn default() -> Self {
        Self {
            path: String::new(),
            speed: 1.0,
            packets: Vec::new(),
            current: 0,
            running: false,
            complete: false,
            error: None,
            total: 0,
            tick_accum: 0.0,
        }
    }
}

impl ReplayState {
    /// Load a PCAP file. Returns true on success.
    pub fn load(&mut self) -> bool {
        self.packets.clear();
        self.current = 0;
        self.complete = false;
        self.running = false;
        self.error = None;

        let path = PathBuf::from(self.path.trim());
        if !path.exists() {
            self.error = Some(format!("File not found: {}", self.path.trim()));
            return false;
        }

        match read_pcap(&path) {
            Ok(pkts) => {
                self.total = pkts.len();
                self.packets = pkts;
                true
            }
            Err(e) => {
                self.error = Some(e);
                false
            }
        }
    }

    pub fn start(&mut self) {
        if self.packets.is_empty() {
            self.error = Some("Load a PCAP file first".into());
            return;
        }
        self.running = true;
        self.current = 0;
        self.complete = false;
        self.tick_accum = 0.0;
    }

    pub fn stop(&mut self) {
        self.running = false;
    }

    pub fn speed_up(&mut self) {
        self.speed = (self.speed * 2.0).min(64.0);
    }
    pub fn speed_down(&mut self) {
        self.speed = (self.speed / 2.0).max(0.125);
    }

    /// Called each app tick. Returns packets to inject (may be empty, may be many).
    pub fn tick(&mut self) -> Vec<Packet> {
        if !self.running || self.packets.is_empty() {
            return vec![];
        }

        // How many packets to emit this tick?
        // At speed=1.0 and 10 ticks/sec, emit proportional to original rate.
        // Simplified: emit ceil(speed) packets per tick, or skip ticks for speed<1.
        let emit_count = if self.speed >= 1.0 {
            self.speed.ceil() as usize
        } else {
            self.tick_accum += self.speed;
            if self.tick_accum >= 1.0 {
                self.tick_accum -= 1.0;
                1
            } else {
                0
            }
        };

        let mut out = Vec::new();
        for _ in 0..emit_count {
            if self.current >= self.packets.len() {
                self.running = false;
                self.complete = true;
                break;
            }
            out.push(self.packets[self.current].clone());
            self.current += 1;
        }
        out
    }

    pub fn progress_pct(&self) -> u8 {
        if self.total == 0 {
            return 0;
        }
        ((self.current * 100) / self.total) as u8
    }
}

/// Minimal classic-PCAP reader. PCAPNG and non-Ethernet link types are rejected.
pub fn read_pcap(path: &std::path::Path) -> Result<Vec<Packet>, String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).map_err(|e| e.to_string())?;

    if buf.len() < 24 {
        return Err("File too small to be a valid PCAP".into());
    }

    // Global header: magic(4), version_major(2), version_minor(2), thiszone(4),
    //               sigfigs(4), snaplen(4), network(4) = 24 bytes
    let (be, timestamp_divisor) = match &buf[..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] => (false, 1_000_000.0),
        [0xa1, 0xb2, 0xc3, 0xd4] => (true, 1_000_000.0),
        [0x4d, 0x3c, 0xb2, 0xa1] => (false, 1_000_000_000.0),
        [0xa1, 0xb2, 0x3c, 0x4d] => (true, 1_000_000_000.0),
        _ => return Err("Not a valid classic PCAP file (wrong magic number)".into()),
    };
    let read_u16 = |offset: usize| {
        let bytes = [buf[offset], buf[offset + 1]];
        if be {
            u16::from_be_bytes(bytes)
        } else {
            u16::from_le_bytes(bytes)
        }
    };
    let read_u32 = |offset: usize| {
        let bytes = [
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ];
        if be {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        }
    };
    if (read_u16(4), read_u16(6)) != (2, 4) {
        return Err("Unsupported PCAP version (expected 2.4)".into());
    }
    if read_u32(20) != 1 {
        return Err("Unsupported PCAP link type (only Ethernet is supported)".into());
    }

    let mut packets = Vec::new();
    let mut offset = 24usize;
    let mut counter = 1u64;
    while offset < buf.len() {
        if buf.len() - offset < 16 {
            return Err("Truncated PCAP packet header".into());
        }
        let ts_sec = read_u32(offset);
        let ts_fraction = read_u32(offset + 4);
        let incl_len = read_u32(offset + 8) as usize;
        let _orig_len = read_u32(offset + 12);
        offset += 16;

        if incl_len == 0 || incl_len > usize::from(u16::MAX) {
            return Err("PCAP packet length is invalid or unsupported".into());
        }
        let end = offset
            .checked_add(incl_len)
            .ok_or("PCAP packet length overflow")?;
        if end > buf.len() {
            return Err("Truncated PCAP packet payload".into());
        }
        let raw = &buf[offset..end];
        offset = end;

        let timestamp = ts_sec as f64 + ts_fraction as f64 / timestamp_divisor;
        let pkt = parse_ethernet(raw, counter, timestamp);
        packets.push(pkt);
        counter += 1;

        if packets.len() >= 100_000 {
            break;
        } // safety cap
    }

    if packets.is_empty() {
        Err("No packets found in PCAP".into())
    } else {
        Ok(packets)
    }
}
