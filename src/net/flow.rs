//! TCP/UDP flow tracker — RITA-style beacon scoring, JA3/HASSH, directionality, credentials.
use std::collections::{HashMap, HashSet, VecDeque};
use crate::net::packet::Packet;

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub struct FlowKey {
    pub ep1:     (String, u16),
    pub ep2:     (String, u16),
    pub proto:   String,
    /// VLAN scope: flows on different VLANs are distinct even if IP+port match.
    pub vlan_id: Option<u16>,
}

impl FlowKey {
    pub fn from_packet(pkt: &Packet) -> Self {
        let a = (pkt.src.clone(), pkt.src_port.unwrap_or(0));
        let b = (pkt.dst.clone(), pkt.dst_port.unwrap_or(0));
        let (ep1, ep2) = if a <= b { (a, b) } else { (b, a) };
        Self { ep1, ep2, proto: pkt.protocol.clone(), vlan_id: pkt.vlan_id }
    }
}

#[derive(Default, Clone)]
pub struct FlowFlags {
    pub beacon:      bool,
    pub large:       bool,
    pub encrypted:   bool,
    pub scan:        bool,
    pub long_conn:   bool,   // duration > 5 minutes
    pub strobe:      bool,   // same pair > 100 pkts/s
    #[allow(dead_code)]
    pub dns_tunnel:  bool,
    pub tcp_anomaly: bool,   // XMAS / NULL / SYN+FIN
}

pub struct Flow {
    pub key:          FlowKey,
    pub packets:      u64,
    pub bytes:        u64,
    pub bytes_in:     u64,   // toward ep1
    pub bytes_out:    u64,   // from ep1
    pub first_seen:   f64,
    pub last_seen:    f64,
    pub flags:        FlowFlags,
    pub beacon_score: f64,   // 0.0–1.0 composite (RITA-style)
    pub throughput:   f64,   // bytes/sec
    pub initiator:    String, // IP that sent first packet
    pub ja3:          Option<String>, // MD5 hex
    pub ja3s:         Option<String>,
    pub hassh:        Option<String>,
    // internal tracking
    last_ts:          f64,
    pub intervals:    VecDeque<f64>,
    pkt_sizes:        VecDeque<u16>,  // for data-size stddev
    strobe_window:    VecDeque<f64>,  // timestamps last 1s
}

#[derive(Clone, PartialEq)]
pub enum FlowSort { Bytes, Packets, Time, BeaconScore }

pub struct FlowTracker {
    pub flows:    HashMap<FlowKey, Flow>,
    scan_seen:    HashMap<String, HashSet<(String, u16)>>,
    syn_seen:     HashMap<String, VecDeque<f64>>,  // for SYN-flood detection
}

impl FlowTracker {
    pub fn new() -> Self {
        Self {
            flows: HashMap::new(),
            scan_seen: HashMap::new(),
            syn_seen: HashMap::new(),
        }
    }

    pub fn update(&mut self, pkt: &Packet) {
        use crate::net::inspector::shannon_entropy;
        let key = FlowKey::from_packet(pkt);

        // Initiator = first src we see for this flow
        let initiator = {
            if let Some(existing) = self.flows.get(&key) {
                existing.initiator.clone()
            } else {
                pkt.src.clone()
            }
        };

        let flow = self.flows.entry(key.clone()).or_insert_with(|| Flow {
            key: key.clone(),
            packets: 0, bytes: 0, bytes_in: 0, bytes_out: 0,
            first_seen: pkt.timestamp, last_seen: pkt.timestamp,
            flags: FlowFlags::default(),
            beacon_score: 0.0, throughput: 0.0,
            initiator: initiator.clone(),
            ja3: None, ja3s: None, hassh: None,
            last_ts: pkt.timestamp,
            intervals: VecDeque::new(),
            pkt_sizes: VecDeque::new(),
            strobe_window: VecDeque::new(),
        });

        // Directional bytes
        if pkt.src == flow.initiator {
            flow.bytes_out += pkt.length as u64;
        } else {
            flow.bytes_in += pkt.length as u64;
        }

        // Interval tracking for beacon detection
        let interval = pkt.timestamp - flow.last_ts;
        if interval > 0.001 && flow.last_ts > 0.0 {
            if flow.intervals.len() >= 60 { flow.intervals.pop_front(); }
            flow.intervals.push_back(interval);
        }
        flow.last_ts = pkt.timestamp;

        // Packet size history for data-size consistency
        if flow.pkt_sizes.len() >= 60 { flow.pkt_sizes.pop_front(); }
        flow.pkt_sizes.push_back(pkt.length);

        // Strobe detection: count packets in last 1s
        flow.strobe_window.push_back(pkt.timestamp);
        let cutoff = pkt.timestamp - 1.0;
        while flow.strobe_window.front().map(|&t| t < cutoff).unwrap_or(false) {
            flow.strobe_window.pop_front();
        }
        flow.flags.strobe = flow.strobe_window.len() > 100;

        flow.packets += 1;
        flow.bytes += pkt.length as u64;
        flow.last_seen = pkt.timestamp;

        // Derived flags
        flow.flags.large     = flow.bytes > 1_000_000;
        flow.flags.long_conn = (flow.last_seen - flow.first_seen) > 300.0; // 5 min
        if pkt.bytes.len() > 20 {
            flow.flags.encrypted = shannon_entropy(&pkt.bytes) > 7.2;
        }

        // Composite RITA-style beacon score
        flow.beacon_score = compute_beacon_score(flow);
        flow.flags.beacon = flow.beacon_score > 0.7;

        // Throughput
        let dur = (flow.last_seen - flow.first_seen).max(0.001);
        flow.throughput = flow.bytes as f64 / dur;

        // JA3 / HASSH fingerprinting
        if flow.ja3.is_none() && (pkt.protocol == "TLS" || pkt.protocol == "HTTPS") {
            if let Some(ja3) = extract_ja3(&pkt.bytes) {
                flow.ja3 = Some(ja3);
            }
        }
        if flow.ja3s.is_none() && (pkt.protocol == "TLS" || pkt.protocol == "HTTPS") {
            if let Some(ja3s) = extract_ja3s(&pkt.bytes) {
                flow.ja3s = Some(ja3s);
            }
        }
        if flow.hassh.is_none() && pkt.protocol == "SSH" {
            if let Some(hassh) = extract_hassh(&pkt.bytes) {
                flow.hassh = Some(hassh);
            }
        }

        // Scan detection
        let dst_entry = self.scan_seen.entry(pkt.src.clone()).or_default();
        dst_entry.insert((pkt.dst.clone(), pkt.dst_port.unwrap_or(0)));
        if dst_entry.len() >= 5 {
            for f in self.flows.values_mut() {
                if f.key.ep1.0 == pkt.src || f.key.ep2.0 == pkt.src {
                    f.flags.scan = true;
                }
            }
        }

        // SYN flood: >50 SYNs from same src in 1s window
        if pkt.protocol == "TCP" {
            // Check for SYN flag (byte 13 of TCP header, bit 1)
            if pkt.bytes.len() >= 34 && pkt.bytes[33] & 0x02 != 0 && pkt.bytes[33] & 0xFC == 0 {
                let syn_w = self.syn_seen.entry(pkt.src.clone()).or_default();
                syn_w.push_back(pkt.timestamp);
                let cutoff2 = pkt.timestamp - 1.0;
                while syn_w.front().map(|&t| t < cutoff2).unwrap_or(false) { syn_w.pop_front(); }
                if syn_w.len() > 50 {
                    if let Some(f) = self.flows.get_mut(&key) {
                        f.flags.tcp_anomaly = true;
                    }
                }
            }
        }
    }

    pub fn sorted_flows(&self, sort: &FlowSort) -> Vec<&Flow> {
        let mut v: Vec<&Flow> = self.flows.values().collect();
        match sort {
            FlowSort::Bytes       => v.sort_by(|a, b| b.bytes.cmp(&a.bytes)),
            FlowSort::Packets     => v.sort_by(|a, b| b.packets.cmp(&a.packets)),
            FlowSort::Time        => v.sort_by(|a, b| b.first_seen.partial_cmp(&a.first_seen).unwrap_or(std::cmp::Ordering::Equal)),
            FlowSort::BeaconScore => v.sort_by(|a, b| b.beacon_score.partial_cmp(&a.beacon_score).unwrap_or(std::cmp::Ordering::Equal)),
        }
        v
    }

    pub fn clear(&mut self) {
        self.flows.clear();
        self.scan_seen.clear();
        self.syn_seen.clear();
    }
}

// ── RITA-style composite beacon score ────────────────────────────────────────

fn compute_beacon_score(flow: &Flow) -> f64 {
    let n = flow.intervals.len();
    if n < 5 { return 0.0; }

    // Sub-score 1: Interval regularity (CV of inter-arrival times)
    let mean_i = flow.intervals.iter().sum::<f64>() / n as f64;
    if mean_i < 0.5 { return 0.0; } // Too fast — not a slow beacon
    let var_i = flow.intervals.iter().map(|x| (x - mean_i).powi(2)).sum::<f64>() / n as f64;
    let cv = var_i.sqrt() / mean_i;
    let score_interval = 1.0 - cv.min(1.0); // low CV → high score

    // Sub-score 2: Data size consistency (CV of packet sizes)
    let score_size = if flow.pkt_sizes.len() >= 5 {
        let ns = flow.pkt_sizes.len() as f64;
        let mean_s = flow.pkt_sizes.iter().map(|&x| x as f64).sum::<f64>() / ns;
        let var_s = flow.pkt_sizes.iter().map(|&x| (x as f64 - mean_s).powi(2)).sum::<f64>() / ns;
        let cv_s = if mean_s > 0.0 { var_s.sqrt() / mean_s } else { 1.0 };
        1.0 - cv_s.min(1.0)
    } else { 0.5 };

    // Sub-score 3: Duration persistence (fraction of observation window active)
    let duration = flow.last_seen - flow.first_seen;
    let score_persist = (duration / 60.0).min(1.0); // capped at 60s for full score

    // Composite: weighted average (interval is the strongest signal)
    let score = score_interval * 0.5 + score_size * 0.3 + score_persist * 0.2;
    score.clamp(0.0, 1.0)
}

// ── JA3 fingerprinting ────────────────────────────────────────────────────────

fn extract_ja3(raw: &[u8]) -> Option<String> {
    // Look for TLS ClientHello signature in the raw packet bytes
    // TLS record: ContentType=22 (0x16), Version (2 bytes), Length (2 bytes)
    // Handshake: HandshakeType=1 (ClientHello)
    let pos = raw.windows(6).position(|w| {
        w[0] == 0x16 && w[1] == 0x03 && w[5] == 0x01
    })?;

    // TLS record header: 5 bytes
    // Handshake header: 4 bytes (type + 3-byte length)
    // Client Version: 2 bytes
    // Random: 32 bytes
    let hs_start = pos + 5;
    if raw.len() < hs_start + 4 + 2 + 32 + 1 { return None; }

    let version_offset = hs_start + 4;
    if raw.len() < version_offset + 2 { return None; }
    let version = u16::from_be_bytes([raw[version_offset], raw[version_offset + 1]]);

    // Session ID length
    let sid_len_offset = version_offset + 2 + 32;
    if raw.len() < sid_len_offset + 1 { return None; }
    let sid_len = raw[sid_len_offset] as usize;

    // Cipher suites
    let cs_len_offset = sid_len_offset + 1 + sid_len;
    if raw.len() < cs_len_offset + 2 { return None; }
    let cs_len = u16::from_be_bytes([raw[cs_len_offset], raw[cs_len_offset + 1]]) as usize;
    if raw.len() < cs_len_offset + 2 + cs_len { return None; }
    let cs_bytes = &raw[cs_len_offset + 2..cs_len_offset + 2 + cs_len];
    let ciphers: Vec<String> = cs_bytes.chunks(2)
        .filter_map(|c| {
            if c.len() < 2 { return None; }
            let v = u16::from_be_bytes([c[0], c[1]]);
            // Exclude GREASE values (0xXaXa pattern)
            if v & 0x0f0f == 0x0a0a { None } else { Some(v.to_string()) }
        })
        .collect();

    // Skip compression methods
    let cm_len_offset = cs_len_offset + 2 + cs_len;
    if raw.len() < cm_len_offset + 1 { return None; }
    let cm_len = raw[cm_len_offset] as usize;

    // Extensions
    let ext_len_offset = cm_len_offset + 1 + cm_len;
    if raw.len() < ext_len_offset + 2 { return None; }
    let ext_total = u16::from_be_bytes([raw[ext_len_offset], raw[ext_len_offset + 1]]) as usize;
    let ext_data = &raw[ext_len_offset + 2..];
    if ext_data.len() < ext_total { return None; }

    let mut ext_types = Vec::new();
    let mut curves = Vec::new();
    let mut point_formats = Vec::new();
    let mut i = 0;
    while i + 4 <= ext_total.min(ext_data.len()) {
        let ext_type = u16::from_be_bytes([ext_data[i], ext_data[i + 1]]);
        let ext_len = u16::from_be_bytes([ext_data[i + 2], ext_data[i + 3]]) as usize;
        // Exclude GREASE
        if ext_type & 0x0f0f != 0x0a0a {
            ext_types.push(ext_type.to_string());
        }
        let ext_body = &ext_data[i + 4..];
        if ext_body.len() < ext_len { break; }
        let body = &ext_body[..ext_len];

        // Supported groups (0x000a)
        if ext_type == 0x000a && body.len() >= 2 {
            let list_len = u16::from_be_bytes([body[0], body[1]]) as usize;
            let list = &body[2..];
            let mut j = 0;
            while j + 2 <= list_len.min(list.len()) {
                let g = u16::from_be_bytes([list[j], list[j + 1]]);
                if g & 0x0f0f != 0x0a0a { curves.push(g.to_string()); }
                j += 2;
            }
        }
        // EC point formats (0x000b)
        if ext_type == 0x000b && !body.is_empty() {
            let pf_len = body[0] as usize;
            for k in 0..pf_len.min(body.len().saturating_sub(1)) {
                point_formats.push(body[1 + k].to_string());
            }
        }
        i += 4 + ext_len;
    }

    let ja3_str = format!("{},{},{},{},{}",
        version,
        ciphers.join("-"),
        ext_types.join("-"),
        curves.join("-"),
        point_formats.join("-"),
    );
    Some(format!("{:x}", md5::compute(ja3_str.as_bytes())))
}

fn extract_ja3s(raw: &[u8]) -> Option<String> {
    // TLS ServerHello: ContentType=22, HandshakeType=2
    let pos = raw.windows(6).position(|w| {
        w[0] == 0x16 && w[1] == 0x03 && w[5] == 0x02
    })?;
    let hs_start = pos + 5;
    if raw.len() < hs_start + 4 + 2 { return None; }
    let version_offset = hs_start + 4;
    let version = u16::from_be_bytes([raw[version_offset], raw[version_offset + 1]]);

    // Random (32) + session id len (1)
    let sid_len_offset = version_offset + 2 + 32;
    if raw.len() < sid_len_offset + 1 { return None; }
    let sid_len = raw[sid_len_offset] as usize;

    let cs_offset = sid_len_offset + 1 + sid_len;
    if raw.len() < cs_offset + 2 { return None; }
    let cipher = u16::from_be_bytes([raw[cs_offset], raw[cs_offset + 1]]);

    // Skip compression
    let cm_offset = cs_offset + 3;
    if raw.len() < cm_offset + 2 { return None; }
    let ext_total = u16::from_be_bytes([raw[cm_offset], raw[cm_offset + 1]]) as usize;
    let ext_data = &raw[cm_offset + 2..];

    let mut ext_types = Vec::new();
    let mut i = 0;
    while i + 4 <= ext_total.min(ext_data.len()) {
        let ext_type = u16::from_be_bytes([ext_data[i], ext_data[i + 1]]);
        let ext_len = u16::from_be_bytes([ext_data[i + 2], ext_data[i + 3]]) as usize;
        if ext_type & 0x0f0f != 0x0a0a { ext_types.push(ext_type.to_string()); }
        i += 4 + ext_len;
    }

    let ja3s_str = format!("{},{},{}", version, cipher, ext_types.join("-"));
    Some(format!("{:x}", md5::compute(ja3s_str.as_bytes())))
}

fn extract_hassh(raw: &[u8]) -> Option<String> {
    // SSH KEX Init: starts with 0x14 (SSH_MSG_KEXINIT) after the SSH header
    let pos = raw.iter().position(|&b| b == 0x14)?;
    // KEXINIT: 16 bytes cookie + lists
    let body = &raw[pos + 1..]; // skip message type byte
    if body.len() < 16 { return None; } // need at least cookie
    let data = &body[16..]; // skip cookie

    // Read a name-list: 4-byte length + string
    let read_list = |buf: &[u8]| -> Option<(String, usize)> {
        if buf.len() < 4 { return None; }
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if buf.len() < 4 + len { return None; }
        let s = std::str::from_utf8(&buf[4..4 + len]).ok()?.to_string();
        Some((s, 4 + len))
    };

    let mut off = 0;
    let mut lists = Vec::new();
    for _ in 0..10 {
        if let Some((s, n)) = read_list(&data[off..]) {
            lists.push(s);
            off += n;
        } else { break; }
    }
    if lists.len() < 7 { return None; }

    // HASSH = MD5(kex_algs;enc_algs_c2s;mac_algs_c2s;comp_algs_c2s)
    let hassh_str = format!("{};{};{};{}", lists[0], lists[2], lists[4], lists[6].chars().take(100).collect::<String>());
    Some(format!("{:x}", md5::compute(hassh_str.as_bytes())))
}
