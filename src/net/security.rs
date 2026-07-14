//! Passive security analysis engine — IDS signatures, ARP anomaly, OS fingerprinting,
//! vulnerability patterns, brute-force detection, HTTP analytics, TLS/SSL weakness,
//! and DNS exfiltration scoring.

use std::collections::{HashMap, HashSet};
use crate::net::packet::Packet;
use crate::net::inspector::shannon_entropy;

// ─── Byte helpers ─────────────────────────────────────────────────────────────

#[inline]
fn byte_at(b: &[u8], off: usize) -> u8 { b.get(off).copied().unwrap_or(0) }

#[inline]
fn u16_be_at(b: &[u8], off: usize) -> u16 {
    if b.len() >= off + 2 { u16::from_be_bytes([b[off], b[off + 1]]) } else { 0 }
}

const MAX_ENTRIES: usize = 1000;
const MAX_FRAGMENT_DATAGRAMS: usize = 512;
const MAX_FRAGMENTS_PER_DATAGRAM: usize = 64;
const FRAGMENT_STATE_TTL_SECS: f64 = 60.0;
const MAX_TCP_FLOWS: usize = 512;
const MAX_TCP_SLICES_PER_DIRECTION: usize = 128;
const TCP_STATE_TTL_SECS: f64 = 300.0;
const SCAN_WINDOW_SECS: f64 = 15.0;
const SYN_FLOOD_WINDOW_SECS: f64 = 1.0;
const SCAN_UNIQUE_THRESHOLD: usize = 12;
const SYN_FLOOD_THRESHOLD: usize = 100;
const MAX_SCAN_STATES: usize = 512;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct FragmentKey {
    src: [u8; 4],
    dst: [u8; 4],
    identification: u16,
    protocol: u8,
}

#[derive(Debug, Clone)]
struct FragmentSlice {
    start: u32,
    data: Vec<u8>,
}

#[derive(Debug, Default)]
struct FragmentState {
    slices: Vec<FragmentSlice>,
    count: usize,
    last_seen: f64,
    overlap_alerted: bool,
    flood_alerted: bool,
}

struct Ipv4Fragment<'a> {
    key: FragmentKey,
    offset: u32,
    more_fragments: bool,
    payload: &'a [u8],
    declared_payload_len: usize,
    malformed_length: bool,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct TcpFlowKey {
    endpoint_a: ([u8; 4], u16),
    endpoint_b: ([u8; 4], u16),
}

#[derive(Debug, Default)]
struct TcpIntegrityState {
    from_a: Vec<FragmentSlice>,
    from_b: Vec<FragmentSlice>,
    last_seen: f64,
    reset_seen: bool,
    overlap_alerted: bool,
    post_reset_alerted: bool,
}

struct TcpSegment<'a> {
    key: TcpFlowKey,
    from_a: bool,
    sequence: u32,
    flags: u8,
    payload: &'a [u8],
}

enum TcpFrame<'a> {
    Malformed(&'static str),
    Segment(TcpSegment<'a>),
}

#[derive(Debug)]
struct ScanProbe {
    timestamp: f64,
    destination: String,
    port: u16,
}

#[derive(Debug, Default)]
struct SourceScanState {
    probes: Vec<ScanProbe>,
    icmp_targets: Vec<(f64, String)>,
    vertical_alerted: HashSet<String>,
    horizontal_alerted: HashSet<u16>,
    icmp_alerted: bool,
    last_seen: f64,
}

#[derive(Debug, Default)]
struct SynFloodState {
    timestamps: Vec<f64>,
    alerted: bool,
    last_seen: f64,
}

// ─── IDS Alerts ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct IdsAlert {
    pub pkt_no: u64,
    pub signature: &'static str,
    pub severity: Severity,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

// ─── ARP Anomaly ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ArpAnomaly {
    pub pkt_no: u64,
    pub ip: String,
    pub old_mac: String,
    pub new_mac: String,
}

// ─── OS Fingerprint ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct OsGuess {
    pub src_ip: String,
    pub os: &'static str,
    pub ttl: u8,
    pub window: u16,
}

// ─── Vulnerability Hit ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct VulnHit {
    pub pkt_no: u64,
    pub kind: &'static str,
    pub detail: String,
}

// ─── Brute Force Alert ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BruteForceAlert {
    pub src_ip: String,
    pub dst_ip: String,
    pub port: u16,
    pub attempts: usize,
    pub service: &'static str,
}

/// Internal tracking key for brute force attempts
#[derive(Hash, Eq, PartialEq, Clone)]
struct BfKey {
    src: String,
    dst: String,
    port: u16,
}

struct BfWindow {
    timestamps: Vec<f64>,
    service: &'static str,
    alerted: bool,
}

// ─── HTTP Record ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct HttpRecord {
    pub pkt_no: u64,
    pub src_ip: String,
    pub dst_ip: String,
    pub port: u16,
    pub method: String,
    pub path: String,
    pub user_agent: String,
    pub response_code: Option<u16>,
}

// ─── TLS Weakness ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TlsWeakness {
    pub pkt_no: u64,
    pub src_ip: String,
    pub dst_ip: String,
    pub kind: &'static str,
    pub detail: String,
}

// ─── DNS Tunnel Suspect ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DnsTunnelSuspect {
    pub apex: String,
    pub query_count: u64,
    pub max_entropy: f64,
    pub max_subdomain_len: usize,
    pub unique_subdomains: usize,
    pub score: f64,
}

/// Internal accumulator per apex domain
struct DnsAccum {
    queries: u64,
    max_entropy: f64,
    max_len: usize,
    unique_subs: std::collections::HashSet<String>,
}

// ─── Summary ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct SecuritySummary {
    pub ids_alerts: usize,
    pub arp_anomalies: usize,
    pub os_guesses: usize,
    pub vuln_hits: usize,
    pub brute_force: usize,
    pub http_records: usize,
    pub tls_weaknesses: usize,
    pub dns_suspects: usize,
    pub cred_hits: usize,
}

// ─── Security Engine ──────────────────────────────────────────────────────────

pub struct SecurityEngine {
    // Results
    pub ids_alerts: Vec<IdsAlert>,
    pub arp_anomalies: Vec<ArpAnomaly>,
    pub os_guesses: Vec<OsGuess>,
    pub vuln_hits: Vec<VulnHit>,
    pub brute_force: Vec<BruteForceAlert>,
    pub http_records: Vec<HttpRecord>,
    pub tls_weaknesses: Vec<TlsWeakness>,
    pub dns_suspects: Vec<DnsTunnelSuspect>,

    // Internal state
    ip_to_mac: HashMap<String, String>,
    os_by_ip: HashMap<String, &'static str>,
    bf_windows: HashMap<BfKey, BfWindow>,
    dns_accum: HashMap<String, DnsAccum>,
    fragment_states: HashMap<FragmentKey, FragmentState>,
    tcp_integrity: HashMap<TcpFlowKey, TcpIntegrityState>,
    scan_sources: HashMap<String, SourceScanState>,
    syn_flood_targets: HashMap<(String, u16), SynFloodState>,
    // External credential count (set by caller)
    pub cred_hit_count: usize,
}

impl SecurityEngine {
    pub fn new() -> Self {
        Self {
            ids_alerts: Vec::new(),
            arp_anomalies: Vec::new(),
            os_guesses: Vec::new(),
            vuln_hits: Vec::new(),
            brute_force: Vec::new(),
            http_records: Vec::new(),
            tls_weaknesses: Vec::new(),
            dns_suspects: Vec::new(),
            ip_to_mac: HashMap::new(),
            os_by_ip: HashMap::new(),
            bf_windows: HashMap::new(),
            dns_accum: HashMap::new(),
            fragment_states: HashMap::new(),
            tcp_integrity: HashMap::new(),
            scan_sources: HashMap::new(),
            syn_flood_targets: HashMap::new(),
            cred_hit_count: 0,
        }
    }

    pub fn clear(&mut self) {
        self.ids_alerts.clear();
        self.arp_anomalies.clear();
        self.os_guesses.clear();
        self.vuln_hits.clear();
        self.brute_force.clear();
        self.http_records.clear();
        self.tls_weaknesses.clear();
        self.dns_suspects.clear();
        self.ip_to_mac.clear();
        self.os_by_ip.clear();
        self.bf_windows.clear();
        self.dns_accum.clear();
        self.fragment_states.clear();
        self.tcp_integrity.clear();
        self.scan_sources.clear();
        self.syn_flood_targets.clear();
        self.cred_hit_count = 0;
    }

    /// Look up the OS guess for a given IP (if fingerprinted).
    pub fn os_guess_for(&self, ip: &str) -> Option<&'static str> {
        self.os_by_ip.get(ip).copied()
    }

    pub fn alert_count(&self) -> usize {
        self.ids_alerts.len()
            + self.arp_anomalies.len()
            + self.vuln_hits.len()
            + self.brute_force.len()
            + self.tls_weaknesses.len()
    }

    pub fn summary(&self) -> SecuritySummary {
        // Count flagged DNS suspects (score > 8)
        let dns_suspects = self.dns_suspects.iter().filter(|d| d.score > 8.0).count();
        SecuritySummary {
            ids_alerts: self.ids_alerts.len(),
            arp_anomalies: self.arp_anomalies.len(),
            os_guesses: self.os_by_ip.len(),
            vuln_hits: self.vuln_hits.len(),
            brute_force: self.brute_force.len(),
            http_records: self.http_records.len(),
            tls_weaknesses: self.tls_weaknesses.len(),
            dns_suspects,
            cred_hits: self.cred_hit_count,
        }
    }

    /// Process a single packet through all detection engines.
    pub fn update(&mut self, pkt: &Packet) {
        self.check_ipv4_fragments(pkt);
        self.check_tcp_integrity(pkt);
        self.check_scan_activity(pkt);
        self.check_ids(pkt);
        self.check_arp(pkt);
        self.check_os_fingerprint(pkt);
        self.check_vuln(pkt);
        self.check_brute_force(pkt);
        self.check_http(pkt);
        self.check_tls(pkt);
        self.check_dns_tunnel(pkt);
    }

    // ─── IDS Signatures ──────────────────────────────────────────────────────

    fn push_ids(&mut self, alert: IdsAlert) {
        if self.ids_alerts.len() >= MAX_ENTRIES {
            self.ids_alerts.remove(0);
        }
        self.ids_alerts.push(alert);
    }

    // ─── IPv4 Fragment Integrity ────────────────────────────────────────────

    fn check_ipv4_fragments(&mut self, pkt: &Packet) {
        let fragment = match parse_ipv4_fragment(&pkt.bytes) {
            Some(fragment) => fragment,
            None => return,
        };

        self.fragment_states.retain(|_, state| {
            pkt.timestamp < state.last_seen || pkt.timestamp - state.last_seen <= FRAGMENT_STATE_TTL_SECS
        });
        if !self.fragment_states.contains_key(&fragment.key)
            && self.fragment_states.len() >= MAX_FRAGMENT_DATAGRAMS
        {
            if let Some(oldest) = self.fragment_states.iter()
                .min_by(|left, right| left.1.last_seen.total_cmp(&right.1.last_seen))
                .map(|(key, _)| key.clone())
            {
                self.fragment_states.remove(&oldest);
            }
        }

        let mut alerts = Vec::new();
        if fragment.malformed_length {
            alerts.push((
                "Malformed IPv4 fragment",
                Severity::High,
                format!("IPv4 fragment has a total length smaller than its header from {}", pkt.src),
            ));
        }
        if fragment.more_fragments && fragment.declared_payload_len < 8 {
            alerts.push((
                "Tiny IPv4 fragment",
                Severity::High,
                format!("IPv4 fragment payload is {} bytes from {}", fragment.declared_payload_len, pkt.src),
            ));
        }

        let state = self.fragment_states.entry(fragment.key.clone()).or_default();
        state.last_seen = pkt.timestamp;
        state.count += 1;

        if !state.overlap_alerted && has_conflicting_fragment_overlap(&state.slices, &fragment) {
            state.overlap_alerted = true;
            alerts.push((
                "Conflicting IPv4 fragments",
                Severity::Critical,
                format!("Overlapping IPv4 fragments carry different bytes from {} to {}", pkt.src, pkt.dst),
            ));
        }

        if !fragment.payload.is_empty() {
            state.slices.push(FragmentSlice {
                start: fragment.offset,
                data: fragment.payload.to_vec(),
            });
        }

        if state.count > MAX_FRAGMENTS_PER_DATAGRAM && !state.flood_alerted {
            state.flood_alerted = true;
            alerts.push((
                "IPv4 fragment flood",
                Severity::High,
                format!("More than {MAX_FRAGMENTS_PER_DATAGRAM} fragments for one datagram from {}", pkt.src),
            ));
        }

        for (signature, severity, detail) in alerts {
            self.push_ids(IdsAlert { pkt_no: pkt.no, signature, severity, detail });
        }
    }

    // ─── TCP Integrity / Evasion ────────────────────────────────────────────

    fn check_tcp_integrity(&mut self, pkt: &Packet) {
        let segment = match parse_ipv4_tcp_frame(&pkt.bytes) {
            Some(TcpFrame::Segment(segment)) => segment,
            Some(TcpFrame::Malformed(reason)) => {
                self.push_ids(IdsAlert {
                    pkt_no: pkt.no,
                    signature: "Malformed TCP header",
                    severity: Severity::High,
                    detail: format!("{reason} from {} to {}", pkt.src, pkt.dst),
                });
                return;
            }
            None => return,
        };

        const FIN: u8 = 0x01;
        const SYN: u8 = 0x02;
        const RST: u8 = 0x04;
        if segment.flags & SYN != 0 && segment.flags & (FIN | RST) != 0 {
            self.push_ids(IdsAlert {
                pkt_no: pkt.no,
                signature: "Illegal TCP flag combination",
                severity: Severity::High,
                detail: format!("TCP SYN combined with FIN or RST from {} to {}", pkt.src, pkt.dst),
            });
        }

        self.tcp_integrity.retain(|_, state| {
            pkt.timestamp < state.last_seen || pkt.timestamp - state.last_seen <= TCP_STATE_TTL_SECS
        });
        if !self.tcp_integrity.contains_key(&segment.key) && self.tcp_integrity.len() >= MAX_TCP_FLOWS {
            if let Some(oldest) = self.tcp_integrity.iter()
                .min_by(|left, right| left.1.last_seen.total_cmp(&right.1.last_seen))
                .map(|(key, _)| key.clone())
            {
                self.tcp_integrity.remove(&oldest);
            }
        }

        let mut alerts = Vec::new();
        let state = self.tcp_integrity.entry(segment.key.clone()).or_default();
        state.last_seen = pkt.timestamp;

        if segment.flags & SYN != 0 {
            state.from_a.clear();
            state.from_b.clear();
            state.reset_seen = false;
            state.overlap_alerted = false;
            state.post_reset_alerted = false;
        }

        if state.reset_seen && !segment.payload.is_empty() && !state.post_reset_alerted {
            state.post_reset_alerted = true;
            alerts.push((
                "TCP payload after reset",
                Severity::High,
                format!("Payload continued after an observed TCP reset from {} to {}", pkt.src, pkt.dst),
            ));
        }

        let slices = if segment.from_a { &mut state.from_a } else { &mut state.from_b };
        if !segment.payload.is_empty() {
            if !state.overlap_alerted && has_conflicting_tcp_overlap(slices, &segment) {
                state.overlap_alerted = true;
                alerts.push((
                    "Conflicting TCP retransmission",
                    Severity::Critical,
                    format!("Overlapping TCP sequence ranges contain different bytes from {} to {}", pkt.src, pkt.dst),
                ));
            }
            if slices.len() < MAX_TCP_SLICES_PER_DIRECTION {
                slices.push(FragmentSlice { start: segment.sequence, data: segment.payload.to_vec() });
            }
        }

        if segment.flags & RST != 0 {
            state.reset_seen = true;
        }

        for (signature, severity, detail) in alerts {
            self.push_ids(IdsAlert { pkt_no: pkt.no, signature, severity, detail });
        }
    }

    // ─── Scan and Flood Correlation ─────────────────────────────────────────

    fn check_scan_activity(&mut self, pkt: &Packet) {
        self.scan_sources.retain(|_, state| {
            pkt.timestamp < state.last_seen || pkt.timestamp - state.last_seen <= SCAN_WINDOW_SECS
        });
        self.syn_flood_targets.retain(|_, state| {
            pkt.timestamp < state.last_seen || pkt.timestamp - state.last_seen <= SYN_FLOOD_WINDOW_SECS
        });
        evict_oldest_scan_source(&mut self.scan_sources);
        evict_oldest_syn_target(&mut self.syn_flood_targets);

        let tcp_flags = match parse_ipv4_tcp_frame(&pkt.bytes) {
            Some(TcpFrame::Segment(segment)) => Some(segment.flags),
            _ => None,
        };
        let mut alerts = Vec::new();

        if let Some(flags) = tcp_flags {
            const FIN: u8 = 0x01;
            const SYN: u8 = 0x02;
            const RST: u8 = 0x04;
            const PSH: u8 = 0x08;
            const ACK: u8 = 0x10;
            const URG: u8 = 0x20;
            let control = flags & (FIN | SYN | RST | PSH | ACK | URG);
            let stealth_kind = if control == 0 {
                Some("NULL")
            } else if control == FIN {
                Some("FIN")
            } else if control & (FIN | PSH | URG) == (FIN | PSH | URG) && control & (SYN | ACK | RST) == 0 {
                Some("Xmas")
            } else {
                None
            };
            if let Some(kind) = stealth_kind {
                alerts.push((
                    "TCP stealth scan probe",
                    Severity::Medium,
                    format!("{kind} probe from {} to {}:{}", pkt.src, pkt.dst, pkt.dst_port.unwrap_or(0)),
                ));
            }

            if flags & SYN != 0 && flags & ACK == 0 {
                let port = pkt.dst_port.unwrap_or(0);
                self.record_scan_probe(pkt, port, &mut alerts);
                self.record_syn_flood(pkt, port, &mut alerts);
            }
        } else if is_empty_ipv4_udp_probe(&pkt.bytes) {
            if let Some(port) = pkt.dst_port {
                self.record_scan_probe(pkt, port, &mut alerts);
            }
        }

        if pkt.protocol.eq_ignore_ascii_case("ICMP")
            && pkt.info.to_ascii_lowercase().contains("echo request")
        {
            let state = self.scan_sources.entry(pkt.src.clone()).or_default();
            state.last_seen = pkt.timestamp;
            state.icmp_targets.retain(|(timestamp, _)| {
                pkt.timestamp < *timestamp || pkt.timestamp - *timestamp <= SCAN_WINDOW_SECS
            });
            if state.icmp_targets.is_empty() {
                state.icmp_alerted = false;
            }
            state.icmp_targets.push((pkt.timestamp, pkt.dst.clone()));
            let unique_targets = state.icmp_targets.iter()
                .map(|(_, destination)| destination.as_str())
                .collect::<HashSet<_>>()
                .len();
            if unique_targets >= SCAN_UNIQUE_THRESHOLD && !state.icmp_alerted {
                state.icmp_alerted = true;
                alerts.push((
                    "ICMP address sweep",
                    Severity::Medium,
                    format!("{} probed {unique_targets} hosts with ICMP echo requests", pkt.src),
                ));
            }
        }

        for (signature, severity, detail) in alerts {
            self.push_ids(IdsAlert { pkt_no: pkt.no, signature, severity, detail });
        }
    }

    fn record_scan_probe(
        &mut self,
        pkt: &Packet,
        port: u16,
        alerts: &mut Vec<(&'static str, Severity, String)>,
    ) {
        let state = self.scan_sources.entry(pkt.src.clone()).or_default();
        state.last_seen = pkt.timestamp;
        state.probes.retain(|probe| {
            pkt.timestamp < probe.timestamp || pkt.timestamp - probe.timestamp <= SCAN_WINDOW_SECS
        });
        if state.probes.is_empty() {
            state.vertical_alerted.clear();
            state.horizontal_alerted.clear();
        }
        state.probes.push(ScanProbe {
            timestamp: pkt.timestamp,
            destination: pkt.dst.clone(),
            port,
        });

        let unique_ports = state.probes.iter()
            .filter(|probe| probe.destination == pkt.dst)
            .map(|probe| probe.port)
            .collect::<HashSet<_>>()
            .len();
        if unique_ports >= SCAN_UNIQUE_THRESHOLD && state.vertical_alerted.insert(pkt.dst.clone()) {
            alerts.push((
                "Vertical port scan",
                Severity::High,
                format!("{} probed {unique_ports} ports on {}", pkt.src, pkt.dst),
            ));
        }

        let unique_targets = state.probes.iter()
            .filter(|probe| probe.port == port)
            .map(|probe| probe.destination.as_str())
            .collect::<HashSet<_>>()
            .len();
        if unique_targets >= SCAN_UNIQUE_THRESHOLD && state.horizontal_alerted.insert(port) {
            alerts.push((
                "Horizontal host scan",
                Severity::High,
                format!("{} probed port {port} on {unique_targets} hosts", pkt.src),
            ));
        }
    }

    fn record_syn_flood(
        &mut self,
        pkt: &Packet,
        port: u16,
        alerts: &mut Vec<(&'static str, Severity, String)>,
    ) {
        let key = (pkt.dst.clone(), port);
        let state = self.syn_flood_targets.entry(key).or_default();
        state.last_seen = pkt.timestamp;
        state.timestamps.retain(|timestamp| {
            pkt.timestamp < *timestamp || pkt.timestamp - *timestamp <= SYN_FLOOD_WINDOW_SECS
        });
        if state.timestamps.is_empty() {
            state.alerted = false;
        }
        state.timestamps.push(pkt.timestamp);
        if state.timestamps.len() >= SYN_FLOOD_THRESHOLD && !state.alerted {
            state.alerted = true;
            alerts.push((
                "SYN flood",
                Severity::Critical,
                format!("{}:{} received {} SYN packets within one second", pkt.dst, port, state.timestamps.len()),
            ));
        }
    }

    fn check_ids(&mut self, pkt: &Packet) {
        let dst_port = pkt.dst_port.unwrap_or(0);
        let src_port = pkt.src_port.unwrap_or(0);
        let bytes = &pkt.bytes;
        let info_lower = pkt.info.to_lowercase();
        let proto_lower = pkt.protocol.to_lowercase();

        // ── EternalBlue ─────────────────────────────────────────────────────
        if dst_port == 445 {
            let sig1: &[u8] = &[0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x00, 0x00, 0x00];
            if Self::contains_bytes(bytes, sig1) || Self::contains_str_ci(bytes, b"SMBr") {
                self.push_ids(IdsAlert {
                    pkt_no: pkt.no,
                    signature: "EternalBlue",
                    severity: Severity::Critical,
                    detail: format!("SMB exploit signature on port 445 from {}", pkt.src),
                });
            }
        }

        // ── BlueKeep ────────────────────────────────────────────────────────
        if dst_port == 3389 && bytes.len() > 100 {
            let sig: &[u8] = &[0x03, 0x00, 0x00];
            if bytes.starts_with(sig) || Self::contains_bytes(bytes, sig) {
                self.push_ids(IdsAlert {
                    pkt_no: pkt.no,
                    signature: "BlueKeep (CVE-2019-0708)",
                    severity: Severity::Critical,
                    detail: format!("RDP anomalous TPKT from {} len={}", pkt.src, bytes.len()),
                });
            }
        }

        // ── Log4Shell ───────────────────────────────────────────────────────
        if Self::contains_str_ci(bytes, b"${jndi:") {
            self.push_ids(IdsAlert {
                pkt_no: pkt.no,
                signature: "Log4Shell (CVE-2021-44228)",
                severity: Severity::Critical,
                detail: format!("${{jndi:}} pattern in payload from {} proto={}", pkt.src, pkt.protocol),
            });
        }

        // ── Shellcode NOP sled ───────────────────────────────────────────────
        if Self::nop_sled_16(bytes) {
            self.push_ids(IdsAlert {
                pkt_no: pkt.no,
                signature: "Shellcode NOP sled",
                severity: Severity::High,
                detail: format!("16+ consecutive 0x90 bytes from {}", pkt.src),
            });
        }

        // ── LLMNR poisoning ─────────────────────────────────────────────────
        if dst_port == 5355 || pkt.dst == "224.0.0.252" {
            if proto_lower.contains("udp") || proto_lower.contains("llmnr") {
                self.push_ids(IdsAlert {
                    pkt_no: pkt.no,
                    signature: "LLMNR Poisoning",
                    severity: Severity::Medium,
                    detail: format!("LLMNR query from {} to {}", pkt.src, pkt.dst),
                });
            }
        }

        // ── NBNS poisoning ──────────────────────────────────────────────────
        if dst_port == 137 && (proto_lower.contains("udp") || proto_lower.contains("nbns")) {
            let nbns_sig: &[u8] = &[0x00, 0x20, 0x43, 0x4b];
            if Self::contains_bytes(bytes, nbns_sig) {
                self.push_ids(IdsAlert {
                    pkt_no: pkt.no,
                    signature: "NBNS WPAD Poisoning",
                    severity: Severity::Medium,
                    detail: format!("NBNS WPAD query from {}", pkt.src),
                });
            }
        }

        // ── Directory traversal ─────────────────────────────────────────────
        if dst_port == 80 || dst_port == 443 || dst_port == 8080 {
            let count = Self::count_pattern_ascii(bytes, b"../");
            if count >= 5 {
                self.push_ids(IdsAlert {
                    pkt_no: pkt.no,
                    signature: "Directory Traversal",
                    severity: Severity::High,
                    detail: format!("Path traversal ({count}x ../) from {}", pkt.src),
                });
            }
        }

        // ── SQL injection probe ──────────────────────────────────────────────
        if dst_port == 80 || dst_port == 443 || dst_port == 8080 || dst_port == 3000 || dst_port == 8000 {
            if Self::contains_str_ci(bytes, b"' OR 1=1")
                || Self::contains_str_ci(bytes, b"'; DROP TABLE")
                || Self::contains_str_ci(bytes, b"UNION SELECT")
            {
                self.push_ids(IdsAlert {
                    pkt_no: pkt.no,
                    signature: "SQL Injection Probe",
                    severity: Severity::High,
                    detail: format!("SQLi pattern in HTTP payload from {}", pkt.src),
                });
            }
        }

        // ── XSS probe ───────────────────────────────────────────────────────
        if Self::contains_str_ci(bytes, b"<script>") || Self::contains_str_ci(bytes, b"javascript:") {
            self.push_ids(IdsAlert {
                pkt_no: pkt.no,
                signature: "XSS Probe",
                severity: Severity::Medium,
                detail: format!("XSS pattern from {}", pkt.src),
            });
        }

        // ── Heartbleed ──────────────────────────────────────────────────────
        if (dst_port == 443 || src_port == 443) && bytes.len() >= 7 {
            // TLS heartbeat record type = 0x18
            if bytes.get(0).copied() == Some(0x18) && bytes.get(1).copied() == Some(0x03) {
                let claimed_len = u16_be_at(bytes, 3) as usize;
                if claimed_len > bytes.len() + 64 {
                    self.push_ids(IdsAlert {
                        pkt_no: pkt.no,
                        signature: "Heartbleed (CVE-2014-0160)",
                        severity: Severity::Critical,
                        detail: format!(
                            "TLS heartbeat claimed_len={claimed_len} actual={} from {}",
                            bytes.len(), pkt.src
                        ),
                    });
                }
            }
        }

        // ── PrintNightmare ───────────────────────────────────────────────────
        if dst_port == 445 || dst_port == 135 {
            let sig_pn: &[u8] = &[0x1c, 0x00];
            if Self::contains_bytes(bytes, sig_pn)
                && (Self::contains_str_ci(bytes, b"SpoolSS")
                    || Self::contains_bytes(bytes, &[0x6e, 0x64, 0x72, 0x76]))
            {
                self.push_ids(IdsAlert {
                    pkt_no: pkt.no,
                    signature: "PrintNightmare (CVE-2021-1675)",
                    severity: Severity::Critical,
                    detail: format!("Print Spooler RPC from {} on port {dst_port}", pkt.src),
                });
            }
        }

        // ── Pass-the-Hash ────────────────────────────────────────────────────
        if dst_port == 445 {
            let has_ntlm = Self::contains_str_ci(bytes, b"NTLMSSP");
            let has_kerb = Self::contains_str_ci(bytes, b"Kerberos")
                || info_lower.contains("kerberos");
            if has_ntlm && !has_kerb {
                // Heuristic: NTLM auth on SMB without Kerberos ticket
                self.push_ids(IdsAlert {
                    pkt_no: pkt.no,
                    signature: "Pass-the-Hash (suspected)",
                    severity: Severity::High,
                    detail: format!("SMB NTLM auth (no Kerberos) from {}", pkt.src),
                });
            }
        }

        // ── CVE-2021-44228 via DNS ───────────────────────────────────────────
        if dst_port == 53 || src_port == 53 || proto_lower.contains("dns") {
            if info_lower.contains("jndi") {
                self.push_ids(IdsAlert {
                    pkt_no: pkt.no,
                    signature: "Log4Shell via DNS (CVE-2021-44228)",
                    severity: Severity::Critical,
                    detail: format!("DNS query contains 'jndi' from {}", pkt.src),
                });
            }
        }
    }

    // ─── ARP Anomaly ─────────────────────────────────────────────────────────

    fn check_arp(&mut self, pkt: &Packet) {
        // ARP packets: protocol == "ARP" or info contains ARP data
        if !pkt.protocol.eq_ignore_ascii_case("ARP") {
            return;
        }
        // ARP reply format: "Who has x.x.x.x? Tell y.y.y.y" or "x.x.x.x is at aa:bb:cc..."
        // Extract IP and MAC from info string
        let info = &pkt.info;
        if let Some((ip, mac)) = Self::parse_arp_info(info) {
            if let Some(known_mac) = self.ip_to_mac.get(&ip).cloned() {
                if known_mac != mac {
                    if self.arp_anomalies.len() >= MAX_ENTRIES {
                        self.arp_anomalies.remove(0);
                    }
                    self.arp_anomalies.push(ArpAnomaly {
                        pkt_no: pkt.no,
                        ip: ip.clone(),
                        old_mac: known_mac,
                        new_mac: mac.clone(),
                    });
                }
            }
            self.ip_to_mac.insert(ip, mac);
        }
    }

    fn parse_arp_info(info: &str) -> Option<(String, String)> {
        // "192.168.1.1 is at aa:bb:cc:dd:ee:ff"
        let lower = info.to_lowercase();
        if let Some(pos) = lower.find(" is at ") {
            let ip = info[..pos].trim().to_string();
            let mac = info[pos + 7..].trim().to_string();
            if !ip.is_empty() && !mac.is_empty() {
                return Some((ip, mac));
            }
        }
        None
    }

    // ─── OS Fingerprinting ───────────────────────────────────────────────────

    fn check_os_fingerprint(&mut self, pkt: &Packet) {
        // Only TCP packets with sufficient bytes
        if !pkt.protocol.eq_ignore_ascii_case("TCP") || pkt.bytes.len() < 50 {
            return;
        }
        let ttl = byte_at(&pkt.bytes, 22);
        let window = u16_be_at(&pkt.bytes, 48);

        // Already fingerprinted this src IP?
        if self.os_by_ip.contains_key(&pkt.src) {
            return;
        }

        let os: &'static str = match (ttl, window) {
            (64, 5840)  => "Linux 2.x",
            (64, 29200) => "Linux 3.x",
            (64, 64240) => "Linux 4.x+",
            (64, 65535) => "macOS/FreeBSD",
            (128, 65535) => "Windows 10/11",
            (128, 8192)  => "Windows XP/2003",
            (128, 16384) => "Windows Server",
            (255, _)    => "Network Device (Cisco/etc)",
            (32, _)     => "Windows 9x/ME",
            _           => return, // Not enough signal
        };

        self.os_by_ip.insert(pkt.src.clone(), os);
        if self.os_guesses.len() >= MAX_ENTRIES {
            self.os_guesses.remove(0);
        }
        self.os_guesses.push(OsGuess {
            src_ip: pkt.src.clone(),
            os,
            ttl,
            window,
        });
    }

    // ─── Vulnerability Patterns ───────────────────────────────────────────────

    fn push_vuln(&mut self, v: VulnHit) {
        if self.vuln_hits.len() >= MAX_ENTRIES {
            self.vuln_hits.remove(0);
        }
        self.vuln_hits.push(v);
    }

    fn check_vuln(&mut self, pkt: &Packet) {
        let dst_port = pkt.dst_port.unwrap_or(0);
        let src_port = pkt.src_port.unwrap_or(0);
        let bytes = &pkt.bytes;

        // HTTP cleartext sensitive paths on port 80
        if dst_port == 80 {
            let payload = Self::ascii_payload(bytes, 54);
            let lower = payload.to_lowercase();
            for sens in &["/admin", "/login", "/passwd", "/password", "/config", "/wp-admin"] {
                if lower.contains(sens) {
                    self.push_vuln(VulnHit {
                        pkt_no: pkt.no,
                        kind: "Cleartext HTTP Sensitive Path",
                        detail: format!("Path '{}' over plaintext HTTP from {}", sens, pkt.src),
                    });
                    break;
                }
            }
        }

        // Weak TLS: TLS 1.0 or SSL 3.0
        if dst_port == 443 || src_port == 443 {
            let tls10: &[u8] = &[0x16, 0x03, 0x01];
            let ssl30: &[u8]  = &[0x16, 0x03, 0x00];
            if bytes.starts_with(tls10) {
                self.push_vuln(VulnHit {
                    pkt_no: pkt.no,
                    kind: "Weak TLS 1.0",
                    detail: format!("TLS 1.0 record from {}", pkt.src),
                });
            } else if bytes.starts_with(ssl30) {
                self.push_vuln(VulnHit {
                    pkt_no: pkt.no,
                    kind: "Weak SSL 3.0",
                    detail: format!("SSL 3.0 record from {}", pkt.src),
                });
            }
        }

        // Cleartext Telnet credentials
        if dst_port == 23 || src_port == 23 {
            let payload = Self::ascii_payload(bytes, 54);
            if payload.contains("login:") || payload.contains("Password:") {
                self.push_vuln(VulnHit {
                    pkt_no: pkt.no,
                    kind: "Cleartext Telnet Credential",
                    detail: format!("Telnet login prompt from {}", pkt.src),
                });
            }
        }

        // Anonymous FTP
        if dst_port == 21 || src_port == 21 {
            let payload = Self::ascii_payload(bytes, 54);
            let lower = payload.to_lowercase();
            if lower.contains("user anonymous") || lower.contains("user ftp") {
                self.push_vuln(VulnHit {
                    pkt_no: pkt.no,
                    kind: "Anonymous FTP Login",
                    detail: format!("FTP anonymous login attempt from {}", pkt.src),
                });
            }
        }

        // SMB null session
        if dst_port == 445 {
            // NTLM with empty credentials signature
            if Self::contains_str_ci(bytes, b"NTLMSSP")
                && Self::contains_bytes(bytes, &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            {
                self.push_vuln(VulnHit {
                    pkt_no: pkt.no,
                    kind: "SMB Null Session",
                    detail: format!("SMB anonymous/null NTLM from {}", pkt.src),
                });
            }
        }
    }

    // ─── Brute Force Detection ────────────────────────────────────────────────

    fn check_brute_force(&mut self, pkt: &Packet) {
        let dst_port = pkt.dst_port.unwrap_or(0);
        let src_port = pkt.src_port.unwrap_or(0);
        let bytes = &pkt.bytes;

        let service: Option<&'static str> = match dst_port {
            22  => Some("SSH"),
            21  => {
                let p = Self::ascii_payload(bytes, 54);
                if p.contains("530 Login incorrect") || p.contains("530 Failed") {
                    Some("FTP")
                } else {
                    None
                }
            }
            80 | 443 => {
                let info = &pkt.info;
                if info.contains("401") { Some("HTTP") } else { None }
            }
            445 => {
                if Self::contains_str_ci(bytes, b"NTLMSSP") { Some("SMB") } else { None }
            }
            _ => {
                // Check response side
                if src_port == 21 {
                    let p = Self::ascii_payload(bytes, 54);
                    if p.contains("530 Login incorrect") || p.contains("530 Failed") {
                        Some("FTP")
                    } else { None }
                } else { None }
            }
        };

        if let Some(svc) = service {
            let key = BfKey {
                src: pkt.src.clone(),
                dst: pkt.dst.clone(),
                port: dst_port,
            };
            let now = pkt.timestamp;
            let window = self.bf_windows.entry(key.clone()).or_insert(BfWindow {
                timestamps: Vec::new(),
                service: svc,
                alerted: false,
            });

            // Prune events older than 30 seconds
            window.timestamps.retain(|&t| now - t <= 30.0);
            window.timestamps.push(now);

            if !window.alerted && window.timestamps.len() >= 5 {
                window.alerted = true;
                let attempts = window.timestamps.len();
                let svc_static = window.service;
                if self.brute_force.len() >= MAX_ENTRIES {
                    self.brute_force.remove(0);
                }
                self.brute_force.push(BruteForceAlert {
                    src_ip: key.src,
                    dst_ip: key.dst,
                    port: key.port,
                    attempts,
                    service: svc_static,
                });
            }
        }
    }

    // ─── HTTP Analytics ───────────────────────────────────────────────────────

    fn check_http(&mut self, pkt: &Packet) {
        let dst_port = pkt.dst_port.unwrap_or(0);
        let src_port = pkt.src_port.unwrap_or(0);
        let http_ports = [80u16, 8080, 3000, 8000, 8888];
        if !http_ports.contains(&dst_port) && !http_ports.contains(&src_port) {
            return;
        }

        let payload = Self::ascii_payload(&pkt.bytes, 54);
        if payload.is_empty() {
            return;
        }

        let mut method = String::new();
        let mut path   = String::new();
        let mut user_agent = String::new();
        let mut response_code: Option<u16> = None;

        let first_line = payload.lines().next().unwrap_or("");

        // Request: "GET /path HTTP/1.1"
        for m in &["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT"] {
            if first_line.starts_with(m) {
                method = m.to_string();
                let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
                if parts.len() >= 2 {
                    path = parts[1].to_string();
                }
                break;
            }
        }

        // Response: "HTTP/1.1 200 OK"
        if first_line.starts_with("HTTP/") {
            let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
            if parts.len() >= 2 {
                if let Ok(code) = parts[1].parse::<u16>() {
                    response_code = Some(code);
                }
            }
        }

        // User-Agent header
        for line in payload.lines() {
            let lower = line.to_lowercase();
            if lower.starts_with("user-agent:") {
                user_agent = line[11..].trim().to_string();
                break;
            }
        }

        if method.is_empty() && response_code.is_none() && path.is_empty() {
            return;
        }

        if self.http_records.len() >= MAX_ENTRIES {
            self.http_records.remove(0);
        }
        self.http_records.push(HttpRecord {
            pkt_no: pkt.no,
            src_ip: pkt.src.clone(),
            dst_ip: pkt.dst.clone(),
            port: if http_ports.contains(&dst_port) { dst_port } else { src_port },
            method,
            path,
            user_agent,
            response_code,
        });
    }

    // ─── TLS/SSL Weakness ─────────────────────────────────────────────────────

    fn push_tls(&mut self, w: TlsWeakness) {
        if self.tls_weaknesses.len() >= MAX_ENTRIES {
            self.tls_weaknesses.remove(0);
        }
        self.tls_weaknesses.push(w);
    }

    fn check_tls(&mut self, pkt: &Packet) {
        let dst_port = pkt.dst_port.unwrap_or(0);
        let src_port = pkt.src_port.unwrap_or(0);
        if dst_port != 443 && src_port != 443 {
            return;
        }
        let bytes = &pkt.bytes;
        if bytes.len() < 6 {
            return;
        }

        // TLS 1.0
        if bytes.starts_with(&[0x16, 0x03, 0x01]) {
            self.push_tls(TlsWeakness {
                pkt_no: pkt.no,
                src_ip: pkt.src.clone(),
                dst_ip: pkt.dst.clone(),
                kind: "TLS 1.0",
                detail: format!("TLS 1.0 handshake from {}", pkt.src),
            });
        }
        // SSL 3.0
        else if bytes.starts_with(&[0x16, 0x03, 0x00]) {
            self.push_tls(TlsWeakness {
                pkt_no: pkt.no,
                src_ip: pkt.src.clone(),
                dst_ip: pkt.dst.clone(),
                kind: "SSL 3.0 (POODLE)",
                detail: format!("SSL 3.0 record from {}", pkt.src),
            });
        }

        // Self-signed: SHA-1 with RSA OID 1.2.840.113549.1.1.5
        let sha1_oid: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05];
        if Self::contains_bytes(bytes, sha1_oid) {
            self.push_tls(TlsWeakness {
                pkt_no: pkt.no,
                src_ip: pkt.src.clone(),
                dst_ip: pkt.dst.clone(),
                kind: "SHA-1 Certificate",
                detail: format!("sha1WithRSA cert OID from {}", pkt.src),
            });
        }

        // RC4 cipher suites in Client Hello (record type 0x16, handshake type 0x01)
        if bytes.get(0).copied() == Some(0x16) && bytes.get(5).copied() == Some(0x01) {
            // Scan for cipher suites 0x0005 (RC4-SHA) or 0x000a (RC4-MD5)
            let rc4_suites: &[&[u8]] = &[&[0x00, 0x05], &[0x00, 0x0a]];
            for suite in rc4_suites {
                if Self::contains_bytes(bytes, suite) {
                    self.push_tls(TlsWeakness {
                        pkt_no: pkt.no,
                        src_ip: pkt.src.clone(),
                        dst_ip: pkt.dst.clone(),
                        kind: "RC4 Cipher Suite",
                        detail: format!("RC4 cipher 0x{:02x}{:02x} offered from {}", suite[0], suite[1], pkt.src),
                    });
                    break;
                }
            }
        }
    }

    // ─── DNS Exfiltration Scoring ─────────────────────────────────────────────

    fn check_dns_tunnel(&mut self, pkt: &Packet) {
        let dst_port = pkt.dst_port.unwrap_or(0);
        let src_port = pkt.src_port.unwrap_or(0);
        if dst_port != 53 && src_port != 53 && !pkt.protocol.eq_ignore_ascii_case("DNS") {
            return;
        }

        // Parse domain from info string formats:
        // "Query 0xXXXX A sub.domain.com"
        // "Response A 1.2.3.4"
        // "Standard query 0xXXXX A hostname.example.com"
        let domain = match Self::extract_dns_domain(&pkt.info) {
            Some(d) => d,
            None => return,
        };

        let (subdomain, apex) = Self::split_apex(&domain);

        if apex.is_empty() {
            return;
        }

        // Compute subdomain entropy
        let sub_entropy = if subdomain.is_empty() {
            0.0
        } else {
            shannon_entropy(subdomain.as_bytes())
        };

        let sub_len = subdomain.len();

        let acc = self.dns_accum.entry(apex.clone()).or_insert(DnsAccum {
            queries: 0,
            max_entropy: 0.0,
            max_len: 0,
            unique_subs: std::collections::HashSet::new(),
        });
        acc.queries += 1;
        if sub_entropy > acc.max_entropy {
            acc.max_entropy = sub_entropy;
        }
        if sub_len > acc.max_len {
            acc.max_len = sub_len;
        }
        if !subdomain.is_empty() {
            acc.unique_subs.insert(subdomain.clone());
        }

        let score = (acc.queries as f64 / 10.0) + acc.max_entropy + (acc.max_len as f64 / 10.0);

        // Update or insert in dns_suspects
        if let Some(existing) = self.dns_suspects.iter_mut().find(|d| d.apex == apex) {
            existing.query_count = acc.queries;
            existing.max_entropy = acc.max_entropy;
            existing.max_subdomain_len = acc.max_len;
            existing.unique_subdomains = acc.unique_subs.len();
            existing.score = score;
        } else {
            if self.dns_suspects.len() >= MAX_ENTRIES {
                self.dns_suspects.remove(0);
            }
            self.dns_suspects.push(DnsTunnelSuspect {
                apex: apex.clone(),
                query_count: acc.queries,
                max_entropy: acc.max_entropy,
                max_subdomain_len: acc.max_len,
                unique_subdomains: acc.unique_subs.len(),
                score,
            });
        }
    }

    fn extract_dns_domain(info: &str) -> Option<String> {
        // Patterns: "Query 0xXXXX A domain", "Standard query 0xXXXX A domain", "Response A domain"
        let lower = info.to_lowercase();
        let words: Vec<&str> = info.split_whitespace().collect();
        // Find a word that looks like a domain (contains a dot, doesn't start with digit for pure IP)
        // Strategy: scan words backwards for a domain-like token
        for word in words.iter().rev() {
            let w = word.trim_end_matches('.');
            if w.contains('.') && !w.starts_with(|c: char| c.is_ascii_digit()) {
                // Skip version-like strings
                if lower.contains("response") && w.parse::<std::net::IpAddr>().is_ok() {
                    continue;
                }
                return Some(w.to_lowercase());
            }
        }
        None
    }

    /// Split "sub.domain.example.com" → ("sub.domain", "example.com")
    fn split_apex(domain: &str) -> (String, String) {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() <= 2 {
            return (String::new(), domain.to_string());
        }
        let apex = parts[parts.len() - 2..].join(".");
        let subdomain = parts[..parts.len() - 2].join(".");
        (subdomain, apex)
    }

    // ─── Byte pattern helpers ─────────────────────────────────────────────────

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || haystack.len() < needle.len() {
            return false;
        }
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    fn contains_str_ci(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || haystack.len() < needle.len() {
            return false;
        }
        let n_lower: Vec<u8> = needle.iter().map(|b| b.to_ascii_lowercase()).collect();
        haystack
            .windows(needle.len())
            .any(|w| w.iter().map(|b| b.to_ascii_lowercase()).collect::<Vec<_>>() == n_lower)
    }

    fn nop_sled_16(data: &[u8]) -> bool {
        let mut run = 0usize;
        for &b in data {
            if b == 0x90 {
                run += 1;
                if run >= 16 {
                    return true;
                }
            } else {
                run = 0;
            }
        }
        false
    }

    fn count_pattern_ascii(data: &[u8], pattern: &[u8]) -> usize {
        if pattern.is_empty() || data.len() < pattern.len() {
            return 0;
        }
        data.windows(pattern.len())
            .filter(|w| *w == pattern)
            .count()
    }

    fn ascii_payload(bytes: &[u8], offset: usize) -> String {
        if bytes.len() <= offset {
            return String::new();
        }
        bytes[offset..]
            .iter()
            .map(|&b| if b.is_ascii() && (b >= 0x20 || b == b'\n' || b == b'\r' || b == b'\t') { b as char } else { '.' })
            .collect()
    }
}

fn parse_ipv4_fragment(raw: &[u8]) -> Option<Ipv4Fragment<'_>> {
    let (ip_offset, ether_type) = ethernet_network_header(raw)?;
    if ether_type != 0x0800 || raw.len() < ip_offset + 20 || raw[ip_offset] >> 4 != 4 {
        return None;
    }

    let header_len = usize::from(raw[ip_offset] & 0x0f) * 4;
    let flags_and_offset = u16::from_be_bytes([raw[ip_offset + 6], raw[ip_offset + 7]]);
    let offset = u32::from(flags_and_offset & 0x1fff) * 8;
    let more_fragments = flags_and_offset & 0x2000 != 0;
    if !more_fragments && offset == 0 {
        return None;
    }

    let total_len = usize::from(u16::from_be_bytes([raw[ip_offset + 2], raw[ip_offset + 3]]));
    let malformed_length = header_len < 20 || total_len < header_len;
    let declared_payload_len = total_len.saturating_sub(header_len);
    let payload_start = ip_offset.saturating_add(header_len).min(raw.len());
    let captured_payload_len = declared_payload_len.min(raw.len().saturating_sub(payload_start));
    let payload = &raw[payload_start..payload_start + captured_payload_len];

    Some(Ipv4Fragment {
        key: FragmentKey {
            src: raw[ip_offset + 12..ip_offset + 16].try_into().ok()?,
            dst: raw[ip_offset + 16..ip_offset + 20].try_into().ok()?,
            identification: u16::from_be_bytes([raw[ip_offset + 4], raw[ip_offset + 5]]),
            protocol: raw[ip_offset + 9],
        },
        offset,
        more_fragments,
        payload,
        declared_payload_len,
        malformed_length,
    })
}

fn ethernet_network_header(raw: &[u8]) -> Option<(usize, u16)> {
    if raw.len() < 14 {
        return None;
    }
    let mut ether_type_offset = 12usize;
    loop {
        let ether_type = u16::from_be_bytes([
            *raw.get(ether_type_offset)?,
            *raw.get(ether_type_offset + 1)?,
        ]);
        if ether_type != 0x8100 && ether_type != 0x88a8 {
            return Some((ether_type_offset + 2, ether_type));
        }
        ether_type_offset = ether_type_offset.checked_add(4)?;
    }
}

fn has_conflicting_fragment_overlap(slices: &[FragmentSlice], fragment: &Ipv4Fragment<'_>) -> bool {
    let new_start = fragment.offset;
    let new_end = new_start.saturating_add(fragment.payload.len() as u32);
    slices.iter().any(|existing| {
        let existing_end = existing.start.saturating_add(existing.data.len() as u32);
        let overlap_start = new_start.max(existing.start);
        let overlap_end = new_end.min(existing_end);
        if overlap_start >= overlap_end {
            return false;
        }

        let new_offset = (overlap_start - new_start) as usize;
        let existing_offset = (overlap_start - existing.start) as usize;
        let overlap_len = (overlap_end - overlap_start) as usize;
        fragment.payload[new_offset..new_offset + overlap_len]
            != existing.data[existing_offset..existing_offset + overlap_len]
    })
}

fn parse_ipv4_tcp_frame(raw: &[u8]) -> Option<TcpFrame<'_>> {
    let (ip_offset, ether_type) = ethernet_network_header(raw)?;
    if ether_type != 0x0800 || raw.len() < ip_offset + 20 || raw[ip_offset] >> 4 != 4 {
        return None;
    }
    let ip_header_len = usize::from(raw[ip_offset] & 0x0f) * 4;
    if ip_header_len < 20 || raw.len() < ip_offset + ip_header_len || raw[ip_offset + 9] != 6 {
        return None;
    }

    let fragment_field = u16::from_be_bytes([raw[ip_offset + 6], raw[ip_offset + 7]]);
    if fragment_field & 0x1fff != 0 {
        return None;
    }

    let total_len = usize::from(u16::from_be_bytes([raw[ip_offset + 2], raw[ip_offset + 3]]));
    if total_len < ip_header_len + 20 {
        return Some(TcpFrame::Malformed("IPv4 payload is shorter than a minimum TCP header"));
    }
    let tcp_offset = ip_offset + ip_header_len;
    if raw.len() < tcp_offset + 20 {
        return Some(TcpFrame::Malformed("captured TCP header is truncated"));
    }

    let tcp_header_len = usize::from(raw[tcp_offset + 12] >> 4) * 4;
    if tcp_header_len < 20 {
        return Some(TcpFrame::Malformed("TCP data offset is smaller than 20 bytes"));
    }
    if total_len < ip_header_len + tcp_header_len {
        return Some(TcpFrame::Malformed("TCP data offset exceeds the IPv4 payload length"));
    }

    let src: [u8; 4] = raw[ip_offset + 12..ip_offset + 16].try_into().ok()?;
    let dst: [u8; 4] = raw[ip_offset + 16..ip_offset + 20].try_into().ok()?;
    let src_port = u16::from_be_bytes([raw[tcp_offset], raw[tcp_offset + 1]]);
    let dst_port = u16::from_be_bytes([raw[tcp_offset + 2], raw[tcp_offset + 3]]);
    let src_endpoint = (src, src_port);
    let dst_endpoint = (dst, dst_port);
    let (endpoint_a, endpoint_b, from_a) = if src_endpoint <= dst_endpoint {
        (src_endpoint, dst_endpoint, true)
    } else {
        (dst_endpoint, src_endpoint, false)
    };
    let sequence = u32::from_be_bytes(raw[tcp_offset + 4..tcp_offset + 8].try_into().ok()?);
    let packet_end = (ip_offset + total_len).min(raw.len());
    let payload_start = (tcp_offset + tcp_header_len).min(packet_end);

    Some(TcpFrame::Segment(TcpSegment {
        key: TcpFlowKey { endpoint_a, endpoint_b },
        from_a,
        sequence,
        flags: raw[tcp_offset + 13],
        payload: &raw[payload_start..packet_end],
    }))
}

fn is_empty_ipv4_udp_probe(raw: &[u8]) -> bool {
    let Some((ip_offset, 0x0800)) = ethernet_network_header(raw) else {
        return false;
    };
    if raw.len() < ip_offset + 20 || raw[ip_offset] >> 4 != 4 || raw[ip_offset + 9] != 17 {
        return false;
    }
    let ip_header_len = usize::from(raw[ip_offset] & 0x0f) * 4;
    let udp_offset = ip_offset + ip_header_len;
    if ip_header_len < 20 || raw.len() < udp_offset + 8 {
        return false;
    }
    u16::from_be_bytes([raw[udp_offset + 4], raw[udp_offset + 5]]) == 8
}

fn has_conflicting_tcp_overlap(slices: &[FragmentSlice], segment: &TcpSegment<'_>) -> bool {
    let new_start = segment.sequence;
    let new_end = new_start.saturating_add(segment.payload.len() as u32);
    slices.iter().any(|existing| {
        let existing_end = existing.start.saturating_add(existing.data.len() as u32);
        let overlap_start = new_start.max(existing.start);
        let overlap_end = new_end.min(existing_end);
        if overlap_start >= overlap_end {
            return false;
        }
        let new_offset = (overlap_start - new_start) as usize;
        let existing_offset = (overlap_start - existing.start) as usize;
        let overlap_len = (overlap_end - overlap_start) as usize;
        segment.payload[new_offset..new_offset + overlap_len]
            != existing.data[existing_offset..existing_offset + overlap_len]
    })
}

fn evict_oldest_scan_source(states: &mut HashMap<String, SourceScanState>) {
    if states.len() < MAX_SCAN_STATES {
        return;
    }
    if let Some(oldest) = states.iter()
        .min_by(|left, right| left.1.last_seen.total_cmp(&right.1.last_seen))
        .map(|(key, _)| key.clone())
    {
        states.remove(&oldest);
    }
}

fn evict_oldest_syn_target(states: &mut HashMap<(String, u16), SynFloodState>) {
    if states.len() < MAX_SCAN_STATES {
        return;
    }
    if let Some(oldest) = states.iter()
        .min_by(|left, right| left.1.last_seen.total_cmp(&right.1.last_seen))
        .map(|(key, _)| key.clone())
    {
        states.remove(&oldest);
    }
}

impl Default for SecurityEngine {
    fn default() -> Self {
        Self::new()
    }
}

// Allow ? operator to return Option in check_dns_tunnel
trait OptionReturn<T> {
    fn check_dns_tunnel_inner(self) -> Option<T>;
}

// We use a separate function returning Option for the DNS helper
impl SecurityEngine {
    fn extract_dns_domain_opt(info: &str) -> Option<String> {
        Self::extract_dns_domain(info)
    }
}
