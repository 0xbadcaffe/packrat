use super::*;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(super) struct FragmentKey {
    pub(super) src: [u8; 4],
    pub(super) dst: [u8; 4],
    pub(super) identification: u16,
    pub(super) protocol: u8,
}

#[derive(Debug, Clone)]
pub(super) struct FragmentSlice {
    pub(super) start: u32,
    pub(super) data: Vec<u8>,
}

#[derive(Debug, Default)]
pub(super) struct FragmentState {
    pub(super) slices: Vec<FragmentSlice>,
    pub(super) count: usize,
    pub(super) last_seen: f64,
    pub(super) overlap_alerted: bool,
    pub(super) flood_alerted: bool,
}

pub(super) struct Ipv4Fragment<'a> {
    pub(super) key: FragmentKey,
    pub(super) offset: u32,
    pub(super) more_fragments: bool,
    pub(super) payload: &'a [u8],
    pub(super) declared_payload_len: usize,
    pub(super) malformed_length: bool,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(super) struct TcpFlowKey {
    pub(super) endpoint_a: ([u8; 4], u16),
    pub(super) endpoint_b: ([u8; 4], u16),
}

#[derive(Debug, Default)]
pub(super) struct TcpIntegrityState {
    pub(super) from_a: Vec<FragmentSlice>,
    pub(super) from_b: Vec<FragmentSlice>,
    pub(super) last_seen: f64,
    pub(super) reset_seen: bool,
    pub(super) overlap_alerted: bool,
    pub(super) post_reset_alerted: bool,
}

pub(super) struct TcpSegment<'a> {
    pub(super) key: TcpFlowKey,
    pub(super) from_a: bool,
    pub(super) sequence: u32,
    pub(super) flags: u8,
    pub(super) payload: &'a [u8],
}

pub(super) enum TcpFrame<'a> {
    Malformed(&'static str),
    Segment(TcpSegment<'a>),
}

#[derive(Debug)]
pub(super) struct ScanProbe {
    pub(super) timestamp: f64,
    pub(super) destination: String,
    pub(super) port: u16,
}

#[derive(Debug, Default)]
pub(super) struct SourceScanState {
    pub(super) probes: Vec<ScanProbe>,
    pub(super) icmp_targets: Vec<(f64, String)>,
    pub(super) vertical_alerted: HashSet<String>,
    pub(super) horizontal_alerted: HashSet<u16>,
    pub(super) icmp_alerted: bool,
    pub(super) last_seen: f64,
}

#[derive(Debug, Default)]
pub(super) struct SynFloodState {
    pub(super) timestamps: Vec<f64>,
    pub(super) alerted: bool,
    pub(super) last_seen: f64,
}

#[derive(Debug, Default)]
pub(super) struct RouterAdvertisementState {
    pub(super) timestamps: Vec<f64>,
    pub(super) alerted: bool,
    pub(super) invalid_source_alerted: bool,
    pub(super) last_seen: f64,
}

pub(super) struct Ipv6Inspection<'a> {
    pub(super) hop_limit: u8,
    pub(super) source: [u8; 16],
    pub(super) next_header: u8,
    pub(super) extension_count: usize,
    pub(super) transport: &'a [u8],
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(super) struct BehaviorFlowKey {
    pub(super) source: String,
    pub(super) destination: String,
    pub(super) source_port: u16,
    pub(super) destination_port: u16,
    pub(super) protocol: String,
}

#[derive(Debug, Default)]
pub(super) struct BeaconState {
    pub(super) timestamps: Vec<f64>,
    pub(super) sizes: Vec<u16>,
    pub(super) last_seen: f64,
    pub(super) alerted: bool,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(super) struct ExfilKey {
    pub(super) internal: String,
    pub(super) external: String,
    pub(super) destination_port: u16,
    pub(super) protocol: String,
}

#[derive(Debug, Default)]
pub(super) struct ExfilState {
    pub(super) outbound_bytes: u64,
    pub(super) inbound_bytes: u64,
    pub(super) high_entropy_bytes: u64,
    pub(super) last_seen: f64,
    pub(super) volume_alerted: bool,
    pub(super) entropy_alerted: bool,
}

#[derive(Debug, Default)]
pub(super) struct TimedCountState {
    pub(super) timestamps: Vec<f64>,
    pub(super) last_seen: f64,
    pub(super) alerted: bool,
}

#[derive(Debug, Default)]
pub(super) struct TimedTargetState {
    pub(super) targets: Vec<(f64, String)>,
    pub(super) last_seen: f64,
    pub(super) alerted: bool,
}

#[derive(Debug, Default)]
pub(super) struct DhcpVlanState {
    pub(super) servers: HashSet<Vec<u8>>,
    pub(super) clients: Vec<(f64, Vec<u8>)>,
    pub(super) starvation_alerted: bool,
}

pub(super) struct DhcpMessage {
    pub(super) message_type: u8,
    pub(super) client_identity: Vec<u8>,
    pub(super) server_identity: Vec<u8>,
}

#[derive(Debug, Default)]
pub(super) struct HttpHeaderState {
    pub(super) bytes: Vec<u8>,
    pub(super) last_seen: f64,
    pub(super) complete: bool,
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
pub(super) struct BfKey {
    pub(super) src: String,
    pub(super) dst: String,
    pub(super) port: u16,
}

pub(super) struct BfWindow {
    pub(super) timestamps: Vec<f64>,
    pub(super) service: &'static str,
    pub(super) alerted: bool,
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
pub(super) struct DnsAccum {
    pub(super) queries: u64,
    pub(super) max_entropy: f64,
    pub(super) max_len: usize,
    pub(super) unique_subs: std::collections::HashSet<String>,
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
    pub ipv6_reassembled: u64,
}

// ─── Security Engine ──────────────────────────────────────────────────────────
