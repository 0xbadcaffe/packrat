use super::*;
use super::scans::ScanProbe;

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct FragmentKey {
    pub(super) src: [u8; 4],
    pub(super) dst: [u8; 4],
    pub(super) identification: u16,
    pub(super) protocol: u8,
}

#[derive(Debug, Clone)]
pub(super) struct FragmentSlice {
    pub(super) packet_no: u64,
    pub(super) start: u32,
    pub(super) data: Vec<u8>,
}

#[derive(Debug, Default)]
pub(super) struct FragmentState {
    pub(super) slices: Vec<FragmentSlice>,
    pub(super) retained_bytes: usize,
    pub(super) offset_frames: Vec<(u32, u64)>,
    pub(super) last_seen: f64,
    pub(super) overlap_alerted: bool,
}

impl FragmentState {
    pub(super) fn observe_offset(&mut self, frame: u64, fragment: &Ipv4Fragment<'_>) -> Option<Vec<u64>> {
        let length = fragment.declared_payload_len;
        if self.offset_frames.len() > MAX_FRAGMENTS_PER_DATAGRAM
            || fragment.malformed_length || length == 0 || fragment.payload.len() != length
            || (fragment.more_fragments && length % 8 != 0)
            || fragment.offset as usize + length > MAX_FRAGMENT_EVIDENCE_BYTES - 20
            || self.offset_frames.iter().any(|&(offset, _)| offset == fragment.offset)
        {
            return None;
        }
        self.offset_frames.push((fragment.offset, frame));
        (self.offset_frames.len() > MAX_FRAGMENTS_PER_DATAGRAM).then(|| {
            self.offset_frames[..MAX_FRAGMENTS_PER_DATAGRAM].iter().map(|&(_, frame)| frame).collect()
        })
    }

    pub(super) fn remember(&mut self, packet_no: u64, offset: u32, payload: &[u8]) {
        if payload.is_empty()
            || self.slices.len() >= MAX_FRAGMENTS_PER_DATAGRAM
            || payload.len() > MAX_FRAGMENT_EVIDENCE_BYTES.saturating_sub(self.retained_bytes)
            || self.slices.iter().any(|slice| slice.start == offset && slice.data == payload)
        {
            return;
        }
        self.retained_bytes += payload.len();
        self.slices.push(FragmentSlice { packet_no, start: offset, data: payload.to_vec() });
    }
}

pub(super) struct Ipv4Fragment<'a> {
    pub(super) key: FragmentKey,
    pub(super) offset: u32,
    pub(super) more_fragments: bool,
    pub(super) payload: &'a [u8],
    pub(super) declared_payload_len: usize,
    pub(super) malformed_length: bool,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct TcpFlowKey {
    pub(super) endpoint_a: std::net::SocketAddr,
    pub(super) endpoint_b: std::net::SocketAddr,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct TcpResetObservation {
    pub(super) packet_no: u64,
    pub(super) timestamp: f64,
    pub(super) sequence: u32,
    pub(super) from_a: bool,
}

#[derive(Debug, Default)]
pub(super) struct TcpIntegrityState {
    pub(super) from_a: TcpPayloadHistory,
    pub(super) from_b: TcpPayloadHistory,
    pub(super) last_seen: f64,
    pub(super) last_seen_frame: u64,
    pub(super) opening_sequences: [Option<u32>; 2],
    pub(super) started_at: Option<f64>,
    pub(super) past_opening: bool,
    pub(super) reset: Option<TcpResetObservation>,
    pub(super) overlap_alerted: bool,
    pub(super) post_reset_alerted: bool,
}

#[derive(Debug, Default)]
pub(super) struct TcpPayloadHistory {
    pub(super) slices: std::collections::VecDeque<FragmentSlice>,
    pub(super) bytes: usize,
}

impl TcpPayloadHistory {
    pub(super) fn contains(&self, start: u32, payload: &[u8]) -> bool {
        self.slices.iter().any(|slice| slice.start == start && slice.data == payload)
    }

    pub(super) fn remember_distinct(&mut self, packet_no: u64, start: u32, payload: &[u8]) {
        if payload.is_empty() || payload.len() > MAX_TCP_EVIDENCE_BYTES_PER_DIRECTION {
            return;
        }
        while self.slices.len() >= MAX_TCP_SLICES_PER_DIRECTION
            || payload.len() > MAX_TCP_EVIDENCE_BYTES_PER_DIRECTION - self.bytes
        {
            let Some(oldest) = self.slices.pop_front() else { return };
            self.bytes -= oldest.data.len();
        }
        self.bytes += payload.len();
        self.slices.push_back(FragmentSlice { packet_no, start, data: payload.to_vec() });
    }
}

pub(super) struct TcpSegment<'a> {
    pub(super) key: TcpFlowKey,
    pub(super) from_a: bool,
    pub(super) sequence: u32,
    pub(super) acknowledgement: u32,
    pub(super) flags: u8,
    pub(super) complete: bool,
    pub(super) payload: &'a [u8],
}

pub(super) enum TcpFrame<'a> {
    Malformed(&'static str),
    Segment(TcpSegment<'a>),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(super) struct ScanSourceKey {
    pub(super) address: String,
    pub(super) transport: &'static str,
    pub(super) scope: ServiceScope,
}

#[derive(Debug, Default)]
pub(super) struct SourceScanState {
    pub(super) probes: Vec<ScanProbe>,
    pub(super) vertical_alerted: HashSet<String>,
    pub(super) horizontal_alerted: HashSet<u16>,
    pub(super) icmp_alerted: bool,
    pub(super) last_seen: f64,
}

#[derive(Debug, Default)]
pub(super) struct SynFloodState {
    pub(super) attempts: Vec<SynAttempt>,
    pub(super) alerted: bool,
    pub(super) last_seen: f64,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct SynTargetKey {
    pub(super) address: String,
    pub(super) port: u16,
    pub(super) scope: ServiceScope,
}

#[derive(Debug)]
pub(super) struct SynAttempt {
    pub(super) source: String,
    pub(super) source_port: u16,
    pub(super) sequence: u32,
    pub(super) timestamp: f64,
    pub(super) packet_no: u64,
}

#[derive(Debug, Default)]
pub(super) struct RouterAdvertisementState {
    pub(super) samples: std::collections::VecDeque<(f64, u64)>,
    pub(super) alerted: bool,
    pub(super) invalid_source_alerted: bool,
    pub(super) last_seen: f64,
}

pub(super) struct Ipv6Inspection<'a> {
    pub(super) hop_limit: u8,
    pub(super) source: [u8; 16],
    pub(super) destination: [u8; 16],
    pub(super) next_header: u8,
    pub(super) extension_count: usize,
    pub(super) fragmented: bool,
    pub(super) complete: bool,
    pub(super) transport: &'a [u8],
}

#[derive(Clone, Copy)]
pub(super) enum Ipv6Probe {
    Tcp(TcpSignal),
    EmptyUdp(u16),
    EchoRequest,
}

#[derive(Clone, Copy)]
pub(super) struct TcpSignal {
    pub(super) flags: u8,
    pub(super) sequence: u32,
    pub(super) acknowledgement: u32,
    pub(super) source_port: u16,
    pub(super) destination_port: u16,
    pub(super) complete: bool,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct BehaviorFlowKey {
    pub(super) first: (String, u16),
    pub(super) second: (String, u16),
    pub(super) transport: &'static str,
    pub(super) scope: ServiceScope,
}

#[derive(Debug)]
pub(super) struct BeaconSample {
    pub(super) timestamp: f64,
    pub(super) size: u32,
    pub(super) packet_no: u64,
}

#[derive(Debug, Default)]
pub(super) struct BeaconState {
    pub(super) directions: [Vec<BeaconSample>; 2],
    pub(super) last_seen: f64,
    pub(super) alerted: bool,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(super) enum TransferTransport {
    Tcp,
    Udp,
    Other(String),
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(super) struct ExfilKey {
    pub(super) internal: String,
    pub(super) external: String,
    pub(super) destination_port: u16,
    pub(super) transport: TransferTransport,
    pub(super) scope: ServiceScope,
}

#[derive(Debug, Default)]
pub(super) struct ExfilState {
    pub(super) outbound_bytes: u64,
    pub(super) outbound_payload_bytes: u64,
    pub(super) inbound_bytes: u64,
    pub(super) high_entropy_bytes: u64,
    pub(super) last_seen: f64,
    pub(super) volume_alerted: bool,
    pub(super) entropy_alerted: bool,
    pub(super) outbound_frames: std::collections::VecDeque<(i64, u64)>,
    pub(super) inbound_frames: std::collections::VecDeque<(i64, u64)>,
    pub(super) entropy_frames: std::collections::VecDeque<(i64, u64)>,
    pub(super) buckets: std::collections::VecDeque<TransferBucket>,
}

#[derive(Debug, Default)]
pub(super) struct TransferBucket {
    pub(super) minute: i64,
    pub(super) outbound: u64,
    pub(super) outbound_payload: u64,
    pub(super) inbound: u64,
    pub(super) entropy: u64,
}

#[derive(Debug, Default)]
pub(super) struct NtlmFanoutState {
    pub(super) targets: std::collections::BTreeMap<String, (f64, u64)>,
    pub(super) last_seen: f64,
    pub(super) alerted: bool,
}

#[derive(Debug, Default)]
pub(super) struct DhcpScopeState {
    pub(super) servers: std::collections::BTreeMap<std::net::Ipv4Addr, (f64, u64)>,
    pub(super) server_high_water: f64,
    pub(super) clients: std::collections::BTreeMap<Vec<u8>, (f64, u64)>,
    pub(super) last_seen: f64,
    pub(super) client_high_water: f64,
    pub(super) starvation_alerted: bool,
}

pub(super) struct DhcpMessage {
    pub(super) message_type: u8,
    pub(super) client_identity: Vec<u8>,
    pub(super) server_identifier: Option<std::net::Ipv4Addr>,
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

#[derive(Debug, Clone, Copy)]
pub(super) struct ArpObservation {
    pub(super) announcement: bool,
    pub(super) mac: [u8; 6],
    pub(super) timestamp: f64,
    pub(super) frame: u64,
}

#[derive(Clone, Copy)]
pub(super) struct NdpObservation {
    pub(super) mac: [u8; 6],
    pub(super) timestamp: f64,
    pub(super) frame: u64,
}

#[derive(Hash, PartialEq, Eq)]
pub(super) struct LldpKey {
    pub(super) scope: ServiceScope,
    pub(super) source: [u8; 6],
    pub(super) destination: [u8; 6],
    pub(super) port: Vec<u8>,
}

pub(super) struct LldpObservation {
    pub(super) chassis: Vec<u8>,
    pub(super) frame: u64,
    pub(super) seen_at: f64,
    pub(super) expires_at: f64,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct ArpClaimHistory {
    pub(super) latest: ArpObservation,
    pub(super) previous_owner: Option<ArpObservation>,
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
    pub packet_refs: Vec<u64>,
}

/// Internal tracking key for brute force attempts
#[derive(Hash, Eq, PartialEq, Clone)]
pub(super) struct BfKey {
    pub(super) src: String,
    pub(super) dst: String,
    pub(super) port: u16,
    pub(super) service: &'static str,
    pub(super) scope: ServiceScope,
}

pub(super) type ServiceScope = (Option<(u32, u32)>, Option<u16>, Option<u16>);

pub(super) fn service_scope(pkt: &Packet) -> ServiceScope {
    (
        pkt.capture.as_ref().map(|c| (c.section_id, c.interface_id)),
        pkt.outer_vlan_id,
        pkt.vlan_id,
    )
}

pub(super) struct BfWindow {
    pub(super) observations: Vec<AuthObservation>,
    pub(super) last_seen: f64,
    pub(super) alerted: bool,
}

pub(super) struct AuthObservation {
    pub(super) timestamp: f64,
    pub(super) packet_no: u64,
    pub(super) transport_token: (u16, u32),
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
