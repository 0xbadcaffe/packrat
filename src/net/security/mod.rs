//! Passive security analysis engine — IDS signatures, ARP anomaly, OS fingerprinting,
//! vulnerability patterns, brute-force detection, HTTP analytics, TLS/SSL weakness,
//! and DNS exfiltration scoring.

use crate::analysis::dns_transactions::{DnsFindingKind, DnsTransactionTracker};
use crate::analysis::industrial_policy;
use crate::analysis::ipv6_fragments::{Ipv6FragmentOutcome, Ipv6FragmentReassembler};
use crate::net::inspector::shannon_entropy;
use crate::net::packet::Packet;
use crate::net::parser::ethernet_network_header;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

// ─── Byte helpers ─────────────────────────────────────────────────────────────

#[inline]
fn byte_at(b: &[u8], off: usize) -> u8 {
    b.get(off).copied().unwrap_or(0)
}

#[inline]
fn u16_be_at(b: &[u8], off: usize) -> u16 {
    if b.len() >= off + 2 {
        u16::from_be_bytes([b[off], b[off + 1]])
    } else {
        0
    }
}

const MAX_ENTRIES: usize = 1000;
const MAX_FRAGMENT_DATAGRAMS: usize = 512;
const MAX_FRAGMENTS_PER_DATAGRAM: usize = 64;
const MAX_FRAGMENT_EVIDENCE_BYTES: usize = u16::MAX as usize;
const FRAGMENT_STATE_TTL_SECS: f64 = 60.0;
const MAX_TCP_FLOWS: usize = 512;
const MAX_TCP_SLICES_PER_DIRECTION: usize = 128;
const MAX_TCP_EVIDENCE_BYTES_PER_DIRECTION: usize = u16::MAX as usize;
const TCP_STATE_TTL_SECS: f64 = 300.0;
const SCAN_WINDOW_SECS: f64 = 15.0;
const SYN_FLOOD_WINDOW_SECS: f64 = 1.0;
const SYN_RETRY_HISTORY_SECS: f64 = 3.0;
const MAX_SYN_HISTORY_PER_TARGET: usize = 256;
const SCAN_UNIQUE_THRESHOLD: usize = 12;
const MAX_SCAN_PROBES_PER_SOURCE: usize = 128;
const SYN_FLOOD_THRESHOLD: usize = 100;
const MAX_SCAN_STATES: usize = 512;
const RA_FLOOD_THRESHOLD: usize = 20;
const MAX_CONTROL_PLANE_IDENTITIES: usize = 1024;
const BEACON_MIN_SAMPLES: usize = 7;
const BEACON_WINDOW_SECS: f64 = 3600.0;
const EXFIL_VOLUME_THRESHOLD: u64 = 1_000_000;
const EXFIL_ENTROPY_THRESHOLD: u64 = 256_000;
const LATERAL_TARGET_THRESHOLD: usize = 8;
const DHCP_STARVATION_THRESHOLD: usize = 64;

/// Stable names emitted by Packrat's built-in passive detectors. Tests require
/// every entry to declare positive replay coverage and a negative control.
pub const DETECTOR_SIGNATURES: &[&str] = &[
    "Malformed IPv4 fragment",
    "Tiny IPv4 fragment",
    "Conflicting IPv4 fragments",
    "IPv4 fragment flood",
    "Malformed TCP header",
    "Illegal TCP flag combination",
    "TCP payload after reset",
    "Conflicting TCP retransmission",
    "TCP stealth scan probe",
    "Vertical port scan",
    "Horizontal host scan",
    "SYN arrival spike",
    "ICMP address sweep",
    "Excessive IPv6 extension headers",
    "Invalid IPv6 neighbor discovery hop limit",
    "Invalid IPv6 router advertisement source",
    "IPv6 router advertisement flood",
    "IPv6 default router Ethernet source changed",
    "IPv6 neighbor binding changed",
    "STP topology change",
    "LLDP chassis identity changed",
    "ARP reply sender differs from Ethernet source",
    "Alternating ARP claims",
    "ARP announcement binding changed",
    "Periodic fixed-size traffic",
    "Large asymmetric outbound transfer",
    "High-entropy outbound transfer",
    "DNS NXDOMAIN burst",
    "DNS tunnel behavior",
    "Oversized DNS TXT traffic",
    "Direct external DNS resolver use",
    "Administrative service response fan-out",
    "NTLM authentication fan-out",
    "DHCP server identity changed",
    "DHCP client identity burst",
    "Conflicting IPv6 fragments",
    "IPv6 fragment reassembly rejected",
    "HTTP request smuggling ambiguity",
    "Cleartext HTTP Basic authorization",
    "Anonymous FTP login accepted",
    "Telnet authentication prompt",
    "Critical industrial control command",
    "Industrial state-changing command",
    "DNS reply without observed query",
    "DNS reply correlation ambiguous",
    "DNS invalid question count",
    "DNS transaction question mismatch",
    "Unexpected DNS responder",
    "Conflicting DNS responses",
    "DNS reply changed at the same resolver",
    "DNS answer set changed at the same resolver",
    "SMBv1 server response",
    "SMB2 anonymous session accepted",
    "SSL 3.0 selected",
    "TLS 1.0 selected",
    "TLS 1.1 selected",
    "RC4 selected",
    "Log4Shell (CVE-2021-44228)",
    "Repeated NOP-like byte pattern",
    "NBNS WPAD address reply",
    "Directory Traversal",
    "SQL Injection Probe",
    "XSS Probe",
    "Heartbleed (CVE-2014-0160)",
    "JNDI label in DNS query",
];

mod admin_fanout;
mod behavior;
use behavior::{BeaconSample, BeaconState, BehaviorFlowKey};
mod control_plane;
mod dns;
mod engine;
mod findings;
pub use findings::{ArpFinding, DetectionBatch, IdsFinding};
mod fragments;
mod ftp_control;
mod http_policy;
mod http_tls;
mod identities;
mod ipv4_wire;
mod ipv6_wire;
mod nbns_wire;
mod ntlm_fanout;
mod protocol_policy;
mod scans;
mod signatures;
mod smb_wire;
mod tcp_wire;
mod telnet_wire;
mod tracking_helpers;
mod types;
mod vulnerabilities;
use http_policy::*;
use ipv4_wire::*;
use ipv6_wire::*;
use tcp_wire::parse_tcp_transport;
use tracking_helpers::*;
use types::*;
pub use types::{
    ArpAnomaly, BruteForceAlert, DnsTunnelSuspect, HttpRecord, IdsAlert, OsGuess, SecuritySummary,
    Severity, TlsWeakness, VulnHit,
};

pub struct SecurityEngine {
    findings: DetectionBatch,
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
    ip_to_mac: HashMap<(ServiceScope, std::net::Ipv4Addr), ArpClaimHistory>,
    os_by_ip: HashMap<String, &'static str>,
    bf_windows: HashMap<BfKey, BfWindow>,
    dns_tunnel: dns::DnsTunnelTracker,
    fragment_states: HashMap<(ServiceScope, FragmentKey), FragmentState>,
    ipv4_fragment_evidence: crate::net::recent_evidence::RecentEvidence<1024, 120>,
    tcp_integrity: HashMap<(ServiceScope, TcpFlowKey), TcpIntegrityState>,
    tcp_overlap_evidence: crate::net::recent_evidence::RecentEvidence<1024, 300>,
    scan_sources: HashMap<ScanSourceKey, SourceScanState>,
    scan_packet_evidence: crate::net::recent_evidence::RecentEvidence<2048, 30>,
    echo_sweep_evidence: crate::net::recent_evidence::RecentEvidence<1024, 30>,
    syn_flood_targets: HashMap<SynTargetKey, SynFloodState>,
    syn_arrival_evidence: crate::net::recent_evidence::RecentEvidence<1024, 3>,
    ndp_bindings: HashMap<(ServiceScope, [u8; 16]), NdpObservation>,
    router_advertisements: HashMap<control_plane::RouterSource, RouterAdvertisementState>,
    router_rate_evidence: control_plane::RouterRateEvidence,
    default_router_links: HashMap<(ServiceScope, [u8; 16]), control_plane::RouterLink>,
    lldp_chassis: HashMap<LldpKey, LldpObservation>,
    beacon_flows: HashMap<BehaviorFlowKey, BeaconState>,
    exfil_flows: HashMap<ExfilKey, ExfilState>,
    admin_fanout: admin_fanout::AdminFanout,
    ftp_control: ftp_control::FtpControl,
    ntlm_fanout: ntlm_fanout::NtlmFanout,
    dhcp_scopes: HashMap<(ServiceScope, Option<Ipv4Addr>), DhcpScopeState>,
    dhcp_server_evidence: crate::net::recent_evidence::RecentEvidence<1024, 3600>,
    dhcp_client_evidence: crate::net::recent_evidence::RecentEvidence<1024, 10>,
    ipv6_fragments: Ipv6FragmentReassembler,
    ipv6_fragment_evidence: crate::net::recent_evidence::RecentEvidence<1024, 120>,
    pub ipv6_reassembled: u64,
    http_headers: HashMap<(TcpFlowKey, bool), HttpHeaderState>,
    dns_transactions: DnsTransactionTracker,
    // Covers the pending-query lifetime plus the reply comparison window.
    dns_packet_evidence: crate::net::recent_evidence::RecentEvidence<2048, 70>,
    // External credential count (set by caller)
    pub cred_hit_count: usize,
}

impl Default for SecurityEngine {
    fn default() -> Self {
        Self::new()
    }
}
