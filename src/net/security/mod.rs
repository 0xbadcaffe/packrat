//! Passive security analysis engine — IDS signatures, ARP anomaly, OS fingerprinting,
//! vulnerability patterns, brute-force detection, HTTP analytics, TLS/SSL weakness,
//! and DNS exfiltration scoring.

use crate::analysis::dns_transactions::{DnsFindingKind, DnsTransactionTracker};
use crate::analysis::industrial_policy;
use crate::analysis::ipv6_fragments::{Ipv6FragmentOutcome, Ipv6FragmentReassembler};
use crate::net::inspector::shannon_entropy;
use crate::net::packet::Packet;
use std::collections::{HashMap, HashSet};

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
const FRAGMENT_STATE_TTL_SECS: f64 = 60.0;
const MAX_TCP_FLOWS: usize = 512;
const MAX_TCP_SLICES_PER_DIRECTION: usize = 128;
const TCP_STATE_TTL_SECS: f64 = 300.0;
const SCAN_WINDOW_SECS: f64 = 15.0;
const SYN_FLOOD_WINDOW_SECS: f64 = 1.0;
const SCAN_UNIQUE_THRESHOLD: usize = 12;
const SYN_FLOOD_THRESHOLD: usize = 100;
const MAX_SCAN_STATES: usize = 512;
const RA_FLOOD_THRESHOLD: usize = 20;
const MAX_CONTROL_PLANE_IDENTITIES: usize = 1024;
const BEACON_MIN_SAMPLES: usize = 7;
const EXFIL_VOLUME_THRESHOLD: u64 = 1_000_000;
const EXFIL_ENTROPY_THRESHOLD: u64 = 256_000;
const DNS_NXDOMAIN_THRESHOLD: usize = 20;
const LATERAL_TARGET_THRESHOLD: usize = 8;
const NTLM_TARGET_THRESHOLD: usize = 3;
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
    "SYN flood",
    "ICMP address sweep",
    "Excessive IPv6 extension headers",
    "Invalid IPv6 neighbor discovery hop limit",
    "Invalid IPv6 router advertisement source",
    "IPv6 router advertisement flood",
    "IPv6 neighbor binding changed",
    "STP topology change",
    "LLDP chassis identity changed",
    "Periodic command-and-control beacon",
    "Large asymmetric outbound transfer",
    "High-entropy outbound transfer",
    "DNS NXDOMAIN burst",
    "Oversized DNS TXT traffic",
    "Direct external DNS resolver use",
    "Administrative service fan-out",
    "NTLM authentication fan-out",
    "DHCP server identity changed",
    "DHCP client identity burst",
    "Conflicting IPv6 fragments",
    "IPv6 fragment reassembly rejected",
    "HTTP request smuggling ambiguity",
    "Critical industrial control command",
    "Industrial state-changing command",
    "Unsolicited DNS response",
    "DNS transaction question mismatch",
    "Unexpected DNS responder",
    "Conflicting DNS responses",
    "EternalBlue",
    "BlueKeep (CVE-2019-0708)",
    "Log4Shell (CVE-2021-44228)",
    "Shellcode NOP sled",
    "LLMNR Poisoning",
    "NBNS WPAD Poisoning",
    "Directory Traversal",
    "SQL Injection Probe",
    "XSS Probe",
    "Heartbleed (CVE-2014-0160)",
    "PrintNightmare (CVE-2021-1675)",
    "Pass-the-Hash (suspected)",
    "Log4Shell via DNS (CVE-2021-44228)",
];

mod behavior;
mod control_plane;
mod dns;
mod engine;
mod fragments;
mod http_policy;
mod http_tls;
mod identities;
mod ipv4_wire;
mod ipv6_wire;
mod protocol_policy;
mod scans;
mod signatures;
mod tracking_helpers;
mod types;
mod vulnerabilities;
use http_policy::*;
use ipv4_wire::*;
use ipv6_wire::*;
use tracking_helpers::*;
use types::*;
pub use types::{
    ArpAnomaly, BruteForceAlert, DnsTunnelSuspect, HttpRecord, IdsAlert, OsGuess, SecuritySummary,
    Severity, TlsWeakness, VulnHit,
};

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
    ndp_bindings: HashMap<[u8; 16], [u8; 6]>,
    router_advertisements: HashMap<[u8; 6], RouterAdvertisementState>,
    lldp_chassis: HashMap<[u8; 6], Vec<u8>>,
    beacon_flows: HashMap<BehaviorFlowKey, BeaconState>,
    exfil_flows: HashMap<ExfilKey, ExfilState>,
    nxdomain_clients: HashMap<String, TimedCountState>,
    external_dns_pairs: HashMap<(String, String), f64>,
    admin_fanout: HashMap<(String, u16), TimedTargetState>,
    ntlm_fanout: HashMap<String, TimedTargetState>,
    dhcp_vlans: HashMap<Option<u16>, DhcpVlanState>,
    ipv6_fragments: Ipv6FragmentReassembler,
    pub ipv6_reassembled: u64,
    http_headers: HashMap<(TcpFlowKey, bool), HttpHeaderState>,
    dns_transactions: DnsTransactionTracker,
    // External credential count (set by caller)
    pub cred_hit_count: usize,
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
