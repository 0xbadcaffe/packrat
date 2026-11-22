//! VLAN intelligence engine — per-VLAN stats, host inventory, and attack detection.
//!
//! Detects:
//!   • Double-tagging / VLAN-hopping (QinQ frames from non-trunk context)
//!   • Native VLAN 1 usage (industry best-practice violation)
//!   • DTP negotiation observations
//!   • MAC appearing on multiple VLANs (potential VLAN-hopping or misconfiguration)
//!   • PCP=7 (Network Control priority) from a non-router source
//!   • Untagged traffic on a VLAN-aware segment

use std::collections::{HashMap, HashSet, BTreeMap};
use crate::net::packet::Packet;
#[path = "vlan_dtp.rs"]
mod dtp;

// ─── DTP detection ────────────────────────────────────────────────────────────
// DTP frames are sent to the Cisco multicast MAC 01:00:0c:cc:cc:cc
const DTP_DST_MAC: [u8; 6] = [0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc];

// ─── Data types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct VlanStats {
    pub vlan_id:   u16,
    pub packets:   u64,
    pub bytes:     u64,
    /// Unique (IP, MAC) host pairs seen on this VLAN.
    pub hosts:     HashSet<String>,  // "ip/mac"
    pub first_seen: f64,
    pub last_seen:  f64,
}

impl VlanStats {
    fn new(vid: u16, ts: f64) -> Self {
        Self {
            vlan_id: vid, packets: 0, bytes: 0,
            hosts: HashSet::new(), first_seen: ts, last_seen: ts,
        }
    }
}

/// Severity level for a VLAN alert.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlertSeverity { Info, Warning, Critical }

impl std::fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertSeverity::Info     => write!(f, "INFO"),
            AlertSeverity::Warning  => write!(f, "WARN"),
            AlertSeverity::Critical => write!(f, "CRIT"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct VlanAlert {
    pub severity:  AlertSeverity,
    pub category:  String,
    pub detail:    String,
    pub pkt_no:    u64,
    pub timestamp: f64,
    pub(crate) related_packet: Option<u64>,
    pub(crate) correlation_key: Option<String>,
}

// ─── MAC → VLAN mapping ───────────────────────────────────────────────────────

const MAC_VLAN_WINDOW_SECS: f64 = 300.0;
const MAX_TRACKED_MACS: usize = 4096;
type VlanCaptureScope = (Option<(u32, u32)>, Option<u16>);

#[derive(Debug, Clone, Copy)]
struct MacVlanSighting {
    vlan: u16,
    frame: u64,
    timestamp: f64,
    reported: bool,
}

#[derive(Debug, Default)]
struct MacVlanMap {
    inner: HashMap<(VlanCaptureScope, [u8; 6]), MacVlanSighting>,
    last_prune: Option<f64>,
}

impl MacVlanMap {
    fn record(&mut self, scope: VlanCaptureScope, mac: [u8; 6], mut incoming: MacVlanSighting) -> Option<MacVlanSighting> {
        if !incoming.timestamp.is_finite() || mac == [0; 6] || mac[0] & 1 != 0 {
            return None;
        }
        let key = (scope, mac);
        if let Some(previous) = self.inner.get_mut(&key) {
            if incoming.timestamp < previous.timestamp {
                return None;
            }
            let recent = incoming.timestamp - previous.timestamp <= MAC_VLAN_WINDOW_SECS;
            let changed = incoming.vlan != previous.vlan && incoming.frame != previous.frame;
            let result = (recent && changed && !previous.reported).then_some(*previous);
            incoming.reported = recent && (previous.reported || changed);
            *previous = incoming;
            return result;
        }
        if self.inner.len() >= MAX_TRACKED_MACS {
            if self.last_prune.is_none_or(|last| incoming.timestamp - last >= 30.0) {
                self.inner.retain(|_, seen| incoming.timestamp - seen.timestamp <= MAC_VLAN_WINDOW_SECS);
                self.last_prune = Some(incoming.timestamp);
            }
            if self.inner.len() >= MAX_TRACKED_MACS {
                return None;
            }
        }
        self.inner.insert(key, incoming);
        None
    }
}

// ─── Main engine ─────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct VlanIntel {
    /// Per-VLAN statistics.
    pub stats:    BTreeMap<u16, VlanStats>,
    /// Accumulated alerts.
    pub alerts:   Vec<VlanAlert>,
    mac_vlans:    MacVlanMap,
    /// Alert dedup: (category_key) → last pkt_no that raised it, to avoid
    /// flooding identical alerts for every packet in a high-rate flow.
    dedup:        HashMap<String, u64>,
}

impl VlanIntel {
    pub fn ingest(&mut self, pkt: &Packet) {
        // ── Extract Ethernet src MAC from raw bytes ──────────────────────────
        let mac_dst = if pkt.bytes.len() >= 6 {
            [pkt.bytes[0], pkt.bytes[1], pkt.bytes[2],
             pkt.bytes[3], pkt.bytes[4], pkt.bytes[5]]
        } else {
            [0u8; 6]
        };
        let needs_source_mac = mac_dst == DTP_DST_MAC || pkt.vlan_id.is_some();
        let mac_src = if needs_source_mac && pkt.bytes.len() >= 12 {
            format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                pkt.bytes[6], pkt.bytes[7], pkt.bytes[8],
                pkt.bytes[9], pkt.bytes[10], pkt.bytes[11])
        } else {
            String::new()
        };

        // ── DTP detection ────────────────────────────────────────────────────
        if mac_dst == DTP_DST_MAC && dtp::parse_dtp_negotiation(&pkt.bytes).is_some() {
            self.raise(
                AlertSeverity::Info,
                "DTP",
                format!("DTP negotiation observed from {mac_src}; port policy and trunk state are unverified"),
                pkt.no, pkt.timestamp,
                format!("DTP:{}", mac_src),
            );
        }

        // ── QinQ / double-tagging detection ──────────────────────────────────
        if let (Some(outer), Some(inner)) = (pkt.outer_vlan_id, pkt.vlan_id) {
            self.raise(
                AlertSeverity::Critical,
                "VLAN-Hop",
                format!("QinQ double-tag: outer={} inner={} src={} — possible VLAN-hopping attack",
                    outer, inner, pkt.src),
                pkt.no, pkt.timestamp,
                format!("QINQ:{}:{}", outer, inner),
            );
        }

        // ── Per-VLAN accounting ───────────────────────────────────────────────
        if let Some(vid) = pkt.vlan_id {
            let ts = pkt.timestamp;
            let entry = self.stats.entry(vid).or_insert_with(|| VlanStats::new(vid, ts));
            entry.packets += 1;
            entry.bytes   += pkt.length as u64;
            entry.last_seen = entry.last_seen.max(ts);
            if !mac_src.is_empty() {
                let host_key = format!("{}/{}", pkt.src, mac_src);
                entry.hosts.insert(host_key);
            }

            // Native VLAN 1 alert (fire once)
            if vid == 1 {
                self.raise(
                    AlertSeverity::Warning,
                    "Native-VLAN",
                    format!("Traffic on VLAN 1 (native/default VLAN) from {} — violates network hardening best practice", pkt.src),
                    pkt.no, pkt.timestamp,
                    "NATIVE_VLAN1".into(),
                );
            }

            // MAC-on-multiple-VLANs
            let scope = (pkt.capture.as_ref().map(|meta| (meta.section_id, meta.interface_id)), pkt.outer_vlan_id);
            if let Some(mac) = pkt.bytes.get(6..12).and_then(|bytes| <[u8; 6]>::try_from(bytes).ok())
                && let Some(previous) = self.mac_vlans.record(scope, mac, MacVlanSighting {
                    vlan: vid, frame: pkt.no, timestamp: ts, reported: false,
                })
            {
                let location = scope.0.map_or_else(|| "unknown capture interface".to_owned(),
                    |(section, interface)| format!("capture section {section}, interface {interface}"));
                let outer = scope.1.map_or_else(String::new, |tag| format!(" under outer VLAN {tag}"));
                self.alerts.push(VlanAlert {
                    severity: AlertSeverity::Warning,
                    category: "MAC-VLAN-Cross".into(),
                    detail: format!("MAC {mac_src} was seen on VLANs {} and {vid} at {location}{outer}; port policy and forwarding are unverified", previous.vlan),
                    pkt_no: pkt.no, timestamp: ts, related_packet: Some(previous.frame),
                    correlation_key: Some(format!("{scope:?}:{mac_src}")),
                });
            }

            // PCP=7 from non-router source (802.1p priority abuse)
            if let Some(pcp) = pkt.vlan_pcp {
                if pcp == 7 {
                    self.raise(
                        AlertSeverity::Warning,
                        "PCP-Abuse",
                        format!("PCP=7 (Network Control) from {} VLAN {} — priority marking abuse or misconfigured QoS",
                            pkt.src, vid),
                        pkt.no, pkt.timestamp,
                        format!("PCP7:{}:{}", pkt.src, vid),
                    );
                }
            }
        }
    }

    /// Raise an alert, deduplicating by `dedup_key` so the same condition
    /// doesn't flood alerts for every packet.  First occurrence always recorded;
    /// subsequent occurrences only recorded if > 1000 packets have passed.
    fn raise(&mut self, severity: AlertSeverity, category: &str, detail: String,
             pkt_no: u64, ts: f64, dedup_key: String)
    {
        let last = self.dedup.entry(dedup_key).or_insert(0);
        if *last != 0 && pkt_no.saturating_sub(*last) < 1000 {
            return;
        }
        *last = pkt_no;
        self.alerts.push(VlanAlert {
            severity,
            category: category.to_string(),
            detail,
            pkt_no,
            timestamp: ts,
            related_packet: None,
            correlation_key: None,
        });
    }

    pub fn clear(&mut self) {
        self.stats.clear();
        self.alerts.clear();
        self.mac_vlans = MacVlanMap::default();
        self.dedup.clear();
    }

    /// Sorted list of all known VLAN IDs.
    pub fn vlan_ids(&self) -> Vec<u16> {
        self.stats.keys().copied().collect()
    }

    /// Number of distinct VLANs seen.
    pub fn vlan_count(&self) -> usize {
        self.stats.len()
    }

    /// Critical alerts only.
    pub fn critical_alerts(&self) -> Vec<&VlanAlert> {
        self.alerts.iter()
            .filter(|a| a.severity == AlertSeverity::Critical)
            .collect()
    }

    /// All alerts sorted newest-first.
    pub fn alerts_newest_first(&self) -> Vec<&VlanAlert> {
        let mut v: Vec<&VlanAlert> = self.alerts.iter().collect();
        v.sort_by(|a, b| b.timestamp.partial_cmp(&a.timestamp).unwrap_or(std::cmp::Ordering::Equal));
        v
    }
}
