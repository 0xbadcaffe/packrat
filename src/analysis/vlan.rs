//! VLAN intelligence engine: per-VLAN stats, host inventory, and wire observations.
//!
//! Detects:
//!   • Stacked VLAN tags observed on the wire
//!   • VLAN ID 1 observed in a tag
//!   • DTP negotiation observations
//!   • MAC appearing on multiple VLANs (potential VLAN-hopping or misconfiguration)
//!   • PCP=7 (Network Control marking) observed in a tag

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use crate::net::packet::Packet;
#[path = "vlan_dtp.rs"]
mod dtp;
#[path = "vlan_policy.rs"]
mod policy;
pub use policy::VlanPolicy;

// ─── DTP detection ────────────────────────────────────────────────────────────
// DTP frames are sent to the Cisco multicast MAC 01:00:0c:cc:cc:cc
const DTP_DST_MAC: [u8; 6] = [0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc];
const MAX_RECENT_VLAN_ALERTS: usize = 512;
const MAX_VLAN_DEDUP_KEYS: usize = 4096;
const MAX_HOST_SAMPLES_PER_VLAN: usize = 128;
const MAX_HOST_SAMPLES: usize = 16_384;

fn vlan_stack_prefix(raw: &[u8]) -> Option<([(u16, u16); 2], bool)> {
    let field = |offset| Some(u16::from_be_bytes(raw.get(offset..offset + 2)?.try_into().ok()?));
    let is_tag = |kind| matches!(kind, 0x8100 | 0x88a8);
    let outer = field(12)?;
    if !is_tag(outer) {
        return None;
    }
    let inner = field(16)?;
    if !is_tag(inner) {
        return None;
    }
    let deeper = is_tag(field(20)?);
    if deeper {
        field(24)?;
    }
    Some(([(outer, field(14)? & 0x0fff), (inner, field(18)? & 0x0fff)], deeper))
}

pub(super) const VLAN_ID_ONE: &str = "VLAN ID 1 observed";
pub(super) const VLAN_PCP_SEVEN: &str = "VLAN PCP 7 observed";

// ─── Data types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct VlanStats {
    pub vlan_id:   u16,
    pub packets:   u64,
    pub bytes:     u64,
    /// Bounded sample of distinct (IP, MAC) host pairs.
    pub hosts:     HashSet<String>,  // "ip/mac"
    pub host_samples_limited: bool,
    pub first_seen: f64,
    pub last_seen:  f64,
}

impl VlanStats {
    fn new(vid: u16, ts: f64) -> Self {
        Self {
            vlan_id: vid, packets: 0, bytes: 0,
            hosts: HashSet::new(), host_samples_limited: false, first_seen: ts, last_seen: ts,
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
    pub policy: VlanPolicy,
    /// Per-VLAN statistics.
    pub stats:    BTreeMap<u16, VlanStats>,
    /// Bounded history for display; the caller still receives each new finding.
    pub alerts: VecDeque<VlanAlert>,
    mac_vlans:    MacVlanMap,
    host_samples: usize,
    dedup: HashMap<Arc<str>, u64>,
    dedup_order: VecDeque<Arc<str>>,
}

impl VlanIntel {
    pub fn ingest(&mut self, pkt: &Packet) -> usize {
        let before = self.alerts.len();
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

        self.observe_tag_markings(pkt);

        let policy_interface = pkt.capture.as_ref().and_then(|meta| meta.interface_name.as_deref())
            .filter(|name| self.policy.expects_single_tag(name));
        if let Some(([(outer_type, outer), (inner_type, inner)], deeper)) = vlan_stack_prefix(&pkt.bytes)
            && (!deeper || policy_interface.is_some())
        {
            let scope = pkt.capture.as_ref().map(|meta| (meta.section_id, meta.interface_id));
            let key = format!("tag_stack:{scope:?}:{outer_type:04x}:{outer}:{inner_type:04x}:{inner}:{deeper}");
            if self.allow_alert(key.clone(), pkt.no) {
                let location = scope.map_or_else(|| "unknown capture interface".to_owned(),
                    |(section, interface)| format!("capture section {section}, interface {interface}"));
                let (severity, category, context) = if let Some(name) = policy_interface {
                    (AlertSeverity::Warning, "Unexpected VLAN tag stack",
                        format!("single-tag policy for {name:?} does not allow this stack; forwarding is unverified"))
                } else {
                    (AlertSeverity::Info, "Stacked VLAN tags", "port policy and forwarding are unverified".into())
                };
                let more = if deeper { "; at least three tags present" } else { "" };
                self.alerts.push_back(VlanAlert {
                    severity,
                    category: category.into(),
                    detail: format!("Observed outer VLAN {outer} (0x{outer_type:04x}) and inner VLAN {inner} (0x{inner_type:04x}) at {location}{more}; {context}"),
                    pkt_no: pkt.no, timestamp: pkt.timestamp, related_packet: None,
                    correlation_key: Some(key),
                });
            }
        }

        // ── Per-VLAN accounting ───────────────────────────────────────────────
        if let Some(vid) = pkt.vlan_id.filter(|&vid| vid <= 0x0fff) {
            let ts = pkt.timestamp;
            let entry = self.stats.entry(vid).or_insert_with(|| VlanStats::new(vid, ts));
            entry.packets += 1;
            entry.bytes   += pkt.length as u64;
            entry.last_seen = entry.last_seen.max(ts);
            if !mac_src.is_empty() && !entry.host_samples_limited {
                if pkt.src.len() > 128 {
                    entry.host_samples_limited = true;
                } else {
                    let host_key = format!("{}/{}", pkt.src, mac_src);
                    if entry.hosts.len() < MAX_HOST_SAMPLES_PER_VLAN && self.host_samples < MAX_HOST_SAMPLES {
                        self.host_samples += usize::from(entry.hosts.insert(host_key));
                    } else if !entry.hosts.contains(&host_key) {
                        entry.host_samples_limited = true;
                    }
                }
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
                self.alerts.push_back(VlanAlert {
                    severity: AlertSeverity::Warning,
                    category: "MAC-VLAN-Cross".into(),
                    detail: format!("MAC {mac_src} was seen on VLANs {} and {vid} at {location}{outer}; port policy and forwarding are unverified", previous.vlan),
                    pkt_no: pkt.no, timestamp: ts, related_packet: Some(previous.frame),
                    correlation_key: Some(format!("{scope:?}:{mac_src}")),
                });
            }

        }
        let added = self.alerts.len() - before;
        if self.alerts.len() > MAX_RECENT_VLAN_ALERTS {
            self.alerts.drain(..self.alerts.len() - MAX_RECENT_VLAN_ALERTS);
        }
        added
    }

    fn observe_tag_markings(&mut self, pkt: &Packet) {
        use crate::net::parser::{ethernet_network_header, supports_capture_link_type};
        let raw = &pkt.bytes;
        if !matches!(raw.get(12..14), Some([0x81, 0] | [0x88, 0xa8]))
            || pkt.capture.as_ref().is_some_and(|meta| !supports_capture_link_type(meta.link_type))
        {
            return;
        }
        let Some((network_offset, _)) = ethernet_network_header(raw) else { return };
        let tags = &raw[12..network_offset - 2];
        let scope = pkt.capture.as_ref().map(|meta| (meta.section_id, meta.interface_id));
        let outer = (tags.len() == 8).then(|| u16::from_be_bytes([tags[2], tags[3]]) & 0x0fff);
        for (index, tag) in tags.chunks_exact(4).enumerate() {
            let tpid = u16::from_be_bytes([tag[0], tag[1]]);
            let tci = u16::from_be_bytes([tag[2], tag[3]]);
            let vid = tci & 0x0fff;
            let role = match (outer, index) {
                (None, _) => "single",
                (Some(_), 0) => "outer",
                _ => "inner",
            };
            for (observed, title, meaning) in [
                (vid == 1, VLAN_ID_ONE, "the port's native VLAN and policy are unverified"),
                (tci >> 13 == 7, VLAN_PCP_SEVEN, "PCP=7 (Network Control); QoS policy and treatment are unverified"),
            ] {
                if !observed { continue; }
                let key = format!("{title}:{scope:?}:{outer:?}:{index}:{tpid:04x}:{vid}");
                if !self.allow_alert(key.clone(), pkt.no) { continue; }
                let location = scope.map_or_else(|| "unknown capture interface".to_owned(),
                    |(section, interface)| format!("capture section {section}, interface {interface}"));
                self.alerts.push_back(VlanAlert {
                    severity: AlertSeverity::Info,
                    category: title.into(),
                    detail: format!("{role} tag 0x{tpid:04x}, VID {vid} at {location}; {meaning}"),
                    pkt_no: pkt.no, timestamp: pkt.timestamp, related_packet: None,
                    correlation_key: Some(key),
                });
            }
        }
    }

    /// Raise an alert, deduplicating by `dedup_key` so the same condition
    /// doesn't flood alerts for every packet.  First occurrence always recorded;
    /// subsequent occurrences only recorded if > 1000 packets have passed.
    fn raise(&mut self, severity: AlertSeverity, category: &str, detail: String,
             pkt_no: u64, ts: f64, dedup_key: String)
    {
        if !self.allow_alert(dedup_key, pkt_no) {
            return;
        }
        self.alerts.push_back(VlanAlert {
            severity,
            category: category.to_string(),
            detail,
            pkt_no,
            timestamp: ts,
            related_packet: None,
            correlation_key: None,
        });
    }

    fn allow_alert(&mut self, key: String, pkt_no: u64) -> bool {
        if let Some(last) = self.dedup.get_mut(key.as_str()) {
            if pkt_no.saturating_sub(*last) < 1000 {
                return false;
            }
            *last = pkt_no;
            return true;
        }
        if self.dedup_order.len() == MAX_VLAN_DEDUP_KEYS
            && let Some(expired) = self.dedup_order.pop_front()
        {
            self.dedup.remove(&expired);
        }
        let key = Arc::<str>::from(key);
        self.dedup.insert(key.clone(), pkt_no);
        self.dedup_order.push_back(key);
        true
    }

    pub fn clear(&mut self) {
        self.stats.clear();
        self.alerts.clear();
        self.mac_vlans = MacVlanMap::default();
        self.host_samples = 0;
        self.dedup.clear();
        self.dedup_order.clear();
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

#[cfg(test)]
#[path = "../../tests/unit/analysis_vlan_retention_tests.rs"]
mod tests;
