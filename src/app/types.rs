use super::*;

/// Sub-sections within the Security tab
#[derive(Debug, Clone, PartialEq)]
pub enum SecuritySubTab {
    Alerts,
    Ids,
    Credentials,
    OsFingerprint,
    ArpWatch,
    DnsTunnel,
    HttpAnalytics,
    TlsWeakness,
    BruteForce,
    VulnHits,
    IocHits,
    VlanIntel,
    ProcessScope,
    RoutePolicy,
    WirePulse,
    NetRegistry,
    Replay,
}

/// A single result from the global command palette search.
#[derive(Debug, Clone)]
pub struct SearchResult {
    pub packet_no: Option<u64>,
    pub(super) alert: Option<AlertSearchRef>,
    /// Short category label (e.g., "Packet", "Host", "IOC Hit", "Rule").
    pub source: &'static str,
    /// Primary display label shown in the list.
    pub label: String,
    /// Secondary detail shown alongside the label.
    pub detail: String,
    /// Tab to switch to when this result is selected.
    pub jump_tab: Tab,
    /// Optional scroll position to apply after tab switch.
    pub scroll: usize,
}

#[derive(Debug, Clone)]
pub(super) struct AlertSearchRef {
    pub(super) id: u64,
    pub(super) capture_id: Option<String>,
}

/// Sub-panels within the Objects tab
#[derive(Debug, Clone, PartialEq, Default)]
pub enum ObjectsSubTab {
    #[default]
    Objects,
    YaraRules,
    YaraMatches,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EncryptedView {
    #[default]
    Tls,
    Quic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvestigationView {
    Summary,
    Decode,
    Bytes,
    Flow,
    Strings,
    Encrypted,
    Security,
    Notes,
    Transactions,
}

impl InvestigationView {
    pub const COUNT: usize = 9;

    pub fn label(self) -> &'static str {
        match self {
            Self::Summary => "Summary",
            Self::Decode => "Headers",
            Self::Bytes => "Bytes",
            Self::Flow => "Flow",
            Self::Strings => "Strings",
            Self::Encrypted => "Encrypted",
            Self::Security => "Security",
            Self::Notes => "Notes",
            Self::Transactions => "Transactions",
        }
    }

    pub fn from_index(index: usize) -> Self {
        match index {
            1 => Self::Decode,
            2 => Self::Bytes,
            3 => Self::Flow,
            4 => Self::Strings,
            5 => Self::Encrypted,
            6 => Self::Security,
            7 => Self::Notes,
            8 => Self::Transactions,
            _ => Self::Summary,
        }
    }

    pub fn index(self) -> usize {
        match self {
            Self::Summary => 0,
            Self::Decode => 1,
            Self::Bytes => 2,
            Self::Flow => 3,
            Self::Strings => 4,
            Self::Encrypted => 5,
            Self::Security => 6,
            Self::Notes => 7,
            Self::Transactions => 8,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvestigationItem {
    Packet(u64),
    Stream(String),
    Host(String),
    Alert(u64),
    AlertRef { id: u64, capture_id: Option<String> },
    Object(u64),
    GraphNode(String),
    Note(u64),
}

impl InvestigationItem {
    pub(super) fn for_alert(alert: &crate::analysis::alert_center::AlertItem) -> Self {
        Self::AlertRef { id: alert.id, capture_id: alert.capture_id.clone() }
    }

    pub fn label(&self) -> String {
        match self {
            Self::Packet(no) => format!("Packet #{no}"),
            Self::Stream(id) => format!("Stream {id}"),
            Self::Host(address) => format!("Host {address}"),
            Self::Alert(id) => format!("Alert #{id}"),
            Self::AlertRef { id, capture_id: Some(scope) } => {
                let prefix: String = scope.chars().take(8).collect();
                format!("Alert #{id} [{prefix}]")
            }
            Self::AlertRef { id, capture_id: None } => format!("Alert #{id}"),
            Self::Object(id) => format!("Object #{id}"),
            Self::GraphNode(id) => format!("Graph {id}"),
            Self::Note(id) => format!("Note #{id}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvestigationContext {
    pub kind: &'static str,
    pub title: String,
    pub details: Vec<(String, String)>,
    pub available: bool,
}

#[derive(Debug, Clone, Default)]
pub struct InvestigationTray {
    pub items: Vec<InvestigationItem>,
    pub active: Option<usize>,
    pub open: bool,
    pub(super) retained_packets: std::collections::HashMap<u64, Packet>,
    pub(super) restored_packet_scopes: std::collections::BTreeMap<u64, String>,
    pub(super) retained_bytes: usize,
}

impl InvestigationTray {
    pub(super) const MAX_RETAINED_PACKETS: usize = crate::model::project::MAX_PINNED_PACKETS;
    pub(super) const MAX_RETAINED_BYTES: usize = crate::model::project::MAX_PINNED_BYTES;

    pub(super) fn retain_packet(&mut self, packet: &Packet) -> Result<(), String> {
        if !self.retained_packets.contains_key(&packet.no) {
            let cost = crate::model::project::pinned_packet_cost(packet);
            if self.retained_packets.len() >= Self::MAX_RETAINED_PACKETS
                || cost > Self::MAX_RETAINED_BYTES.saturating_sub(self.retained_bytes)
            {
                return Err(
                    "Investigation retention limit reached; remove a pinned packet first".into(),
                );
            }
            self.retained_packets.insert(packet.no, packet.clone());
            self.retained_bytes += cost;
        }
        Ok(())
    }

    pub fn pin_packet(&mut self, packet: &Packet) -> Result<bool, String> {
        self.retain_packet(packet)?;
        Ok(self.add_packet(packet.no))
    }

    pub(super) fn reserve_verified_archive_packet(&mut self, packet: &Packet) -> Result<bool, String> {
        use crate::storage::alert_evidence::{FrameStatus, frame_status};
        if let Some(prior) = self.retained_packets.get_mut(&packet.no)
            && frame_status(prior) == FrameStatus::Unreadable
        {
            let without_prior = self.retained_bytes - crate::model::project::pinned_packet_cost(prior);
            let cost = crate::model::project::pinned_packet_cost(packet);
            if cost > Self::MAX_RETAINED_BYTES.saturating_sub(without_prior) {
                return Err("Investigation retention limit reached; remove a pinned packet first".into());
            }
            *prior = packet.clone();
            self.retained_bytes = without_prior + cost;
            return Ok(true);
        }
        self.retain_packet(packet)?;
        Ok(false)
    }

    pub fn retained_packet(&self, no: u64) -> Option<&Packet> {
        self.retained_packets.get(&no)
    }

    pub fn add(&mut self, item: InvestigationItem) -> bool {
        if let Some(index) = self.items.iter().position(|existing| *existing == item) {
            self.active = Some(index);
            return false;
        }
        self.items.push(item);
        self.active = Some(self.items.len() - 1);
        true
    }

    pub fn add_packet(&mut self, packet_no: u64) -> bool {
        self.add(InvestigationItem::Packet(packet_no))
    }

    pub fn remove_active(&mut self) -> Option<InvestigationItem> {
        let index = self.active?;
        if index >= self.items.len() {
            return None;
        }
        let removed = self.items.remove(index);
        if let InvestigationItem::Packet(no) = &removed {
            self.restored_packet_scopes.remove(no);
            if let Some(packet) = self.retained_packets.remove(no) {
                self.retained_bytes -= crate::model::project::pinned_packet_cost(&packet);
            }
        }
        self.active = if self.items.is_empty() {
            None
        } else {
            Some(index.min(self.items.len() - 1))
        };
        Some(removed)
    }

    pub fn active_packet_no(&self) -> Option<u64> {
        match self.active.and_then(|index| self.items.get(index)) {
            Some(InvestigationItem::Packet(no)) => Some(*no),
            _ => None,
        }
    }

    pub fn packet_nos(&self) -> Vec<u64> {
        self.items
            .iter()
            .filter_map(|item| match item {
                InvestigationItem::Packet(no) => Some(*no),
                _ => None,
            })
            .collect()
    }

    pub fn next(&mut self) {
        if self.items.is_empty() {
            return;
        }
        self.active = Some(
            self.active
                .map(|index| (index + 1) % self.items.len())
                .unwrap_or(0),
        );
    }

    pub fn prev(&mut self) {
        if self.items.is_empty() {
            return;
        }
        self.active = Some(
            self.active
                .map(|index| {
                    if index == 0 {
                        self.items.len() - 1
                    } else {
                        index - 1
                    }
                })
                .unwrap_or(0),
        );
    }
}
