use super::packet::Packet;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};

const MAX_PACKET_COST: usize = 2048;
type CaptureClock = Option<(u32, u32)>;
type CandidateKey = (CaptureClock, Option<u16>, Option<u16>, [u16; 2], u64);
type AgeKey = (CaptureClock, OrderedTime, u64);

#[derive(Clone, Copy)]
struct OrderedTime(f64);

impl PartialEq for OrderedTime {
    fn eq(&self, other: &Self) -> bool { self.0.to_bits() == other.0.to_bits() }
}
impl Eq for OrderedTime {}
impl Ord for OrderedTime {
    fn cmp(&self, other: &Self) -> Ordering { self.0.total_cmp(&other.0) }
}
impl PartialOrd for OrderedTime {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

fn key(packet: &Packet, frame: u64) -> CandidateKey {
    (
        packet.capture.as_ref().map(|c| (c.section_id, c.interface_id)),
        packet.outer_vlan_id,
        packet.vlan_id,
        super::parser::ethernet_vlan_tag_types(&packet.bytes),
        frame,
    )
}

#[cfg(test)]
#[path = "../../tests/unit/recent_evidence_tests.rs"]
mod tests;

#[derive(Default)]
pub(crate) struct RecentEvidence<const CAPACITY: usize, const MAX_AGE_SECS: u64> {
    packets: HashMap<CandidateKey, Packet>,
    order: BTreeMap<u64, CandidateKey>,
    by_age: BTreeSet<AgeKey>,
    last_order: u64,
}

impl<const CAPACITY: usize, const MAX_AGE_SECS: u64> RecentEvidence<CAPACITY, MAX_AGE_SECS> {
    fn remove(&mut self, order: u64) {
        if let Some(key) = self.order.remove(&order)
            && let Some(packet) = self.packets.remove(&key)
        {
            self.by_age.remove(&(key.0, OrderedTime(packet.timestamp), order));
        }
    }

    pub(crate) fn remember(&mut self, packet: &Packet) {
        if CAPACITY == 0 || !packet.timestamp.is_finite()
            || crate::model::project::pinned_packet_cost(packet) > MAX_PACKET_COST {
            return;
        }
        let key = key(packet, packet.no);
        if self.packets.contains_key(&key) { return; }
        let Some(order) = self.last_order.checked_add(1) else { return; };
        // Expire by event time only within the current capture clock, even for late arrivals.
        let start = (key.0, OrderedTime(f64::NEG_INFINITY), 0);
        while let Some(&(clock, time, expired)) = self.by_age.range(start..).next() {
            if clock != key.0 || packet.timestamp - time.0 <= MAX_AGE_SECS as f64 { break; }
            self.remove(expired);
        }
        if self.order.len() >= CAPACITY
            && let Some((&oldest, _)) = self.order.first_key_value()
        {
            self.remove(oldest);
        }
        self.last_order = order;
        self.packets.insert(key, packet.clone());
        self.order.insert(order, key);
        self.by_age.insert((key.0, OrderedTime(packet.timestamp), order));
    }

    pub(crate) fn supporting_packet(&self, trigger: &Packet, frame: u64) -> Option<&Packet> {
        self.supporting_packet_at(trigger, frame, trigger.timestamp)
    }

    pub(crate) fn supporting_packet_at(&self, trigger: &Packet, frame: u64, window_end: f64) -> Option<&Packet> {
        self.cited_packet(trigger, frame).filter(|packet| {
            (0.0..=MAX_AGE_SECS as f64).contains(&(window_end - packet.timestamp))
        })
    }

    // Use for an exact reference selected by a tracker that already checked its own time window.
    pub(crate) fn cited_packet(&self, trigger: &Packet, frame: u64) -> Option<&Packet> {
        if frame == trigger.no { return None; }
        self.packets.get(&key(trigger, frame))
    }
}
