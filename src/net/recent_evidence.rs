use super::packet::Packet;
use std::collections::{HashMap, VecDeque};

const MAX_PACKET_COST: usize = 2048;
type CandidateKey = (Option<(u32, u32)>, Option<u16>, Option<u16>, [u16; 2], u64);

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
    order: VecDeque<(CandidateKey, f64)>,
}

impl<const CAPACITY: usize, const MAX_AGE_SECS: u64> RecentEvidence<CAPACITY, MAX_AGE_SECS> {
    pub(crate) fn remember(&mut self, packet: &Packet) {
        if CAPACITY == 0 || !packet.timestamp.is_finite()
            || crate::model::project::pinned_packet_cost(packet) > MAX_PACKET_COST {
            return;
        }
        let key = key(packet, packet.no);
        if self.packets.contains_key(&key) { return; }
        while self.order.len() >= CAPACITY
            || self.order.front().is_some_and(|(_, time)| packet.timestamp - time > MAX_AGE_SECS as f64)
        {
            let Some((expired, _)) = self.order.pop_front() else { break; };
            self.packets.remove(&expired);
        }
        self.packets.insert(key, packet.clone());
        self.order.push_back((key, packet.timestamp));
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
