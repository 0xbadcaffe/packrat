use super::{Packet, ServiceScope, service_scope};
use std::collections::{HashMap, VecDeque};

const MAX_CANDIDATES: usize = 2048;
const MAX_PACKET_COST: usize = 2048;
// Covers the longest tracked pending query and its subsequent reply comparison window.
const MAX_AGE_SECS: f64 = 70.0;
pub(super) const MAX_DNS_EVIDENCE_PER_PACKET: usize = 128;

type CandidateKey = (ServiceScope, u64);

#[derive(Default)]
pub(super) struct DnsPacketEvidence {
    packets: HashMap<CandidateKey, Packet>,
    order: VecDeque<(CandidateKey, f64)>,
}

impl DnsPacketEvidence {
    pub(super) fn remember(&mut self, packet: &Packet) {
        if !packet.timestamp.is_finite() || !(packet.src_port == Some(53) || packet.dst_port == Some(53)) {
            return;
        }
        let carries_dns = crate::analysis::dns_transactions::udp_payload(packet)
            .is_some_and(|(source, destination, bytes)| (source == 53 || destination == 53) && bytes.len() >= 12)
            || crate::analysis::stream::tcp_data_port_pair(packet)
                .is_some_and(|(source, destination)| source == 53 || destination == 53);
        if !carries_dns || crate::model::project::pinned_packet_cost(packet) > MAX_PACKET_COST {
            return;
        }
        let key = (service_scope(packet), packet.no);
        if self.packets.contains_key(&key) { return; }
        while self.order.len() >= MAX_CANDIDATES
            || self.order.front().is_some_and(|(_, time)| packet.timestamp - time > MAX_AGE_SECS)
        {
            let Some((expired, _)) = self.order.pop_front() else { break; };
            self.packets.remove(&expired);
        }
        self.packets.insert(key, packet.clone());
        self.order.push_back((key, packet.timestamp));
    }

    pub(super) fn supporting_packet(&self, trigger: &Packet, frame: u64) -> Option<&Packet> {
        if frame == trigger.no { return None; }
        self.packets.get(&(service_scope(trigger), frame)).filter(|packet| {
            (0.0..=MAX_AGE_SECS).contains(&(trigger.timestamp - packet.timestamp))
        })
    }
}
