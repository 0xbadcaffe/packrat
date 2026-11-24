//! Bounded IPv6 fragment reassembly with conflicting-overlap detection.

use std::collections::HashMap;

use crate::net::packet::Packet;
use crate::net::parser::ethernet_network_header;

const MAX_DATAGRAMS: usize = 512;
const MAX_FRAGMENTS: usize = 128;
const MAX_PAYLOAD_BYTES: usize = u16::MAX as usize;
const STATE_TTL_SECS: f64 = 60.0;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Ipv6FragmentKey {
    pub source: [u8; 16],
    pub destination: [u8; 16],
    pub identification: u32,
    pub next_header: u8,
}

#[derive(Debug, Clone)]
pub struct ReassembledIpv6Payload {
    pub key: Ipv6FragmentKey,
    pub payload: Vec<u8>,
    pub fragment_count: usize,
    pub frame_numbers: Vec<u64>,
}

#[derive(Debug, Clone)]
pub enum Ipv6FragmentOutcome {
    Ignored,
    Pending { fragment_count: usize },
    Complete { datagram: ReassembledIpv6Payload },
    Overlap { identification: u32, previous_frame: u64, conflicting_bytes: bool },
    Rejected { reason: &'static str },
}

#[derive(Debug)]
struct DatagramState {
    fragments: Vec<Fragment>,
    final_len: Option<usize>,
    first_seen: f64,
    admitted_order: u64,
    first_header: Option<u8>,
    discarded: bool,
}

#[derive(Debug)]
struct Fragment {
    offset: usize,
    data: Vec<u8>,
    frame: u64,
    more_fragments: bool,
}

struct ParsedFragment<'a> {
    key: Ipv6FragmentKey,
    offset: usize,
    more_fragments: bool,
    data: &'a [u8],
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct ScopedDatagram {
    interface: Option<(u32, u32)>,
    outer_vlan: Option<u16>,
    vlan: Option<u16>,
    vlan_tag_types: [u16; 2],
    source: [u8; 16],
    destination: [u8; 16],
    identification: u32,
}

#[derive(Debug, Default)]
pub struct Ipv6FragmentReassembler {
    datagrams: HashMap<ScopedDatagram, DatagramState>,
    last_admission: u64,
}

impl Ipv6FragmentReassembler {
    pub fn ingest(&mut self, packet: &Packet) -> Ipv6FragmentOutcome {
        self.ingest_tracking(packet, |_| {}, |_| {})
    }

    pub(crate) fn ingest_tracking(
        &mut self, packet: &Packet, pending: impl FnOnce(&Packet), mut rejected_frame: impl FnMut(u64),
    ) -> Ipv6FragmentOutcome {
        let Some(fragment) = parse_fragment(&packet.bytes) else {
            return Ipv6FragmentOutcome::Ignored;
        };
        let end = fragment.offset + fragment.data.len();
        if end > MAX_PAYLOAD_BYTES {
            return Ipv6FragmentOutcome::Rejected { reason: "IPv6 fragment payload exceeds reassembly limit" };
        }
        if fragment.offset == 0 && !fragment.more_fragments {
            return Ipv6FragmentOutcome::Complete {
                datagram: ReassembledIpv6Payload {
                    key: fragment.key, payload: fragment.data.to_vec(), fragment_count: 1,
                    frame_numbers: vec![packet.no],
                },
            };
        }
        if fragment.data.is_empty() || (fragment.more_fragments && fragment.data.len() % 8 != 0) {
            return Ipv6FragmentOutcome::Rejected { reason: "Invalid IPv6 fragment payload length" };
        }
        if !packet.timestamp.is_finite() {
            return Ipv6FragmentOutcome::Ignored;
        }

        let scope = ScopedDatagram {
            interface: packet.capture.as_ref().map(|c| (c.section_id, c.interface_id)),
            outer_vlan: packet.outer_vlan_id,
            vlan: packet.vlan_id,
            vlan_tag_types: crate::net::parser::ethernet_vlan_tag_types(&packet.bytes),
            source: fragment.key.source,
            destination: fragment.key.destination,
            identification: fragment.key.identification,
        };
        self.datagrams.retain(|observed, state| {
            observed.interface != scope.interface || packet.timestamp - state.first_seen <= STATE_TTL_SECS
        });
        if !self.datagrams.contains_key(&scope) && self.datagrams.len() >= MAX_DATAGRAMS {
            if let Some(oldest) = self.datagrams.iter()
                .min_by(|(key_a, a), (key_b, b)| a.admitted_order.cmp(&b.admitted_order).then(key_a.cmp(key_b)))
                .map(|(key, _)| key.clone())
            {
                self.datagrams.remove(&oldest);
            }
        }

        let state = self.datagrams.entry(scope.clone()).or_insert_with(|| {
            self.last_admission = self.last_admission.saturating_add(1);
            DatagramState {
                fragments: Vec::new(), final_len: None, first_seen: packet.timestamp,
                admitted_order: self.last_admission, first_header: None, discarded: false,
            }
        });
        if state.discarded || state.first_seen - packet.timestamp > STATE_TTL_SECS {
            return Ipv6FragmentOutcome::Ignored;
        }
        if (fragment.offset != 0 || state.first_header == Some(fragment.key.next_header))
            && is_exact_duplicate(&state.fragments, &fragment)
        {
            return Ipv6FragmentOutcome::Pending { fragment_count: state.fragments.len() };
        }
        if let Some((previous_frame, conflicting_bytes)) = overlapping_fragment(&state.fragments, &fragment) {
            state.discard();
            return Ipv6FragmentOutcome::Overlap {
                identification: scope.identification, previous_frame, conflicting_bytes,
            };
        }
        if state.fragments.len() >= MAX_FRAGMENTS {
            state.fragments.iter().for_each(|fragment| rejected_frame(fragment.frame));
            state.discard();
            return Ipv6FragmentOutcome::Rejected { reason: "IPv6 datagram exceeds fragment-count limit" };
        }

        let prior = if state.final_len.is_some_and(|length| end > length || !fragment.more_fragments) {
            state.fragments.iter().find(|f| !f.more_fragments)
        } else if !fragment.more_fragments {
            state.fragments.iter().find(|f| f.offset + f.data.len() >= end)
        } else {
            None
        };
        if let Some(prior) = prior {
            rejected_frame(prior.frame);
            state.discard();
            return Ipv6FragmentOutcome::Rejected { reason: "Inconsistent IPv6 final fragment length" };
        }
        if !fragment.more_fragments {
            state.final_len = Some(end);
        }
        if fragment.offset == 0 {
            state.first_header = Some(fragment.key.next_header);
        }
        state.fragments.push(Fragment {
            offset: fragment.offset, data: fragment.data.to_vec(),
            frame: packet.no, more_fragments: fragment.more_fragments,
        });

        let fragment_count = state.fragments.len();
        let (Some(final_len), Some(next_header)) = (state.final_len, state.first_header) else {
            pending(packet);
            return Ipv6FragmentOutcome::Pending { fragment_count };
        };
        let Some(payload) = assemble_if_complete(&state.fragments, final_len) else {
            pending(packet);
            return Ipv6FragmentOutcome::Pending { fragment_count };
        };
        let key = Ipv6FragmentKey { next_header, ..fragment.key };
        let mut frame_numbers: Vec<_> = state.fragments.iter().map(|fragment| fragment.frame).collect();
        frame_numbers.sort_unstable();
        self.datagrams.remove(&scope);
        Ipv6FragmentOutcome::Complete {
            datagram: ReassembledIpv6Payload { key, payload, fragment_count, frame_numbers },
        }
    }

    pub fn clear(&mut self) {
        self.datagrams.clear();
        self.last_admission = 0;
    }
}

impl DatagramState {
    fn discard(&mut self) {
        self.fragments = Vec::new();
        self.discarded = true;
    }
}

fn parse_fragment(raw: &[u8]) -> Option<ParsedFragment<'_>> {
    let (ip_offset, ether_type) = ethernet_network_header(raw)?;
    if ether_type != 0x86dd || raw.len() < ip_offset + 40 || raw[ip_offset] >> 4 != 6 {
        return None;
    }
    let payload_len = usize::from(u16::from_be_bytes([raw[ip_offset + 4], raw[ip_offset + 5]]));
    let packet_end = ip_offset + 40 + payload_len;
    if packet_end > raw.len() {
        return None;
    }
    let mut next_header = raw[ip_offset + 6];
    let mut cursor = ip_offset + 40;

    while matches!(next_header, 0 | 43 | 51 | 60) {
        let current = next_header;
        next_header = *raw.get(cursor)?;
        let length = if current == 51 {
            (usize::from(*raw.get(cursor + 1)?) + 2) * 4
        } else {
            (usize::from(*raw.get(cursor + 1)?) + 1) * 8
        };
        cursor = cursor.checked_add(length)?;
        if cursor > packet_end {
            return None;
        }
    }
    if next_header != 44 || cursor + 8 > packet_end {
        return None;
    }

    let fragment_next_header = raw[cursor];
    let offset_flags = u16::from_be_bytes([raw[cursor + 2], raw[cursor + 3]]);
    let offset = usize::from(offset_flags & 0xfff8);
    let more_fragments = offset_flags & 1 != 0;
    Some(ParsedFragment {
        key: Ipv6FragmentKey {
            source: raw[ip_offset + 8..ip_offset + 24].try_into().ok()?,
            destination: raw[ip_offset + 24..ip_offset + 40].try_into().ok()?,
            identification: u32::from_be_bytes(raw[cursor + 4..cursor + 8].try_into().ok()?),
            next_header: fragment_next_header,
        },
        offset,
        more_fragments,
        data: &raw[cursor + 8..packet_end],
    })
}

fn overlapping_fragment(existing: &[Fragment], incoming: &ParsedFragment<'_>) -> Option<(u64, bool)> {
    let mut equal_overlap = None;
    for fragment in existing {
        let overlap_start = fragment.offset.max(incoming.offset);
        let overlap_end = (fragment.offset + fragment.data.len())
            .min(incoming.offset + incoming.data.len());
        if overlap_start >= overlap_end {
            continue;
        }
        let old_start = overlap_start - fragment.offset;
        let new_start = overlap_start - incoming.offset;
        let length = overlap_end - overlap_start;
        if fragment.data[old_start..old_start + length] != incoming.data[new_start..new_start + length] {
            return Some((fragment.frame, true));
        }
        equal_overlap.get_or_insert((fragment.frame, false));
    }
    equal_overlap
}

fn is_exact_duplicate(existing: &[Fragment], incoming: &ParsedFragment<'_>) -> bool {
    existing.iter().any(|fragment| fragment.offset == incoming.offset
        && fragment.more_fragments == incoming.more_fragments && fragment.data == incoming.data)
}

fn assemble_if_complete(fragments: &[Fragment], final_len: usize) -> Option<Vec<u8>> {
    if fragments.iter().map(|fragment| fragment.data.len()).sum::<usize>() != final_len {
        return None;
    }
    let mut payload = vec![0_u8; final_len];
    for fragment in fragments {
        let end = fragment.offset + fragment.data.len();
        payload[fragment.offset..end].copy_from_slice(&fragment.data);
    }
    Some(payload)
}
