//! Bounded IPv6 fragment reassembly with conflicting-overlap detection.

use std::collections::HashMap;

use crate::net::packet::Packet;

const MAX_DATAGRAMS: usize = 512;
const MAX_FRAGMENTS: usize = 128;
const MAX_PAYLOAD_BYTES: usize = 1_048_576;
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
}

#[derive(Debug, Clone)]
pub enum Ipv6FragmentOutcome {
    Ignored,
    Pending { conflicting_overlap: bool, fragment_count: usize },
    Complete { datagram: ReassembledIpv6Payload, conflicting_overlap: bool },
    Rejected { reason: &'static str },
}

#[derive(Debug, Default)]
struct DatagramState {
    fragments: Vec<Fragment>,
    final_len: Option<usize>,
    last_seen: f64,
}

#[derive(Debug)]
struct Fragment {
    offset: usize,
    data: Vec<u8>,
}

struct ParsedFragment<'a> {
    key: Ipv6FragmentKey,
    offset: usize,
    more_fragments: bool,
    data: &'a [u8],
}

#[derive(Debug, Default)]
pub struct Ipv6FragmentReassembler {
    datagrams: HashMap<Ipv6FragmentKey, DatagramState>,
}

impl Ipv6FragmentReassembler {
    pub fn ingest(&mut self, packet: &Packet) -> Ipv6FragmentOutcome {
        let Some(fragment) = parse_fragment(&packet.bytes) else {
            return Ipv6FragmentOutcome::Ignored;
        };
        if fragment.offset.saturating_add(fragment.data.len()) > MAX_PAYLOAD_BYTES {
            return Ipv6FragmentOutcome::Rejected { reason: "IPv6 fragment payload exceeds reassembly limit" };
        }

        self.datagrams.retain(|_, state| {
            packet.timestamp < state.last_seen || packet.timestamp - state.last_seen <= STATE_TTL_SECS
        });
        if !self.datagrams.contains_key(&fragment.key) && self.datagrams.len() >= MAX_DATAGRAMS {
            if let Some(oldest) = self.datagrams.iter()
                .min_by(|left, right| left.1.last_seen.total_cmp(&right.1.last_seen))
                .map(|(key, _)| key.clone())
            {
                self.datagrams.remove(&oldest);
            }
        }

        let state = self.datagrams.entry(fragment.key.clone()).or_default();
        state.last_seen = packet.timestamp;
        if state.fragments.len() >= MAX_FRAGMENTS {
            return Ipv6FragmentOutcome::Rejected { reason: "IPv6 datagram exceeds fragment-count limit" };
        }

        let conflicting_overlap = has_conflicting_overlap(&state.fragments, &fragment);
        if !fragment.more_fragments {
            state.final_len = Some(fragment.offset + fragment.data.len());
        }
        if !is_exact_duplicate(&state.fragments, &fragment) {
            state.fragments.push(Fragment { offset: fragment.offset, data: fragment.data.to_vec() });
        }

        let fragment_count = state.fragments.len();
        let Some(final_len) = state.final_len else {
            return Ipv6FragmentOutcome::Pending { conflicting_overlap, fragment_count };
        };
        let Some(payload) = assemble_if_complete(&state.fragments, final_len) else {
            return Ipv6FragmentOutcome::Pending { conflicting_overlap, fragment_count };
        };
        let key = fragment.key;
        self.datagrams.remove(&key);
        Ipv6FragmentOutcome::Complete {
            datagram: ReassembledIpv6Payload { key, payload, fragment_count },
            conflicting_overlap,
        }
    }

    pub fn clear(&mut self) {
        self.datagrams.clear();
    }
}

fn parse_fragment(raw: &[u8]) -> Option<ParsedFragment<'_>> {
    let (ip_offset, ether_type) = ethernet_network_header(raw)?;
    if ether_type != 0x86dd || raw.len() < ip_offset + 40 || raw[ip_offset] >> 4 != 6 {
        return None;
    }
    let payload_len = usize::from(u16::from_be_bytes([raw[ip_offset + 4], raw[ip_offset + 5]]));
    let packet_end = (ip_offset + 40 + payload_len).min(raw.len());
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

fn has_conflicting_overlap(existing: &[Fragment], incoming: &ParsedFragment<'_>) -> bool {
    existing.iter().any(|fragment| {
        let overlap_start = fragment.offset.max(incoming.offset);
        let overlap_end = (fragment.offset + fragment.data.len())
            .min(incoming.offset + incoming.data.len());
        if overlap_start >= overlap_end {
            return false;
        }
        let old_start = overlap_start - fragment.offset;
        let new_start = overlap_start - incoming.offset;
        let length = overlap_end - overlap_start;
        fragment.data[old_start..old_start + length] != incoming.data[new_start..new_start + length]
    })
}

fn is_exact_duplicate(existing: &[Fragment], incoming: &ParsedFragment<'_>) -> bool {
    existing.iter().any(|fragment| fragment.offset == incoming.offset && fragment.data == incoming.data)
}

fn assemble_if_complete(fragments: &[Fragment], final_len: usize) -> Option<Vec<u8>> {
    if final_len > MAX_PAYLOAD_BYTES {
        return None;
    }
    let mut payload = vec![0_u8; final_len];
    let mut covered = vec![false; final_len];
    for fragment in fragments {
        let end = (fragment.offset + fragment.data.len()).min(final_len);
        if fragment.offset >= end {
            continue;
        }
        let length = end - fragment.offset;
        payload[fragment.offset..end].copy_from_slice(&fragment.data[..length]);
        covered[fragment.offset..end].fill(true);
    }
    covered.iter().all(|covered| *covered).then_some(payload)
}

fn ethernet_network_header(raw: &[u8]) -> Option<(usize, u16)> {
    if raw.len() < 14 {
        return None;
    }
    let mut ether_type_offset = 12usize;
    loop {
        let ether_type = u16::from_be_bytes([
            *raw.get(ether_type_offset)?,
            *raw.get(ether_type_offset + 1)?,
        ]);
        if ether_type != 0x8100 && ether_type != 0x88a8 {
            return Some((ether_type_offset + 2, ether_type));
        }
        ether_type_offset = ether_type_offset.checked_add(4)?;
    }
}
