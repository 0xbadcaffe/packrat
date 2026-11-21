use std::{collections::HashMap, net::IpAddr};

use crate::net::packet::Packet;

use super::{DnsFinding, DnsFindingKind, DnsMessage, DnsScope, PendingQuery};

const TTL_SECS: f64 = 3600.0;
const MAX_PAIRS: usize = 512;

#[derive(Debug, Default)]
pub(super) struct ExternalResolvers {
    pairs: HashMap<(DnsScope, IpAddr, IpAddr), f64>,
}

impl ExternalResolvers {
    pub(super) fn clear(&mut self) {
        self.pairs.clear();
    }

    pub(super) fn observe(
        &mut self,
        scope: DnsScope,
        packet: &Packet,
        query: &PendingQuery,
        message: &DnsMessage<'_>,
    ) -> Option<DnsFinding> {
        if query.server != packet.src || query.question != message.question
            || message.bytes[2] & 0x78 != 0 || message.bytes[4..6] != [0, 1]
        {
            return None;
        }
        let client: IpAddr = packet.dst.parse().ok()?;
        let resolver: IpAddr = packet.src.parse().ok()?;
        if !is_local_client(client) || !is_external_unicast(resolver) {
            return None;
        }
        let key = (scope, client, resolver);
        let timestamp = packet.timestamp;
        if let Some(prior) = self.pairs.get_mut(&key)
            && timestamp - *prior <= TTL_SECS
        {
            *prior = prior.max(timestamp);
            return None;
        }
        if self.pairs.len() >= MAX_PAIRS {
            self.pairs.retain(|_, seen| timestamp - *seen <= TTL_SECS);
            if self.pairs.len() >= MAX_PAIRS {
                return None;
            }
        }
        self.pairs.insert(key, timestamp);
        Some(DnsFinding {
            kind: DnsFindingKind::ExternalResolver,
            detail: format!("{client} exchanged DNS with {resolver}; resolver policy not verified"),
            related_packets: vec![query.packet_no],
        })
    }
}

fn is_local_client(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_link_local() || ip.is_loopback()
            || matches!(ip.octets(), [100, 64..=127, ..]),
        IpAddr::V6(ip) => ip.is_unique_local() || ip.is_unicast_link_local() || ip.is_loopback(),
    }
}

fn is_external_unicast(ip: IpAddr) -> bool {
    // Special-use destinations are not evidence of a public resolver.
    match ip {
        IpAddr::V4(ip) => !is_local_client(ip.into()) && !matches!(ip.octets(),
            [0 | 224..=255, ..] | [192, 0, 0 | 2, _] | [192, 88, 99, _]
            | [198, 18..=19, ..] | [198, 51, 100, _] | [203, 0, 113, _]),
        IpAddr::V6(ip) => {
            let [first, second, ..] = ip.segments();
            first & 0xe000 == 0x2000
                && !matches!((first, second), (0x2001, 0..=0x01ff | 0x0db8)
                    | (0x2002, _) | (0x3fff, 0..=0x0fff))
        }
    }
}
