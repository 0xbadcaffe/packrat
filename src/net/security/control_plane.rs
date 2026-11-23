use super::*;
use std::net::Ipv6Addr;

const NDP_BINDING_WINDOW_SECS: f64 = 300.0;
const MAX_ROUTER_EVIDENCE_BYTES: usize = 2_048;

pub(super) struct RouterLink {
    mac: [u8; 6],
    order: (f64, u64),
    expires_at: f64,
    evidence: Option<Box<Packet>>,
    episode: Option<RouterLinkEpisode>,
}

#[derive(Clone, Copy)]
struct RouterLinkEpisode {
    pair: [[u8; 6]; 2],
    first_frame: u64,
    expires_at: f64,
}

impl RouterLink {
    fn advance_episode(&self, mac: [u8; 6], timestamp: f64, expires_at: f64) -> Option<RouterLinkEpisode> {
        if timestamp >= self.expires_at {
            return None;
        }
        let active = self.episode.filter(|episode| timestamp < episode.expires_at);
        if self.mac == mac {
            return active;
        }
        let mut pair = [self.mac, mac];
        pair.sort_unstable();
        Some(RouterLinkEpisode {
            pair,
            first_frame: active.filter(|episode| episode.pair == pair)
                .map_or(self.order.1, |episode| episode.first_frame),
            expires_at: self.expires_at.min(expires_at),
        })
    }
}

fn icmpv6_checksum_valid(inspection: &Ipv6Inspection<'_>) -> bool {
    let sum_words = |bytes: &[u8]| bytes.chunks(2).map(|word| {
        u64::from(u16::from_be_bytes([word[0], word.get(1).copied().unwrap_or(0)]))
    }).sum::<u64>();
    let length = inspection.transport.len() as u32;
    let mut sum = sum_words(&inspection.source) + sum_words(&inspection.destination)
        + sum_words(&length.to_be_bytes()) + 58 + sum_words(inspection.transport);
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum == 0xffff
}

impl SecurityEngine {
    // ─── IPv6 / Layer-2 Control Plane ───────────────────────────────────────

    pub(super) fn check_ipv6_control_plane(&mut self, pkt: &Packet, archive_rules: Option<&[String]>) {
        let inspection = match parse_ipv6_inspection(&pkt.bytes) {
            Some(inspection) => inspection,
            None => return,
        };
        let mut alerts = Vec::new();

        if inspection.extension_count > 8 {
            alerts.push((
                "Excessive IPv6 extension headers",
                Severity::High,
                format!(
                    "Captured {} IPv6 extension headers from {} to {}",
                    inspection.extension_count, pkt.src, pkt.dst
                ),
            ));
        }
        if inspection.next_header != 58 || inspection.transport.is_empty() {
            for (signature, severity, detail) in alerts {
                self.push_ids(IdsAlert {
                    pkt_no: pkt.no,
                    signature,
                    severity,
                    detail,
                });
            }
            return;
        }

        let icmp_type = inspection.transport[0];
        if inspection.hop_limit != 255
            && inspection.complete && !inspection.fragmented && inspection.extension_count <= 32
            && let Some(message) = ndp_message_name(inspection.transport)
        {
            let scope = service_scope(pkt);
            let source = Ipv6Addr::from(inspection.source);
            let destination = Ipv6Addr::from(inspection.destination);
            self.push_ids_finding(IdsFinding {
                alert: IdsAlert {
                    pkt_no: pkt.no,
                    signature: "Invalid IPv6 neighbor discovery hop limit",
                    severity: Severity::Medium,
                    detail: format!(
                        "{message} from {source} to {destination} used hop limit {} instead of 255; endpoint behavior unverified",
                        inspection.hop_limit,
                    ),
                },
                related_packets: Vec::new(),
                correlation_key: Some(format!("{scope:?}:{source}>{destination}:{icmp_type}")),
            });
        }

        if icmp_type == 134 {
            self.track_router_advertisement(pkt, &inspection, archive_rules);
        }

        if icmp_type == 136 {
            self.track_neighbor_advertisement(pkt, &inspection);
        }

        for (signature, severity, detail) in alerts {
            self.push_ids(IdsAlert {
                pkt_no: pkt.no,
                signature,
                severity,
                detail,
            });
        }
    }

    fn track_router_advertisement(&mut self, pkt: &Packet, inspection: &Ipv6Inspection<'_>, archive_rules: Option<&[String]>) {
        let data = inspection.transport;
        let now = pkt.timestamp;
        if !inspection.complete || inspection.fragmented || inspection.extension_count > 32
            || inspection.hop_limit != 255 || !now.is_finite() || now < 0.0
            || data.len() < 16 || data[1] != 0 || !ndp_options_well_formed(&data[16..])
        {
            return;
        }
        let Some(mac) = ethernet_source_mac(&pkt.bytes)
            .filter(|address| *address != [0; 6] && address[0] & 1 == 0) else { return };
        let scope = service_scope(pkt);
        if is_ipv6_link_local(&inspection.source) && icmpv6_checksum_valid(inspection) {
            let retain = archive_rules.is_some_and(|rules| rules.iter().any(|rule| rule == "ipv6.ra_router_link_change"));
            self.track_default_router_link(pkt, inspection.source, mac, u16::from_be_bytes([data[6], data[7]]), retain);
        }
        let key = (scope, mac);
        if self.router_advertisements.len() >= MAX_CONTROL_PLANE_IDENTITIES
            && !self.router_advertisements.contains_key(&key)
        {
            self.router_advertisements.retain(|_, state| now - state.last_seen <= 1.0);
            if self.router_advertisements.len() >= MAX_CONTROL_PLANE_IDENTITIES { return; }
        }
        let state = self.router_advertisements.entry(key).or_default();
        if now < state.last_seen { return; }
        if now - state.last_seen > 1.0 { *state = RouterAdvertisementState::default(); }
        state.last_seen = now;

        if !is_ipv6_link_local(&inspection.source) {
            if !state.invalid_source_alerted {
                state.invalid_source_alerted = true;
                let source = Ipv6Addr::from(inspection.source);
                self.push_ids_finding(IdsFinding {
                    alert: IdsAlert {
                        pkt_no: pkt.no,
                        signature: "Invalid IPv6 router advertisement source",
                        severity: Severity::Medium,
                        detail: format!("Router Advertisement used non-link-local source {source}; endpoint acceptance unverified"),
                    },
                    related_packets: Vec::new(),
                    correlation_key: Some(format!("{scope:?}:{mac:?}:{source}")),
                });
            }
            return;
        }

        state.samples.retain(|&(seen, _)| now - seen <= 1.0);
        if state.samples.len() <= RA_FLOOD_THRESHOLD / 2 { state.alerted = false; }
        if state.samples.iter().any(|&(_, frame)| frame == pkt.no) { return; }
        if state.samples.len() == RA_FLOOD_THRESHOLD { state.samples.pop_front(); }
        state.samples.push_back((now, pkt.no));
        if state.samples.len() == RA_FLOOD_THRESHOLD && !state.alerted {
            state.alerted = true;
            let related_packets = state.samples.iter().take(RA_FLOOD_THRESHOLD - 1)
                .map(|&(_, frame)| frame).collect();
            self.push_ids_finding(IdsFinding {
                alert: IdsAlert {
                    pkt_no: pkt.no,
                    signature: "IPv6 router advertisement flood",
                    severity: Severity::Medium,
                    detail: format!(
                        "Observed {RA_FLOOD_THRESHOLD} Router Advertisements from {} within one second in one capture scope; routing impact unverified",
                        format_mac(mac),
                    ),
                },
                related_packets,
                correlation_key: Some(format!("{scope:?}:{mac:?}:{}", pkt.no)),
            });
        }
    }

    fn track_default_router_link(&mut self, pkt: &Packet, source: [u8; 16], mac: [u8; 6], lifetime: u16, retain: bool) {
        let scope = service_scope(pkt);
        let key = (scope, source);
        let order = (pkt.timestamp, pkt.no);
        if let Some(prior) = self.default_router_links.get(&key)
            && (prior.order.1 == pkt.no || !observation_precedes(prior.order, order))
        {
            return;
        }
        if lifetime == 0 {
            if let Some(prior) = self.default_router_links.get_mut(&key) && prior.mac == mac {
                prior.order = order;
                prior.expires_at = pkt.timestamp;
                prior.evidence = None;
                prior.episode = None;
            }
            return;
        }
        if self.default_router_links.len() >= MAX_CONTROL_PLANE_IDENTITIES
            && !self.default_router_links.contains_key(&key)
        {
            self.default_router_links.retain(|_, prior| prior.expires_at > pkt.timestamp);
            if self.default_router_links.len() >= MAX_CONTROL_PLANE_IDENTITIES { return; }
        }
        let expires_at = pkt.timestamp + f64::from(lifetime);
        let episode = self.default_router_links.get(&key)
            .and_then(|prior| prior.advance_episode(mac, pkt.timestamp, expires_at));
        let previous = self.default_router_links.insert(key, RouterLink {
            mac, order, expires_at, episode,
            evidence: (retain && crate::model::project::pinned_packet_cost(pkt) <= MAX_ROUTER_EVIDENCE_BYTES)
                .then(|| Box::new(pkt.clone())),
        });
        if let (Some(prior), Some(episode)) = (previous, episode) && prior.mac != mac {
            if retain && let Some(packet) = prior.evidence {
                self.findings.retained_evidence.push(*packet);
            }
            let source = Ipv6Addr::from(source);
            self.push_ids_finding(IdsFinding {
                alert: IdsAlert {
                    pkt_no: pkt.no,
                    signature: "IPv6 default router Ethernet source changed",
                    severity: Severity::Medium,
                    detail: format!("Default-router advertisements for {source} arrived from {} and then {} before the earlier advertised lifetime expired; endpoint route changes were not verified",
                        format_mac(prior.mac), format_mac(mac)),
                },
                related_packets: vec![prior.order.1],
                correlation_key: Some(format!("{scope:?}:{source}:{}", episode.first_frame)),
            });
        }
    }

    fn track_neighbor_advertisement(&mut self, pkt: &Packet, inspection: &Ipv6Inspection<'_>) {
        let data = inspection.transport;
        if !inspection.complete || inspection.fragmented || inspection.extension_count > 32
            || inspection.hop_limit != 255 || !pkt.timestamp.is_finite() || data.len() < 24 || data[1] != 0
            || (data[4] & 0x40 != 0 && Ipv6Addr::from(inspection.destination).is_multicast())
        {
            return;
        }
        let Ok(target) = <[u8; 16]>::try_from(&data[8..24]) else { return };
        if [target, inspection.source].into_iter().map(Ipv6Addr::from)
            .any(|address| address.is_multicast() || address.is_unspecified())
        {
            return;
        }
        let Some(mac) = ndp_target_link_layer_address(&data[24..]) else { return };
        let scope = service_scope(pkt);
        let key = (scope, target);
        let previous = self.ndp_bindings.get(&key).copied();
        if previous.is_some_and(|entry| {
            entry.frame == pkt.no
                || !observation_precedes((entry.timestamp, entry.frame), (pkt.timestamp, pkt.no))
        }) {
            return;
        }
        if previous.is_none() && self.ndp_bindings.len() >= MAX_CONTROL_PLANE_IDENTITIES {
            self.ndp_bindings.retain(|_, entry| pkt.timestamp - entry.timestamp <= NDP_BINDING_WINDOW_SECS);
            if self.ndp_bindings.len() >= MAX_CONTROL_PLANE_IDENTITIES { return; }
        }
        self.ndp_bindings.insert(key, NdpObservation { mac, timestamp: pkt.timestamp, frame: pkt.no });
        if let Some(previous) = previous
            && previous.mac != mac && pkt.timestamp - previous.timestamp <= NDP_BINDING_WINDOW_SECS
        {
            let target = Ipv6Addr::from(target);
            self.push_ids_finding(IdsFinding {
                alert: IdsAlert {
                    pkt_no: pkt.no,
                    signature: "IPv6 neighbor binding changed",
                    severity: Severity::Medium,
                    detail: format!(
                        "Neighbor Advertisements for {target} claimed {} and then {}; endpoint cache change was not verified",
                        format_mac(previous.mac), format_mac(mac),
                    ),
                },
                related_packets: vec![previous.frame],
                correlation_key: Some(format!("{scope:?}:{target}")),
            });
        }
    }

    pub(super) fn check_layer2_control_plane(&mut self, pkt: &Packet) {
        let raw = &pkt.bytes;
        if let Some(indication) = stp_topology_indication(raw)
            && let Some(mac) = ethernet_source_mac(raw)
                .filter(|address| *address != [0; 6] && address[0] & 1 == 0)
        {
            let scope = service_scope(pkt);
            let source = format_mac(mac);
            self.push_ids_finding(IdsFinding {
                alert: IdsAlert {
                    pkt_no: pkt.no,
                    signature: "STP topology change",
                    severity: Severity::Medium,
                    detail: format!("{indication} from {source}; forwarding changes were not verified"),
                },
                related_packets: Vec::new(),
                correlation_key: Some(format!("{scope:?}:{source}:{indication}")),
            });
        }

        let Some(advertisement) = lldp_advertisement(raw) else { return };
        let now = pkt.timestamp;
        if !now.is_finite() { return; }
        let scope = service_scope(pkt);
        let key = LldpKey { scope, source: advertisement.source, destination: advertisement.destination,
            port: advertisement.port.to_vec() };
        let existing = self.lldp_chassis.get(&key);
        if existing.is_some_and(|previous| {
            previous.frame == pkt.no
                || !observation_precedes((previous.seen_at, previous.frame), (now, pkt.no))
        }) {
            return;
        }
        if advertisement.ttl == 0 {
            if let Some(previous) = self.lldp_chassis.get_mut(&key)
                && previous.chassis == advertisement.chassis
            {
                // Keep the withdrawal's order, but let capacity cleanup reclaim this entry.
                previous.seen_at = now;
                previous.frame = pkt.no;
                previous.expires_at = now;
            }
            return;
        }
        if existing.is_none() && self.lldp_chassis.len() >= MAX_CONTROL_PLANE_IDENTITIES {
            self.lldp_chassis.retain(|_, previous| previous.expires_at > now);
            if self.lldp_chassis.len() >= MAX_CONTROL_PLANE_IDENTITIES { return; }
        }
        let previous = self.lldp_chassis.insert(key, LldpObservation {
            chassis: advertisement.chassis.to_vec(), frame: pkt.no,
            seen_at: now, expires_at: now + f64::from(advertisement.ttl),
        });
        if let Some(previous) = previous
            && now < previous.expires_at && previous.chassis != advertisement.chassis
        {
            let source = format_mac(advertisement.source);
            self.push_ids_finding(IdsFinding {
                alert: IdsAlert {
                    pkt_no: pkt.no,
                    signature: "LLDP chassis identity changed",
                    severity: Severity::Medium,
                    detail: format!("LLDP source {source} advertised a different chassis on the same port within its prior TTL; physical identity unverified"),
                },
                related_packets: vec![previous.frame],
                correlation_key: Some(format!("{scope:?}:{source}:{}", previous.frame)),
            });
        }
    }
}
