use super::*;

const DHCP_CLIENT_WINDOW_SECS: f64 = 10.0;
const DHCP_SERVER_WINDOW_SECS: f64 = 3600.0;
const MAX_DHCP_SCOPES: usize = 128;
const MAX_DHCP_CLIENTS: usize = 128;
const MAX_DHCP_SERVERS: usize = 32;

impl SecurityEngine {
    // ─── DHCP Authority and Starvation ──────────────────────────────────────

    pub(super) fn check_dhcp_integrity(&mut self, pkt: &Packet) {
        if !pkt.timestamp.is_finite() || pkt.timestamp < 0.0 {
            return;
        }
        let Some(message) = parse_dhcp_message(&pkt.bytes) else {
            return;
        };
        if !matches!(message.message_type, 1 | 2 | 5) {
            return;
        }
        let scope = service_scope(pkt);
        if self.dhcp_scopes.len() >= MAX_DHCP_SCOPES
            && !self.dhcp_scopes.contains_key(&scope)
            && let Some(oldest) = self.dhcp_scopes.iter()
                .min_by(|(key_a, a), (key_b, b)| a.last_seen.total_cmp(&b.last_seen).then(key_a.cmp(key_b)))
                .map(|(key, _)| *key)
        {
            self.dhcp_scopes.remove(&oldest);
        }
        let state = self.dhcp_scopes.entry(scope).or_default();
        state.last_seen = state.last_seen.max(pkt.timestamp);
        if matches!(message.message_type, 2 | 5) {
            if let Some(server) = message.server_identifier
                && let Some((previous, frame)) = observe_dhcp_server(state, server, pkt)
            {
                let kind = if message.message_type == 2 { "OFFER" } else { "ACK" };
                let scope_name = dhcp_scope_name(scope);
                self.push_ids_finding(IdsFinding {
                    alert: IdsAlert {
                        pkt_no: pkt.no,
                        signature: "DHCP server identity changed",
                        severity: Severity::Medium,
                        detail: format!(
                            "DHCP {kind} advertised server identifier {server} on {scope_name}; previously observed {previous} within one hour. Authorization is unknown."
                        ),
                    },
                    related_packets: vec![frame],
                    correlation_key: Some(format!("dhcp-server:{scope:?}:{server}")),
                });
            }
        } else if !message.client_identity.is_empty()
            && let Some((count, related_packets)) = dhcp_client_burst(state, message.client_identity, pkt)
        {
            let scope_name = dhcp_scope_name(scope);
            self.push_ids_finding(IdsFinding {
                alert: IdsAlert {
                    pkt_no: pkt.no,
                    signature: "DHCP client identity burst",
                    severity: Severity::Medium,
                    detail: format!(
                        "{count} distinct DHCPDISCOVER identities in 10 seconds on {scope_name}; lease exhaustion was not observed"
                    ),
                },
                related_packets,
                correlation_key: Some(format!("dhcp-discover:{scope:?}")),
            });
        }
    }

    pub(super) fn check_ipv6_fragment_reassembly(&mut self, pkt: &Packet) {
        match self.ipv6_fragments.ingest(pkt) {
            Ipv6FragmentOutcome::Ignored | Ipv6FragmentOutcome::Pending { .. } => {}
            Ipv6FragmentOutcome::Overlap { identification, previous_frame, conflicting_bytes } => {
                self.push_ids_finding(IdsFinding {
                    alert: IdsAlert {
                        pkt_no: pkt.no,
                        signature: if conflicting_bytes { "Conflicting IPv6 fragments" } else { "IPv6 fragment reassembly rejected" },
                        severity: if conflicting_bytes { Severity::High } else { Severity::Medium },
                        detail: format!("IPv6 fragment overlap in datagram {identification} from {} to {}; Packrat discarded reassembly, endpoint outcome unknown", pkt.src, pkt.dst),
                    },
                    related_packets: vec![previous_frame],
                    correlation_key: Some(format!("{:?}:{}>{}:{identification}", service_scope(pkt), pkt.src, pkt.dst)),
                });
            }
            Ipv6FragmentOutcome::Rejected { reason } => {
                self.push_ids(IdsAlert {
                    pkt_no: pkt.no,
                    signature: "IPv6 fragment reassembly rejected",
                    severity: Severity::High,
                    detail: format!("{reason} from {}", pkt.src),
                });
            }
            Ipv6FragmentOutcome::Complete { datagram } => {
                self.ipv6_reassembled = self.ipv6_reassembled.saturating_add(1);
                let transport_ports = datagram.payload.get(..4).map(|bytes| {
                    (
                        u16::from_be_bytes([bytes[0], bytes[1]]),
                        u16::from_be_bytes([bytes[2], bytes[3]]),
                    )
                });
                let (protocol, ports) = match datagram.key.next_header {
                    6 => ("TCP", transport_ports),
                    17 => ("UDP", transport_ports),
                    58 => ("ICMPv6", None),
                    _ => ("IPv6-Reassembled", None),
                };
                let synthetic = Packet {
                    capture: None,
                    no: pkt.no,
                    timestamp: pkt.timestamp,
                    src: pkt.src.clone(),
                    dst: pkt.dst.clone(),
                    protocol: protocol.into(),
                    length: datagram.payload.len().min(u16::MAX as usize) as u16,
                    info: format!(
                        "Reassembled from {} IPv6 fragments",
                        datagram.fragment_count
                    ),
                    src_port: ports.map(|pair| pair.0),
                    dst_port: ports.map(|pair| pair.1),
                    vlan_id: pkt.vlan_id,
                    vlan_pcp: pkt.vlan_pcp,
                    vlan_dei: pkt.vlan_dei,
                    outer_vlan_id: pkt.outer_vlan_id,
                    bytes: datagram.payload,
                };
                self.check_reassembled_ids(pkt, &synthetic, &datagram.frame_numbers, datagram.key.identification);
            }
        }
    }

    pub(super) fn check_http_request_smuggling(&mut self, pkt: &Packet) {
        let Some(TcpFrame::Segment(segment)) = parse_ipv4_tcp_frame(&pkt.bytes) else {
            return;
        };
        let destination_port = pkt.dst_port.unwrap_or(0);
        if !matches!(destination_port, 80 | 3000 | 8000 | 8080 | 8888) || segment.payload.is_empty()
        {
            return;
        }
        self.http_headers.retain(|_, state| {
            pkt.timestamp < state.last_seen || pkt.timestamp - state.last_seen <= 30.0
        });
        if self.http_headers.len() >= MAX_SCAN_STATES
            && !self
                .http_headers
                .contains_key(&(segment.key.clone(), segment.from_a))
        {
            if let Some(oldest) = self
                .http_headers
                .iter()
                .min_by(|left, right| left.1.last_seen.total_cmp(&right.1.last_seen))
                .map(|(key, _)| key.clone())
            {
                self.http_headers.remove(&oldest);
            }
        }

        let state = self
            .http_headers
            .entry((segment.key, segment.from_a))
            .or_default();
        state.last_seen = pkt.timestamp;
        if state.complete {
            return;
        }
        let remaining = 32_768usize.saturating_sub(state.bytes.len());
        state
            .bytes
            .extend_from_slice(&segment.payload[..segment.payload.len().min(remaining)]);
        let Some(header_end) = find_http_header_end(&state.bytes) else {
            if state.bytes.len() >= 32_768 {
                state.complete = true;
            }
            return;
        };
        state.complete = true;
        if let Some(reason) = http_smuggling_reason(&state.bytes[..header_end]) {
            self.push_ids(IdsAlert {
                pkt_no: pkt.no,
                signature: "HTTP request smuggling ambiguity",
                severity: Severity::Critical,
                detail: format!(
                    "{reason} from {} to {}:{destination_port}",
                    pkt.src, pkt.dst
                ),
            });
        }
    }

    pub(super) fn check_industrial_policy(&mut self, pkt: &Packet) {
        let Some(finding) = industrial_policy::inspect(pkt) else {
            return;
        };
        self.push_ids(IdsAlert {
            pkt_no: pkt.no,
            signature: if finding.critical {
                "Critical industrial control command"
            } else {
                "Industrial state-changing command"
            },
            severity: if finding.critical {
                Severity::Critical
            } else {
                Severity::High
            },
            detail: finding.detail(pkt),
        });
    }

    pub(super) fn check_dns_transaction_integrity(&mut self, pkt: &Packet) {
        for finding in self.dns_transactions.observe(pkt) {
            let (signature, severity) = match finding.kind {
                DnsFindingKind::ReplyWithoutObservedQuery => {
                    ("DNS reply without observed query", Severity::Low)
                }
                DnsFindingKind::AmbiguousReply => ("DNS reply correlation ambiguous", Severity::Low),
                DnsFindingKind::NxDomainBurst => ("DNS NXDOMAIN burst", Severity::Medium),
                DnsFindingKind::LargeTxtResponse => ("Oversized DNS TXT traffic", Severity::Low),
                DnsFindingKind::ExternalResolver => ("Direct external DNS resolver use", Severity::Low),
                DnsFindingKind::QuestionMismatch => {
                    ("DNS transaction question mismatch", Severity::Critical)
                }
                DnsFindingKind::UnexpectedResponder => {
                    ("Unexpected DNS responder", Severity::Critical)
                }
                DnsFindingKind::ConflictingResponse => {
                    ("Conflicting DNS responses", Severity::Critical)
                }
                DnsFindingKind::ChangedReply => {
                    ("DNS reply changed at the same resolver", Severity::Low)
                }
                DnsFindingKind::ChangedAnswerSet => {
                    ("DNS answer set changed at the same resolver", Severity::Medium)
                }
            };
            let correlation_key = crate::analysis::dns_transactions::alert_correlation_key(pkt, &finding);
            self.push_ids_finding(IdsFinding {
                alert: IdsAlert {
                    pkt_no: pkt.no,
                    signature,
                    severity,
                    detail: finding.detail,
                },
                related_packets: finding.related_packets,
                correlation_key: Some(correlation_key),
            });
        }
    }
}

fn dhcp_scope_name(scope: ServiceScope) -> String {
    let (interface, outer_vlan, vlan) = scope;
    let interface = interface.map_or_else(
        || "unknown capture interface".to_owned(),
        |(section, id)| format!("capture section {section}, interface {id}"),
    );
    match (outer_vlan, vlan) {
        (Some(outer), Some(inner)) => format!("{interface}, VLAN {outer}/{inner}"),
        (_, Some(vlan)) | (Some(vlan), _) => format!("{interface}, VLAN {vlan}"),
        _ => format!("{interface}, untagged"),
    }
}

fn observe_dhcp_server(
    state: &mut DhcpScopeState,
    server: std::net::Ipv4Addr,
    pkt: &Packet,
) -> Option<(std::net::Ipv4Addr, u64)> {
    if server.is_unspecified() || server.is_broadcast() || server.is_multicast()
        || pkt.timestamp < state.server_high_water
    {
        return None;
    }
    state.server_high_water = pkt.timestamp;
    let cutoff = pkt.timestamp - DHCP_SERVER_WINDOW_SECS;
    state.servers.retain(|_, (timestamp, _)| *timestamp >= cutoff);
    if let Some(observation) = state.servers.get_mut(&server) {
        *observation = (pkt.timestamp, pkt.no);
        return None;
    }
    if state.servers.len() >= MAX_DHCP_SERVERS {
        return None;
    }
    let previous = state.servers.iter()
        .max_by(|(_, (a, _)), (_, (b, _))| a.total_cmp(b))
        .map(|(&id, &(_, frame))| (id, frame));
    state.servers.insert(server, (pkt.timestamp, pkt.no));
    previous
}

fn dhcp_client_burst(state: &mut DhcpScopeState, identity: Vec<u8>, pkt: &Packet) -> Option<(usize, Vec<u64>)> {
    state.client_high_water = state.client_high_water.max(pkt.timestamp);
    let cutoff = state.client_high_water - DHCP_CLIENT_WINDOW_SECS;
    if pkt.timestamp < cutoff {
        return None;
    }
    state.clients.retain(|_, (timestamp, _)| *timestamp >= cutoff);
    if state.clients.len() < DHCP_STARVATION_THRESHOLD {
        state.starvation_alerted = false;
    }
    if state.clients.len() == MAX_DHCP_CLIENTS
        && !state.clients.contains_key(&identity)
        && let Some(oldest) = state.clients.iter()
            .min_by(|(_, (a, _)), (_, (b, _))| a.total_cmp(b))
            .map(|(identity, _)| identity.clone())
    {
        state.clients.remove(&oldest);
    }
    let current = state.clients.entry(identity).or_insert((pkt.timestamp, pkt.no));
    if pkt.timestamp > current.0 {
        *current = (pkt.timestamp, pkt.no);
    }
    let count = state.clients.len();
    if count < DHCP_STARVATION_THRESHOLD || state.starvation_alerted {
        return None;
    }
    state.starvation_alerted = true;
    let mut frames: Vec<_> = state.clients.values().map(|&(_, frame)| frame).collect();
    frames.sort_unstable();
    Some((count, frames))
}
