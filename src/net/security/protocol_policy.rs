use super::*;

impl SecurityEngine {
    // ─── DHCP Authority and Starvation ──────────────────────────────────────

    pub(super) fn check_dhcp_integrity(&mut self, pkt: &Packet) {
        let Some(message) = parse_dhcp_message(&pkt.bytes) else {
            return;
        };
        let state = self.dhcp_vlans.entry(pkt.vlan_id).or_default();
        let mut alerts = Vec::new();

        if matches!(message.message_type, 2 | 5) && !message.server_identity.is_empty() {
            if !state.servers.is_empty() && !state.servers.contains(&message.server_identity) {
                alerts.push((
                    "DHCP server identity changed",
                    Severity::High,
                    format!(
                        "A new DHCP OFFER/ACK authority appeared on VLAN {} from {}",
                        pkt.vlan_id
                            .map(|id| id.to_string())
                            .unwrap_or_else(|| "untagged".into()),
                        pkt.src
                    ),
                ));
            }
            if state.servers.len() < 32 {
                state.servers.insert(message.server_identity);
            }
        }

        if message.message_type == 1 && !message.client_identity.is_empty() {
            state.clients.retain(|(timestamp, _)| {
                pkt.timestamp < *timestamp || pkt.timestamp - *timestamp <= 10.0
            });
            if state.clients.is_empty() {
                state.starvation_alerted = false;
            }
            state.clients.push((pkt.timestamp, message.client_identity));
            if state.clients.len() > 256 {
                state.clients.remove(0);
            }
            let unique_clients = state
                .clients
                .iter()
                .map(|(_, identity)| identity.as_slice())
                .collect::<HashSet<_>>()
                .len();
            if unique_clients >= DHCP_STARVATION_THRESHOLD && !state.starvation_alerted {
                state.starvation_alerted = true;
                alerts.push((
                    "DHCP client identity burst",
                    Severity::Critical,
                    format!("{unique_clients} distinct DHCP clients appeared on one VLAN within 10 seconds"),
                ));
            }
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

    pub(super) fn check_ipv6_fragment_reassembly(&mut self, pkt: &Packet) {
        match self.ipv6_fragments.ingest(pkt) {
            Ipv6FragmentOutcome::Ignored => {}
            Ipv6FragmentOutcome::Pending {
                conflicting_overlap,
                fragment_count,
            } => {
                if conflicting_overlap {
                    self.push_ids(IdsAlert {
                        pkt_no: pkt.no,
                        signature: "Conflicting IPv6 fragments",
                        severity: Severity::Critical,
                        detail: format!(
                            "Conflicting overlap among {fragment_count} IPv6 fragments from {}",
                            pkt.src
                        ),
                    });
                }
            }
            Ipv6FragmentOutcome::Rejected { reason } => {
                self.push_ids(IdsAlert {
                    pkt_no: pkt.no,
                    signature: "IPv6 fragment reassembly rejected",
                    severity: Severity::High,
                    detail: format!("{reason} from {}", pkt.src),
                });
            }
            Ipv6FragmentOutcome::Complete {
                datagram,
                conflicting_overlap,
            } => {
                if conflicting_overlap {
                    self.push_ids(IdsAlert {
                        pkt_no: pkt.no,
                        signature: "Conflicting IPv6 fragments",
                        severity: Severity::Critical,
                        detail: format!(
                            "Conflicting overlap in completed IPv6 datagram from {}",
                            pkt.src
                        ),
                    });
                }
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
                self.check_ids(&synthetic);
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
                DnsFindingKind::UnsolicitedResponse => ("Unsolicited DNS response", Severity::High),
                DnsFindingKind::QuestionMismatch => {
                    ("DNS transaction question mismatch", Severity::Critical)
                }
                DnsFindingKind::UnexpectedResponder => {
                    ("Unexpected DNS responder", Severity::Critical)
                }
                DnsFindingKind::ConflictingResponse => {
                    ("Conflicting DNS responses", Severity::Critical)
                }
            };
            self.push_ids(IdsAlert {
                pkt_no: pkt.no,
                signature,
                severity,
                detail: finding.detail,
            });
        }
    }
}
