use super::*;

impl SecurityEngine {
    // ─── IPv6 / Layer-2 Control Plane ───────────────────────────────────────

    pub(super) fn check_ipv6_control_plane(&mut self, pkt: &Packet) {
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
                    "{} IPv6 extension headers from {} to {}",
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
        if matches!(icmp_type, 133..=137) && inspection.hop_limit != 255 {
            alerts.push((
                "Invalid IPv6 neighbor discovery hop limit",
                Severity::Critical,
                format!(
                    "ICMPv6 type {icmp_type} used hop limit {} instead of 255 from {}",
                    inspection.hop_limit, pkt.src
                ),
            ));
        }

        if icmp_type == 134 {
            let invalid_source = !is_ipv6_link_local(&inspection.source);
            if let Some(source_mac) = ethernet_source_mac(&pkt.bytes) {
                self.router_advertisements.retain(|_, state| {
                    pkt.timestamp < state.last_seen || pkt.timestamp - state.last_seen <= 1.0
                });
                if self.router_advertisements.len() < MAX_CONTROL_PLANE_IDENTITIES
                    || self.router_advertisements.contains_key(&source_mac)
                {
                    let state = self.router_advertisements.entry(source_mac).or_default();
                    state.last_seen = pkt.timestamp;
                    if invalid_source && !state.invalid_source_alerted {
                        state.invalid_source_alerted = true;
                        alerts.push((
                            "Invalid IPv6 router advertisement source",
                            Severity::Critical,
                            format!(
                                "Router Advertisement originated from non-link-local address {}",
                                pkt.src
                            ),
                        ));
                    }
                    state.timestamps.retain(|timestamp| {
                        pkt.timestamp < *timestamp || pkt.timestamp - *timestamp <= 1.0
                    });
                    if state.timestamps.is_empty() {
                        state.alerted = false;
                    }
                    state.timestamps.push(pkt.timestamp);
                    if state.timestamps.len() >= RA_FLOOD_THRESHOLD && !state.alerted {
                        state.alerted = true;
                        alerts.push((
                            "IPv6 router advertisement flood",
                            Severity::Critical,
                            format!(
                                "{} Router Advertisements from one MAC within one second",
                                state.timestamps.len()
                            ),
                        ));
                    }
                }
            }
        }

        if icmp_type == 136 && inspection.transport.len() >= 24 {
            let target: [u8; 16] = inspection.transport[8..24].try_into().unwrap_or([0; 16]);
            if let Some(mac) = ndp_target_link_layer_address(&inspection.transport[24..]) {
                if let Some(previous) = self.ndp_bindings.get(&target).copied() {
                    if previous != mac {
                        alerts.push((
                            "IPv6 neighbor binding changed",
                            Severity::Critical,
                            format!(
                                "Neighbor Advertisement changed target ownership from {} to {}",
                                format_mac(previous),
                                format_mac(mac)
                            ),
                        ));
                    }
                }
                if self.ndp_bindings.len() < MAX_CONTROL_PLANE_IDENTITIES
                    || self.ndp_bindings.contains_key(&target)
                {
                    self.ndp_bindings.insert(target, mac);
                }
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

    pub(super) fn check_layer2_control_plane(&mut self, pkt: &Packet) {
        let raw = &pkt.bytes;
        if is_stp_topology_change(raw) {
            self.push_ids(IdsAlert {
                pkt_no: pkt.no,
                signature: "STP topology change",
                severity: Severity::Medium,
                detail: format!(
                    "Spanning Tree topology-change BPDU from {}",
                    ethernet_source_mac(raw)
                        .map(format_mac)
                        .unwrap_or_else(|| "unknown".into())
                ),
            });
        }

        let Some((source_mac, chassis)) = lldp_chassis_identity(raw) else {
            return;
        };
        if let Some(previous) = self.lldp_chassis.get(&source_mac) {
            if previous != &chassis {
                self.push_ids(IdsAlert {
                    pkt_no: pkt.no,
                    signature: "LLDP chassis identity changed",
                    severity: Severity::High,
                    detail: format!(
                        "LLDP source {} changed its advertised chassis identity",
                        format_mac(source_mac)
                    ),
                });
            }
        }
        if self.lldp_chassis.len() < MAX_CONTROL_PLANE_IDENTITIES
            || self.lldp_chassis.contains_key(&source_mac)
        {
            self.lldp_chassis.insert(source_mac, chassis);
        }
    }
}
