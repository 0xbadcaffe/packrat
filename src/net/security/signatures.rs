use super::*;

impl SecurityEngine {
    pub(super) fn check_ids(&mut self, pkt: &Packet) {
        Self::scan_ids(pkt, |alert, correlation_key| {
            // Reassembly may already have reported the same signature on this frame.
            if !self.findings.ids.iter().any(|finding| {
                finding.alert.pkt_no == alert.pkt_no && finding.alert.signature == alert.signature
            }) {
                self.push_ids_finding(IdsFinding {
                    alert,
                    related_packets: Vec::new(),
                    correlation_key,
                });
            }
        });
    }

    pub(super) fn check_reassembled_ids(
        &mut self,
        triggering_frame: &Packet,
        synthetic: &Packet,
        frames: &[u64],
        identification: u32,
    ) {
        Self::scan_ids(synthetic, |mut alert, _| {
            alert.detail = format!(
                "{}; matched after IPv6 reassembly of {} captured frames",
                alert.detail,
                frames.len()
            );
            self.push_ids_finding(IdsFinding {
                alert,
                related_packets: frames
                    .iter()
                    .copied()
                    .filter(|&frame| frame != triggering_frame.no)
                    .collect(),
                correlation_key: Some(format!(
                    "ipv6-datagram:{:?}:{}>{}:{identification}",
                    service_scope(triggering_frame),
                    triggering_frame.src,
                    triggering_frame.dst,
                )),
            });
        });
    }

    fn scan_ids(pkt: &Packet, mut emit: impl FnMut(IdsAlert, Option<String>)) {
        let dst_port = pkt.dst_port.unwrap_or(0);
        let src_port = pkt.src_port.unwrap_or(0);
        let bytes = &pkt.bytes;

        if src_port == 445
            && crate::analysis::stream::tcp_segment_payload(pkt)
                .is_some_and(|(_, payload)| smb_wire::is_successful_legacy_reply(payload))
        {
            emit(
                IdsAlert {
                    pkt_no: pkt.no,
                    signature: "SMBv1 server response",
                    severity: Severity::Medium,
                    detail: format!(
                        "{} sent a successful SMBv1 response to {}; patch and exploitation status unverified",
                        pkt.src, pkt.dst
                    ),
                },
                Some(format!("{:?}:{}>{}", service_scope(pkt), pkt.src, pkt.dst)),
            );
        }

        // ── Log4Shell ───────────────────────────────────────────────────────
        if Self::contains_str_ci(bytes, b"${jndi:") {
            emit(
                IdsAlert {
                    pkt_no: pkt.no,
                    signature: "Log4Shell (CVE-2021-44228)",
                    severity: Severity::Critical,
                    detail: format!(
                        "${{jndi:}} pattern in payload from {} proto={}",
                        pkt.src, pkt.protocol
                    ),
                },
                None,
            );
        }

        // ── Shellcode NOP sled ───────────────────────────────────────────────
        if Self::nop_sled_16(bytes) {
            emit(
                IdsAlert {
                    pkt_no: pkt.no,
                    signature: "Shellcode NOP sled",
                    severity: Severity::High,
                    detail: format!("16+ consecutive 0x90 bytes from {}", pkt.src),
                },
                None,
            );
        }

        if src_port == 137
            && let Some((id, address, count)) = nbns_wire::wpad_address_reply(pkt)
        {
            emit(
                IdsAlert {
                    pkt_no: pkt.no,
                    signature: "NBNS WPAD address reply",
                    severity: Severity::Medium,
                    detail: format!(
                        "{} returned a WPAD address to {} (transaction 0x{id:04x}, first address {address}, total {count}); client use unverified",
                        pkt.src, pkt.dst
                    ),
                },
                Some(format!("{:?}:{}>{}", service_scope(pkt), pkt.src, pkt.dst)),
            );
        }

        // ── Directory traversal ─────────────────────────────────────────────
        if dst_port == 80 || dst_port == 443 || dst_port == 8080 {
            let count = Self::count_pattern_ascii(bytes, b"../");
            if count >= 5 {
                emit(
                    IdsAlert {
                        pkt_no: pkt.no,
                        signature: "Directory Traversal",
                        severity: Severity::High,
                        detail: format!("Path traversal ({count}x ../) from {}", pkt.src),
                    },
                    None,
                );
            }
        }

        // ── SQL injection probe ──────────────────────────────────────────────
        if dst_port == 80
            || dst_port == 443
            || dst_port == 8080
            || dst_port == 3000
            || dst_port == 8000
        {
            if Self::contains_str_ci(bytes, b"' OR 1=1")
                || Self::contains_str_ci(bytes, b"'; DROP TABLE")
                || Self::contains_str_ci(bytes, b"UNION SELECT")
            {
                emit(
                    IdsAlert {
                        pkt_no: pkt.no,
                        signature: "SQL Injection Probe",
                        severity: Severity::High,
                        detail: format!("SQLi pattern in HTTP payload from {}", pkt.src),
                    },
                    None,
                );
            }
        }

        // ── XSS probe ───────────────────────────────────────────────────────
        if Self::contains_str_ci(bytes, b"<script>") || Self::contains_str_ci(bytes, b"javascript:")
        {
            emit(
                IdsAlert {
                    pkt_no: pkt.no,
                    signature: "XSS Probe",
                    severity: Severity::Medium,
                    detail: format!("XSS pattern from {}", pkt.src),
                },
                None,
            );
        }

        // ── Heartbleed ──────────────────────────────────────────────────────
        if (dst_port == 443 || src_port == 443) && bytes.len() >= 7 {
            // TLS heartbeat record type = 0x18
            if bytes.get(0).copied() == Some(0x18) && bytes.get(1).copied() == Some(0x03) {
                let claimed_len = u16_be_at(bytes, 3) as usize;
                if claimed_len > bytes.len() + 64 {
                    emit(
                        IdsAlert {
                            pkt_no: pkt.no,
                            signature: "Heartbleed (CVE-2014-0160)",
                            severity: Severity::Critical,
                            detail: format!(
                                "TLS heartbeat claimed_len={claimed_len} actual={} from {}",
                                bytes.len(),
                                pkt.src
                            ),
                        },
                        None,
                    );
                }
            }
        }

    }
}
