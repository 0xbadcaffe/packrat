use super::*;

impl SecurityEngine {
    pub(super) fn check_ids(&mut self, pkt: &Packet) {
        let dst_port = pkt.dst_port.unwrap_or(0);
        let src_port = pkt.src_port.unwrap_or(0);
        let bytes = &pkt.bytes;

        if src_port == 445
            && crate::analysis::stream::tcp_segment_payload(pkt)
                .is_some_and(|(_, payload)| smb_wire::is_successful_legacy_reply(payload))
        {
            self.push_ids_finding(IdsFinding {
                alert: IdsAlert {
                    pkt_no: pkt.no,
                    signature: "SMBv1 server response",
                    severity: Severity::Medium,
                    detail: format!(
                        "{} sent a successful SMBv1 response to {}; patch and exploitation status unverified",
                        pkt.src, pkt.dst
                    ),
                },
                related_packets: Vec::new(),
                correlation_key: Some(format!("{:?}:{}>{}", service_scope(pkt), pkt.src, pkt.dst)),
            });
        }

        // ── Log4Shell ───────────────────────────────────────────────────────
        if Self::contains_str_ci(bytes, b"${jndi:") {
            self.push_ids(IdsAlert {
                pkt_no: pkt.no,
                signature: "Log4Shell (CVE-2021-44228)",
                severity: Severity::Critical,
                detail: format!(
                    "${{jndi:}} pattern in payload from {} proto={}",
                    pkt.src, pkt.protocol
                ),
            });
        }

        // ── Shellcode NOP sled ───────────────────────────────────────────────
        if Self::nop_sled_16(bytes) {
            self.push_ids(IdsAlert {
                pkt_no: pkt.no,
                signature: "Shellcode NOP sled",
                severity: Severity::High,
                detail: format!("16+ consecutive 0x90 bytes from {}", pkt.src),
            });
        }

        if src_port == 137
            && let Some((id, address, count)) = nbns_wire::wpad_address_reply(pkt)
        {
            self.push_ids_finding(IdsFinding {
                alert: IdsAlert {
                    pkt_no: pkt.no,
                    signature: "NBNS WPAD address reply",
                    severity: Severity::Medium,
                    detail: format!(
                        "{} returned a WPAD address to {} (transaction 0x{id:04x}, first address {address}, total {count}); client use unverified",
                        pkt.src, pkt.dst
                    ),
                },
                related_packets: Vec::new(),
                correlation_key: Some(format!("{:?}:{}>{}", service_scope(pkt), pkt.src, pkt.dst)),
            });
        }

        // ── Directory traversal ─────────────────────────────────────────────
        if dst_port == 80 || dst_port == 443 || dst_port == 8080 {
            let count = Self::count_pattern_ascii(bytes, b"../");
            if count >= 5 {
                self.push_ids(IdsAlert {
                    pkt_no: pkt.no,
                    signature: "Directory Traversal",
                    severity: Severity::High,
                    detail: format!("Path traversal ({count}x ../) from {}", pkt.src),
                });
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
                self.push_ids(IdsAlert {
                    pkt_no: pkt.no,
                    signature: "SQL Injection Probe",
                    severity: Severity::High,
                    detail: format!("SQLi pattern in HTTP payload from {}", pkt.src),
                });
            }
        }

        // ── XSS probe ───────────────────────────────────────────────────────
        if Self::contains_str_ci(bytes, b"<script>") || Self::contains_str_ci(bytes, b"javascript:")
        {
            self.push_ids(IdsAlert {
                pkt_no: pkt.no,
                signature: "XSS Probe",
                severity: Severity::Medium,
                detail: format!("XSS pattern from {}", pkt.src),
            });
        }

        // ── Heartbleed ──────────────────────────────────────────────────────
        if (dst_port == 443 || src_port == 443) && bytes.len() >= 7 {
            // TLS heartbeat record type = 0x18
            if bytes.get(0).copied() == Some(0x18) && bytes.get(1).copied() == Some(0x03) {
                let claimed_len = u16_be_at(bytes, 3) as usize;
                if claimed_len > bytes.len() + 64 {
                    self.push_ids(IdsAlert {
                        pkt_no: pkt.no,
                        signature: "Heartbleed (CVE-2014-0160)",
                        severity: Severity::Critical,
                        detail: format!(
                            "TLS heartbeat claimed_len={claimed_len} actual={} from {}",
                            bytes.len(),
                            pkt.src
                        ),
                    });
                }
            }
        }

        // ── CVE-2021-44228 via DNS ───────────────────────────────────────────
        if dst_port == 53
            || src_port == 53
            || Self::contains_str_ci(pkt.protocol.as_bytes(), b"dns")
        {
            if Self::contains_str_ci(pkt.info.as_bytes(), b"jndi") {
                self.push_ids(IdsAlert {
                    pkt_no: pkt.no,
                    signature: "Log4Shell via DNS (CVE-2021-44228)",
                    severity: Severity::Critical,
                    detail: format!("DNS query contains 'jndi' from {}", pkt.src),
                });
            }
        }
    }
}
