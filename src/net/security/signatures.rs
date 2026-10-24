use super::*;

impl SecurityEngine {
    pub(super) fn check_ids(&mut self, pkt: &Packet) {
        let dst_port = pkt.dst_port.unwrap_or(0);
        let src_port = pkt.src_port.unwrap_or(0);
        let bytes = &pkt.bytes;

        // ── EternalBlue ─────────────────────────────────────────────────────
        if dst_port == 445 {
            let sig1: &[u8] = &[0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x00, 0x00, 0x00];
            if Self::contains_bytes(bytes, sig1) || Self::contains_str_ci(bytes, b"SMBr") {
                self.push_ids(IdsAlert {
                    pkt_no: pkt.no,
                    signature: "EternalBlue",
                    severity: Severity::Critical,
                    detail: format!("SMB exploit signature on port 445 from {}", pkt.src),
                });
            }
        }

        // ── BlueKeep ────────────────────────────────────────────────────────
        if dst_port == 3389 && bytes.len() > 100 {
            let sig: &[u8] = &[0x03, 0x00, 0x00];
            if bytes.starts_with(sig) || Self::contains_bytes(bytes, sig) {
                self.push_ids(IdsAlert {
                    pkt_no: pkt.no,
                    signature: "BlueKeep (CVE-2019-0708)",
                    severity: Severity::Critical,
                    detail: format!("RDP anomalous TPKT from {} len={}", pkt.src, bytes.len()),
                });
            }
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

        // ── LLMNR poisoning ─────────────────────────────────────────────────
        if dst_port == 5355 || pkt.dst == "224.0.0.252" {
            if Self::contains_str_ci(pkt.protocol.as_bytes(), b"udp")
                || Self::contains_str_ci(pkt.protocol.as_bytes(), b"llmnr")
            {
                self.push_ids(IdsAlert {
                    pkt_no: pkt.no,
                    signature: "LLMNR Poisoning",
                    severity: Severity::Medium,
                    detail: format!("LLMNR query from {} to {}", pkt.src, pkt.dst),
                });
            }
        }

        // ── NBNS poisoning ──────────────────────────────────────────────────
        if dst_port == 137
            && (Self::contains_str_ci(pkt.protocol.as_bytes(), b"udp")
                || Self::contains_str_ci(pkt.protocol.as_bytes(), b"nbns"))
        {
            let nbns_sig: &[u8] = &[0x00, 0x20, 0x43, 0x4b];
            if Self::contains_bytes(bytes, nbns_sig) {
                self.push_ids(IdsAlert {
                    pkt_no: pkt.no,
                    signature: "NBNS WPAD Poisoning",
                    severity: Severity::Medium,
                    detail: format!("NBNS WPAD query from {}", pkt.src),
                });
            }
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

        // ── PrintNightmare ───────────────────────────────────────────────────
        if dst_port == 445 || dst_port == 135 {
            let sig_pn: &[u8] = &[0x1c, 0x00];
            if Self::contains_bytes(bytes, sig_pn)
                && (Self::contains_str_ci(bytes, b"SpoolSS")
                    || Self::contains_bytes(bytes, &[0x6e, 0x64, 0x72, 0x76]))
            {
                self.push_ids(IdsAlert {
                    pkt_no: pkt.no,
                    signature: "PrintNightmare (CVE-2021-1675)",
                    severity: Severity::Critical,
                    detail: format!("Print Spooler RPC from {} on port {dst_port}", pkt.src),
                });
            }
        }

        // ── Pass-the-Hash ────────────────────────────────────────────────────
        if dst_port == 445 {
            let has_ntlm = Self::contains_str_ci(bytes, b"NTLMSSP");
            let has_kerb = Self::contains_str_ci(bytes, b"Kerberos")
                || Self::contains_str_ci(pkt.info.as_bytes(), b"kerberos");
            if has_ntlm && !has_kerb {
                // Heuristic: NTLM auth on SMB without Kerberos ticket
                self.push_ids(IdsAlert {
                    pkt_no: pkt.no,
                    signature: "Pass-the-Hash (suspected)",
                    severity: Severity::High,
                    detail: format!("SMB NTLM auth (no Kerberos) from {}", pkt.src),
                });
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
