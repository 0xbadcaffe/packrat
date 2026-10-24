use super::*;

impl SecurityEngine {
    // ─── Vulnerability Patterns ───────────────────────────────────────────────

    pub(super) fn push_vuln(&mut self, v: VulnHit) {
        if self.vuln_hits.len() >= MAX_ENTRIES {
            self.vuln_hits.remove(0);
        }
        self.vuln_hits.push(v);
    }

    pub(super) fn check_vuln(&mut self, pkt: &Packet) {
        let dst_port = pkt.dst_port.unwrap_or(0);
        let src_port = pkt.src_port.unwrap_or(0);
        let bytes = &pkt.bytes;

        // HTTP cleartext sensitive paths on port 80
        if dst_port == 80 {
            let payload = Self::ascii_payload(bytes, 54);
            let lower = payload.to_lowercase();
            for sens in &[
                "/admin",
                "/login",
                "/passwd",
                "/password",
                "/config",
                "/wp-admin",
            ] {
                if lower.contains(sens) {
                    self.push_vuln(VulnHit {
                        pkt_no: pkt.no,
                        kind: "Cleartext HTTP Sensitive Path",
                        detail: format!("Path '{}' over plaintext HTTP from {}", sens, pkt.src),
                    });
                    break;
                }
            }
        }

        // Weak TLS: TLS 1.0 or SSL 3.0
        if dst_port == 443 || src_port == 443 {
            let tls10: &[u8] = &[0x16, 0x03, 0x01];
            let ssl30: &[u8] = &[0x16, 0x03, 0x00];
            if bytes.starts_with(tls10) {
                self.push_vuln(VulnHit {
                    pkt_no: pkt.no,
                    kind: "Weak TLS 1.0",
                    detail: format!("TLS 1.0 record from {}", pkt.src),
                });
            } else if bytes.starts_with(ssl30) {
                self.push_vuln(VulnHit {
                    pkt_no: pkt.no,
                    kind: "Weak SSL 3.0",
                    detail: format!("SSL 3.0 record from {}", pkt.src),
                });
            }
        }

        // Cleartext Telnet credentials
        if dst_port == 23 || src_port == 23 {
            let payload = Self::ascii_payload(bytes, 54);
            if payload.contains("login:") || payload.contains("Password:") {
                self.push_vuln(VulnHit {
                    pkt_no: pkt.no,
                    kind: "Cleartext Telnet Credential",
                    detail: format!("Telnet login prompt from {}", pkt.src),
                });
            }
        }

        // Anonymous FTP
        if dst_port == 21 || src_port == 21 {
            let payload = Self::ascii_payload(bytes, 54);
            let lower = payload.to_lowercase();
            if lower.contains("user anonymous") || lower.contains("user ftp") {
                self.push_vuln(VulnHit {
                    pkt_no: pkt.no,
                    kind: "Anonymous FTP Login",
                    detail: format!("FTP anonymous login attempt from {}", pkt.src),
                });
            }
        }

        // SMB null session
        if dst_port == 445 {
            // NTLM with empty credentials signature
            if Self::contains_str_ci(bytes, b"NTLMSSP")
                && Self::contains_bytes(bytes, &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            {
                self.push_vuln(VulnHit {
                    pkt_no: pkt.no,
                    kind: "SMB Null Session",
                    detail: format!("SMB anonymous/null NTLM from {}", pkt.src),
                });
            }
        }
    }

    // ─── Brute Force Detection ────────────────────────────────────────────────

    pub(super) fn check_brute_force(&mut self, pkt: &Packet) {
        let dst_port = pkt.dst_port.unwrap_or(0);
        let src_port = pkt.src_port.unwrap_or(0);
        let bytes = &pkt.bytes;

        let service: Option<&'static str> = match dst_port {
            22 => Some("SSH"),
            21 => {
                let p = Self::ascii_payload(bytes, 54);
                if p.contains("530 Login incorrect") || p.contains("530 Failed") {
                    Some("FTP")
                } else {
                    None
                }
            }
            80 | 443 => {
                let info = &pkt.info;
                if info.contains("401") {
                    Some("HTTP")
                } else {
                    None
                }
            }
            445 => {
                if Self::contains_str_ci(bytes, b"NTLMSSP") {
                    Some("SMB")
                } else {
                    None
                }
            }
            _ => {
                // Check response side
                if src_port == 21 {
                    let p = Self::ascii_payload(bytes, 54);
                    if p.contains("530 Login incorrect") || p.contains("530 Failed") {
                        Some("FTP")
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
        };

        if let Some(svc) = service {
            let key = BfKey {
                src: pkt.src.clone(),
                dst: pkt.dst.clone(),
                port: dst_port,
            };
            let now = pkt.timestamp;
            let window = self.bf_windows.entry(key.clone()).or_insert(BfWindow {
                timestamps: Vec::new(),
                service: svc,
                alerted: false,
            });

            // Prune events older than 30 seconds
            window.timestamps.retain(|&t| now - t <= 30.0);
            window.timestamps.push(now);

            if !window.alerted && window.timestamps.len() >= 5 {
                window.alerted = true;
                let attempts = window.timestamps.len();
                let svc_static = window.service;
                if self.brute_force.len() >= MAX_ENTRIES {
                    self.brute_force.remove(0);
                }
                self.brute_force.push(BruteForceAlert {
                    src_ip: key.src,
                    dst_ip: key.dst,
                    port: key.port,
                    attempts,
                    service: svc_static,
                });
            }
        }
    }
}
