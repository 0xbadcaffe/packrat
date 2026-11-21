use super::*;

impl SecurityEngine {
    // ─── Vulnerability Patterns ───────────────────────────────────────────────

    pub(super) fn push_vuln(&mut self, v: VulnHit) {
        self.findings.vulnerabilities.push(v.clone());
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

        let http_failure = matches!(src_port, 80 | 443 | 8080)
            .then(|| crate::analysis::stream::tcp_segment_payload(pkt))
            .flatten()
            .filter(|(_, payload)| is_http_unauthorized(payload))
            .map(|(sequence, _)| (dst_port, sequence));
        let service: Option<&'static str> = match dst_port {
            _ if http_failure.is_some() => Some("HTTP"),
            22 => Some("SSH"),
            21 => {
                let p = Self::ascii_payload(bytes, 54);
                if p.contains("530 Login incorrect") || p.contains("530 Failed") {
                    Some("FTP")
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
            let key = if http_failure.is_some() {
                BfKey {
                    src: pkt.dst.clone(),
                    dst: pkt.src.clone(),
                    port: src_port,
                }
            } else {
                BfKey {
                    src: pkt.src.clone(),
                    dst: pkt.dst.clone(),
                    port: dst_port,
                }
            };
            let now = pkt.timestamp;
            if self.bf_windows.len() >= MAX_ENTRIES && !self.bf_windows.contains_key(&key) {
                if let Some(oldest) = self
                    .bf_windows
                    .iter()
                    .min_by(|(_, a), (_, b)| {
                        let last = |window: &BfWindow| {
                            window
                                .observations
                                .last()
                                .map_or(f64::NEG_INFINITY, |entry| entry.0)
                        };
                        last(a).total_cmp(&last(b))
                    })
                    .map(|(key, _)| key.clone())
                {
                    self.bf_windows.remove(&oldest);
                }
            }
            let window = self.bf_windows.entry(key.clone()).or_insert(BfWindow {
                observations: Vec::new(),
                service: svc,
                alerted: false,
            });

            // Prune events older than 30 seconds
            window
                .observations
                .retain(|&(t, _)| (0.0..=30.0).contains(&(now - t)));
            if window.observations.is_empty() {
                window.alerted = false;
            }
            if http_failure.is_some()
                && window.observations.iter().any(|&(_, token)| token == http_failure)
            {
                return;
            }
            if window.observations.len() == 5 {
                window.observations.remove(0);
            }
            window.observations.push((now, http_failure));

            if !window.alerted && window.observations.len() >= 5 {
                window.alerted = true;
                let attempts = window.observations.len();
                let svc_static = window.service;
                if self.brute_force.len() >= MAX_ENTRIES {
                    self.brute_force.remove(0);
                }
                let alert = BruteForceAlert {
                    src_ip: key.src,
                    dst_ip: key.dst,
                    port: key.port,
                    attempts,
                    service: svc_static,
                };
                self.findings.authentication.push(alert.clone());
                self.brute_force.push(alert);
            }
        }
    }
}

fn is_http_unauthorized(payload: &[u8]) -> bool {
    let Some(status) = payload
        .strip_prefix(b"HTTP/1.1 ")
        .or_else(|| payload.strip_prefix(b"HTTP/1.0 "))
        .and_then(|line| line.strip_prefix(b"401 "))
    else {
        return false;
    };
    status
        .iter()
        .position(|byte| matches!(byte, b'\r' | b'\n'))
        .is_some_and(|end| status.get(end..end + 2) == Some(b"\r\n"))
}
