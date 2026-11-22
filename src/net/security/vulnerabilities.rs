use super::*;

const AUTH_WINDOW_SECS: f64 = 30.0;
const AUTH_BURST_THRESHOLD: usize = 5;

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

    // ─── Repeated Service Observations ────────────────────────────────────────

    pub(super) fn check_brute_force(&mut self, pkt: &Packet) {
        let (Some(server_port @ (21 | 80 | 443 | 445 | 8080)), Some(client_port)) =
            (pkt.src_port, pkt.dst_port)
        else {
            return;
        };
        let Some((sequence, payload)) = crate::analysis::stream::tcp_segment_payload(pkt) else {
            return;
        };
        let service = match server_port {
            21 if is_ftp_not_logged_in(payload) => "FTP",
            445 if smb_wire::is_smb2_logon_failure(payload) => "SMB",
            80 | 443 | 8080 if is_http_unauthorized(payload) => "HTTP",
            _ => return,
        };
        self.record_service_observation(pkt, service, true, server_port, (client_port, sequence));
    }

    pub(super) fn record_service_observation(
        &mut self,
        pkt: &Packet,
        service: &'static str,
        response: bool,
        port: u16,
        token: (u16, u32),
    ) {
        let (client, server) = if response { (&pkt.dst, &pkt.src) } else { (&pkt.src, &pkt.dst) };
        let key = BfKey {
            src: client.clone(),
            dst: server.clone(),
            port,
            service,
            scope: service_scope(pkt),
        };
        let now = pkt.timestamp;
        if !now.is_finite() {
            return;
        }
        if self.bf_windows.len() >= MAX_ENTRIES && !self.bf_windows.contains_key(&key) {
            if let Some(oldest) = self
                .bf_windows
                .iter()
                .min_by(|(_, a), (_, b)| a.last_seen.total_cmp(&b.last_seen))
                .map(|(key, _)| key.clone())
            {
                self.bf_windows.remove(&oldest);
            }
        }
        let window = self.bf_windows.entry(key.clone()).or_insert(BfWindow {
            observations: Vec::new(),
            last_seen: now,
            alerted: false,
        });
        window.last_seen = window.last_seen.max(now);
        if window.last_seen - now > AUTH_WINDOW_SECS {
            return;
        }

        window
            .observations
            .retain(|entry| window.last_seen - entry.timestamp <= AUTH_WINDOW_SECS);
        if window.observations.len() < AUTH_BURST_THRESHOLD.div_ceil(2) {
            window.alerted = false;
        }
        if window.observations.iter().any(|entry| entry.transport_token == token) {
            return;
        }
        window.observations.push(AuthObservation {
            timestamp: now,
            packet_no: pkt.no,
            transport_token: token,
        });
        if window.observations.len() > AUTH_BURST_THRESHOLD {
            if let Some((oldest, _)) = window.observations.iter().enumerate()
                .min_by(|(_, a), (_, b)| a.timestamp.total_cmp(&b.timestamp))
            {
                window.observations.remove(oldest);
            }
        }

        if !window.alerted && window.observations.len() == AUTH_BURST_THRESHOLD {
            window.alerted = true;
            if self.brute_force.len() >= MAX_ENTRIES {
                self.brute_force.remove(0);
            }
            let alert = BruteForceAlert {
                src_ip: key.src,
                dst_ip: key.dst,
                port,
                attempts: window.observations.len(),
                service,
                packet_refs: window.observations.iter().map(|entry| entry.packet_no).collect(),
            };
            self.findings.authentication.push(alert.clone());
            self.brute_force.push(alert);
        }
    }
}

fn is_ftp_not_logged_in(payload: &[u8]) -> bool {
    payload.strip_prefix(b"530 ").is_some_and(|line| {
        let Some(end) = line.iter().position(|&byte| matches!(byte, b'\r' | b'\n')) else {
            return false;
        };
        line.get(end..end + 2) == Some(b"\r\n")
            && line[..end].iter().all(|&byte| byte.is_ascii_graphic() || byte == b' ')
    })
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
