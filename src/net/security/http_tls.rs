use super::*;

impl SecurityEngine {
    // ─── HTTP Analytics ───────────────────────────────────────────────────────

    pub(super) fn check_http(&mut self, pkt: &Packet) {
        let dst_port = pkt.dst_port.unwrap_or(0);
        let src_port = pkt.src_port.unwrap_or(0);
        let http_ports = [80u16, 8080, 3000, 8000, 8888];
        if !http_ports.contains(&dst_port) && !http_ports.contains(&src_port) {
            return;
        }

        let payload = Self::ascii_payload(&pkt.bytes, 54);
        if payload.is_empty() {
            return;
        }

        let mut method = String::new();
        let mut path = String::new();
        let mut user_agent = String::new();
        let mut response_code: Option<u16> = None;

        let first_line = payload.lines().next().unwrap_or("");

        // Request: "GET /path HTTP/1.1"
        for m in &[
            "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT",
        ] {
            if first_line.starts_with(m) {
                method = m.to_string();
                let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
                if parts.len() >= 2 {
                    path = parts[1].to_string();
                }
                break;
            }
        }

        // Response: "HTTP/1.1 200 OK"
        if first_line.starts_with("HTTP/") {
            let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
            if parts.len() >= 2 {
                if let Ok(code) = parts[1].parse::<u16>() {
                    response_code = Some(code);
                }
            }
        }

        // User-Agent header
        for line in payload.lines() {
            let lower = line.to_lowercase();
            if lower.starts_with("user-agent:") {
                user_agent = line[11..].trim().to_string();
                break;
            }
        }

        if method.is_empty() && response_code.is_none() && path.is_empty() {
            return;
        }

        if self.http_records.len() >= MAX_ENTRIES {
            self.http_records.remove(0);
        }
        self.http_records.push(HttpRecord {
            pkt_no: pkt.no,
            src_ip: pkt.src.clone(),
            dst_ip: pkt.dst.clone(),
            port: if http_ports.contains(&dst_port) {
                dst_port
            } else {
                src_port
            },
            method,
            path,
            user_agent,
            response_code,
        });
    }

    // ─── TLS/SSL Weakness ─────────────────────────────────────────────────────

    pub(super) fn push_tls(&mut self, w: TlsWeakness) {
        if self.tls_weaknesses.len() >= MAX_ENTRIES {
            self.tls_weaknesses.remove(0);
        }
        self.tls_weaknesses.push(w);
    }

    pub(super) fn check_tls(&mut self, pkt: &Packet) {
        let dst_port = pkt.dst_port.unwrap_or(0);
        let src_port = pkt.src_port.unwrap_or(0);
        if dst_port != 443 && src_port != 443 {
            return;
        }
        let bytes = &pkt.bytes;
        if bytes.len() < 6 {
            return;
        }

        // TLS 1.0
        if bytes.starts_with(&[0x16, 0x03, 0x01]) {
            self.push_tls(TlsWeakness {
                pkt_no: pkt.no,
                src_ip: pkt.src.clone(),
                dst_ip: pkt.dst.clone(),
                kind: "TLS 1.0",
                detail: format!("TLS 1.0 handshake from {}", pkt.src),
            });
        }
        // SSL 3.0
        else if bytes.starts_with(&[0x16, 0x03, 0x00]) {
            self.push_tls(TlsWeakness {
                pkt_no: pkt.no,
                src_ip: pkt.src.clone(),
                dst_ip: pkt.dst.clone(),
                kind: "SSL 3.0 (POODLE)",
                detail: format!("SSL 3.0 record from {}", pkt.src),
            });
        }

        // Self-signed: SHA-1 with RSA OID 1.2.840.113549.1.1.5
        let sha1_oid: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05];
        if Self::contains_bytes(bytes, sha1_oid) {
            self.push_tls(TlsWeakness {
                pkt_no: pkt.no,
                src_ip: pkt.src.clone(),
                dst_ip: pkt.dst.clone(),
                kind: "SHA-1 Certificate",
                detail: format!("sha1WithRSA cert OID from {}", pkt.src),
            });
        }

        // RC4 cipher suites in Client Hello (record type 0x16, handshake type 0x01)
        if bytes.get(0).copied() == Some(0x16) && bytes.get(5).copied() == Some(0x01) {
            // Scan for cipher suites 0x0005 (RC4-SHA) or 0x000a (RC4-MD5)
            let rc4_suites: &[&[u8]] = &[&[0x00, 0x05], &[0x00, 0x0a]];
            for suite in rc4_suites {
                if Self::contains_bytes(bytes, suite) {
                    self.push_tls(TlsWeakness {
                        pkt_no: pkt.no,
                        src_ip: pkt.src.clone(),
                        dst_ip: pkt.dst.clone(),
                        kind: "RC4 Cipher Suite",
                        detail: format!(
                            "RC4 cipher 0x{:02x}{:02x} offered from {}",
                            suite[0], suite[1], pkt.src
                        ),
                    });
                    break;
                }
            }
        }
    }
}
