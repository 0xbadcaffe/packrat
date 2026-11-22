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
        self.findings.tls.push(w.clone());
        if self.tls_weaknesses.len() >= MAX_ENTRIES {
            self.tls_weaknesses.remove(0);
        }
        self.tls_weaknesses.push(w);
    }

    pub(super) fn check_tls(&mut self, pkt: &Packet) {
        if pkt.src_port != Some(443)
            || !matches!(crate::analysis::stream::tcp_port_pair(pkt), Some((443, _)))
        {
            return;
        }
        let Some((version, cipher)) = crate::analysis::stream::tcp_segment_payload(pkt)
            .and_then(|(_, payload)| crate::analysis::encrypted_insight::parse_anchored_server_hello(payload))
        else {
            return;
        };
        let legacy = match version {
            0x0300 => Some("SSL 3.0 selected"),
            0x0301 => Some("TLS 1.0 selected"),
            0x0302 => Some("TLS 1.1 selected"),
            _ => None,
        };
        if let Some(kind) = legacy {
            self.push_tls(TlsWeakness {
                pkt_no: pkt.no,
                src_ip: pkt.src.clone(),
                dst_ip: pkt.dst.clone(),
                kind,
                detail: format!("{}: {kind} in ServerHello; handshake completion unverified", pkt.src),
            });
        }
        if version <= 0x0303 && matches!(cipher, 0x0003..=0x0005) {
            self.push_tls(TlsWeakness {
                pkt_no: pkt.no,
                src_ip: pkt.src.clone(),
                dst_ip: pkt.dst.clone(),
                kind: "RC4 selected",
                detail: format!("{} selected RC4 cipher 0x{cipher:04x} in ServerHello; handshake completion unverified", pkt.src),
            });
        }
    }
}
