use super::*;

const HTTP_PORTS: [u16; 5] = [80, 8080, 3000, 8000, 8888];
const MAX_HTTP_HEADER_BYTES: usize = 16_384;
const MAX_HTTP_HEADERS: usize = 48;

impl SecurityEngine {
    // ─── HTTP Analytics ───────────────────────────────────────────────────────

    pub(super) fn check_http(&mut self, pkt: &Packet) {
        if ![pkt.src_port, pkt.dst_port].into_iter().flatten().any(|port| HTTP_PORTS.contains(&port)) {
            return;
        }
        let Some((source, destination)) = crate::analysis::stream::tcp_port_pair(pkt) else {
            return;
        };
        let Some((_, payload)) = crate::analysis::stream::tcp_segment_payload(pkt) else {
            return;
        };
        let Some(record) = http_observation(pkt, source, destination, payload) else { return };

        if self.http_records.len() >= MAX_ENTRIES {
            self.http_records.remove(0);
        }
        self.http_records.push(record);
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

fn http_observation(pkt: &Packet, source: u16, destination: u16, payload: &[u8]) -> Option<HttpRecord> {
    let payload = &payload[..payload.len().min(MAX_HTTP_HEADER_BYTES)];
    let mut headers = [httparse::EMPTY_HEADER; MAX_HTTP_HEADERS];
    let (port, method, path, user_agent, response_code) = if payload.starts_with(b"HTTP/") {
        if !HTTP_PORTS.contains(&source) {
            return None;
        }
        let mut response = httparse::Response::new(&mut headers);
        if !response.parse(payload).ok()?.is_complete() {
            return None;
        }
        let status = response.code.filter(|code| (100..=599).contains(code))?;
        (source, String::new(), String::new(), String::new(), Some(status))
    } else {
        if !HTTP_PORTS.contains(&destination) {
            return None;
        }
        let mut request = httparse::Request::new(&mut headers);
        if !request.parse(payload).ok()?.is_complete() {
            return None;
        }
        let user_agent = request.headers.iter().find(|field| field.name.eq_ignore_ascii_case("user-agent"))
            .and_then(|field| std::str::from_utf8(field.value).ok()).unwrap_or_default();
        (destination, display_field(request.method?, 32), display_field(request.path?, 512),
            display_field(user_agent, 256), None)
    };
    Some(HttpRecord { pkt_no: pkt.no, src_ip: pkt.src.clone(), dst_ip: pkt.dst.clone(), port,
        method, path, user_agent, response_code })
}

fn display_field(value: &str, limit: usize) -> String {
    value.chars().take(limit).map(|ch| if ch.is_control() { ' ' } else { ch }).collect()
}
