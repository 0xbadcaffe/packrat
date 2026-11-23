use super::*;

const AUTH_WINDOW_SECS: f64 = 30.0;
const AUTH_BURST_THRESHOLD: usize = 5;
const AUTH_RETRY_HISTORY_SECS: f64 = 2.0 * AUTH_WINDOW_SECS;
const MAX_AUTH_RETRY_TOKENS: usize = 64;

#[derive(Default)]
pub(super) struct AuthRetryHistory(Vec<(f64, (u16, u32))>);

impl AuthRetryHistory {
    fn remember(&mut self, now: f64, last_seen: f64, token: (u16, u32)) -> bool {
        self.0.retain(|(seen, _)| last_seen - seen <= AUTH_RETRY_HISTORY_SECS);
        if self.0.iter().any(|(_, previous)| *previous == token) {
            return false;
        }
        if self.0.len() == MAX_AUTH_RETRY_TOKENS {
            let oldest = self.0.iter().enumerate()
                .min_by(|(_, (a, _)), (_, (b, _))| a.total_cmp(b))
                .map_or(0, |(index, _)| index);
            self.0.remove(oldest);
        }
        self.0.push((now, token));
        true
    }
}

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
        if pkt.src_port != Some(23)
            || pkt.capture.as_ref().is_some_and(|capture| capture.link_type != 1)
        {
            return;
        }
        let Some(TcpFrame::Segment(segment)) =
            parse_ipv4_tcp_frame(&pkt.bytes).or_else(|| parse_ipv6_tcp_frame(&pkt.bytes))
        else { return };
        let source = if segment.from_a { segment.key.endpoint_a } else { segment.key.endpoint_b };
        if segment.complete && source.port() == 23 && segment.flags & 0x07 == 0
            && let Some(prompt) = telnet_wire::authentication_prompt(segment.payload)
        {
            self.push_vuln(VulnHit {
                pkt_no: pkt.no,
                kind: "Telnet authentication prompt",
                detail: format!("{source} sent a {prompt} prompt over Telnet; client credentials were not observed"),
            });
        }
    }

    // ─── Repeated Service Observations ────────────────────────────────────────

    pub(super) fn check_brute_force(&mut self, pkt: &Packet) {
        let (Some(server_port @ (21 | 80 | 443 | 445 | 8080)), Some(client_port)) =
            (pkt.src_port, pkt.dst_port)
        else {
            return;
        };
        let Some((sequence, payload)) =
            crate::analysis::stream::tcp_payload_with_ack(pkt, (server_port, client_port))
        else {
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
            recent_tokens: AuthRetryHistory::default(),
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
        if window.observations.iter().any(|entry| entry.transport_token == token)
            || !window.recent_tokens.remember(now, window.last_seen, token)
        {
            return;
        }
        window.observations.push(AuthObservation {
            timestamp: now,
            packet_no: pkt.no,
            transport_token: token,
            http_stream: if service == "HTTP" {
                crate::analysis::stream::StreamKey::from_packet(pkt).map(|key| key.id())
            } else {
                None
            },
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
                http_streams: window.observations.iter().filter_map(|entry| {
                    Some((entry.packet_no, entry.http_stream.clone()?))
                }).collect(),
            };
            self.findings.authentication.push(alert.clone());
            self.brute_force.push(alert);
        }
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/auth_retry_history_tests.rs"]
mod tests;

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
    (payload.starts_with(b"HTTP/1.1 401") || payload.starts_with(b"HTTP/1.0 401"))
        && http_policy::response_status(payload) == Some(401)
}
