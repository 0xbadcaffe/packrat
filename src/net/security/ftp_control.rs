use super::*;

const MAX_ATTEMPTS: usize = 1024;
const WINDOW_SECS: f64 = 30.0;

#[derive(Clone, Copy)]
enum Phase {
    User,
    Challenge(u64),
    Password { challenge: u64, frame: u64 },
    Closed,
}

struct Attempt {
    user: u64,
    next_sequence: u32,
    seen_at: f64,
    phase: Phase,
}

#[derive(Default)]
pub(super) struct FtpControl {
    attempts: HashMap<(ServiceScope, TcpFlowKey), Attempt>,
}

impl FtpControl {
    pub(super) fn clear(&mut self) {
        self.attempts.clear();
    }

    fn observe(&mut self, pkt: &Packet, segment: TcpSegment<'_>) -> Option<IdsFinding> {
        let (source, destination) = if segment.from_a {
            (segment.key.endpoint_a, segment.key.endpoint_b)
        } else {
            (segment.key.endpoint_b, segment.key.endpoint_a)
        };
        if !segment.complete || !pkt.timestamp.is_finite()
            || (source.port() == 21) == (destination.port() == 21)
        {
            return None;
        }
        let scope = service_scope(pkt);
        let key = (scope, segment.key);
        if segment.flags & 0x07 != 0 { // FIN, SYN, or RST ends the prior observation.
            self.attempts.remove(&key);
            return None;
        }
        if segment.flags & 0x10 == 0 || segment.payload.is_empty() {
            return None;
        }
        if let Some(previous) = self.attempts.get(&key) {
            if pkt.timestamp < previous.seen_at {
                return None;
            }
            if pkt.timestamp - previous.seen_at > WINDOW_SECS {
                self.attempts.remove(&key);
            }
        }
        let line = single_line(segment.payload)?;
        if destination.port() == 21 {
            if self.attempts.get(&key).is_some_and(|attempt| {
                (segment.sequence.wrapping_sub(attempt.next_sequence) as i32) < 0
            }) {
                return None;
            }
            let (command, value) = line.split_once(' ').unwrap_or((line, ""));
            let next_sequence = segment.sequence.wrapping_add(segment.payload.len() as u32);
            if command.eq_ignore_ascii_case("USER")
                && (value.eq_ignore_ascii_case("anonymous") || value.eq_ignore_ascii_case("ftp"))
            {
                if self.attempts.len() >= MAX_ATTEMPTS && !self.attempts.contains_key(&key) {
                    self.attempts.retain(|_, attempt| pkt.timestamp - attempt.seen_at <= WINDOW_SECS);
                    if self.attempts.len() >= MAX_ATTEMPTS {
                        return None;
                    }
                }
                self.attempts.insert(key, Attempt {
                    user: pkt.no, next_sequence, seen_at: pkt.timestamp, phase: Phase::User,
                });
            } else if command.eq_ignore_ascii_case("PASS") && !value.is_empty()
                && let Some(attempt) = self.attempts.get_mut(&key)
                && let Phase::Challenge(challenge) = attempt.phase
                && segment.sequence == attempt.next_sequence
            {
                attempt.next_sequence = next_sequence;
                attempt.seen_at = pkt.timestamp;
                attempt.phase = Phase::Password { challenge, frame: pkt.no };
            } else {
                self.attempts.remove(&key);
            }
            return None;
        }

        let attempt = self.attempts.get_mut(&key)?;
        if segment.acknowledgement != attempt.next_sequence || line.as_bytes().get(3) != Some(&b' ') {
            return None;
        }
        match (line.get(..3)?, attempt.phase) {
            (_, Phase::Closed) => None,
            ("331", Phase::User) => {
                attempt.seen_at = pkt.timestamp;
                attempt.phase = Phase::Challenge(pkt.no);
                None
            }
            ("230", Phase::User | Phase::Password { .. }) => {
                let mut related_packets = vec![attempt.user];
                if let Phase::Password { challenge, frame } = attempt.phase {
                    related_packets.extend([challenge, frame]);
                }
                attempt.seen_at = pkt.timestamp;
                attempt.phase = Phase::Closed;
                Some(IdsFinding {
                    alert: IdsAlert {
                        pkt_no: pkt.no,
                        signature: "Anonymous FTP login accepted",
                        severity: Severity::Medium,
                        detail: format!("{source} accepted an anonymous FTP login from {destination}; file access not observed"),
                    },
                    related_packets,
                    correlation_key: Some(format!("{scope:?}:{source}>{destination}:{}", attempt.user)),
                })
            }
            // A duplicate challenge cannot reopen or advance an attempt.
            ("331", _) => None,
            _ => {
                attempt.seen_at = pkt.timestamp;
                attempt.phase = Phase::Closed;
                None
            }
        }
    }
}

fn single_line(payload: &[u8]) -> Option<&str> {
    let line = std::str::from_utf8(payload.strip_suffix(b"\r\n")?).ok()?;
    (!line.is_empty() && !line.bytes().any(|byte| byte.is_ascii_control())).then_some(line)
}

impl SecurityEngine {
    pub(super) fn check_ftp_control(&mut self, pkt: &Packet) {
        if pkt.src_port != Some(21) && pkt.dst_port != Some(21) {
            return;
        }
        if pkt.capture.as_ref().is_some_and(|capture| capture.link_type != 1) {
            return;
        }
        if let Some(TcpFrame::Segment(segment)) =
            parse_ipv4_tcp_frame(&pkt.bytes).or_else(|| parse_ipv6_tcp_frame(&pkt.bytes))
            && let Some(finding) = self.ftp_control.observe(pkt, segment)
        {
            self.push_ids_finding(finding);
        }
    }
}
