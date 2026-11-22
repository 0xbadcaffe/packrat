use super::*;
use std::net::Ipv4Addr;

const ARP_COMPARISON_WINDOW_SECS: f64 = 300.0;

fn arp_reply_sender(raw: &[u8]) -> Option<(Ipv4Addr, [u8; 6])> {
    let (offset, 0x0806) = ethernet_network_header(raw)? else { return None };
    let arp = raw.get(offset..offset + 28)?;
    // Ethernet hardware, IPv4 protocol, 6-byte MAC, 4-byte IP, and reply opcode.
    if arp[..8] != [0, 1, 8, 0, 6, 4, 0, 2] {
        return None;
    }
    let mac: [u8; 6] = arp[8..14].try_into().ok()?;
    let ip = Ipv4Addr::from(<[u8; 4]>::try_from(&arp[14..18]).ok()?);
    if mac == [0; 6] || mac[0] & 1 != 0 || ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() {
        return None;
    }
    Some((ip, mac))
}

impl SecurityEngine {
    // ─── ARP Anomaly ─────────────────────────────────────────────────────────

    pub(super) fn check_arp(&mut self, pkt: &Packet) {
        if !pkt.protocol.eq_ignore_ascii_case("ARP") || !pkt.timestamp.is_finite() {
            return;
        }
        let Some((ip, mac)) = arp_reply_sender(&pkt.bytes) else { return };
        let scope = service_scope(pkt);
        let key = (scope, ip);
        let known = self.ip_to_mac.get(&key).copied();
        if known.is_some_and(|entry| entry.timestamp > pkt.timestamp) {
            return;
        }
        if known.is_none() && self.ip_to_mac.len() >= MAX_CONTROL_PLANE_IDENTITIES
            && let Some(oldest) = self.ip_to_mac.iter().min_by(|a, b| {
                a.1.timestamp.total_cmp(&b.1.timestamp).then(a.0.cmp(b.0))
            }).map(|(key, _)| *key)
        {
            self.ip_to_mac.remove(&oldest);
        }
        self.ip_to_mac.insert(key, ArpObservation { mac, timestamp: pkt.timestamp, frame: pkt.no });

        if let Some(known) = known
            && known.mac != mac
            && pkt.timestamp - known.timestamp <= ARP_COMPARISON_WINDOW_SECS
        {
            if self.arp_anomalies.len() >= MAX_ENTRIES {
                self.arp_anomalies.remove(0);
            }
            let anomaly = ArpAnomaly {
                pkt_no: pkt.no,
                ip: ip.to_string(),
                old_mac: format_mac(known.mac),
                new_mac: format_mac(mac),
            };
            self.arp_anomalies.push(anomaly.clone());
            self.findings.arp.push(ArpFinding {
                anomaly,
                previous_frame: known.frame,
                correlation_key: format!("{scope:?}:{ip}"),
            });
        }
    }

    // ─── OS Fingerprinting ───────────────────────────────────────────────────

    pub(super) fn check_os_fingerprint(&mut self, pkt: &Packet) {
        // Only TCP packets with sufficient bytes
        if !pkt.protocol.eq_ignore_ascii_case("TCP") || pkt.bytes.len() < 50 {
            return;
        }
        let ttl = byte_at(&pkt.bytes, 22);
        let window = u16_be_at(&pkt.bytes, 48);

        // Already fingerprinted this src IP?
        if self.os_by_ip.contains_key(&pkt.src) {
            return;
        }

        let os: &'static str = match (ttl, window) {
            (64, 5840) => "Linux 2.x",
            (64, 29200) => "Linux 3.x",
            (64, 64240) => "Linux 4.x+",
            (64, 65535) => "macOS/FreeBSD",
            (128, 65535) => "Windows 10/11",
            (128, 8192) => "Windows XP/2003",
            (128, 16384) => "Windows Server",
            (255, _) => "Network Device (Cisco/etc)",
            (32, _) => "Windows 9x/ME",
            _ => return, // Not enough signal
        };

        self.os_by_ip.insert(pkt.src.clone(), os);
        if self.os_guesses.len() >= MAX_ENTRIES {
            self.os_guesses.remove(0);
        }
        self.os_guesses.push(OsGuess {
            src_ip: pkt.src.clone(),
            os,
            ttl,
            window,
        });
    }
}
