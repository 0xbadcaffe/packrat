use super::*;
use std::net::Ipv4Addr;

const ARP_COMPARISON_WINDOW_SECS: f64 = 300.0;
const ARP_ALTERNATION_WINDOW_SECS: f64 = 30.0;
const ARP_SOURCE_MISMATCH: &str = "ARP reply sender differs from Ethernet source";

fn arp_claim_sender(raw: &[u8]) -> Option<(Ipv4Addr, [u8; 6], bool)> {
    let (offset, 0x0806) = ethernet_network_header(raw)? else { return None };
    let arp = raw.get(offset..offset + 28)?;
    // Ethernet hardware, IPv4 protocol, 6-byte MAC, and 4-byte IP.
    if arp[..6] != [0, 1, 8, 0, 6, 4] {
        return None;
    }
    let mac: [u8; 6] = arp[8..14].try_into().ok()?;
    let ip = Ipv4Addr::from(<[u8; 4]>::try_from(&arp[14..18]).ok()?);
    if mac == [0; 6] || mac[0] & 1 != 0 || ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() {
        return None;
    }
    let announcement = match arp[6..8] {
        [0, 2] => false,
        // RFC 5227: an announcement is a broadcast request with matching sender and target IP.
        [0, 1] if raw.get(..6)? == [255; 6] && raw.get(6..12)? == mac
            && arp[18..24] == [0; 6] && arp[14..18] == arp[24..28] => true,
        _ => return None,
    };
    Some((ip, mac, announcement))
}

impl SecurityEngine {
    // ─── ARP Anomaly ─────────────────────────────────────────────────────────

    pub(super) fn check_arp(&mut self, pkt: &Packet) {
        if !pkt.protocol.eq_ignore_ascii_case("ARP") || !pkt.timestamp.is_finite() {
            return;
        }
        let Some((ip, mac, announcement)) = arp_claim_sender(&pkt.bytes) else { return };
        let scope = service_scope(pkt);
        let Some(ethernet_mac) = pkt.bytes.get(6..12).and_then(|bytes| <[u8; 6]>::try_from(bytes).ok())
        else { return };
        // VRRP IPv4 replies can put a physical MAC in Ethernet and a virtual MAC in ARP.
        let vrrp_ipv4_sender = matches!(mac, [0, 0, 0x5e, 0, 1, 1..=255]);
        if ethernet_mac != mac && ethernet_mac != [0; 6] && ethernet_mac[0] & 1 == 0
            && !vrrp_ipv4_sender
        {
            let ethernet = format_mac(ethernet_mac);
            let sender = format_mac(mac);
            self.push_ids_finding(IdsFinding {
                alert: IdsAlert {
                    pkt_no: pkt.no,
                    signature: ARP_SOURCE_MISMATCH,
                    severity: Severity::Low,
                    detail: format!(
                        "ARP reply for {ip} names sender {sender}, while the Ethernet source is {ethernet}; whether any host accepted the ARP claim is unknown"
                    ),
                },
                related_packets: Vec::new(),
                correlation_key: Some(format!("{scope:?}:{ip}:{ethernet}:{sender}")),
            });
        }
        let key = (scope, ip);
        let known = self.ip_to_mac.get(&key).copied();
        if known.is_some_and(|entry| entry.latest.timestamp > pkt.timestamp) {
            return;
        }
        if known.is_none() && self.ip_to_mac.len() >= MAX_CONTROL_PLANE_IDENTITIES
            && let Some(oldest) = self.ip_to_mac.iter().min_by(|a, b| {
                a.1.latest.timestamp.total_cmp(&b.1.latest.timestamp).then(a.0.cmp(b.0))
            }).map(|(key, _)| *key)
        {
            self.ip_to_mac.remove(&oldest);
        }
        let latest = ArpObservation { mac, timestamp: pkt.timestamp, frame: pkt.no, announcement };
        let previous_owner = known.and_then(|entry| {
            if entry.latest.mac == mac { entry.previous_owner } else { Some(entry.latest) }
        });
        self.ip_to_mac.insert(key, ArpClaimHistory { latest, previous_owner });

        if let Some(history) = known
            && history.latest.mac != mac
            && pkt.timestamp - history.latest.timestamp <= ARP_COMPARISON_WINDOW_SECS
        {
            let known = history.latest;
            if let Some(first) = history.previous_owner
                && first.mac == mac
                && first.timestamp < known.timestamp && known.timestamp < pkt.timestamp
                && pkt.timestamp - first.timestamp <= ARP_ALTERNATION_WINDOW_SECS
                && first.frame != known.frame && first.frame != pkt.no && known.frame != pkt.no
            {
                let returning = format_mac(mac);
                let other = format_mac(known.mac);
                let (a, b) = if mac < known.mac { (&returning, &other) } else { (&other, &returning) };
                self.push_ids_finding(IdsFinding {
                    alert: IdsAlert {
                        pkt_no: pkt.no,
                        signature: "Alternating ARP claims",
                        severity: Severity::Medium,
                        detail: format!(
                            "ARP claims for {ip} alternated {returning}, {other}, {returning} within 30 seconds; failover, duplicate addressing, and spoofing are possible"
                        ),
                    },
                    related_packets: vec![first.frame, known.frame],
                    correlation_key: Some(format!("{scope:?}:{ip}:{a}:{b}")),
                });
            }
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
                involves_announcement: announcement || known.announcement,
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
