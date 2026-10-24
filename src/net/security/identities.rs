use super::*;

impl SecurityEngine {
    // ─── ARP Anomaly ─────────────────────────────────────────────────────────

    pub(super) fn check_arp(&mut self, pkt: &Packet) {
        // ARP packets: protocol == "ARP" or info contains ARP data
        if !pkt.protocol.eq_ignore_ascii_case("ARP") {
            return;
        }
        // ARP reply format: "Who has x.x.x.x? Tell y.y.y.y" or "x.x.x.x is at aa:bb:cc..."
        // Extract IP and MAC from info string
        let info = &pkt.info;
        if let Some((ip, mac)) = Self::parse_arp_info(info) {
            if let Some(known_mac) = self.ip_to_mac.get(&ip).cloned() {
                if known_mac != mac {
                    if self.arp_anomalies.len() >= MAX_ENTRIES {
                        self.arp_anomalies.remove(0);
                    }
                    let anomaly = ArpAnomaly {
                        pkt_no: pkt.no,
                        ip: ip.clone(),
                        old_mac: known_mac,
                        new_mac: mac.clone(),
                    };
                    self.findings.arp.push(anomaly.clone());
                    self.arp_anomalies.push(anomaly);
                }
            }
            self.ip_to_mac.insert(ip, mac);
        }
    }

    pub(super) fn parse_arp_info(info: &str) -> Option<(String, String)> {
        // "192.168.1.1 is at aa:bb:cc:dd:ee:ff"
        let lower = info.to_lowercase();
        if let Some(pos) = lower.find(" is at ") {
            let ip = info[..pos].trim().to_string();
            let mac = info[pos + 7..].trim().to_string();
            if !ip.is_empty() && !mac.is_empty() {
                return Some((ip, mac));
            }
        }
        None
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
