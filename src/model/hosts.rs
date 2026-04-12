//! Host-centric network inventory — tracks every observed endpoint.

use std::collections::{HashMap, HashSet};
use crate::analysis::geo;
use crate::net::packet::Packet;

/// Everything observed about a single IP address.
#[derive(Debug, Clone, Default)]
pub struct Host {
    pub ip:           String,
    pub mac:          Option<String>,
    /// Hostnames from DNS responses, TLS SNI, HTTP Host header.
    pub hostnames:    HashSet<String>,
    /// Open/observed ports (dst port when this IP was the destination).
    pub open_ports:   HashSet<u16>,
    /// Protocols seen.
    pub protocols:    HashSet<String>,
    /// First packet timestamp.
    pub first_seen:   f64,
    /// Last packet timestamp.
    pub last_seen:    f64,
    /// Total bytes sent by this host.
    pub bytes_out:    u64,
    /// Total bytes received by this host.
    pub bytes_in:     u64,
    /// Number of packets sent.
    pub pkts_out:     u64,
    /// Number of packets received.
    pub pkts_in:      u64,
    /// Number of security alerts associated with this host.
    pub alert_count:  u32,
    /// Tags applied to this host.
    pub tags:         HashSet<String>,
    /// Analyst notes.
    pub notes:        Vec<String>,
    /// Geo hint (country code if available — not resolved by default).
    pub geo:          Option<String>,
    /// Whether this host appears to be a gateway/router (TTL ≤ 1 responses).
    pub is_gateway:   bool,
    /// OS guess from passive fingerprinting.
    pub os_guess:     Option<String>,
}

impl Host {
    pub fn new(ip: impl Into<String>, ts: f64) -> Self {
        Self {
            ip: ip.into(),
            first_seen: ts,
            last_seen: ts,
            ..Default::default()
        }
    }

    pub fn display_name(&self) -> &str {
        self.hostnames.iter().next().map(String::as_str).unwrap_or(&self.ip)
    }
}

/// Host inventory — maintains a live map of all observed endpoints.
#[derive(Debug, Default)]
pub struct HostInventory {
    hosts: HashMap<String, Host>,
}

impl HostInventory {
    pub fn update(&mut self, pkt: &Packet) {
        let ts = pkt.timestamp;

        // Update sending host
        self.touch(&pkt.src, ts, |h| {
            h.pkts_out += 1;
            h.bytes_out += pkt.length as u64;
            h.protocols.insert(pkt.protocol.clone());
            if let Some(p) = pkt.dst_port { h.open_ports.insert(p); }
        });

        // Update receiving host
        self.touch(&pkt.dst, ts, |h| {
            h.pkts_in += 1;
            h.bytes_in += pkt.length as u64;
            h.protocols.insert(pkt.protocol.clone());
            if let Some(p) = pkt.dst_port { h.open_ports.insert(p); }
        });

        // Sniff MAC from ARP or Ethernet src
        if pkt.protocol == "ARP" && pkt.bytes.len() >= 28 {
            // ARP sender IP is at offset 28 in Ethernet+ARP
            let sender_ip = format!("{}.{}.{}.{}",
                pkt.bytes.get(28).copied().unwrap_or(0),
                pkt.bytes.get(29).copied().unwrap_or(0),
                pkt.bytes.get(30).copied().unwrap_or(0),
                pkt.bytes.get(31).copied().unwrap_or(0));
            if let Some(h) = self.hosts.get_mut(&sender_ip) {
                if h.mac.is_none() {
                    let mac = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        pkt.bytes.get(8).copied().unwrap_or(0),
                        pkt.bytes.get(9).copied().unwrap_or(0),
                        pkt.bytes.get(10).copied().unwrap_or(0),
                        pkt.bytes.get(11).copied().unwrap_or(0),
                        pkt.bytes.get(12).copied().unwrap_or(0),
                        pkt.bytes.get(13).copied().unwrap_or(0));
                    h.mac = Some(mac);
                }
            }
        }

        // Sniff hostnames from DNS response info field
        if pkt.protocol == "DNS" && pkt.info.contains("Response") {
            if let Some(name) = extract_dns_name(&pkt.info) {
                // Associate name with dst IP (the DNS server answered about this name)
                if let Some(h) = self.hosts.get_mut(&pkt.dst) {
                    h.hostnames.insert(name);
                }
            }
        }

        // Sniff hostname from HTTP Host header
        if pkt.protocol == "HTTP" {
            if let Some(host) = extract_http_host(&pkt.info) {
                if let Some(h) = self.hosts.get_mut(&pkt.dst) {
                    h.hostnames.insert(host);
                }
            }
        }
    }

    fn touch(&mut self, ip: &str, ts: f64, f: impl FnOnce(&mut Host)) {
        if ip.is_empty() || ip == "0.0.0.0" { return; }
        let host = self.hosts.entry(ip.to_string())
            .or_insert_with(|| {
                let mut h = Host::new(ip, ts);
                h.geo = Some(geo::classify(ip).to_string());
                h
            });
        host.last_seen = ts.max(host.last_seen);
        if ts < host.first_seen { host.first_seen = ts; }
        f(host);
    }

    pub fn get(&self, ip: &str) -> Option<&Host> { self.hosts.get(ip) }
    pub fn get_mut(&mut self, ip: &str) -> Option<&mut Host> { self.hosts.get_mut(ip) }

    pub fn all(&self) -> Vec<&Host> {
        let mut v: Vec<_> = self.hosts.values().collect();
        v.sort_by(|a, b| b.bytes_out.cmp(&a.bytes_out));
        v
    }

    pub fn len(&self) -> usize { self.hosts.len() }
    pub fn is_empty(&self) -> bool { self.hosts.is_empty() }

    pub fn add_alert(&mut self, ip: &str) {
        if let Some(h) = self.hosts.get_mut(ip) { h.alert_count += 1; }
    }

    pub fn add_hostname(&mut self, ip: &str, name: impl Into<String>) {
        if let Some(h) = self.hosts.get_mut(ip) { h.hostnames.insert(name.into()); }
    }

    pub fn set_os_guess(&mut self, ip: &str, os: impl Into<String>) {
        if let Some(h) = self.hosts.get_mut(ip) {
            h.os_guess = Some(os.into());
        }
    }

    pub fn clear(&mut self) { self.hosts.clear(); }

    /// Pre-seed tags for a host IP, creating a placeholder entry if needed.
    /// When real traffic arrives for this IP the host entry is updated in-place,
    /// preserving the pre-seeded tags.
    pub fn seed_tags(&mut self, ip: &str, tags: impl IntoIterator<Item = String>) {
        if ip.is_empty() || ip == "0.0.0.0" { return; }
        let h = self.hosts.entry(ip.to_string())
            .or_insert_with(|| Host::new(ip, 0.0));
        for t in tags { h.tags.insert(t); }
    }

    /// Filter hosts by search string (IP, hostname, protocol, tag).
    pub fn search(&self, q: &str) -> Vec<&Host> {
        let q = q.to_lowercase();
        self.hosts.values()
            .filter(|h|
                h.ip.contains(&q)
                || h.hostnames.iter().any(|n| n.to_lowercase().contains(&q))
                || h.protocols.iter().any(|p| p.to_lowercase().contains(&q))
                || h.tags.iter().any(|t| t.to_lowercase().contains(&q))
            )
            .collect()
    }
}

fn extract_dns_name(info: &str) -> Option<String> {
    // "Response A 1.2.3.4" or "Response CNAME foo.bar"
    let parts: Vec<&str> = info.split_whitespace().collect();
    if parts.len() >= 3 && parts[0] == "Response" {
        let name = parts[2];
        if name.contains('.') { return Some(name.to_string()); }
    }
    None
}

fn extract_http_host(info: &str) -> Option<String> {
    // Look for "Host: foo.bar" patterns in the info string
    if let Some(pos) = info.find("Host:") {
        let rest = &info[pos + 5..];
        let name = rest.split_whitespace().next()?.trim_end_matches(',');
        if name.contains('.') { return Some(name.to_string()); }
    }
    None
}
