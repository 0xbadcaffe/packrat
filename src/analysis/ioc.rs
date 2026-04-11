//! IOC (Indicator of Compromise) matching engine.
//!
//! Maintains lists of known-bad IPs, domains, hashes, and URLs.
//! Packets and flows are checked against these lists in real-time.

use std::collections::HashSet;
use crate::net::packet::Packet;

// ─── IOC types ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum IocKind {
    Ip,
    Domain,
    Hash,
    Url,
    Email,
}

impl std::fmt::Display for IocKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IocKind::Ip     => write!(f, "IP"),
            IocKind::Domain => write!(f, "Domain"),
            IocKind::Hash   => write!(f, "Hash"),
            IocKind::Url    => write!(f, "URL"),
            IocKind::Email  => write!(f, "Email"),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Ioc {
    pub value:       String,
    pub kind:        IocKind,
    pub description: String,
    pub source:      String,
}

// ─── IOC hit ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct IocHit {
    pub ioc:     Ioc,
    pub context: String,   // what matched (e.g., "src_ip", "dns_query")
    pub pkt_no:  u64,
    pub ts:      f64,
}

// ─── IOC engine ───────────────────────────────────────────────────────────────

const MAX_HITS: usize = 1000;

#[derive(Debug, Default)]
pub struct IocEngine {
    ips:     HashSet<String>,
    domains: HashSet<String>,
    hashes:  HashSet<String>,
    urls:    HashSet<String>,
    /// Full IOC records for reference
    iocs:    Vec<Ioc>,
    pub hits: Vec<IocHit>,
}

impl IocEngine {
    pub fn load_ioc(&mut self, ioc: Ioc) {
        match ioc.kind {
            IocKind::Ip     => { self.ips.insert(ioc.value.clone()); }
            IocKind::Domain => { self.domains.insert(ioc.value.to_lowercase()); }
            IocKind::Hash   => { self.hashes.insert(ioc.value.to_lowercase()); }
            IocKind::Url    => { self.urls.insert(ioc.value.clone()); }
            IocKind::Email  => {}
        }
        self.iocs.push(ioc);
    }

    pub fn load_csv(&mut self, csv: &str, source: &str) {
        // Simple CSV: type,value[,description]
        for line in csv.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() { continue; }
            let parts: Vec<&str> = line.splitn(3, ',').collect();
            if parts.len() < 2 { continue; }
            let kind = match parts[0].trim().to_lowercase().as_str() {
                "ip"     => IocKind::Ip,
                "domain" => IocKind::Domain,
                "hash"   => IocKind::Hash,
                "url"    => IocKind::Url,
                "email"  => IocKind::Email,
                _        => continue,
            };
            let description = parts.get(2).unwrap_or(&"").to_string();
            self.load_ioc(Ioc {
                value:       parts[1].trim().to_string(),
                kind,
                description,
                source:      source.to_string(),
            });
        }
    }

    pub fn check_packet(&mut self, pkt: &Packet) {
        if self.ips.contains(&pkt.src) {
            self.record_hit(&pkt.src, IocKind::Ip, "src_ip", pkt.no, pkt.timestamp);
        }
        if self.ips.contains(&pkt.dst) {
            self.record_hit(&pkt.dst, IocKind::Ip, "dst_ip", pkt.no, pkt.timestamp);
        }

        // DNS query domain check
        if pkt.protocol == "DNS" {
            for word in pkt.info.split_whitespace() {
                let w = word.to_lowercase();
                if self.domains.contains(&w) {
                    self.record_hit(word, IocKind::Domain, "dns_query", pkt.no, pkt.timestamp);
                }
                // Suffix match (e.g., IOC "evil.com" matches "sub.evil.com")
                for dom in &self.domains {
                    if w.ends_with(dom.as_str()) && w.len() > dom.len() {
                        let d = dom.clone();
                        self.record_hit(&d, IocKind::Domain, "dns_subdomain", pkt.no, pkt.timestamp);
                        break;
                    }
                }
            }
        }
    }

    fn record_hit(&mut self, value: &str, kind: IocKind, context: &str, pkt_no: u64, ts: f64) {
        if self.hits.len() >= MAX_HITS { return; }
        let ioc = self.iocs.iter()
            .find(|i| i.kind == kind && i.value.to_lowercase() == value.to_lowercase())
            .cloned()
            .unwrap_or_else(|| Ioc {
                value:       value.to_string(),
                kind,
                description: String::new(),
                source:      "auto".into(),
            });
        self.hits.push(IocHit {
            ioc,
            context: context.to_string(),
            pkt_no,
            ts,
        });
    }

    /// Load IOC feeds from all `.csv`, `.txt`, `.ioc` files in `~/.config/packrat/ioc/`.
    /// Each file is expected to be in simple CSV format: `type,value[,description]`.
    /// Also supports plain-text single-column files where each line is an IP or domain.
    pub fn load_from_dir(&mut self) -> Vec<String> {
        let dir = dirs_next::config_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("packrat")
            .join("ioc");

        let mut errors: Vec<String> = Vec::new();
        if !dir.exists() { return errors; }

        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) => { errors.push(format!("read dir: {e}")); return errors; }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
            if !matches!(ext.as_str(), "csv" | "txt" | "ioc") { continue; }

            let source = path.file_name().and_then(|n| n.to_str()).unwrap_or("?").to_string();

            match std::fs::read_to_string(&path) {
                Ok(text) => {
                    if ext == "csv" {
                        self.load_csv(&text, &source);
                    } else {
                        // Plain text: detect type per line
                        for line in text.lines() {
                            let line = line.trim();
                            if line.starts_with('#') || line.is_empty() { continue; }
                            // If line looks like an IP
                            let kind = if line.parse::<std::net::Ipv4Addr>().is_ok() {
                                IocKind::Ip
                            } else if line.contains('.') && !line.contains('/') {
                                IocKind::Domain
                            } else {
                                continue; // skip unrecognised
                            };
                            self.load_ioc(Ioc {
                                value:       line.to_string(),
                                kind,
                                description: String::new(),
                                source:      source.clone(),
                            });
                        }
                    }
                }
                Err(e) => errors.push(format!("{source}: {e}")),
            }
        }
        errors
    }

    pub fn ioc_count(&self) -> usize { self.iocs.len() }
    pub fn hit_count(&self) -> usize { self.hits.len() }

    pub fn clear_hits(&mut self) { self.hits.clear(); }
    pub fn clear_all(&mut self) {
        self.ips.clear();
        self.domains.clear();
        self.hashes.clear();
        self.urls.clear();
        self.iocs.clear();
        self.hits.clear();
    }
}
