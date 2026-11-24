//! IOC (Indicator of Compromise) matching engine.
//!
//! Maintains lists of known-bad IPs, domains, hashes, and URLs.
//! Packets and flows are checked against these lists in real-time.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::{io::ErrorKind, path::Path};
use crate::analysis::dns_transactions::single_packet_query_name;
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
    ips:     HashMap<IpAddr, usize>,
    domains: HashMap<String, usize>,
    hashes:  HashSet<String>,
    urls:    HashSet<String>,
    /// Full IOC records for reference
    iocs:    Vec<Ioc>,
    file_ioc_count: usize,
    pub hits: VecDeque<IocHit>,
    evicted_hits: u64,
}

impl IocEngine {
    pub fn load_ioc(&mut self, ioc: Ioc) {
        let _ = self.register_indicator(ioc);
    }

    fn register_indicator(&mut self, ioc: Ioc) -> Result<(), &'static str> {
        if ioc.value.trim().is_empty() { return Err("missing indicator value"); }
        match ioc.kind {
            IocKind::Ip => {
                let address = ioc.value.trim().parse::<IpAddr>().map_err(|_| "invalid IP address")?;
                self.ips.entry(address).or_insert(self.iocs.len());
            }
            IocKind::Domain => {
                let id = ioc.value.trim().to_ascii_lowercase();
                let name = id.strip_suffix('.').unwrap_or(&id);
                if !valid_indicator_name(name) { return Err("invalid domain name"); }
                self.domains.entry(name.to_owned()).or_insert(self.iocs.len());
            }
            IocKind::Hash   => { self.hashes.insert(ioc.value.to_lowercase()); }
            IocKind::Url    => { self.urls.insert(ioc.value.clone()); }
            IocKind::Email  => {}
        }
        self.iocs.push(ioc);
        Ok(())
    }

    pub fn load_csv(&mut self, csv: &str, source: &str) {
        for (_, line) in feed_lines(csv) {
            if let Ok(ioc) = csv_entry(line, source) {
                self.load_ioc(ioc);
            }
        }
    }

    /// Return the number of new matches at the tail of the rolling history.
    pub fn check_packet(&mut self, pkt: &Packet) -> usize {
        let mut matched = 0;
        if !self.ips.is_empty() {
            for (observed, context) in [(&pkt.src, "src_ip"), (&pkt.dst, "dst_ip")] {
                if let Ok(address) = observed.parse::<IpAddr>()
                    && let Some(&index) = self.ips.get(&address)
                {
                    self.record_hit(index, context, pkt);
                    matched += 1;
                }
            }
        }

        if !self.domains.is_empty()
            && let Some(name) = single_packet_query_name(pkt)
            && valid_indicator_name(&name)
            && let Some((indicator, exact)) = self.domain_match(&name)
        {
            self.record_hit(indicator, if exact { "dns_query" } else { "dns_subdomain" }, pkt);
            matched += 1;
        }
        matched
    }

    fn domain_match(&self, mut name: &str) -> Option<(usize, bool)> {
        let mut exact = true;
        loop {
            if let Some(&index) = self.domains.get(name) {
                return Some((index, exact));
            }
            name = name.split_once('.')?.1;
            exact = false;
        }
    }

    fn record_hit(&mut self, index: usize, context: &str, packet: &Packet) {
        self.remember_hit(IocHit {
            ioc: self.iocs[index].clone(),
            context: context.into(),
            pkt_no: packet.no,
            ts: packet.timestamp,
        });
    }

    fn remember_hit(&mut self, hit: IocHit) {
        if self.hits.len() == MAX_HITS {
            self.hits.pop_front();
            self.evicted_hits = self.evicted_hits.saturating_add(1);
        }
        self.hits.push_back(hit);
    }

    /// Load IOC feeds from all `.csv`, `.txt`, `.ioc` files in `~/.config/packrat/ioc/`.
    /// Each file is expected to be in simple CSV format: `type,value[,description]`.
    /// Also supports plain-text single-column files where each line is an IP or domain.
    pub fn load_from_dir(&mut self) -> Result<(), String> {
        let dir = dirs_next::config_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("packrat")
            .join("ioc");
        self.reload_from_path(&dir)
    }

    fn reload_from_path(&mut self, dir: &Path) -> Result<(), String> {
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == ErrorKind::NotFound && self.file_ioc_count == 0 => return Ok(()),
            Err(error) => return Err(format!("{}: {error}", dir.display())),
        };
        let mut paths = entries.map(|entry| entry.map(|entry| entry.path()))
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(|error| format!("{}: {error}", dir.display()))?;
        paths.sort_unstable();
        let mut next = Self::default();
        for path in paths {
            let ext = path.extension().and_then(|ext| ext.to_str()).unwrap_or("").to_ascii_lowercase();
            if !matches!(ext.as_str(), "csv" | "txt" | "ioc") { continue; }
            let text = std::fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
            let source = path.file_name().and_then(|name| name.to_str()).unwrap_or("?");
            next.load_file_entries(&text, source, ext == "csv")
                .map_err(|(line, error)| format!("{}:{line}: {error}", path.display()))?;
        }
        // File records occupy a prefix; public load methods append session records.
        next.file_ioc_count = next.iocs.len();
        for ioc in self.iocs[self.file_ioc_count..].iter().cloned() {
            next.load_ioc(ioc);
        }
        next.hits = std::mem::take(&mut self.hits);
        next.evicted_hits = self.evicted_hits;
        *self = next;
        Ok(())
    }

    fn load_file_entries(&mut self, text: &str, source: &str, csv: bool) -> Result<(), (usize, &'static str)> {
        for (number, line) in feed_lines(text) {
            let entry = if csv { csv_entry(line, source) } else { plain_entry(line, source) };
            entry.and_then(|ioc| self.register_indicator(ioc)).map_err(|error| (number, error))?;
        }
        Ok(())
    }

    pub fn ioc_count(&self) -> usize { self.iocs.len() }
    pub fn hit_count(&self) -> usize { self.hits.len() }
    pub fn evicted_hit_count(&self) -> u64 { self.evicted_hits }

    pub fn clear_hits(&mut self) {
        self.hits.clear();
        self.evicted_hits = 0;
    }
    pub fn clear_all(&mut self) {
        self.ips.clear();
        self.domains.clear();
        self.hashes.clear();
        self.urls.clear();
        self.iocs.clear();
        self.file_ioc_count = 0;
        self.clear_hits();
    }
}

fn feed_lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines().map(str::trim).enumerate()
        .filter(|(_, line)| !line.is_empty() && !line.starts_with('#'))
        .map(|(index, line)| (index + 1, line))
}

fn csv_entry(line: &str, source: &str) -> Result<Ioc, &'static str> {
    // Compact feed format: type,value[,description]. The description may contain commas.
    let mut fields = line.splitn(3, ',');
    let kind = fields.next().ok_or("expected type,value")?;
    let value = fields.next().ok_or("expected type,value")?.trim();
    let kind = match kind.trim().to_ascii_lowercase().as_str() {
        "ip" => IocKind::Ip,
        "domain" => IocKind::Domain,
        "hash" => IocKind::Hash,
        "url" => IocKind::Url,
        "email" => IocKind::Email,
        _ => return Err("unknown indicator type"),
    };
    Ok(Ioc { value: value.into(), kind, description: fields.next().unwrap_or("").into(), source: source.into() })
}

fn plain_entry(line: &str, source: &str) -> Result<Ioc, &'static str> {
    let kind = if line.parse::<IpAddr>().is_ok() {
        IocKind::Ip
    } else if line.contains('.') {
        IocKind::Domain
    } else {
        return Err("expected an IP address or domain name");
    };
    Ok(Ioc { value: line.into(), kind, description: String::new(), source: source.into() })
}

fn valid_indicator_name(name: &str) -> bool {
    // Reject escaped wire labels so a literal dot cannot become a separator.
    name.len() <= 253 && name.split('.').all(|label| {
        !label.is_empty() && label.len() <= 63
            && label.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    })
}

#[cfg(test)]
#[path = "../../tests/unit/ioc_feed_tests.rs"]
mod feed_tests;
