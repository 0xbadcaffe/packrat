//! Address enrichment from local prefix maps with explicit WHOIS refresh.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct PrefixIdentity {
    network: IpAddr,
    prefix: u8,
    pub asn: Option<String>,
    pub organization: String,
}

#[derive(Debug, Clone)]
pub struct AddressIdentity {
    pub address: IpAddr,
    pub asn: Option<String>,
    pub organization: String,
    pub source: String,
    pub updated_at: f64,
}

#[derive(Debug)]
pub struct NetRegistry {
    pub map_path: Option<PathBuf>,
    pub prefixes: Vec<PrefixIdentity>,
    pub observed: HashMap<IpAddr, AddressIdentity>,
    pub last_error: Option<String>,
}

impl Default for NetRegistry {
    fn default() -> Self {
        let path = dirs_next::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("packrat")
            .join("identity-map.csv");
        let mut registry = Self {
            map_path: Some(path.clone()),
            prefixes: Vec::new(),
            observed: HashMap::new(),
            last_error: None,
        };
        if path.exists() {
            if let Err(error) = registry.load_map(path) {
                registry.last_error = Some(error);
            }
        }
        registry
    }
}

impl NetRegistry {
    /// CSV format: CIDR,ASN,organization. Lines beginning with # are ignored.
    pub fn load_map(&mut self, path: impl AsRef<Path>) -> Result<usize, String> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .map_err(|error| format!("read identity map {}: {error}", path.display()))?;
        let mut prefixes = Vec::new();
        for (line_no, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            let fields: Vec<_> = line.splitn(3, ',').map(str::trim).collect();
            if fields.len() != 3 {
                return Err(format!("identity map line {} must have CIDR,ASN,organization", line_no + 1));
            }
            let (network, prefix) = parse_cidr(fields[0])
                .ok_or_else(|| format!("invalid CIDR on identity map line {}", line_no + 1))?;
            prefixes.push(PrefixIdentity {
                network,
                prefix,
                asn: (!fields[1].is_empty()).then(|| fields[1].to_string()),
                organization: fields[2].into(),
            });
        }
        prefixes.sort_by_key(|identity| std::cmp::Reverse(identity.prefix));
        self.map_path = Some(path.to_path_buf());
        self.prefixes = prefixes;
        self.last_error = None;
        Ok(self.prefixes.len())
    }

    pub fn observe(&mut self, address: &str) {
        let Ok(address) = address.parse::<IpAddr>() else { return; };
        if self.observed.contains_key(&address) { return; }
        let identity = if is_private(address) {
            AddressIdentity {
                address,
                asn: None,
                organization: "Private network".into(),
                source: "local classification".into(),
                updated_at: now(),
            }
        } else if let Some(prefix) = self.prefixes.iter().find(|prefix| contains(prefix, address)) {
            AddressIdentity {
                address,
                asn: prefix.asn.clone(),
                organization: prefix.organization.clone(),
                source: "prefix map".into(),
                updated_at: now(),
            }
        } else {
            AddressIdentity {
                address,
                asn: None,
                organization: "Unresolved".into(),
                source: "observed".into(),
                updated_at: now(),
            }
        };
        self.observed.insert(address, identity);
    }

    pub fn sorted(&self) -> Vec<&AddressIdentity> {
        let mut entries: Vec<_> = self.observed.values().collect();
        entries.sort_by_key(|identity| identity.address);
        entries
    }

    /// Explicit network operation. The caller chooses the selected address;
    /// packet ingestion never launches WHOIS automatically.
    pub fn refresh_whois(&mut self, address: IpAddr) -> Result<&AddressIdentity, String> {
        if is_private(address) { return Err("WHOIS is not used for private addresses".into()); }
        let output = Command::new("whois")
            .arg(address.to_string())
            .output()
            .map_err(|error| format!("run whois: {error}"))?;
        if !output.status.success() {
            return Err(format!("whois failed: {}", String::from_utf8_lossy(&output.stderr).trim()));
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let asn = field(&text, &["origin", "originas", "aut-num"]);
        let organization = field(&text, &["org-name", "orgname", "organization", "descr"])
            .unwrap_or_else(|| "WHOIS record".into());
        self.observed.insert(address, AddressIdentity {
            address,
            asn,
            organization,
            source: "whois".into(),
            updated_at: now(),
        });
        Ok(self.observed.get(&address).unwrap())
    }

    pub fn clear_session(&mut self) {
        self.observed.clear();
    }
}

fn parse_cidr(value: &str) -> Option<(IpAddr, u8)> {
    let (address, prefix) = value.split_once('/')?;
    let address = address.parse::<IpAddr>().ok()?;
    let prefix = prefix.parse::<u8>().ok()?;
    if (address.is_ipv4() && prefix <= 32) || (address.is_ipv6() && prefix <= 128) {
        Some((address, prefix))
    } else {
        None
    }
}

fn contains(prefix: &PrefixIdentity, address: IpAddr) -> bool {
    match (prefix.network, address) {
        (IpAddr::V4(network), IpAddr::V4(address)) => {
            let mask = if prefix.prefix == 0 { 0 } else { u32::MAX << (32 - prefix.prefix) };
            u32::from(network) & mask == u32::from(address) & mask
        }
        (IpAddr::V6(network), IpAddr::V6(address)) => {
            let mask = if prefix.prefix == 0 { 0 } else { u128::MAX << (128 - prefix.prefix) };
            u128::from(network) & mask == u128::from(address) & mask
        }
        _ => false,
    }
}

fn is_private(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_private() || address.is_loopback() || address.is_link_local(),
        IpAddr::V6(address) => address.is_loopback() || address.is_unique_local() || address.is_unicast_link_local(),
    }
}

fn field(text: &str, names: &[&str]) -> Option<String> {
    text.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        names.iter().any(|candidate| name.trim().eq_ignore_ascii_case(candidate))
            .then(|| value.trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

fn now() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default().as_secs_f64()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn longest_prefix_map_enriches_observed_address() {
        let path = std::env::temp_dir().join(format!("packrat-prefix-{}.csv", std::process::id()));
        std::fs::write(&path, "203.0.113.0/24,AS64500,Example Network\n").unwrap();
        let mut registry = NetRegistry::default();
        assert_eq!(registry.load_map(&path).unwrap(), 1);
        registry.observe("203.0.113.9");
        let identity = registry.observed.get(&"203.0.113.9".parse().unwrap()).unwrap();
        assert_eq!(identity.asn.as_deref(), Some("AS64500"));
        assert_eq!(identity.organization, "Example Network");
        let _ = std::fs::remove_file(path);
    }
}
