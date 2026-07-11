//! Address enrichment from local prefix maps with explicit WHOIS refresh.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::io::Write;
use std::process::Command;

use crate::analysis::helper_process::spawn_stdin_stdout_helper;

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
    pub reputation: Option<ReputationFinding>,
    pub updated_at: f64,
}

#[derive(Debug)]
pub struct NetRegistry {
    pub map_path: Option<PathBuf>,
    pub reputation_path: Option<PathBuf>,
    pub prefixes: Vec<PrefixIdentity>,
    pub reputation: ReputationBook,
    pub observed: HashMap<IpAddr, AddressIdentity>,
    pub last_error: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct ReputationHelperRequest {
    kind: &'static str,
    target: String,
}

#[derive(Debug, serde::Deserialize)]
struct ReputationHelperResponse {
    ok: bool,
    severity: Option<String>,
    label: Option<String>,
    source: Option<String>,
    detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReputationFinding {
    pub severity: String,
    pub label: String,
    pub source: String,
}

#[derive(Debug, Clone)]
struct ReputationEntry {
    target: ReputationTarget,
    finding: ReputationFinding,
}

#[derive(Debug, Clone)]
enum ReputationTarget {
    Prefix { network: IpAddr, prefix: u8 },
    Fingerprint(String),
}

#[derive(Debug, Default, Clone)]
pub struct ReputationBook {
    entries: Vec<ReputationEntry>,
}

impl Default for NetRegistry {
    fn default() -> Self {
        let config_dir = dirs_next::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("packrat");
        let path = config_dir.join("identity-map.csv");
        let reputation_path = config_dir.join("reputation-map.csv");
        let mut registry = Self {
            map_path: Some(path.clone()),
            reputation_path: Some(reputation_path.clone()),
            prefixes: Vec::new(),
            reputation: ReputationBook::default(),
            observed: HashMap::new(),
            last_error: None,
        };
        if path.exists() {
            if let Err(error) = registry.load_map(path) {
                registry.last_error = Some(error);
            }
        }
        if reputation_path.exists() {
            if let Err(error) = registry.load_reputation(reputation_path) {
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

    /// CSV format: target,severity,label,source.
    /// Target may be an IP/CIDR or a fingerprint such as ratq1_* / t13*.
    pub fn load_reputation(&mut self, path: impl AsRef<Path>) -> Result<usize, String> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .map_err(|error| format!("read reputation map {}: {error}", path.display()))?;
        let mut book = ReputationBook::default();
        for (line_no, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            let fields: Vec<_> = line.splitn(4, ',').map(str::trim).collect();
            if fields.len() != 4 {
                return Err(format!("reputation map line {} must have target,severity,label,source", line_no + 1));
            }
            book.add(fields[0], fields[1], fields[2], fields[3])
                .map_err(|error| format!("reputation map line {}: {error}", line_no + 1))?;
        }
        let count = book.len();
        self.reputation_path = Some(path.to_path_buf());
        self.reputation = book;
        self.refresh_reputation_marks();
        self.last_error = None;
        Ok(count)
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
                reputation: self.reputation.lookup_address(address),
                updated_at: now(),
            }
        } else if let Some(prefix) = self.prefixes.iter().find(|prefix| contains(prefix, address)) {
            AddressIdentity {
                address,
                asn: prefix.asn.clone(),
                organization: prefix.organization.clone(),
                source: "prefix map".into(),
                reputation: self.reputation.lookup_address(address),
                updated_at: now(),
            }
        } else {
            AddressIdentity {
                address,
                asn: None,
                organization: "Unresolved".into(),
                source: "observed".into(),
                reputation: self.reputation.lookup_address(address),
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
            reputation: self.reputation.lookup_address(address),
            updated_at: now(),
        });
        Ok(self.observed.get(&address).unwrap())
    }

    /// Explicit operator action. The helper owns any outbound reputation lookup
    /// or API credentials; packet ingestion never invokes it automatically.
    pub fn refresh_reputation_with_helper(
        &mut self,
        address: IpAddr,
        helper: impl AsRef<Path>,
    ) -> Result<&AddressIdentity, String> {
        let finding = run_reputation_helper("address", &address.to_string(), helper.as_ref())?;
        self.reputation.add(&address.to_string(), &finding.severity, &finding.label, &finding.source)?;
        let entry = self.observed.entry(address).or_insert_with(|| AddressIdentity {
            address,
            asn: None,
            organization: if is_private(address) { "Private network".into() } else { "Unresolved".into() },
            source: "observed".into(),
            reputation: None,
            updated_at: now(),
        });
        entry.reputation = Some(finding);
        entry.updated_at = now();
        Ok(entry)
    }

    pub fn refresh_fingerprint_reputation_with_helper(
        &mut self,
        fingerprint: &str,
        helper: impl AsRef<Path>,
    ) -> Result<ReputationFinding, String> {
        let finding = run_reputation_helper("fingerprint", fingerprint, helper.as_ref())?;
        self.reputation.add(fingerprint, &finding.severity, &finding.label, &finding.source)?;
        Ok(finding)
    }

    pub fn clear_session(&mut self) {
        self.observed.clear();
    }

    pub fn reputation_for_fingerprint(&self, fingerprint: &str) -> Option<ReputationFinding> {
        self.reputation.lookup_fingerprint(fingerprint)
    }

    fn refresh_reputation_marks(&mut self) {
        for identity in self.observed.values_mut() {
            identity.reputation = self.reputation.lookup_address(identity.address);
        }
    }
}

fn run_reputation_helper(kind: &'static str, target: &str, helper: &Path) -> Result<ReputationFinding, String> {
    let mut child = spawn_stdin_stdout_helper(helper, "reputation")?;
    let request = serde_json::to_vec(&ReputationHelperRequest { kind, target: target.to_string() })
        .map_err(|error| format!("encode reputation helper request: {error}"))?;
    child.stdin.as_mut().ok_or("reputation helper stdin unavailable")?
        .write_all(&request).map_err(|error| format!("write reputation helper request: {error}"))?;
    let output = child.wait_with_output().map_err(|error| format!("wait for reputation helper: {error}"))?;
    if !output.status.success() {
        return Err(format!("reputation helper failed: {}", String::from_utf8_lossy(&output.stderr).trim()));
    }
    let response: ReputationHelperResponse = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("decode reputation helper response: {error}"))?;
    if !response.ok {
        return Err(response.detail.unwrap_or_else(|| "reputation helper returned no finding".into()));
    }
    Ok(ReputationFinding {
        severity: response.severity.ok_or("reputation helper response missing severity")?,
        label: response.label.ok_or("reputation helper response missing label")?,
        source: response.source.unwrap_or_else(|| format!("helper:{}", helper.display())),
    })
}

impl ReputationBook {
    pub fn add(&mut self, target: &str, severity: &str, label: &str, source: &str) -> Result<(), String> {
        let target = if let Some((network, prefix)) = parse_cidr(target) {
            ReputationTarget::Prefix { network, prefix }
        } else if let Ok(address) = target.parse::<IpAddr>() {
            ReputationTarget::Prefix {
                network: address,
                prefix: if address.is_ipv4() { 32 } else { 128 },
            }
        } else if !target.is_empty() {
            ReputationTarget::Fingerprint(target.to_ascii_lowercase())
        } else {
            return Err("empty target".into());
        };
        self.entries.push(ReputationEntry {
            target,
            finding: ReputationFinding {
                severity: severity.to_string(),
                label: label.to_string(),
                source: source.to_string(),
            },
        });
        Ok(())
    }

    pub fn len(&self) -> usize { self.entries.len() }

    pub fn lookup_address(&self, address: IpAddr) -> Option<ReputationFinding> {
        self.entries.iter()
            .filter_map(|entry| match entry.target {
                ReputationTarget::Prefix { network, prefix } if contains_prefix(network, prefix, address) => {
                    Some((prefix, entry.finding.clone()))
                }
                _ => None,
            })
            .max_by_key(|(prefix, _)| *prefix)
            .map(|(_, finding)| finding)
    }

    pub fn lookup_fingerprint(&self, fingerprint: &str) -> Option<ReputationFinding> {
        let fingerprint = fingerprint.to_ascii_lowercase();
        self.entries.iter().find_map(|entry| match &entry.target {
            ReputationTarget::Fingerprint(value) if value == &fingerprint => Some(entry.finding.clone()),
            _ => None,
        })
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
    contains_prefix(prefix.network, prefix.prefix, address)
}

fn contains_prefix(network: IpAddr, prefix: u8, address: IpAddr) -> bool {
    match (network, address) {
        (IpAddr::V4(network), IpAddr::V4(address)) => {
            let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
            u32::from(network) & mask == u32::from(address) & mask
        }
        (IpAddr::V6(network), IpAddr::V6(address)) => {
            let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
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

    #[test]
    fn reputation_map_marks_addresses_and_fingerprints() {
        let path = std::env::temp_dir().join(format!("packrat-reputation-{}.csv", std::process::id()));
        std::fs::write(
            &path,
            "203.0.113.0/24,high,test block,lab\nratq1_deadbeefcafe,medium,known quic shape,lab\n",
        ).unwrap();
        let mut registry = NetRegistry::default();
        assert_eq!(registry.load_reputation(&path).unwrap(), 2);
        registry.observe("203.0.113.9");
        let identity = registry.observed.get(&"203.0.113.9".parse().unwrap()).unwrap();
        assert_eq!(identity.reputation.as_ref().unwrap().label, "test block");
        assert_eq!(
            registry.reputation_for_fingerprint("RATQ1_DEADBEEFCAFE").unwrap().severity,
            "medium",
        );
        let _ = std::fs::remove_file(path);
    }

    #[cfg(unix)]
    #[test]
    fn helper_refresh_marks_selected_address_reputation() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!("packrat-reputation-helper-{}-{}.sh", std::process::id(), unique_test_suffix()));
        std::fs::write(
            &path,
            "#!/bin/sh\ncat >/dev/null\nprintf '{\"ok\":true,\"severity\":\"high\",\"label\":\"helper listed\",\"source\":\"unit helper\"}'\n",
        ).unwrap();
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&path, permissions).unwrap();

        let mut registry = NetRegistry::default();
        let identity = registry
            .refresh_reputation_with_helper("203.0.113.9".parse().unwrap(), &path)
            .unwrap();
        let finding = identity.reputation.as_ref().unwrap();
        assert_eq!(finding.severity, "high");
        assert_eq!(finding.label, "helper listed");
        assert_eq!(finding.source, "unit helper");
        let _ = std::fs::remove_file(path);
    }

    #[cfg(unix)]
    #[test]
    fn helper_refresh_caches_fingerprint_reputation() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!("packrat-fingerprint-helper-{}-{}.sh", std::process::id(), unique_test_suffix()));
        std::fs::write(
            &path,
            "#!/bin/sh\ncat >/dev/null\nprintf '{\"ok\":true,\"severity\":\"medium\",\"label\":\"fingerprint listed\",\"source\":\"unit helper\"}'\n",
        ).unwrap();
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&path, permissions).unwrap();

        let mut registry = NetRegistry::default();
        let finding = registry
            .refresh_fingerprint_reputation_with_helper("ratq1_deadbeefcafe", &path)
            .unwrap();
        assert_eq!(finding.label, "fingerprint listed");
        assert_eq!(
            registry.reputation_for_fingerprint("ratq1_deadbeefcafe").unwrap().severity,
            "medium",
        );
        let _ = std::fs::remove_file(path);
    }

    #[cfg(unix)]
    fn unique_test_suffix() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    }
}
