//! Linux socket-to-process attribution and per-process traffic accounting.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::net::packet::Packet;

#[derive(Debug, Clone)]
pub struct SocketOwner {
    pub pid: u32,
    pub uid: u32,
    pub process: String,
    pub command: String,
    pub protocol: String,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    pub inode: u64,
}

#[derive(Debug, Clone, Default)]
pub struct ProcessTraffic {
    pub pid: u32,
    pub uid: u32,
    pub process: String,
    pub bytes_out: u64,
    pub bytes_in: u64,
    pub packets_out: u64,
    pub packets_in: u64,
    pub last_seen: f64,
}

#[derive(Debug, Default)]
pub struct SocketScope {
    pub owners: Vec<SocketOwner>,
    pub traffic: HashMap<u32, ProcessTraffic>,
    port_index: HashMap<(String, u16), Vec<usize>>,
    imported_owners: Vec<SocketOwner>,
    pub imported_events: usize,
    pub ebpf_lost_events: u64,
    pub ebpf_invalid_events: u64,
    pub event_path: Option<PathBuf>,
    event_offset: u64,
    pub last_error: Option<String>,
    pub refreshes: u64,
}

impl SocketScope {
    pub fn refresh(&mut self) -> Result<usize, String> {
        #[cfg(target_os = "linux")]
        {
            let sockets = read_linux_sockets()?;
            let processes = read_linux_processes();
            self.owners = sockets.into_iter().filter_map(|socket| {
                let process = processes.get(&socket.inode)?;
                Some(SocketOwner {
                    pid: process.pid,
                    uid: process.uid,
                    process: process.name.clone(),
                    command: process.command.clone(),
                    protocol: socket.protocol,
                    local_addr: socket.local_addr,
                    local_port: socket.local_port,
                    remote_addr: socket.remote_addr,
                    remote_port: socket.remote_port,
                    inode: socket.inode,
                })
            }).collect();
            self.owners.extend(self.imported_owners.clone());
            self.rebuild_index();
            self.last_error = None;
            self.refreshes += 1;
            Ok(self.owners.len())
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.last_error = Some("socket attribution is currently available on Linux".into());
            Err(self.last_error.clone().unwrap())
        }
    }

    pub fn observe(&mut self, packet: &Packet) -> Option<String> {
        let (owner, outbound) = self.attribute_with_direction(packet)?;
        let owner = owner.clone();
        let usage = self.traffic.entry(owner.pid).or_insert_with(|| ProcessTraffic {
            pid: owner.pid,
            uid: owner.uid,
            process: owner.process.clone(),
            ..Default::default()
        });
        if outbound {
            usage.bytes_out += packet.length as u64;
            usage.packets_out += 1;
        } else {
            usage.bytes_in += packet.length as u64;
            usage.packets_in += 1;
        }
        usage.last_seen = packet.timestamp;
        Some(owner.process)
    }

    pub fn sorted_traffic(&self) -> Vec<&ProcessTraffic> {
        let mut values: Vec<_> = self.traffic.values().collect();
        values.sort_by_key(|usage| std::cmp::Reverse(usage.bytes_in + usage.bytes_out));
        values
    }

    /// Import socket ownership rows captured by an external helper. CSV format:
    /// protocol,local_addr,local_port,remote_addr,remote_port,pid,uid,process,command
    pub fn load_event_file(&mut self, path: impl AsRef<Path>) -> Result<usize, String> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .map_err(|error| format!("read socket event file {}: {error}", path.display()))?;
        let mut owners = Vec::new();
        for (line_no, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.starts_with("# packrat-ebpf-stats") {
                self.parse_ebpf_stats(line);
                continue;
            }
            if line.is_empty() || line.starts_with('#') { continue; }
            owners.push(parse_event_owner(line, line_no + 1)?);
        }
        let count = owners.len();
        self.event_path = Some(path.to_path_buf());
        self.imported_events = count;
        self.imported_owners = owners;
        self.event_offset = text.len() as u64;
        self.owners.retain(|owner| owner.inode != 0);
        self.owners.extend(self.imported_owners.clone());
        self.rebuild_index();
        self.last_error = None;
        Ok(count)
    }

    /// Import only newly appended helper rows. Handles collector restarts that
    /// truncate the file and never advances beyond an incomplete final line.
    pub fn refresh_event_file(&mut self) -> Result<usize, String> {
        let Some(path) = self.event_path.clone() else { return Ok(0); };
        let mut file = std::fs::File::open(&path)
            .map_err(|error| format!("read socket event file {}: {error}", path.display()))?;
        let length = file.metadata().map_err(|error| format!("stat socket event file: {error}"))?.len();
        if length < self.event_offset {
            self.event_offset = 0;
            self.imported_owners.clear();
        }
        file.seek(SeekFrom::Start(self.event_offset))
            .map_err(|error| format!("seek socket event file: {error}"))?;
        let mut appended = String::new();
        file.read_to_string(&mut appended)
            .map_err(|error| format!("read appended socket events: {error}"))?;
        let complete_length = appended.rfind('\n').map(|index| index + 1).unwrap_or(0);
        let mut imported = 0;
        for (index, line) in appended[..complete_length].lines().enumerate() {
            let line = line.trim();
            if line.is_empty() { continue; }
            if line.starts_with("# packrat-ebpf-stats") {
                self.parse_ebpf_stats(line);
                continue;
            }
            if line.starts_with('#') { continue; }
            let owner = parse_event_owner(line, index + 1)?;
            self.imported_owners.push(owner);
            imported += 1;
        }
        self.event_offset += complete_length as u64;
        self.imported_events = self.imported_events.saturating_add(imported);
        if self.imported_owners.len() > 10_000 {
            self.imported_owners.drain(0..self.imported_owners.len() - 10_000);
        }
        self.owners.retain(|owner| owner.inode != 0);
        self.owners.extend(self.imported_owners.clone());
        self.rebuild_index();
        self.last_error = None;
        Ok(imported)
    }

    fn parse_ebpf_stats(&mut self, line: &str) {
        for field in line.split_whitespace() {
            if let Some(value) = field.strip_prefix("kernel_lost=").and_then(|value| value.parse().ok()) {
                self.ebpf_lost_events = value;
            } else if let Some(value) = field.strip_prefix("userspace_invalid=").and_then(|value| value.parse().ok()) {
                self.ebpf_invalid_events = value;
            }
        }
    }

    fn rebuild_index(&mut self) {
        self.port_index.clear();
        for (index, owner) in self.owners.iter().enumerate() {
            self.port_index
                .entry((owner.protocol.to_ascii_uppercase(), owner.local_port))
                .or_default()
                .push(index);
        }
    }

    fn attribute_with_direction(&self, packet: &Packet) -> Option<(&SocketOwner, bool)> {
        let protocol = if packet.protocol.eq_ignore_ascii_case("UDP") { "UDP" } else { "TCP" };
        let source_port = packet.src_port?;
        let target_port = packet.dst_port?;
        if let Some(owner) = self.match_candidates(protocol, source_port, &packet.src, target_port, &packet.dst) {
            return Some((owner, true));
        }
        self.match_candidates(protocol, target_port, &packet.dst, source_port, &packet.src)
            .map(|owner| (owner, false))
    }

    fn match_candidates(
        &self,
        protocol: &str,
        local_port: u16,
        local_ip: &str,
        remote_port: u16,
        remote_ip: &str,
    ) -> Option<&SocketOwner> {
        let candidates = self.port_index.get(&(protocol.to_string(), local_port))?;
        let local_ip = local_ip.parse::<IpAddr>().ok();
        let remote_ip = remote_ip.parse::<IpAddr>().ok();
        candidates.iter().rev().filter_map(|index| self.owners.get(*index)).find(|owner| {
            address_matches(owner.local_addr, local_ip)
                && (owner.remote_port == 0 || owner.remote_port == remote_port)
                && address_matches(owner.remote_addr, remote_ip)
        })
    }
}

fn parse_event_owner(line: &str, line_no: usize) -> Result<SocketOwner, String> {
    let fields: Vec<_> = line.splitn(9, ',').map(str::trim).collect();
    if fields.len() != 9 {
        return Err(format!("socket event line {line_no} must have 9 CSV fields"));
    }
    let protocol = fields[0].to_ascii_uppercase();
    if !matches!(protocol.as_str(), "TCP" | "UDP") {
        return Err(format!("socket event line {line_no} has unsupported protocol"));
    }
    Ok(SocketOwner {
        protocol,
        local_addr: fields[1].parse().map_err(|_| format!("socket event line {line_no} has invalid local_addr"))?,
        local_port: fields[2].parse().map_err(|_| format!("socket event line {line_no} has invalid local_port"))?,
        remote_addr: fields[3].parse().map_err(|_| format!("socket event line {line_no} has invalid remote_addr"))?,
        remote_port: fields[4].parse().map_err(|_| format!("socket event line {line_no} has invalid remote_port"))?,
        pid: fields[5].parse().map_err(|_| format!("socket event line {line_no} has invalid pid"))?,
        uid: fields[6].parse().map_err(|_| format!("socket event line {line_no} has invalid uid"))?,
        process: fields[7].to_string(),
        command: fields[8].to_string(),
        inode: 0,
    })
}

fn address_matches(socket: IpAddr, packet: Option<IpAddr>) -> bool {
    socket.is_unspecified() || packet == Some(socket)
}

#[derive(Debug)]
struct SocketRow {
    protocol: String,
    local_addr: IpAddr,
    local_port: u16,
    remote_addr: IpAddr,
    remote_port: u16,
    inode: u64,
}

#[derive(Debug, Clone)]
struct ProcessOwner {
    pid: u32,
    uid: u32,
    name: String,
    command: String,
}

#[cfg(target_os = "linux")]
fn read_linux_sockets() -> Result<Vec<SocketRow>, String> {
    let mut sockets = Vec::new();
    for (path, protocol, ipv6) in [
        ("/proc/net/tcp", "TCP", false),
        ("/proc/net/tcp6", "TCP", true),
        ("/proc/net/udp", "UDP", false),
        ("/proc/net/udp6", "UDP", true),
    ] {
        let Ok(text) = std::fs::read_to_string(path) else { continue; };
        for line in text.lines().skip(1) {
            if let Some(row) = parse_socket_row(line, protocol, ipv6) {
                sockets.push(row);
            }
        }
    }
    Ok(sockets)
}

fn parse_socket_row(line: &str, protocol: &str, ipv6: bool) -> Option<SocketRow> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 10 { return None; }
    let (local_addr, local_port) = parse_endpoint(fields[1], ipv6)?;
    let (remote_addr, remote_port) = parse_endpoint(fields[2], ipv6)?;
    Some(SocketRow {
        protocol: protocol.into(),
        local_addr,
        local_port,
        remote_addr,
        remote_port,
        inode: fields[9].parse().ok()?,
    })
}

fn parse_endpoint(value: &str, ipv6: bool) -> Option<(IpAddr, u16)> {
    let (address, port) = value.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let address = if ipv6 {
        if address.len() != 32 { return None; }
        let mut bytes = [0_u8; 16];
        for block in 0..4 {
            let start = block * 8;
            let value = u32::from_str_radix(&address[start..start + 8], 16).ok()?;
            bytes[start / 2..start / 2 + 4].copy_from_slice(&value.to_le_bytes());
        }
        IpAddr::V6(Ipv6Addr::from(bytes))
    } else {
        let value = u32::from_str_radix(address, 16).ok()?;
        IpAddr::V4(Ipv4Addr::from(value.to_le_bytes()))
    };
    Some((address, port))
}

#[cfg(target_os = "linux")]
fn read_linux_processes() -> HashMap<u64, ProcessOwner> {
    use std::os::unix::fs::MetadataExt;

    let mut owners = HashMap::new();
    let Ok(entries) = std::fs::read_dir("/proc") else { return owners; };
    for entry in entries.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|name| name.parse::<u32>().ok()) else { continue; };
        let base = entry.path();
        let uid = std::fs::metadata(&base).map(|metadata| metadata.uid()).unwrap_or(0);
        let name = std::fs::read_to_string(base.join("comm"))
            .unwrap_or_else(|_| "unknown".into()).trim().to_string();
        let command = std::fs::read(base.join("cmdline"))
            .map(|bytes| String::from_utf8_lossy(&bytes).replace('\0', " ").trim().to_string())
            .unwrap_or_default();
        let Ok(descriptors) = std::fs::read_dir(base.join("fd")) else { continue; };
        for descriptor in descriptors.flatten() {
            let Ok(target) = std::fs::read_link(descriptor.path()) else { continue; };
            let target = target.to_string_lossy();
            let Some(inode) = target.strip_prefix("socket:[").and_then(|value| value.strip_suffix(']')).and_then(|value| value.parse().ok()) else { continue; };
            owners.entry(inode).or_insert_with(|| ProcessOwner {
                pid,
                uid,
                name: name.clone(),
                command: command.clone(),
            });
        }
    }
    owners
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_linux_ipv4_socket_row() {
        let row = parse_socket_row(
            "  0: 0100007F:1F90 070000CB:C350 01 00000000:00000000 00:00000000 00000000 1000 0 12345 1",
            "TCP",
            false,
        ).unwrap();
        assert_eq!(row.local_addr, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(row.local_port, 8080);
        assert_eq!(row.remote_addr, "203.0.0.7".parse::<IpAddr>().unwrap());
        assert_eq!(row.remote_port, 50000);
        assert_eq!(row.inode, 12345);
    }

    #[test]
    fn imported_event_owner_attributes_matching_packet() {
        let path = std::env::temp_dir().join(format!("packrat-socket-events-{}.csv", std::process::id()));
        std::fs::write(
            &path,
            "tcp,192.0.2.10,4444,198.51.100.7,443,4242,1000,curl,curl https://example.test\n",
        ).unwrap();
        let mut scope = SocketScope::default();
        assert_eq!(scope.load_event_file(&path).unwrap(), 1);
        let packet = Packet {
            no: 1,
            timestamp: 7.0,
            src: "192.0.2.10".into(),
            dst: "198.51.100.7".into(),
            protocol: "TCP".into(),
            length: 120,
            info: String::new(),
            src_port: Some(4444),
            dst_port: Some(443),
            vlan_id: None,
            vlan_pcp: None,
            vlan_dei: None,
            outer_vlan_id: None,
            bytes: Vec::new(),
        };
        assert_eq!(scope.observe(&packet).as_deref(), Some("curl"));
        let usage = scope.traffic.get(&4242).unwrap();
        assert_eq!(usage.bytes_out, 120);
        assert_eq!(usage.packets_out, 1);
        let _ = std::fs::remove_file(path);
    }
}
