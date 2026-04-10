//! Port scanner state — simulation and (with `real-capture` feature) real TCP connect scans.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

// ─── Port state / entry ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    Unknown,
}

impl std::fmt::Display for PortState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortState::Open     => write!(f, "open"),
            PortState::Closed   => write!(f, "closed"),
            PortState::Filtered => write!(f, "filtered"),
            PortState::Unknown  => write!(f, "unknown"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PortEntry {
    pub port: u16,
    pub state: PortState,
    pub service: &'static str,
    pub banner: Option<String>,
}

// ─── Scan mode / focus field ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanMode {
    TcpConnect,
    Syn,
    Udp,
}

impl std::fmt::Display for ScanMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanMode::TcpConnect => write!(f, "TCP Connect"),
            ScanMode::Syn        => write!(f, "SYN"),
            ScanMode::Udp        => write!(f, "UDP"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanField {
    Target,
    PortStart,
    PortEnd,
    Mode,
}

// ─── Scan state ───────────────────────────────────────────────────────────────

pub struct ScanState {
    pub target: String,
    pub port_range_start: String,
    pub port_range_end: String,
    pub scan_mode: ScanMode,
    pub results: Vec<PortEntry>,
    pub running: bool,
    pub complete: bool,
    pub current_port: u16,
    pub total_ports: u16,
    pub selected: usize,
    pub error: Option<String>,
    pub focused_field: ScanField,

    // Internal
    port_start: u16,
    port_end: u16,
    target_seed: u64,
}

impl ScanState {
    pub fn new() -> Self {
        Self {
            target: String::new(),
            port_range_start: "1".to_string(),
            port_range_end: "1024".to_string(),
            scan_mode: ScanMode::TcpConnect,
            results: Vec::new(),
            running: false,
            complete: false,
            current_port: 0,
            total_ports: 0,
            selected: 0,
            error: None,
            focused_field: ScanField::Target,
            port_start: 1,
            port_end: 1024,
            target_seed: 0,
        }
    }

    /// Parse inputs and begin scan simulation.
    pub fn start(&mut self) {
        self.error = None;
        self.results.clear();
        self.complete = false;
        self.selected = 0;

        // Parse port range
        let start: u16 = match self.port_range_start.trim().parse() {
            Ok(v) => v,
            Err(_) => {
                self.error = Some(format!("Invalid port start: '{}'", self.port_range_start));
                return;
            }
        };
        let end: u16 = match self.port_range_end.trim().parse() {
            Ok(v) => v,
            Err(_) => {
                self.error = Some(format!("Invalid port end: '{}'", self.port_range_end));
                return;
            }
        };
        if start > end {
            self.error = Some(format!("Port start {start} > end {end}"));
            return;
        }
        if self.target.trim().is_empty() {
            self.error = Some("Target is empty".to_string());
            return;
        }

        self.port_start = start;
        self.port_end = end;
        self.current_port = start;
        self.total_ports = end.saturating_sub(start).saturating_add(1);

        // Compute a stable seed from the target string bytes
        let mut hasher = DefaultHasher::new();
        self.target.hash(&mut hasher);
        self.target_seed = hasher.finish();

        self.running = true;
    }

    /// Advance simulation by up to 4 ports. Returns true if any port was processed.
    pub fn tick(&mut self) -> bool {
        if !self.running || self.complete {
            return false;
        }

        let mut processed = false;
        for _ in 0..4 {
            if self.current_port > self.port_end {
                self.running = false;
                self.complete = true;
                break;
            }
            let port = self.current_port;
            let state = self.simulate_port(port);
            let service = Self::service_for(port);
            self.results.push(PortEntry {
                port,
                state,
                service,
                banner: None,
            });
            self.current_port = self.current_port.saturating_add(1);
            processed = true;
        }
        processed
    }

    /// Determine simulated port state using a deterministic hash.
    fn simulate_port(&self, port: u16) -> PortState {
        let mut hasher = DefaultHasher::new();
        port.hash(&mut hasher);
        self.target_seed.hash(&mut hasher);
        let h = hasher.finish();

        // Common ports have 60% chance of open
        const COMMON: &[u16] = &[
            22, 80, 443, 8080, 3389, 445, 21, 25, 53, 3306, 5432, 6379, 27017, 9200, 5601, 8888,
        ];
        let pct = (h % 100) as u8;

        if COMMON.contains(&port) {
            if pct < 60 {
                PortState::Open
            } else if pct < 80 {
                PortState::Closed
            } else {
                PortState::Filtered
            }
        } else {
            if pct < 15 {
                PortState::Open
            } else if pct < 90 {
                PortState::Closed
            } else {
                PortState::Filtered
            }
        }
    }

    /// Reset to defaults.
    pub fn clear(&mut self) {
        *self = Self::new();
    }

    /// Count open ports.
    pub fn open_count(&self) -> usize {
        self.results.iter().filter(|e| e.state == PortState::Open).count()
    }

    /// Well-known port → service name lookup.
    pub fn service_for(port: u16) -> &'static str {
        match port {
            1    => "TCPMUX",
            7    => "echo",
            9    => "discard",
            13   => "daytime",
            17   => "qotd",
            19   => "chargen",
            20   => "ftp-data",
            21   => "ftp",
            22   => "ssh",
            23   => "telnet",
            25   => "smtp",
            37   => "time",
            43   => "whois",
            49   => "tacacs",
            53   => "dns",
            67   => "dhcp",
            68   => "dhcp-client",
            69   => "tftp",
            70   => "gopher",
            79   => "finger",
            80   => "http",
            88   => "kerberos",
            102  => "iso-tsap",
            110  => "pop3",
            111  => "rpcbind",
            113  => "ident",
            119  => "nntp",
            123  => "ntp",
            135  => "msrpc",
            137  => "netbios-ns",
            138  => "netbios-dgm",
            139  => "netbios-ssn",
            143  => "imap",
            161  => "snmp",
            162  => "snmp-trap",
            179  => "bgp",
            194  => "irc",
            389  => "ldap",
            443  => "https",
            445  => "smb",
            465  => "smtps",
            500  => "ike",
            514  => "syslog",
            515  => "lpd",
            520  => "rip",
            554  => "rtsp",
            587  => "smtp-submission",
            636  => "ldaps",
            873  => "rsync",
            902  => "vmware",
            989  => "ftps-data",
            990  => "ftps",
            993  => "imaps",
            995  => "pop3s",
            1080 => "socks",
            1194 => "openvpn",
            1433 => "mssql",
            1434 => "mssql-monitor",
            1521 => "oracle",
            1723 => "pptp",
            1883 => "mqtt",
            2049 => "nfs",
            2181 => "zookeeper",
            2375 => "docker",
            2376 => "docker-tls",
            2379 => "etcd",
            2380 => "etcd-peer",
            3000 => "grafana/dev",
            3306 => "mysql",
            3389 => "rdp",
            4369 => "epmd",
            4443 => "alt-https",
            4505 => "salt-master",
            4506 => "salt-master2",
            5000 => "upnp/flask",
            5432 => "postgresql",
            5601 => "kibana",
            5672 => "amqp",
            5900 => "vnc",
            5901 => "vnc-1",
            5984 => "couchdb",
            6379 => "redis",
            6443 => "kubernetes-api",
            7001 => "weblogic",
            7077 => "spark",
            8000 => "http-alt",
            8008 => "http-alt2",
            8080 => "http-proxy",
            8081 => "http-alt3",
            8083 => "influxdb",
            8086 => "influxdb-api",
            8088 => "riak",
            8443 => "alt-https",
            8888 => "jupyter/http-alt",
            9000 => "sonarqube",
            9092 => "kafka",
            9200 => "elasticsearch",
            9300 => "elasticsearch-cluster",
            10000 => "webmin",
            11211 => "memcached",
            15672 => "rabbitmq-mgmt",
            27017 => "mongodb",
            27018 => "mongodb-shard",
            27019 => "mongodb-config",
            50000 => "db2",
            50070 => "hdfs-namenode",
            _     => "unknown",
        }
    }
}

impl Default for ScanState {
    fn default() -> Self {
        Self::new()
    }
}
