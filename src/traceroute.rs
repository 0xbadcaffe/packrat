/// Traceroute state — simulates or runs real hop-by-hop path discovery.
/// Under the `real-capture` feature, executes the OS traceroute command and
/// parses its output. Falls back to simulation otherwise.
use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq)]
pub enum HopResult {
    Reply { rtt_ms: f64 },
    Timeout,
}

#[derive(Debug, Clone)]
pub struct TraceHop {
    pub ttl:      u8,
    pub ip:       String,
    pub hostname: Option<String>,
    pub result:   HopResult,
}

pub struct TracerouteState {
    pub target:        String,
    pub editing:       bool,   // true while user is typing the target
    pub hops:          Vec<TraceHop>,
    pub running:       bool,
    pub complete:      bool,
    pub selected:      usize,
    pub error:         Option<String>,
    /// Tick counter for simulation pacing
    pub pending_ticks: u8,
    pub next_hop_ttl:  u8,
    pub target_ip:     Option<Ipv4Addr>,
    /// Real-mode: lines of raw output buffered for parsing
    #[cfg(feature = "real-capture")]
    real_lines:        Vec<String>,
    #[cfg(feature = "real-capture")]
    child:             Option<std::process::Child>,
    #[cfg(feature = "real-capture")]
    reader:            Option<std::io::BufReader<std::process::ChildStdout>>,
}

impl Default for TracerouteState {
    fn default() -> Self {
        Self {
            target:        String::new(),
            editing:       false,
            hops:          Vec::new(),
            running:       false,
            complete:      false,
            selected:      0,
            error:         None,
            pending_ticks: 0,
            next_hop_ttl:  1,
            target_ip:     None,
            #[cfg(feature = "real-capture")]
            real_lines:    Vec::new(),
            #[cfg(feature = "real-capture")]
            child:         None,
            #[cfg(feature = "real-capture")]
            reader:        None,
        }
    }
}

impl TracerouteState {
    pub fn start(&mut self) {
        let tgt = self.target.trim().to_string();
        if tgt.is_empty() { return; }

        self.hops.clear();
        self.complete = false;
        self.error = None;
        self.selected = 0;
        self.next_hop_ttl = 1;
        self.pending_ticks = 0;
        self.target_ip = tgt.parse::<Ipv4Addr>().ok().or_else(|| {
            Some(hostname_to_fake_ip(&tgt))
        });

        #[cfg(feature = "real-capture")]
        self.start_real(&tgt);
        #[cfg(not(feature = "real-capture"))]
        { self.running = true; }
    }

    #[cfg(feature = "real-capture")]
    fn start_real(&mut self, target: &str) {
        use std::process::{Command, Stdio};
        use std::io::BufReader;

        // Cross-platform: Windows uses `tracert`, Unix uses `traceroute`
        let (cmd, args): (&str, Vec<&str>) = if cfg!(target_os = "windows") {
            ("tracert", vec!["-d", target])   // -d = no DNS reverse lookup
        } else if cfg!(target_os = "macos") {
            ("traceroute", vec!["-n", "-q", "1", "-w", "1", target])
        } else {
            // Linux: prefer traceroute, fallback handled at runtime
            ("traceroute", vec!["-n", "-q", "1", "-w", "1", target])
        };

        match Command::new(cmd)
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(mut child) => {
                let stdout = child.stdout.take().unwrap();
                self.reader = Some(BufReader::new(stdout));
                self.child  = Some(child);
                self.running = true;
                self.real_lines.clear();
            }
            Err(e) => {
                // traceroute not installed — fall back to simulation
                self.error = Some(format!(
                    "traceroute unavailable ({}), showing simulation", e
                ));
                self.running = true;   // simulation mode
            }
        }
    }

    pub fn tick(&mut self) -> bool {
        if !self.running { return false; }

        #[cfg(feature = "real-capture")]
        if self.reader.is_some() {
            return self.tick_real();
        }

        self.tick_simulated()
    }

    #[cfg(feature = "real-capture")]
    fn tick_real(&mut self) -> bool {
        use std::io::BufRead;

        let reader = match self.reader.as_mut() {
            Some(r) => r,
            None    => return self.tick_simulated(),
        };

        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => {
                // EOF
                self.running = false;
                self.complete = true;
                self.reader = None;
                if let Some(mut child) = self.child.take() { let _ = child.wait(); }
                false
            }
            Ok(_) => {
                let line = line.trim().to_string();
                if let Some(hop) = parse_traceroute_line(&line) {
                    let ttl = hop.ttl;
                    let is_target = self.target_ip
                        .map(|ip| hop.ip == ip.to_string())
                        .unwrap_or(false);
                    self.hops.push(hop);
                    if is_target || ttl >= 30 {
                        self.running = false;
                        self.complete = true;
                        self.reader = None;
                        if let Some(mut child) = self.child.take() { let _ = child.wait(); }
                    }
                    true
                } else {
                    false
                }
            }
            Err(_) => {
                self.running = false;
                self.complete = true;
                false
            }
        }
    }

    fn tick_simulated(&mut self) -> bool {
        self.pending_ticks += 1;
        if self.pending_ticks < 6 { return false; }
        self.pending_ticks = 0;

        let ttl = self.next_hop_ttl;
        let target_ip = match self.target_ip {
            Some(ip) => ip,
            None     => { self.running = false; return false; }
        };

        let hop = simulate_hop(ttl, target_ip);
        let is_dest = hop.ip == target_ip.to_string();
        self.hops.push(hop);
        self.next_hop_ttl += 1;

        if is_dest || ttl >= 30 {
            self.running = false;
            self.complete = true;
        }
        true
    }

    pub fn clear(&mut self) {
        #[cfg(feature = "real-capture")]
        {
            if let Some(mut child) = self.child.take() { let _ = child.kill(); }
            self.reader = None;
            self.real_lines.clear();
        }
        *self = Self::default();
    }

    pub fn scroll_down(&mut self) {
        if self.selected + 1 < self.hops.len() { self.selected += 1; }
    }
    pub fn scroll_up(&mut self) {
        if self.selected > 0 { self.selected -= 1; }
    }
}

// ─── Real output parser ───────────────────────────────────────────────────────
/// Parse a single traceroute line (works for Linux/macOS/Windows output).
/// Returns None for header lines or unparseable lines.
#[cfg(feature = "real-capture")]
fn parse_traceroute_line(line: &str) -> Option<TraceHop> {
    // Formats:
    //   Linux/macOS: " 1  192.168.1.1  1.234 ms"
    //                " 2  * * *"
    //   Windows tracert: "  1    <1 ms    <1 ms    <1 ms  192.168.1.1"
    //                    "  2     *        *        *     Request timed out."

    let line = line.trim();
    if line.is_empty() || line.starts_with("traceroute") || line.starts_with("Tracing") {
        return None;
    }

    // Try Linux/macOS format: "N  IP  RTT ms" or "N  * * *"
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 { return None; }

    let ttl: u8 = parts[0].parse().ok()?;

    if parts.get(1) == Some(&"*") {
        return Some(TraceHop {
            ttl,
            ip: "*".into(),
            hostname: None,
            result: HopResult::Timeout,
        });
    }

    // Windows: "N  <1 ms  <1 ms  <1 ms  IP"
    // Linux:   "N  IP  RTT ms"
    // Try to find an IP address in the parts
    let ip_str = parts.iter().find(|&&p| p.parse::<Ipv4Addr>().is_ok())?;
    let ip = ip_str.to_string();

    // Find RTT — first number followed by "ms"
    let rtt_ms = parts.windows(2)
        .find(|w| w[1] == "ms")
        .and_then(|w| w[0].trim_start_matches('<').parse::<f64>().ok())
        .unwrap_or(0.0);

    // Check if hostname differs from IP
    let hostname = parts.iter()
        .find(|&&p| p != *ip_str && p.contains('.') && !p.ends_with("ms"))
        .map(|&s| s.trim_end_matches(')').trim_start_matches('(').to_string());

    Some(TraceHop {
        ttl,
        ip,
        hostname,
        result: HopResult::Reply { rtt_ms },
    })
}

// ─── Simulation ───────────────────────────────────────────────────────────────

/// Hash a hostname to a deterministic, plausible-looking public IP address.
/// Different hostnames always produce different IPs; same hostname always produces the same IP.
fn hostname_to_fake_ip(host: &str) -> Ipv4Addr {
    // FNV-1a hash of the full hostname
    let mut h: u64 = 14_695_981_039_346_656_037;
    for b in host.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(1_099_511_628_211);
    }
    // Map into realistic-looking public IP ranges (ASN prefixes)
    let prefixes: &[(u8, u8)] = &[
        (8,   8),   // Google Public DNS aesthetic
        (1,   1),   // Cloudflare DNS aesthetic
        (142, 250), // Google
        (172, 217), // Google
        (31,  13),  // Meta/Facebook
        (157, 240), // Meta/Facebook
        (13,  107), // Microsoft
        (40,  76),  // Microsoft Azure
        (104, 244), // Twitter/X
        (199, 16),  // Twitter/X
        (23,  185), // Fastly CDN
        (151, 101), // Fastly CDN
        (104, 16),  // Cloudflare
        (172, 64),  // Cloudflare
        (52,  0),   // AWS
        (54,  0),   // AWS
    ];
    let (a, b) = prefixes[(h as usize) % prefixes.len()];
    let c = ((h >> 16) & 0xFF) as u8;
    let d = (((h >> 24) & 0xFE) as u8) | 1; // ensure non-zero
    Ipv4Addr::new(a, b, c, d)
}

fn simulate_hop(ttl: u8, target: Ipv4Addr) -> TraceHop {
    let seed = (ttl as u64)
        .wrapping_mul(2654435761)
        .wrapping_add(u32::from(target) as u64);

    let tgt_octets = target.octets();
    let max_ttl = 8u8 + (seed % 8) as u8;

    if ttl >= max_ttl {
        let rtt = 10.0 + (seed % 200) as f64 / 10.0;
        return TraceHop {
            ttl,
            ip:       target.to_string(),
            hostname: Some(synthesize_hostname(tgt_octets)),
            result:   HopResult::Reply { rtt_ms: rtt },
        };
    }

    let timeout = (seed >> 4) % 5 == 0;
    let hop_ip = intermediate_ip(ttl, seed, tgt_octets);
    let rtt = 1.0 * ttl as f64 + (seed % 50) as f64 / 10.0;

    TraceHop {
        ttl,
        ip:       if timeout { "*".into() } else { hop_ip.to_string() },
        hostname: if timeout { None } else { Some(synthesize_hostname(hop_ip.octets())) },
        result:   if timeout { HopResult::Timeout } else { HopResult::Reply { rtt_ms: rtt } },
    }
}

fn intermediate_ip(ttl: u8, seed: u64, tgt: [u8; 4]) -> Ipv4Addr {
    let prefixes: [[u8; 3]; 7] = [
        [10, 0, 0], [172, 16, 0], [100, 64, 0],
        [195, 66, 36], [23, 0, 0], [34, 0, 0], [74, 125, 0],
    ];
    let a = prefixes[(seed as usize) % prefixes.len()];
    Ipv4Addr::new(a[0], a[1].wrapping_add(ttl), a[2].wrapping_add((seed >> 8) as u8), tgt[3].wrapping_add(ttl))
}

fn synthesize_hostname(ip: [u8; 4]) -> String {
    let suffixes = [
        "core.net", "be.net", "r.isp.net", "backbone.com",
        "akamai.net", "goog.com", "cloudflare.com", "level3.net",
    ];
    let idx = (ip[2] as usize + ip[3] as usize) % suffixes.len();
    format!("{}-{}-{}-{}.{}", ip[0], ip[1], ip[2], ip[3], suffixes[idx])
}
