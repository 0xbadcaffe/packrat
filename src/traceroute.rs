/// Traceroute state — simulates (or runs) hop-by-hop path discovery.
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
    pub target:        String,   // current text in the input field
    pub hops:          Vec<TraceHop>,
    pub running:       bool,
    pub complete:      bool,
    pub selected:      usize,    // scroll cursor in results
    pub error:         Option<String>,
    /// Tick counter used to animate the running state one hop at a time.
    pub pending_ticks: u8,
    pub next_hop_ttl:  u8,       // next TTL to generate
    pub target_ip:     Option<Ipv4Addr>,
}

impl Default for TracerouteState {
    fn default() -> Self {
        Self {
            target:        String::new(),
            hops:          Vec::new(),
            running:       false,
            complete:      false,
            selected:      0,
            error:         None,
            pending_ticks: 0,
            next_hop_ttl:  1,
            target_ip:     None,
        }
    }
}

impl TracerouteState {
    /// Start a new traceroute to the current target string.
    pub fn start(&mut self) {
        let tgt = self.target.trim().to_string();
        if tgt.is_empty() { return; }

        self.hops.clear();
        self.running = false;
        self.complete = false;
        self.error = None;
        self.selected = 0;
        self.next_hop_ttl = 1;
        self.pending_ticks = 0;

        // Parse target IP or simulate one from the hostname
        let ip = tgt.parse::<Ipv4Addr>().unwrap_or_else(|_| {
            // Deterministic fake IP from hostname bytes
            let b: Vec<u8> = tgt.bytes().collect();
            let a = 8u8;
            let bb = b.first().copied().unwrap_or(8).wrapping_add(1).max(1);
            let c = b.get(1).copied().unwrap_or(8).wrapping_add(1).max(1);
            let d = b.get(2).copied().unwrap_or(8).wrapping_add(1).max(1);
            Ipv4Addr::new(a, bb, c, d)
        });
        self.target_ip = Some(ip);
        self.running = true;
    }

    /// Called each app tick while running — generates the next hop.
    /// Returns true if a new hop was added.
    pub fn tick(&mut self) -> bool {
        if !self.running { return false; }

        self.pending_ticks += 1;
        if self.pending_ticks < 6 { return false; }  // ~300ms per hop at 50ms tick
        self.pending_ticks = 0;

        let ttl = self.next_hop_ttl;
        let target_ip = match self.target_ip {
            Some(ip) => ip,
            None => { self.running = false; return false; }
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
        *self = Self::default();
    }

    pub fn scroll_down(&mut self) {
        if self.selected + 1 < self.hops.len() { self.selected += 1; }
    }

    pub fn scroll_up(&mut self) {
        if self.selected > 0 { self.selected -= 1; }
    }
}

/// Generate a single simulated hop.
fn simulate_hop(ttl: u8, target: Ipv4Addr) -> TraceHop {
    // Use TTL + target octets as a deterministic seed
    let seed = (ttl as u64)
        .wrapping_mul(2654435761)
        .wrapping_add(u32::from(target) as u64);

    let tgt_octets = target.octets();
    let max_ttl = 8u8 + (seed % 8) as u8; // 8–15 hops total

    // Last hop reaches destination
    if ttl >= max_ttl {
        let rtt = 10.0 + (seed % 200) as f64 / 10.0;
        return TraceHop {
            ttl,
            ip:       target.to_string(),
            hostname: Some(synthesize_hostname(target.octets())),
            result:   HopResult::Reply { rtt_ms: rtt },
        };
    }

    // Some intermediate hops time out
    let timeout = (seed >> 4) % 5 == 0;  // ~20% chance

    // Build a plausible intermediate hop IP
    let hop_ip = intermediate_ip(ttl, seed, tgt_octets);
    let rtt = 1.0 * ttl as f64 + (seed % 50) as f64 / 10.0;

    TraceHop {
        ttl,
        ip:       if timeout { "*".into() } else { hop_ip.to_string() },
        hostname: if timeout { None } else { Some(synthesize_hostname(hop_ip.octets())) },
        result:   if timeout {
            HopResult::Timeout
        } else {
            HopResult::Reply { rtt_ms: rtt }
        },
    }
}

fn intermediate_ip(ttl: u8, seed: u64, tgt: [u8; 4]) -> Ipv4Addr {
    // Mix TTL and target to get intermediate hop IPs
    let a = [
        [10, 0, 0],
        [172, 16, 0],
        [100, 64, 0],
        [195, 66, 36],
        [23, 0, 0],
        [34, 0, 0],
        [74, 125, 0],
    ][(seed as usize) % 7];
    Ipv4Addr::new(
        a[0],
        a[1].wrapping_add(ttl),
        a[2].wrapping_add((seed >> 8) as u8),
        tgt[3].wrapping_add(ttl),
    )
}

fn synthesize_hostname(ip: [u8; 4]) -> String {
    let suffixes = [
        "core.net",    "be.net",   "r.isp.net",  "backbone.com",
        "akamai.net",  "goog.com", "cloudflare.com", "level3.net",
    ];
    let idx = (ip[2] as usize + ip[3] as usize) % suffixes.len();
    format!("{}-{}-{}-{}.{}", ip[0], ip[1], ip[2], ip[3], suffixes[idx])
}
