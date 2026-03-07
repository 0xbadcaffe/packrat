/// Simulated packet generator for demo / testing without a real interface.
use rand::Rng;
use crate::net::packet::Packet;

const LOCAL_IPS: &[&str] = &[
    "192.168.1.1", "192.168.1.42", "192.168.1.100",
    "10.0.0.1", "10.0.0.23", "172.16.0.5",
];
const REMOTE_IPS: &[&str] = &[
    "8.8.8.8", "1.1.1.1", "151.101.64.81",
    "142.250.80.46", "104.21.55.33", "172.217.14.206",
    "13.107.42.14", "52.84.17.200", "34.120.208.123",
];
const DNS_NAMES: &[&str] = &[
    "google.com", "github.com", "api.stripe.com",
    "fonts.googleapis.com", "cdn.cloudflare.com",
    "s3.amazonaws.com", "app.slack.com", "discord.com",
];
const PROTOS: &[&str] = &[
    "TCP", "UDP", "DNS", "HTTP", "HTTPS", "TLS", "ARP", "ICMP", "DHCP",
];
const WEIGHTS: &[u32] = &[30, 15, 20, 8, 12, 8, 3, 3, 1];

static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

pub fn generate_packet(counter: u64) -> Packet {
    let start = START.get_or_init(std::time::Instant::now);
    let ts = start.elapsed().as_secs_f64();
    let mut rng = rand::thread_rng();
    let proto = weighted_pick(PROTOS, WEIGHTS, &mut rng);

    let length: u16 = match proto {
        "ARP"  => 42,
        "ICMP" => rng.gen_range(60..=128),
        _      => rng.gen_range(60..=1460),
    };

    let bytes: Vec<u8> = (0..length).map(|i| {
        let b: u8 = rng.gen();
        if i < 54 { b }
        else if b % 3 == 0 { rng.gen_range(32..127) }
        else { b }
    }).collect();

    let (src, dst, src_port, dst_port, info) = match proto {
        "ARP" => {
            let src = rand_ip(LOCAL_IPS, &mut rng).to_string();
            let tgt = rand_ip(LOCAL_IPS, &mut rng);
            (src.clone(), "ff:ff:ff:ff:ff:ff".to_string(), None, None,
             format!("Who has {}? Tell {}", tgt, src))
        }
        "ICMP" => {
            let src = rand_ip(LOCAL_IPS, &mut rng).to_string();
            let dst = rand_ip(REMOTE_IPS, &mut rng).to_string();
            let id: u16 = rng.gen();
            let seq: u16 = rng.gen_range(1..=100);
            (src, dst, None, None,
             format!("Echo request id=0x{:04x} seq={}", id, seq))
        }
        "DNS" => {
            let src = rand_ip(LOCAL_IPS, &mut rng).to_string();
            let dst = if rng.gen_bool(0.7) { "8.8.8.8" } else { "1.1.1.1" }.to_string();
            let name = DNS_NAMES[rng.gen_range(0..DNS_NAMES.len())];
            let tid: u16 = rng.gen();
            let info = if rng.gen_bool(0.5) {
                format!("Query 0x{:04x} A {}", tid, name)
            } else {
                format!("Response A {}.{}.{}.{}",
                    rng.gen_range(1..=254u8), rng.gen::<u8>(),
                    rng.gen::<u8>(), rng.gen_range(1..=254u8))
            };
            let sp: u16 = rng.gen_range(1024..=65535);
            (src, dst, Some(sp), Some(53u16), info)
        }
        "DHCP" => {
            let msg = ["Discover", "Request", "Offer", "ACK"][rng.gen_range(0..4)];
            let tid: u32 = rng.gen();
            ("0.0.0.0".into(), "255.255.255.255".into(),
             Some(68u16), Some(67u16),
             format!("DHCP {} TID=0x{:08x}", msg, tid))
        }
        "HTTP" => {
            let src = rand_ip(LOCAL_IPS, &mut rng).to_string();
            let dst = rand_ip(REMOTE_IPS, &mut rng).to_string();
            let methods = ["GET", "POST", "PUT", "DELETE", "HEAD"];
            let paths = ["/api/v1/users", "/index.html", "/assets/main.js", "/api/data"];
            let m = methods[rng.gen_range(0..methods.len())];
            let p = paths[rng.gen_range(0..paths.len())];
            let sp: u16 = rng.gen_range(1024..=65535);
            (src, dst, Some(sp), Some(80u16), format!("{} {} HTTP/1.1", m, p))
        }
        "HTTPS" | "TLS" => {
            let src = rand_ip(LOCAL_IPS, &mut rng).to_string();
            let dst = rand_ip(REMOTE_IPS, &mut rng).to_string();
            let hs = ["Client Hello", "Server Hello", "Certificate", "Finished", "Application Data"];
            let sp: u16 = rng.gen_range(1024..=65535);
            (src, dst, Some(sp), Some(443u16),
             format!("TLS {}", hs[rng.gen_range(0..hs.len())]))
        }
        _ => {
            let src = rand_ip(LOCAL_IPS, &mut rng).to_string();
            let dst_pool = if rng.gen_bool(0.4) { LOCAL_IPS } else { REMOTE_IPS };
            let dst = rand_ip(dst_pool, &mut rng).to_string();
            let sp: u16 = rng.gen_range(1024..=65535);
            let dp_opts = [22u16, 80, 443, 3306, 5432, 6379, 8080, 9200];
            let dp = dp_opts[rng.gen_range(0..dp_opts.len())];
            let info = if proto == "TCP" {
                let flags = ["SYN", "ACK", "PSH, ACK", "FIN, ACK", "RST, ACK", "SYN, ACK"];
                let f = flags[rng.gen_range(0..flags.len())];
                let seq: u32 = rng.gen();
                let ack: u32 = rng.gen();
                format!("{} → {} [{}] Seq={} Ack={}", sp, dp, f, seq, ack)
            } else {
                format!("{} → {} Len={}", sp, dp, length.saturating_sub(42))
            };
            (src, dst, Some(sp), Some(dp), info)
        }
    };

    Packet {
        no: counter + 1,
        timestamp: ts,
        src,
        dst,
        protocol: proto.to_string(),
        length,
        info,
        src_port,
        dst_port,
        vlan_id: None,
        bytes,
    }
}

fn weighted_pick<'a>(items: &[&'a str], weights: &[u32], rng: &mut impl Rng) -> &'a str {
    let total: u32 = weights.iter().sum();
    let mut r = rng.gen_range(0..total);
    for (item, w) in items.iter().zip(weights.iter()) {
        if r < *w { return item; }
        r -= w;
    }
    items[0]
}

fn rand_ip<'a>(pool: &[&'a str], rng: &mut impl Rng) -> &'a str {
    pool[rng.gen_range(0..pool.len())]
}

pub fn rand_mac(rng: &mut impl Rng) -> String {
    (0..6).map(|i| {
        if i == 0 { format!("{:02x}", rng.gen::<u8>() & 0xfe) }
        else       { format!("{:02x}", rng.gen::<u8>()) }
    }).collect::<Vec<_>>().join(":")
}
