use rand::Rng;

#[derive(Debug, Clone)]
pub struct Packet {
    pub no: u64,
    pub timestamp: f64,
    pub src: String,
    pub dst: String,
    pub protocol: String,
    pub length: u16,
    pub info: String,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub bytes: Vec<u8>,
}

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
    "fonts.googleapis.com", "cdn.cloudflare.com", "s3.amazonaws.com",
    "app.slack.com", "discord.com",
];
const PROTOS: &[&str] = &[
    "TCP", "UDP", "DNS", "HTTP", "HTTPS", "TLS", "ARP", "ICMP", "DHCP",
];
// Weights for protocol selection
const WEIGHTS: &[u32] = &[30, 15, 20, 8, 12, 8, 3, 3, 1];

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

fn rand_mac(rng: &mut impl Rng) -> String {
    (0..6).map(|i| {
        if i == 0 { format!("{:02x}", rng.gen::<u8>() & 0xfe) }
        else       { format!("{:02x}", rng.gen::<u8>()) }
    }).collect::<Vec<_>>().join(":")
}

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
        if i < 14 { rng.gen() }       // ethernet
        else if i < 34 { rng.gen() }  // ip
        else if i < 54 { rng.gen() }  // transport
        else {
            // payload: mix of printable and binary
            let b: u8 = rng.gen();
            if b % 3 == 0 { rng.gen_range(32..127) } else { b }
        }
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
             format!("Echo (ping) request  id=0x{:04x}, seq={}/{}",
                     id, seq, seq.to_be()))
        }
        "DNS" => {
            let src = rand_ip(LOCAL_IPS, &mut rng).to_string();
            let dst = if rng.gen_bool(0.7) { "8.8.8.8" } else { "1.1.1.1" }.to_string();
            let name = DNS_NAMES[rng.gen_range(0..DNS_NAMES.len())];
            let tid: u16 = rng.gen();
            let info = if rng.gen_bool(0.5) {
                format!("Standard query 0x{:04x} A {}", tid, name)
            } else {
                format!("Standard query response A {}.{}.{}.{}",
                        rng.gen_range(1..=254), rng.gen_range(0..=255),
                        rng.gen_range(0..=255), rng.gen_range(1..=254))
            };
            let sp: u16 = rng.gen_range(1024..=65535);
            (src, dst, Some(sp), Some(53u16), info)
        }
        "DHCP" => {
            let msg = ["Discover","Request","Offer","ACK"][rng.gen_range(0..4)];
            let tid: u32 = rng.gen();
            ("0.0.0.0".to_string(), "255.255.255.255".to_string(),
             Some(68u16), Some(67u16),
             format!("DHCP {} - Transaction ID 0x{:08x}", msg, tid))
        }
        "HTTP" => {
            let src = rand_ip(LOCAL_IPS, &mut rng).to_string();
            let dst = rand_ip(REMOTE_IPS, &mut rng).to_string();
            let methods = ["GET","POST","PUT","DELETE","HEAD"];
            let paths = ["/api/v1/users","/index.html","/assets/main.js","/api/data"];
            let m = methods[rng.gen_range(0..methods.len())];
            let p = paths[rng.gen_range(0..paths.len())];
            let sp: u16 = rng.gen_range(1024..=65535);
            (src, dst, Some(sp), Some(80u16), format!("{} {} HTTP/1.1", m, p))
        }
        "HTTPS" | "TLS" => {
            let src = rand_ip(LOCAL_IPS, &mut rng).to_string();
            let dst = rand_ip(REMOTE_IPS, &mut rng).to_string();
            let hs = ["Client Hello","Server Hello","Certificate","Finished","Application Data"];
            let sp: u16 = rng.gen_range(1024..=65535);
            (src, dst, Some(sp), Some(443u16),
             format!("TLS {}", hs[rng.gen_range(0..hs.len())]))
        }
        _ => { // TCP, UDP
            let src = rand_ip(LOCAL_IPS, &mut rng).to_string();
            let dst_pool = if rng.gen_bool(0.4) { LOCAL_IPS } else { REMOTE_IPS };
            let dst = rand_ip(dst_pool, &mut rng).to_string();
            let sp: u16 = rng.gen_range(1024..=65535);
            let dp_opts = [22u16, 80, 443, 3306, 5432, 6379, 8080, 9200];
            let dp = dp_opts[rng.gen_range(0..dp_opts.len())];
            let info = if proto == "TCP" {
                let flags = ["SYN","ACK","PSH, ACK","FIN, ACK","RST, ACK","SYN, ACK"];
                let f = flags[rng.gen_range(0..flags.len())];
                let seq: u32 = rng.gen();
                let ack: u32 = rng.gen();
                let win: u16 = rng.gen_range(1024..=65535);
                format!("{} → {} [{}] Seq={} Ack={} Win={} Len={}", sp, dp, f, seq, ack, win, length.saturating_sub(54))
            } else {
                format!("{} → {} Len={}", sp, dp, length.saturating_sub(42))
            };
            (src, dst, Some(sp), Some(dp), info)
        }
    };

    Packet { no: counter + 1, timestamp: ts, src, dst, protocol: proto.to_string(), length, info, src_port, dst_port, bytes }
}

// Protocol tree for a packet
#[derive(Debug, Clone)]
pub struct TreeField {
    pub key: String,
    pub val: String,
    pub color: FieldColor,
}

#[derive(Debug, Clone)]
pub enum FieldColor { Default, Cyan, Green, Yellow, Red, Magenta, Orange }

#[derive(Debug, Clone)]
pub struct TreeSection {
    pub title: String,
    pub fields: Vec<TreeField>,
    pub expanded: bool,
}

impl Packet {
    pub fn build_tree(&self) -> Vec<TreeSection> {
        let mut rng = rand::thread_rng();
        let mut sections = Vec::new();

        // Frame
        sections.push(TreeSection {
            title: format!("Frame {}: {} bytes on wire", self.no, self.length),
            expanded: true,
            fields: vec![
                tf("Frame Number:", &self.no.to_string(), FieldColor::Cyan),
                tf("Frame Length:", &format!("{} bytes", self.length), FieldColor::Yellow),
                tf("Capture Length:", &format!("{} bytes", self.length), FieldColor::Default),
                tf("Protocols in frame:", &format!("eth:ip:{}", self.protocol.to_lowercase()), FieldColor::Green),
            ],
        });

        // Ethernet
        let src_mac = rand_mac(&mut rng);
        let dst_mac = rand_mac(&mut rng);
        let eth_type = if self.protocol == "ARP" { "ARP (0x0806)" } else { "IPv4 (0x0800)" };
        sections.push(TreeSection {
            title: format!("Ethernet II, Src: {}, Dst: {}", src_mac, dst_mac),
            expanded: true,
            fields: vec![
                tf("Destination:", &dst_mac, FieldColor::Cyan),
                tf("Source:",      &src_mac, FieldColor::Cyan),
                tf("Type:",        eth_type, FieldColor::Yellow),
            ],
        });

        if self.protocol == "ARP" {
            sections.push(TreeSection {
                title: "Address Resolution Protocol".into(),
                expanded: true,
                fields: vec![
                    tf("Hardware type:", "Ethernet (1)", FieldColor::Default),
                    tf("Protocol type:", "IPv4 (0x0800)", FieldColor::Default),
                    tf("Opcode:", "request (1)", FieldColor::Yellow),
                    tf("Sender IP:", &self.src, FieldColor::Green),
                    tf("Target IP:", &self.dst, FieldColor::Red),
                ],
            });
            return sections;
        }

        // IP
        let ttl: u8 = rng.gen_range(48..=128);
        let id: u16 = rng.gen();
        let proto_num = match self.protocol.as_str() {
            "TCP"|"HTTP"|"HTTPS"|"TLS" => "6 (TCP)",
            "UDP"|"DNS"|"DHCP"         => "17 (UDP)",
            "ICMP"                     => "1 (ICMP)",
            _                          => "6 (TCP)",
        };
        sections.push(TreeSection {
            title: format!("Internet Protocol Version 4, Src: {}, Dst: {}", self.src, self.dst),
            expanded: true,
            fields: vec![
                tf("Version:", "4", FieldColor::Default),
                tf("Header Length:", "20 bytes (5)", FieldColor::Default),
                tf("Total Length:", &self.length.to_string(), FieldColor::Yellow),
                tf("Identification:", &format!("0x{:04x} ({})", id, id), FieldColor::Default),
                tf("TTL:", &ttl.to_string(), if ttl < 64 { FieldColor::Red } else { FieldColor::Green }),
                tf("Protocol:", proto_num, FieldColor::Cyan),
                tf("Src Address:", &self.src, FieldColor::Green),
                tf("Dst Address:", &self.dst, FieldColor::Orange),
            ],
        });

        // Transport layer
        match self.protocol.as_str() {
            "ICMP" => {
                let id: u16 = rng.gen();
                sections.push(TreeSection {
                    title: "Internet Control Message Protocol".into(),
                    expanded: true,
                    fields: vec![
                        tf("Type:", "8 (Echo Request)", FieldColor::Yellow),
                        tf("Code:", "0", FieldColor::Default),
                        tf("Identifier:", &format!("0x{:04x}", id), FieldColor::Cyan),
                        tf("Sequence Number:", &rng.gen_range(0..=100u16).to_string(), FieldColor::Default),
                    ],
                });
            }
            "DNS" => {
                let sp = self.src_port.unwrap_or(12345);
                let tid: u16 = rng.gen();
                let name = DNS_NAMES[rng.gen_range(0..DNS_NAMES.len())];
                let qry = rng.gen_bool(0.5);
                sections.push(TreeSection {
                    title: format!("User Datagram Protocol, Src Port: {}, Dst Port: 53", sp),
                    expanded: false,
                    fields: vec![
                        tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
                        tf("Destination Port:", "53", FieldColor::Yellow),
                        tf("Length:", &(self.length as usize).saturating_sub(20).to_string(), FieldColor::Default),
                    ],
                });
                let mut dns_fields = vec![
                    tf("Transaction ID:", &format!("0x{:04x}", tid), FieldColor::Cyan),
                    tf("Flags:", if qry { "0x0100 Standard query" } else { "0x8180 Standard response" }, FieldColor::Yellow),
                    tf("Questions:", "1", FieldColor::Default),
                    tf("Query Name:", name, FieldColor::Green),
                    tf("Query Type:", "A (Host Address)", FieldColor::Cyan),
                ];
                if !qry {
                    dns_fields.push(tf("Answer Addr:", &format!("{}.{}.{}.{}", rng.gen_range(1..254u8), rng.gen::<u8>(), rng.gen::<u8>(), rng.gen_range(1..254u8)), FieldColor::Orange));
                }
                sections.push(TreeSection { title: format!("Domain Name System ({})", if qry {"query"} else {"response"}), expanded: true, fields: dns_fields });
            }
            "TCP" | "HTTP" | "HTTPS" | "TLS" => {
                let sp = self.src_port.unwrap_or(12345);
                let dp = self.dst_port.unwrap_or(80);
                let seq: u32 = rng.gen();
                let ack: u32 = rng.gen();
                let win: u16 = rng.gen_range(1024..=65535);
                let flags = ["ACK","PSH, ACK","SYN","FIN, ACK","RST, ACK"][rng.gen_range(0..5)];
                let chk: u16 = rng.gen();
                sections.push(TreeSection {
                    title: format!("Transmission Control Protocol, Src Port: {}, Dst Port: {}", sp, dp),
                    expanded: true,
                    fields: vec![
                        tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
                        tf("Destination Port:", &dp.to_string(), FieldColor::Yellow),
                        tf("Sequence Number:", &seq.to_string(), FieldColor::Default),
                        tf("Acknowledgment Number:", &ack.to_string(), FieldColor::Default),
                        tf("Flags:", &format!("0x{:03x} ({})", rng.gen_range(0..=0xfffu16), flags), FieldColor::Magenta),
                        tf("Window:", &win.to_string(), FieldColor::Default),
                        tf("Checksum:", &format!("0x{:04x} [unverified]", chk), FieldColor::Default),
                    ],
                });
                if self.protocol == "HTTP" {
                    let methods = ["GET","POST","PUT","DELETE"];
                    let paths = ["/api/users","/index.html","/static/app.js"];
                    sections.push(TreeSection {
                        title: "Hypertext Transfer Protocol".into(),
                        expanded: true,
                        fields: vec![
                            tf("Request Method:", methods[rng.gen_range(0..methods.len())], FieldColor::Green),
                            tf("Request URI:", paths[rng.gen_range(0..paths.len())], FieldColor::Cyan),
                            tf("Request Version:", "HTTP/1.1", FieldColor::Default),
                            tf("Host:", "api.example.com", FieldColor::Yellow),
                            tf("Content-Length:", &rng.gen_range(0..=4096u16).to_string(), FieldColor::Default),
                        ],
                    });
                }
                if self.protocol == "TLS" || self.protocol == "HTTPS" {
                    let hs_types = ["Client Hello (1)","Server Hello (2)","Certificate (11)","Finished (20)","Application Data (23)"];
                    let ciphers = ["TLS_AES_128_GCM_SHA256","TLS_CHACHA20_POLY1305_SHA256","TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"];
                    sections.push(TreeSection {
                        title: "Transport Layer Security".into(),
                        expanded: true,
                        fields: vec![
                            tf("Content Type:", "Application Data (23)", FieldColor::Yellow),
                            tf("Version:", "TLS 1.3 (0x0304)", FieldColor::Cyan),
                            tf("Handshake Type:", hs_types[rng.gen_range(0..hs_types.len())], FieldColor::Green),
                            tf("Cipher Suite:", ciphers[rng.gen_range(0..ciphers.len())], FieldColor::Magenta),
                        ],
                    });
                }
            }
            "UDP" | "DHCP" => {
                let sp = self.src_port.unwrap_or(12345);
                let dp = self.dst_port.unwrap_or(53);
                sections.push(TreeSection {
                    title: format!("User Datagram Protocol, Src Port: {}, Dst Port: {}", sp, dp),
                    expanded: true,
                    fields: vec![
                        tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
                        tf("Destination Port:", &dp.to_string(), FieldColor::Yellow),
                        tf("Length:", &(self.length as usize).saturating_sub(20).to_string(), FieldColor::Default),
                    ],
                });
            }
            _ => {}
        }
        sections
    }
}

fn tf(key: &str, val: &str, color: FieldColor) -> TreeField {
    TreeField { key: key.to_string(), val: val.to_string(), color }
}
