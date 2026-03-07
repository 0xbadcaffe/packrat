/// Build a protocol dissector tree for a packet (for the UI detail pane).
use rand::Rng;
use crate::net::packet::{FieldColor, Packet, TreeField, TreeSection, make_field};
use crate::net::generator::rand_mac;

const DNS_NAMES: &[&str] = &[
    "google.com", "github.com", "api.stripe.com",
    "fonts.googleapis.com", "cdn.cloudflare.com",
];

pub fn build_tree(pkt: &Packet) -> Vec<TreeSection> {
    let mut rng = rand::thread_rng();
    let mut sections = Vec::new();

    // Frame section
    sections.push(TreeSection {
        title: format!("Frame {}: {} bytes on wire", pkt.no, pkt.length),
        expanded: true,
        fields: vec![
            tf("Frame Number:", &pkt.no.to_string(), FieldColor::Cyan),
            tf("Frame Length:", &format!("{} bytes", pkt.length), FieldColor::Yellow),
            tf("Capture Length:", &format!("{} bytes", pkt.length), FieldColor::Default),
            tf("Protocols:", &format!("eth:{}:{}", if pkt.protocol == "ARP" {"arp"} else {"ip"}, pkt.protocol.to_lowercase()), FieldColor::Green),
        ],
    });

    // VLAN tag (if present)
    if let Some(vid) = pkt.vlan_id {
        sections.push(TreeSection {
            title: format!("802.1Q Virtual LAN, PRI: 0, DEI: 0, ID: {}", vid),
            expanded: true,
            fields: vec![
                tf("VLAN ID:", &vid.to_string(), FieldColor::Cyan),
                tf("Priority:", "0 (Best Effort)", FieldColor::Default),
                tf("DEI:", "0", FieldColor::Default),
            ],
        });
    }

    // Ethernet
    let src_mac = rand_mac(&mut rng);
    let dst_mac = rand_mac(&mut rng);
    let eth_type = if pkt.protocol == "ARP" { "ARP (0x0806)" } else { "IPv4 (0x0800)" };
    sections.push(TreeSection {
        title: format!("Ethernet II, Src: {}, Dst: {}", src_mac, dst_mac),
        expanded: true,
        fields: vec![
            tf("Destination:", &dst_mac, FieldColor::Cyan),
            tf("Source:", &src_mac, FieldColor::Cyan),
            tf("Type:", eth_type, FieldColor::Yellow),
        ],
    });

    if pkt.protocol == "ARP" {
        sections.push(TreeSection {
            title: "Address Resolution Protocol".into(),
            expanded: true,
            fields: vec![
                tf("Hardware type:", "Ethernet (1)", FieldColor::Default),
                tf("Protocol type:", "IPv4 (0x0800)", FieldColor::Default),
                tf("Opcode:", "request (1)", FieldColor::Yellow),
                tf("Sender IP:", &pkt.src, FieldColor::Green),
                tf("Target IP:", &pkt.dst, FieldColor::Red),
            ],
        });
        return sections;
    }

    // IP layer
    let ttl: u8 = rng.gen_range(48..=128);
    let id: u16 = rng.gen();
    let proto_num = match pkt.protocol.as_str() {
        "TCP" | "HTTP" | "HTTPS" | "TLS" | "SSH" | "SMTP" | "MySQL" | "Redis" => "6 (TCP)",
        "UDP" | "DNS" | "mDNS" | "DHCP" | "NTP" | "QUIC" | "SNMP"            => "17 (UDP)",
        "ICMP"                                                                  => "1 (ICMP)",
        "ICMPv6"                                                                => "58 (ICMPv6)",
        _                                                                       => "6 (TCP)",
    };
    sections.push(TreeSection {
        title: format!("Internet Protocol Version 4, Src: {}, Dst: {}", pkt.src, pkt.dst),
        expanded: true,
        fields: vec![
            tf("Version:", "4", FieldColor::Default),
            tf("Header Length:", "20 bytes (5)", FieldColor::Default),
            tf("Total Length:", &pkt.length.to_string(), FieldColor::Yellow),
            tf("Identification:", &format!("0x{:04x} ({})", id, id), FieldColor::Default),
            tf("TTL:", &ttl.to_string(), if ttl < 64 { FieldColor::Red } else { FieldColor::Green }),
            tf("Protocol:", proto_num, FieldColor::Cyan),
            tf("Src Address:", &pkt.src, FieldColor::Green),
            tf("Dst Address:", &pkt.dst, FieldColor::Orange),
        ],
    });

    // Transport layer
    match pkt.protocol.as_str() {
        "ICMP" | "ICMPv6" => {
            sections.push(TreeSection {
                title: "Internet Control Message Protocol".into(),
                expanded: true,
                fields: vec![
                    tf("Type:", "8 (Echo Request)", FieldColor::Yellow),
                    tf("Code:", "0", FieldColor::Default),
                    tf("Identifier:", &format!("0x{:04x}", rng.gen::<u16>()), FieldColor::Cyan),
                    tf("Sequence Number:", &rng.gen_range(0..=100u16).to_string(), FieldColor::Default),
                ],
            });
        }
        "DNS" | "mDNS" => {
            let sp = pkt.src_port.unwrap_or(12345);
            let tid: u16 = rng.gen();
            let name = DNS_NAMES[rng.gen_range(0..DNS_NAMES.len())];
            let is_query = rng.gen_bool(0.5);
            sections.push(TreeSection {
                title: format!("User Datagram Protocol, Src Port: {}, Dst Port: 53", sp),
                expanded: false,
                fields: vec![
                    tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
                    tf("Destination Port:", "53", FieldColor::Yellow),
                ],
            });
            let mut dns_fields = vec![
                tf("Transaction ID:", &format!("0x{:04x}", tid), FieldColor::Cyan),
                tf("Flags:", if is_query { "0x0100 Standard query" } else { "0x8180 Response" }, FieldColor::Yellow),
                tf("Questions:", "1", FieldColor::Default),
                tf("Query Name:", name, FieldColor::Green),
                tf("Query Type:", "A", FieldColor::Cyan),
            ];
            if !is_query {
                dns_fields.push(tf("Answer Addr:",
                    &format!("{}.{}.{}.{}", rng.gen_range(1..254u8), rng.gen::<u8>(), rng.gen::<u8>(), rng.gen_range(1..254u8)),
                    FieldColor::Orange));
            }
            sections.push(TreeSection {
                title: format!("Domain Name System ({})", if is_query { "query" } else { "response" }),
                expanded: true,
                fields: dns_fields,
            });
        }
        "DHCP" => {
            let sp = pkt.src_port.unwrap_or(68);
            let dp = pkt.dst_port.unwrap_or(67);
            sections.push(TreeSection {
                title: format!("User Datagram Protocol, Src Port: {}, Dst Port: {}", sp, dp),
                expanded: true,
                fields: vec![
                    tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
                    tf("Destination Port:", &dp.to_string(), FieldColor::Yellow),
                ],
            });
            sections.push(TreeSection {
                title: "Dynamic Host Configuration Protocol".into(),
                expanded: true,
                fields: vec![
                    tf("Message type:", "DHCP Discover (1)", FieldColor::Yellow),
                    tf("Client IP:", "0.0.0.0", FieldColor::Default),
                    tf("Your IP:", "0.0.0.0", FieldColor::Default),
                    tf("Server IP:", "0.0.0.0", FieldColor::Default),
                ],
            });
        }
        "NTP" => {
            sections.push(TreeSection {
                title: "Network Time Protocol".into(),
                expanded: true,
                fields: vec![
                    tf("Leap Indicator:", "0 (no warning)", FieldColor::Default),
                    tf("Version:", "4", FieldColor::Cyan),
                    tf("Mode:", "3 (client)", FieldColor::Yellow),
                    tf("Stratum:", "0 (unspecified)", FieldColor::Default),
                ],
            });
        }
        "QUIC" => {
            sections.push(TreeSection {
                title: "QUIC (RFC 9000)".into(),
                expanded: true,
                fields: vec![
                    tf("Version:", "1 (0x00000001)", FieldColor::Cyan),
                    tf("Packet Type:", "Initial", FieldColor::Yellow),
                    tf("Destination CID:", &format!("0x{:016x}", rng.gen::<u64>()), FieldColor::Green),
                ],
            });
        }
        proto if matches!(proto, "TCP" | "HTTP" | "HTTPS" | "TLS" | "SSH" | "MySQL" | "Redis" | "PostgreSQL") => {
            let sp = pkt.src_port.unwrap_or(12345);
            let dp = pkt.dst_port.unwrap_or(80);
            let seq: u32 = rng.gen();
            let ack: u32 = rng.gen();
            let win: u16 = rng.gen_range(1024..=65535);
            let flags = ["ACK", "PSH, ACK", "SYN", "FIN, ACK", "RST, ACK"][rng.gen_range(0..5)];
            sections.push(TreeSection {
                title: format!("Transmission Control Protocol, Src Port: {}, Dst Port: {}", sp, dp),
                expanded: true,
                fields: vec![
                    tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
                    tf("Destination Port:", &dp.to_string(), FieldColor::Yellow),
                    tf("Sequence Number:", &seq.to_string(), FieldColor::Default),
                    tf("Acknowledgment:", &ack.to_string(), FieldColor::Default),
                    tf("Flags:", &format!("0x{:03x} ({})", rng.gen_range(0..=0xfffu16), flags), FieldColor::Magenta),
                    tf("Window Size:", &win.to_string(), FieldColor::Default),
                ],
            });
            if proto == "HTTP" {
                let methods = ["GET", "POST", "PUT", "DELETE"];
                let paths = ["/api/users", "/index.html", "/static/app.js"];
                sections.push(TreeSection {
                    title: "Hypertext Transfer Protocol".into(),
                    expanded: true,
                    fields: vec![
                        tf("Method:", methods[rng.gen_range(0..methods.len())], FieldColor::Green),
                        tf("URI:", paths[rng.gen_range(0..paths.len())], FieldColor::Cyan),
                        tf("Version:", "HTTP/1.1", FieldColor::Default),
                        tf("Host:", "api.example.com", FieldColor::Yellow),
                    ],
                });
            }
            if matches!(proto, "TLS" | "HTTPS") {
                let hs = ["Client Hello (1)", "Server Hello (2)", "Certificate (11)", "Application Data (23)"];
                let ciphers = ["TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"];
                sections.push(TreeSection {
                    title: "Transport Layer Security".into(),
                    expanded: true,
                    fields: vec![
                        tf("Version:", "TLS 1.3 (0x0304)", FieldColor::Cyan),
                        tf("Handshake Type:", hs[rng.gen_range(0..hs.len())], FieldColor::Yellow),
                        tf("Cipher Suite:", ciphers[rng.gen_range(0..ciphers.len())], FieldColor::Magenta),
                    ],
                });
            }
        }
        proto if matches!(proto, "UDP" | "SNMP") => {
            let sp = pkt.src_port.unwrap_or(12345);
            let dp = pkt.dst_port.unwrap_or(53);
            sections.push(TreeSection {
                title: format!("User Datagram Protocol, Src Port: {}, Dst Port: {}", sp, dp),
                expanded: true,
                fields: vec![
                    tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
                    tf("Destination Port:", &dp.to_string(), FieldColor::Yellow),
                    tf("Length:", &(pkt.length as usize).saturating_sub(20).to_string(), FieldColor::Default),
                ],
            });
        }
        _ => {}
    }

    sections
}

fn tf(key: &str, val: &str, color: FieldColor) -> TreeField {
    make_field(key, val, color)
}
