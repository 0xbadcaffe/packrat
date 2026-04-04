/// Build a protocol dissector tree for a packet (for the UI detail pane).
use rand::Rng;
use crate::net::packet::{FieldColor, Packet, TreeField, TreeSection, make_field};
use crate::sim::generator::rand_mac;

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
    let id: u16 = rng.r#gen();
    let proto_num = match pkt.protocol.as_str() {
        "TCP" | "HTTP" | "HTTPS" | "TLS" | "SSH" | "SMTP" | "MySQL" | "Redis"
        | "PostgreSQL" | "IMAP" | "IMAPS" | "POP3" | "MongoDB" | "Elasticsearch"
        | "Modbus" | "MQTT" | "MQTT-TLS" | "OPC-UA" | "DNP3" | "S7comm"
        | "EtherNet/IP" | "IEC-104" | "SIP" | "SIPS" | "BGP" | "FTP"
        | "Telnet" | "LDAP" | "DoIP" | "SOME/IP"                              => "6 (TCP)",
        "UDP" | "DNS" | "mDNS" | "DHCP" | "NTP" | "QUIC" | "SNMP"
        | "CoAP" | "CoAP-DTLS" | "BACnet" | "PTP" | "DHCPv6" | "VXLAN"
        | "WireGuard" | "GTP" | "Radius" | "WoL" | "SNMP-trap" | "Syslog"   => "17 (UDP)",
        "ICMP"   => "1 (ICMP)",
        "IGMP"   => "2 (IGMP)",
        "GRE"    => "47 (GRE)",
        "ESP"    => "50 (ESP)",
        "AH"     => "51 (AH)",
        "ICMPv6" => "58 (ICMPv6)",
        "VRRP"   => "112 (VRRP)",
        _        => "6 (TCP)",
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
                    tf("Identifier:", &format!("0x{:04x}", rng.r#gen::<u16>()), FieldColor::Cyan),
                    tf("Sequence Number:", &rng.gen_range(0..=100u16).to_string(), FieldColor::Default),
                ],
            });
        }
        "DNS" | "mDNS" => {
            let sp = pkt.src_port.unwrap_or(12345);
            let tid: u16 = rng.r#gen();
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
                    &format!("{}.{}.{}.{}", rng.gen_range(1..254u8), rng.r#gen::<u8>(), rng.r#gen::<u8>(), rng.gen_range(1..254u8)),
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
            let sp = pkt.src_port.unwrap_or(rng.gen_range(1024u16..=65535));
            sections.push(TreeSection {
                title: format!("User Datagram Protocol, Src Port: {}, Dst Port: 123", sp),
                expanded: false,
                fields: vec![
                    tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
                    tf("Destination Port:", "123", FieldColor::Yellow),
                    tf("Length:", "48", FieldColor::Default),
                ],
            });
            let strata = ["1 (primary reference)", "2 (secondary reference)", "3 (tertiary reference)", "4"];
            let stratum_idx = rng.gen_range(0..strata.len());
            let stratum = strata[stratum_idx];
            let modes = ["3 (client)", "4 (server)", "5 (broadcast)"];
            let mode = modes[rng.gen_range(0..modes.len())];
            let poll: u8 = rng.gen_range(6..=10);
            let precision: i8 = -rng.gen_range(10i8..=20);
            let ref_ids = ["GPS\0", "PPS\0", "ACTS", "USNO"];
            let ref_id = if stratum_idx == 0 {
                ref_ids[rng.gen_range(0..ref_ids.len())].trim_end_matches('\0').to_string()
            } else {
                format!("{}.{}.{}.{}", rng.gen_range(1u8..=254), rng.r#gen::<u8>(), rng.r#gen::<u8>(), rng.gen_range(1u8..=254))
            };
            let base_ts: u64 = 3_915_000_000 + rng.gen_range(0u64..=86400);
            sections.push(TreeSection {
                title: "Network Time Protocol (v4)".into(),
                expanded: true,
                fields: vec![
                    tf("Leap Indicator:", "0 (no warning)", FieldColor::Default),
                    tf("Version:", "4", FieldColor::Cyan),
                    tf("Mode:", mode, FieldColor::Yellow),
                    tf("Stratum:", stratum, FieldColor::Default),
                    tf("Poll Interval:", &format!("{} ({} sec)", poll, 1u32 << poll), FieldColor::Default),
                    tf("Precision:", &format!("{}", precision), FieldColor::Default),
                    tf("Root Delay:", &format!("0.{:04} sec", rng.gen_range(0u32..=5000)), FieldColor::Default),
                    tf("Root Dispersion:", &format!("0.{:04} sec", rng.gen_range(0u32..=5000)), FieldColor::Default),
                    tf("Reference ID:", &ref_id, FieldColor::Cyan),
                    tf("Reference Timestamp:", &format!("{}.{:06}", base_ts, rng.gen_range(0u32..=999999)), FieldColor::Default),
                    tf("Originate Timestamp:", &format!("{}.{:06}", base_ts + 1, rng.gen_range(0u32..=999999)), FieldColor::Default),
                    tf("Receive Timestamp:", &format!("{}.{:06}", base_ts + 1, rng.gen_range(0u32..=999999)), FieldColor::Default),
                    tf("Transmit Timestamp:", &format!("{}.{:06}", base_ts + 1, rng.gen_range(0u32..=999999)), FieldColor::Green),
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
                    tf("Destination CID:", &format!("0x{:016x}", rng.r#gen::<u64>()), FieldColor::Green),
                ],
            });
        }
        proto if matches!(proto, "TCP" | "HTTP" | "HTTPS" | "TLS" | "SSH" | "MySQL" | "Redis" | "PostgreSQL") => {
            let sp = pkt.src_port.unwrap_or(12345);
            let dp = pkt.dst_port.unwrap_or(80);
            let seq: u32 = rng.r#gen();
            let ack: u32 = rng.r#gen();
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

        "Modbus" => {
            let sp = pkt.src_port.unwrap_or(1024);
            sections.push(TreeSection {
                title: format!("Transmission Control Protocol, Src Port: {}, Dst Port: 502", sp),
                expanded: false,
                fields: vec![
                    tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
                    tf("Destination Port:", "502", FieldColor::Yellow),
                ],
            });
            let tid: u16 = rng.r#gen();
            let unit_id: u8 = rng.gen_range(1..=247);
            let fn_codes = [
                (1u8, "Read Coils"), (2, "Read Discrete Inputs"),
                (3, "Read Holding Registers"), (4, "Read Input Registers"),
                (5, "Write Single Coil"), (6, "Write Single Register"),
                (15, "Write Multiple Coils"), (16, "Write Multiple Registers"),
            ];
            let (fc, fc_name) = fn_codes[rng.gen_range(0..fn_codes.len())];
            let addr: u16 = rng.gen_range(0..=1000);
            let qty: u16 = rng.gen_range(1..=125);
            sections.push(TreeSection {
                title: "Modbus/TCP".into(),
                expanded: true,
                fields: vec![
                    tf("Transaction ID:", &format!("0x{:04x}", tid), FieldColor::Cyan),
                    tf("Protocol ID:", "0x0000 (Modbus)", FieldColor::Default),
                    tf("Length:", &(6u16).to_string(), FieldColor::Default),
                    tf("Unit ID:", &unit_id.to_string(), FieldColor::Yellow),
                    tf("Function Code:", &format!("{} ({})", fc, fc_name), FieldColor::Green),
                    tf("Starting Address:", &format!("0x{:04x} ({})", addr, addr), FieldColor::Default),
                    tf("Quantity:", &qty.to_string(), FieldColor::Default),
                ],
            });
        }

        "MQTT" | "MQTT-TLS" => {
            let sp = pkt.src_port.unwrap_or(1024);
            let dp = if pkt.protocol == "MQTT-TLS" { 8883u16 } else { 1883 };
            sections.push(TreeSection {
                title: format!("Transmission Control Protocol, Src Port: {}, Dst Port: {}", sp, dp),
                expanded: false,
                fields: vec![
                    tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
                    tf("Destination Port:", &dp.to_string(), FieldColor::Yellow),
                ],
            });
            let topics = ["sensors/temperature", "sensors/pressure", "actuators/valve", "plant/line1/status"];
            let topic = topics[rng.gen_range(0..topics.len())];
            let msg_types = [
                (1u8, "CONNECT"), (2, "CONNACK"), (3, "PUBLISH"),
                (4, "PUBACK"), (8, "SUBSCRIBE"), (9, "SUBACK"), (14, "DISCONNECT"),
            ];
            let (mt, mt_name) = msg_types[rng.gen_range(0..msg_types.len())];
            let mut fields = vec![
                tf("Message Type:", &format!("{} ({})", mt, mt_name), FieldColor::Yellow),
                tf("QoS:", "0 (At most once)", FieldColor::Default),
                tf("Retain:", "0", FieldColor::Default),
            ];
            if mt == 3 {
                fields.push(tf("Topic:", topic, FieldColor::Cyan));
                fields.push(tf("Payload Length:", &rng.gen_range(4u16..=64).to_string(), FieldColor::Default));
            } else if mt == 1 {
                let client = ["sensor_01", "plc_gateway", "hmi_client", "mqtt_logger"];
                fields.push(tf("Client ID:", client[rng.gen_range(0..client.len())], FieldColor::Cyan));
                fields.push(tf("Keep Alive:", "60", FieldColor::Default));
                fields.push(tf("Clean Session:", "1", FieldColor::Default));
            }
            sections.push(TreeSection {
                title: format!("MQ Telemetry Transport Protocol ({} v3.1.1)", mt_name),
                expanded: true,
                fields,
            });
        }

        "OPC-UA" => {
            let sp = pkt.src_port.unwrap_or(1024);
            sections.push(TreeSection {
                title: format!("Transmission Control Protocol, Src Port: {}, Dst Port: 4840", sp),
                expanded: false,
                fields: vec![
                    tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
                    tf("Destination Port:", "4840", FieldColor::Yellow),
                ],
            });
            let services = [
                (631u32, "ReadRequest"), (634, "ReadResponse"),
                (673, "WriteRequest"), (676, "WriteResponse"),
                (527, "CreateSessionRequest"), (461, "Browse"),
                (839, "PublishRequest"), (842, "PublishResponse"),
            ];
            let (svc_id, svc_name) = services[rng.gen_range(0..services.len())];
            let ns: u8 = rng.gen_range(1..=3);
            let node: u16 = rng.gen_range(1000..=9999);
            let req_id: u32 = rng.gen_range(1..=9999);
            sections.push(TreeSection {
                title: "OPC UA Binary".into(),
                expanded: true,
                fields: vec![
                    tf("Message Type:", "MSG", FieldColor::Cyan),
                    tf("Chunk Type:", "F (Final)", FieldColor::Default),
                    tf("Message Size:", &pkt.length.to_string(), FieldColor::Default),
                    tf("Security Channel ID:", &format!("0x{:08x}", rng.r#gen::<u32>()), FieldColor::Default),
                    tf("Request ID:", &req_id.to_string(), FieldColor::Yellow),
                    tf("Service:", &format!("{} (id={})", svc_name, svc_id), FieldColor::Green),
                    tf("Node ID:", &format!("ns={};i={}", ns, node), FieldColor::Cyan),
                ],
            });
        }

        "DNP3" => {
            let sp = pkt.src_port.unwrap_or(1024);
            sections.push(TreeSection {
                title: format!("Transmission Control Protocol, Src Port: {}, Dst Port: 20000", sp),
                expanded: false,
                fields: vec![
                    tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
                    tf("Destination Port:", "20000", FieldColor::Yellow),
                ],
            });
            let fn_codes = [
                (1u8, "Read"), (2, "Write"), (3, "Select"), (4, "Operate"),
                (5, "Direct Operate"), (129, "Response"), (130, "Unsolicited Response"),
            ];
            let (fc, fc_name) = fn_codes[rng.gen_range(0..fn_codes.len())];
            let dst_addr: u16 = rng.gen_range(1..=10);
            let src_addr: u16 = rng.gen_range(1..=5);
            sections.push(TreeSection {
                title: "DNP3 Application Layer".into(),
                expanded: true,
                fields: vec![
                    tf("Start:", "0x0564", FieldColor::Cyan),
                    tf("Length:", &pkt.length.to_string(), FieldColor::Default),
                    tf("Control:", "0x44", FieldColor::Default),
                    tf("Destination:", &dst_addr.to_string(), FieldColor::Yellow),
                    tf("Source:", &src_addr.to_string(), FieldColor::Green),
                    tf("Function Code:", &format!("{} ({})", fc, fc_name), FieldColor::Green),
                    tf("IIN:", "0x0000", FieldColor::Default),
                ],
            });
        }

        "CoAP" | "CoAP-DTLS" => {
            let sp = pkt.src_port.unwrap_or(1024);
            let dp = if pkt.protocol == "CoAP-DTLS" { 5684u16 } else { 5683 };
            sections.push(TreeSection {
                title: format!("User Datagram Protocol, Src Port: {}, Dst Port: {}", sp, dp),
                expanded: false,
                fields: vec![
                    tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
                    tf("Destination Port:", &dp.to_string(), FieldColor::Yellow),
                ],
            });
            let coap_types = [(0u8, "CON"), (1, "NON"), (2, "ACK"), (3, "RST")];
            let (ct, ct_name) = coap_types[rng.gen_range(0..coap_types.len())];
            let codes = [(1u8, "GET"), (2, "POST"), (3, "PUT"), (4, "DELETE")];
            let (code, code_name) = codes[rng.gen_range(0..codes.len())];
            let mid: u16 = rng.r#gen();
            let resources = ["/sensors/temp", "/sensors/pressure", "/actuators/relay", "/status"];
            let res = resources[rng.gen_range(0..resources.len())];
            sections.push(TreeSection {
                title: "Constrained Application Protocol".into(),
                expanded: true,
                fields: vec![
                    tf("Version:", "1", FieldColor::Default),
                    tf("Type:", &format!("{} ({})", ct, ct_name), FieldColor::Yellow),
                    tf("Token Length:", "4", FieldColor::Default),
                    tf("Code:", &format!("0.0{} {}", code, code_name), FieldColor::Green),
                    tf("Message ID:", &format!("0x{:04x}", mid), FieldColor::Cyan),
                    tf("Token:", &format!("0x{:08x}", rng.r#gen::<u32>()), FieldColor::Default),
                    tf("Uri-Path:", res, FieldColor::Cyan),
                ],
            });
        }

        "BACnet" => {
            let sp = pkt.src_port.unwrap_or(1024);
            sections.push(TreeSection {
                title: format!("User Datagram Protocol, Src Port: {}, Dst Port: 47808", sp),
                expanded: false,
                fields: vec![
                    tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
                    tf("Destination Port:", "47808 (0xBAC0)", FieldColor::Yellow),
                ],
            });
            let bvlc_fns = [(0x0au8, "Original-Unicast-NPDU"), (0x0b, "Original-Broadcast-NPDU"), (0x04, "Forwarded-NPDU")];
            let (bvlc_fn, bvlc_name) = bvlc_fns[rng.gen_range(0..bvlc_fns.len())];
            let services = ["ReadProperty-Request", "WriteProperty-Request", "Who-Is", "I-Am", "SubscribeCOV-Request"];
            let svc = services[rng.gen_range(0..services.len())];
            let objs = ["Analog Input 1", "Analog Output 1", "Binary Input 2", "Binary Value 5", "Analog Value 10"];
            let obj = objs[rng.gen_range(0..objs.len())];
            let props = ["present-value", "object-name", "units", "description", "status-flags"];
            let prop = props[rng.gen_range(0..props.len())];
            sections.push(TreeSection {
                title: "BACnet/IP".into(),
                expanded: true,
                fields: vec![
                    tf("BVLC Function:", &format!("0x{:02x} ({})", bvlc_fn, bvlc_name), FieldColor::Cyan),
                    tf("BVLC Length:", &pkt.length.to_string(), FieldColor::Default),
                    tf("NPDU Version:", "1", FieldColor::Default),
                    tf("Service:", svc, FieldColor::Green),
                    tf("Object ID:", obj, FieldColor::Yellow),
                    tf("Property:", prop, FieldColor::Cyan),
                ],
            });
        }

        "S7comm" => {
            let sp = pkt.src_port.unwrap_or(1024);
            sections.push(TreeSection {
                title: format!("Transmission Control Protocol, Src Port: {}, Dst Port: 102", sp),
                expanded: false,
                fields: vec![
                    tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
                    tf("Destination Port:", "102 (ISO-TSAP)", FieldColor::Yellow),
                ],
            });
            let fns = [
                (0x04u8, "Read Var"), (0x05, "Write Var"),
                (0x1a, "Request Download"), (0x1b, "Download Block"),
                (0x29, "PLC Stop"), (0x28, "PLC Start"),
            ];
            let (fc, fc_name) = fns[rng.gen_range(0..fns.len())];
            let db: u16 = rng.gen_range(1..=100);
            let offset: u16 = rng.gen_range(0..=512);
            let pdu_ref: u16 = rng.r#gen();
            sections.push(TreeSection {
                title: "S7 Communication".into(),
                expanded: true,
                fields: vec![
                    tf("Header:", "0x32 (S7comm)", FieldColor::Cyan),
                    tf("ROSCTR:", "1 (Job)", FieldColor::Yellow),
                    tf("PDU Reference:", &format!("0x{:04x}", pdu_ref), FieldColor::Default),
                    tf("Function:", &format!("0x{:02x} ({})", fc, fc_name), FieldColor::Green),
                    tf("Item Count:", "1", FieldColor::Default),
                    tf("Area:", "Data Block", FieldColor::Default),
                    tf("DB Number:", &db.to_string(), FieldColor::Cyan),
                    tf("Byte Offset:", &format!("0x{:04x} ({})", offset, offset), FieldColor::Default),
                ],
            });
        }

        "EtherNet/IP" => {
            let sp = pkt.src_port.unwrap_or(1024);
            sections.push(TreeSection {
                title: format!("Transmission Control Protocol, Src Port: {}, Dst Port: 44818", sp),
                expanded: false,
                fields: vec![
                    tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
                    tf("Destination Port:", "44818 (EtherNet/IP)", FieldColor::Yellow),
                ],
            });
            let cmds = [
                (0x0065u16, "RegisterSession"), (0x0066, "UnRegisterSession"),
                (0x0063, "ListIdentity"), (0x0064, "ListInterfaces"),
                (0x0065, "SendRRData"), (0x0070, "SendUnitData"),
            ];
            let (cmd, cmd_name) = cmds[rng.gen_range(0..cmds.len())];
            let session: u32 = rng.r#gen();
            sections.push(TreeSection {
                title: "EtherNet/IP (ENIP)".into(),
                expanded: true,
                fields: vec![
                    tf("Command:", &format!("0x{:04x} ({})", cmd, cmd_name), FieldColor::Green),
                    tf("Length:", &pkt.length.to_string(), FieldColor::Default),
                    tf("Session Handle:", &format!("0x{:08x}", session), FieldColor::Cyan),
                    tf("Status:", "0x00000000 (Success)", FieldColor::Default),
                    tf("Sender Context:", &format!("0x{:016x}", rng.r#gen::<u64>()), FieldColor::Default),
                    tf("Service:", "Get Attribute Single", FieldColor::Yellow),
                    tf("Class:", "0x01 (Identity)", FieldColor::Default),
                    tf("Instance:", "0x01", FieldColor::Default),
                ],
            });
        }

        "PTP" => {
            let sp = pkt.src_port.unwrap_or(319);
            let dp = pkt.dst_port.unwrap_or(319);
            sections.push(TreeSection {
                title: format!("User Datagram Protocol, Src Port: {}, Dst Port: {}", sp, dp),
                expanded: false,
                fields: vec![
                    tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
                    tf("Destination Port:", &dp.to_string(), FieldColor::Yellow),
                ],
            });
            let msg_types = [(0u8,"Sync"),(1,"Delay_Req"),(8,"Follow_Up"),(9,"Delay_Resp"),(11,"Announce"),(12,"Signaling")];
            let (mt, mt_name) = msg_types[rng.gen_range(0..msg_types.len())];
            let domain: u8 = rng.gen_range(0..=3);
            let seq_id: u16 = rng.r#gen();
            let clock_hi: u32 = rng.r#gen();
            let clock_lo: u32 = rng.r#gen();
            sections.push(TreeSection {
                title: format!("Precision Time Protocol v2 (IEEE 1588) — {}", mt_name),
                expanded: true,
                fields: vec![
                    tf("Message Type:", &format!("0x{:02x} ({})", mt, mt_name), FieldColor::Yellow),
                    tf("Version PTP:", "2", FieldColor::Cyan),
                    tf("Message Length:", "44", FieldColor::Default),
                    tf("Domain Number:", &domain.to_string(), FieldColor::Default),
                    tf("Flags:", "0x0000", FieldColor::Default),
                    tf("Correction Field:", "0 ns", FieldColor::Default),
                    tf("Clock Identity:", &format!("0x{:08x}{:08x}", clock_hi, clock_lo), FieldColor::Cyan),
                    tf("Source Port ID:", "1", FieldColor::Default),
                    tf("Sequence ID:", &seq_id.to_string(), FieldColor::Yellow),
                    tf("Control Field:", &format!("0x{:02x}", mt), FieldColor::Default),
                    tf("Log Message Interval:", "-1", FieldColor::Default),
                ],
            });
        }

        "SIP" | "SIPS" => {
            let sp = pkt.src_port.unwrap_or(rng.gen_range(5060u16..=5070));
            let dp = pkt.dst_port.unwrap_or(5060);
            sections.push(TreeSection {
                title: format!("User Datagram Protocol, Src Port: {}, Dst Port: {}", sp, dp),
                expanded: false,
                fields: vec![
                    tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
                    tf("Destination Port:", &dp.to_string(), FieldColor::Yellow),
                ],
            });
            let methods = [("INVITE","Initiate session"),("BYE","Terminate session"),
                           ("ACK","Acknowledge"),("REGISTER","Register UA"),
                           ("OPTIONS","Query capabilities"),("CANCEL","Cancel pending request")];
            let (method, _desc) = methods[rng.gen_range(0..methods.len())];
            let ext: u16 = rng.gen_range(1000..=9999);
            let call_id = format!("{:08x}-{:04x}@sip.local", rng.r#gen::<u32>(), rng.r#gen::<u16>());
            let cseq: u32 = rng.gen_range(1..=100);
            sections.push(TreeSection {
                title: format!("Session Initiation Protocol — {}", method),
                expanded: true,
                fields: vec![
                    tf("Method:", method, FieldColor::Green),
                    tf("Request-URI:", &format!("sip:{}@{}", ext, pkt.dst), FieldColor::Cyan),
                    tf("Via:", &format!("SIP/2.0/UDP {};branch=z9hG4bK{:08x}", pkt.src, rng.r#gen::<u32>()), FieldColor::Default),
                    tf("From:", &format!("<sip:user@{}>", pkt.src), FieldColor::Yellow),
                    tf("To:", &format!("<sip:{}>", ext), FieldColor::Yellow),
                    tf("Call-ID:", &call_id, FieldColor::Cyan),
                    tf("CSeq:", &format!("{} {}", cseq, method), FieldColor::Default),
                    tf("Max-Forwards:", "70", FieldColor::Default),
                    tf("Content-Length:", "0", FieldColor::Default),
                ],
            });
        }

        "BGP" => {
            let sp = pkt.src_port.unwrap_or(rng.gen_range(1024u16..=65535));
            sections.push(TreeSection {
                title: format!("Transmission Control Protocol, Src Port: {}, Dst Port: 179", sp),
                expanded: false,
                fields: vec![
                    tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
                    tf("Destination Port:", "179", FieldColor::Yellow),
                ],
            });
            let types = [(1u8,"OPEN"),(2,"UPDATE"),(3,"NOTIFICATION"),(4,"KEEPALIVE")];
            let (bt, bt_name) = types[rng.gen_range(0..types.len())];
            let asn: u32 = rng.gen_range(64512..=65534);
            let hold: u16 = 90;
            let mut fields = vec![
                tf("Marker:", "0xffffffffffffffffffffffffffffffff", FieldColor::Default),
                tf("Length:", &pkt.length.to_string(), FieldColor::Default),
                tf("Type:", &format!("{} ({})", bt, bt_name), FieldColor::Yellow),
            ];
            if bt == 1 {
                fields.push(tf("Version:", "4", FieldColor::Cyan));
                fields.push(tf("My AS:", &asn.to_string(), FieldColor::Green));
                fields.push(tf("Hold Time:", &hold.to_string(), FieldColor::Default));
                fields.push(tf("BGP ID:", &pkt.src, FieldColor::Cyan));
            } else if bt == 2 {
                let prefix = format!("{}.0.0/8", rng.gen_range(1u8..=254));
                let next_hop = format!("{}.{}.{}.{}", rng.gen_range(1u8..=254), rng.r#gen::<u8>(), rng.r#gen::<u8>(), rng.gen_range(1u8..=254));
                fields.push(tf("NLRI Prefix:", &prefix, FieldColor::Cyan));
                fields.push(tf("Next Hop:", &next_hop, FieldColor::Green));
                fields.push(tf("AS Path:", &format!("AS{} AS{}", asn, rng.gen_range(1u32..=64511)), FieldColor::Yellow));
                fields.push(tf("Origin:", "IGP (0)", FieldColor::Default));
            }
            sections.push(TreeSection {
                title: format!("Border Gateway Protocol — {}", bt_name),
                expanded: true,
                fields,
            });
        }

        "FTP" => {
            let sp = pkt.src_port.unwrap_or(rng.gen_range(1024u16..=65535));
            sections.push(TreeSection {
                title: format!("Transmission Control Protocol, Src Port: {}, Dst Port: 21", sp),
                expanded: false,
                fields: vec![
                    tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
                    tf("Destination Port:", "21", FieldColor::Yellow),
                ],
            });
            let cmds = [
                ("USER", "anonymous"), ("PASS", "guest@example.com"), ("LIST", ""),
                ("RETR", "file.txt"), ("STOR", "upload.bin"), ("PWD", ""),
                ("CWD", "/pub/data"), ("QUIT", ""), ("PASV", ""), ("TYPE", "I"),
            ];
            let (cmd, arg) = cmds[rng.gen_range(0..cmds.len())];
            let arg_str = if arg.is_empty() { String::new() } else { format!(" {}", arg) };
            sections.push(TreeSection {
                title: "File Transfer Protocol (FTP)".into(),
                expanded: true,
                fields: vec![
                    tf("Command:", cmd, FieldColor::Yellow),
                    tf("Argument:", if arg.is_empty() { "(none)" } else { arg }, FieldColor::Cyan),
                    tf("Request:", &format!("{}{}\r\n", cmd, arg_str), FieldColor::Green),
                ],
            });
        }

        "Telnet" => {
            let sp = pkt.src_port.unwrap_or(rng.gen_range(1024u16..=65535));
            sections.push(TreeSection {
                title: format!("Transmission Control Protocol, Src Port: {}, Dst Port: 23", sp),
                expanded: false,
                fields: vec![
                    tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
                    tf("Destination Port:", "23", FieldColor::Yellow),
                ],
            });
            let cmds = [
                ("IAC DO", "Terminal Type (0x18)"),
                ("IAC WILL", "Terminal Speed (0x20)"),
                ("IAC SB", "Terminal Type IS xterm-256color"),
                ("Data", "login: "),
            ];
            let (cmd, detail) = cmds[rng.gen_range(0..cmds.len())];
            sections.push(TreeSection {
                title: "Telnet Protocol".into(),
                expanded: true,
                fields: vec![
                    tf("Command:", cmd, FieldColor::Yellow),
                    tf("Option:", detail, FieldColor::Cyan),
                    tf("Length:", &pkt.length.to_string(), FieldColor::Default),
                ],
            });
        }

        "LDAP" => {
            let sp = pkt.src_port.unwrap_or(rng.gen_range(1024u16..=65535));
            sections.push(TreeSection {
                title: format!("Transmission Control Protocol, Src Port: {}, Dst Port: 389", sp),
                expanded: false,
                fields: vec![
                    tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
                    tf("Destination Port:", "389", FieldColor::Yellow),
                ],
            });
            let ops = [
                (0u8, "BindRequest"), (1, "BindResponse"), (3, "SearchRequest"),
                (4, "SearchResultEntry"), (5, "SearchResultDone"), (6, "ModifyRequest"),
                (8, "AddRequest"), (10, "DelRequest"),
            ];
            let (op, op_name) = ops[rng.gen_range(0..ops.len())];
            let msg_id: u32 = rng.gen_range(1..=9999);
            sections.push(TreeSection {
                title: format!("Lightweight Directory Access Protocol (LDAP) — {}", op_name),
                expanded: true,
                fields: vec![
                    tf("Message ID:", &msg_id.to_string(), FieldColor::Cyan),
                    tf("Operation:", &format!("{} ({})", op_name, op), FieldColor::Yellow),
                    tf("Base Object:", "dc=example,dc=com", FieldColor::Green),
                    tf("Scope:", "2 (wholeSubtree)", FieldColor::Default),
                    tf("Filter:", "(objectClass=*)", FieldColor::Cyan),
                ],
            });
        }

        "DHCPv6" => {
            let sp = pkt.src_port.unwrap_or(546);
            let dp = pkt.dst_port.unwrap_or(547);
            sections.push(TreeSection {
                title: format!("User Datagram Protocol, Src Port: {}, Dst Port: {}", sp, dp),
                expanded: false,
                fields: vec![
                    tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
                    tf("Destination Port:", &dp.to_string(), FieldColor::Yellow),
                ],
            });
            let msg_types = [
                (1u8,"Solicit"),(2,"Advertise"),(3,"Request"),(5,"Renew"),
                (7,"Reply"),(8,"Release"),(11,"Inform-request"),
            ];
            let (mt, mt_name) = msg_types[rng.gen_range(0..msg_types.len())];
            let tid: u32 = rng.r#gen::<u32>() & 0xFFFFFF;
            sections.push(TreeSection {
                title: format!("DHCPv6 — {}", mt_name),
                expanded: true,
                fields: vec![
                    tf("Message type:", &format!("{} ({})", mt, mt_name), FieldColor::Yellow),
                    tf("Transaction ID:", &format!("0x{:06x}", tid), FieldColor::Cyan),
                    tf("Client DUID:", &format!("0003000100{:012x}", rng.r#gen::<u64>() & 0xFFFFFFFFFFFF), FieldColor::Default),
                    tf("IA_NA:", &format!("IAID=0x{:08x}", rng.r#gen::<u32>()), FieldColor::Default),
                ],
            });
        }

        "VXLAN" => {
            let sp = pkt.src_port.unwrap_or(rng.gen_range(1024u16..=65535));
            sections.push(TreeSection {
                title: format!("User Datagram Protocol, Src Port: {}, Dst Port: 4789", sp),
                expanded: false,
                fields: vec![
                    tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
                    tf("Destination Port:", "4789", FieldColor::Yellow),
                ],
            });
            let vni: u32 = rng.gen_range(1..=16_777_215);
            let inner_src = format!("{}.{}.{}.{}", rng.gen_range(10u8..=10), rng.r#gen::<u8>(), rng.r#gen::<u8>(), rng.gen_range(1u8..=254));
            let inner_dst = format!("{}.{}.{}.{}", rng.gen_range(10u8..=10), rng.r#gen::<u8>(), rng.r#gen::<u8>(), rng.gen_range(1u8..=254));
            sections.push(TreeSection {
                title: format!("Virtual eXtensible Local Area Network (VNI={})", vni),
                expanded: true,
                fields: vec![
                    tf("Flags:", "0x08 (VNI present)", FieldColor::Default),
                    tf("VNI:", &vni.to_string(), FieldColor::Yellow),
                    tf("Reserved:", "0x000000", FieldColor::Default),
                    tf("Inner Src MAC:", &rand_mac(&mut rng), FieldColor::Cyan),
                    tf("Inner Dst MAC:", &rand_mac(&mut rng), FieldColor::Cyan),
                    tf("Inner Src IP:", &inner_src, FieldColor::Green),
                    tf("Inner Dst IP:", &inner_dst, FieldColor::Orange),
                ],
            });
        }

        "WireGuard" => {
            let sp = pkt.src_port.unwrap_or(rng.gen_range(1024u16..=65535));
            sections.push(TreeSection {
                title: format!("User Datagram Protocol, Src Port: {}, Dst Port: 51820", sp),
                expanded: false,
                fields: vec![
                    tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
                    tf("Destination Port:", "51820", FieldColor::Yellow),
                ],
            });
            let types = [(1u8,"Handshake Initiation"),(2,"Handshake Response"),(3,"Cookie Reply"),(4,"Transport Data")];
            let (wt, wt_name) = types[rng.gen_range(0..types.len())];
            let sender: u32 = rng.r#gen();
            let mut fields = vec![
                tf("Message Type:", &format!("{} ({})", wt, wt_name), FieldColor::Yellow),
                tf("Reserved:", "0x000000", FieldColor::Default),
            ];
            if wt == 4 {
                let receiver: u32 = rng.r#gen();
                let counter: u64 = rng.r#gen();
                fields.push(tf("Receiver Index:", &format!("0x{:08x}", receiver), FieldColor::Cyan));
                fields.push(tf("Counter:", &counter.to_string(), FieldColor::Default));
                fields.push(tf("Encrypted Payload:", &format!("[{} bytes]", pkt.length.saturating_sub(32)), FieldColor::Magenta));
            } else {
                fields.push(tf("Sender Index:", &format!("0x{:08x}", sender), FieldColor::Cyan));
                fields.push(tf("Ephemeral Key:", &format!("0x{:064x}", rng.r#gen::<u64>()), FieldColor::Green));
                fields.push(tf("Encrypted Static:", "[32 bytes]", FieldColor::Default));
                fields.push(tf("Encrypted Timestamp:", "[12 bytes]", FieldColor::Default));
                fields.push(tf("MAC1:", &format!("0x{:032x}", rng.r#gen::<u64>()), FieldColor::Default));
            }
            sections.push(TreeSection {
                title: format!("WireGuard — {}", wt_name),
                expanded: true,
                fields,
            });
        }

        "GRE" => {
            sections.push(TreeSection {
                title: "Generic Routing Encapsulation (GRE)".into(),
                expanded: true,
                fields: vec![
                    tf("Flags:", "0x0000", FieldColor::Default),
                    tf("Version:", "0", FieldColor::Default),
                    tf("Protocol Type:", "0x0800 (IPv4)", FieldColor::Yellow),
                    tf("Key:", &format!("0x{:08x}", rng.r#gen::<u32>()), FieldColor::Cyan),
                    tf("Sequence Number:", &rng.r#gen::<u32>().to_string(), FieldColor::Default),
                ],
            });
        }

        "IGMP" => {
            let group = format!("239.{}.{}.{}", rng.gen_range(1u8..=2), rng.r#gen::<u8>(), rng.gen_range(1u8..=254));
            let types = [(0x11u8,"Membership Query"),(0x16,"Membership Report v2"),(0x17,"Leave Group"),(0x22,"Membership Report v3")];
            let (it, it_name) = types[rng.gen_range(0..types.len())];
            sections.push(TreeSection {
                title: format!("Internet Group Management Protocol ({})", it_name),
                expanded: true,
                fields: vec![
                    tf("Type:", &format!("0x{:02x} ({})", it, it_name), FieldColor::Yellow),
                    tf("Max Resp Time:", "10.0 sec", FieldColor::Default),
                    tf("Checksum:", &format!("0x{:04x}", rng.r#gen::<u16>()), FieldColor::Default),
                    tf("Multicast Address:", &group, FieldColor::Cyan),
                    tf("S Flag:", "0", FieldColor::Default),
                    tf("QRV:", "2", FieldColor::Default),
                ],
            });
        }

        "VRRP" => {
            let vrid: u8 = rng.gen_range(1..=255);
            let prio: u8 = rng.gen_range(1..=254);
            let ips: u8 = rng.gen_range(1..=3);
            sections.push(TreeSection {
                title: format!("Virtual Router Redundancy Protocol (VRID={})", vrid),
                expanded: true,
                fields: vec![
                    tf("Version:", "3", FieldColor::Cyan),
                    tf("Type:", "1 (Advertisement)", FieldColor::Yellow),
                    tf("Virtual Router ID:", &vrid.to_string(), FieldColor::Yellow),
                    tf("Priority:", &prio.to_string(), if prio == 255 { FieldColor::Green } else { FieldColor::Default }),
                    tf("Count IP Addrs:", &ips.to_string(), FieldColor::Default),
                    tf("Adver Interval:", "100 centiseconds", FieldColor::Default),
                    tf("Checksum:", &format!("0x{:04x}", rng.r#gen::<u16>()), FieldColor::Default),
                    tf("Virtual IP:", &format!("10.0.0.{}", rng.gen_range(1u8..=10)), FieldColor::Cyan),
                ],
            });
        }

        "ESP" => {
            let spi: u32 = rng.r#gen();
            let seq: u32 = rng.r#gen();
            sections.push(TreeSection {
                title: "IPSec Encapsulating Security Payload (ESP)".into(),
                expanded: true,
                fields: vec![
                    tf("SPI:", &format!("0x{:08x}", spi), FieldColor::Cyan),
                    tf("Sequence Number:", &seq.to_string(), FieldColor::Default),
                    tf("Payload Data:", &format!("[{} bytes encrypted]", pkt.length.saturating_sub(8)), FieldColor::Magenta),
                ],
            });
        }

        "AH" => {
            let spi: u32 = rng.r#gen();
            let seq: u32 = rng.r#gen();
            sections.push(TreeSection {
                title: "IPSec Authentication Header (AH)".into(),
                expanded: true,
                fields: vec![
                    tf("Next Header:", "6 (TCP)", FieldColor::Default),
                    tf("Length:", "4", FieldColor::Default),
                    tf("SPI:", &format!("0x{:08x}", spi), FieldColor::Cyan),
                    tf("Sequence Number:", &seq.to_string(), FieldColor::Default),
                    tf("ICV:", &format!("0x{:032x}", rng.r#gen::<u64>()), FieldColor::Green),
                ],
            });
        }

        "GTP" => {
            let sp = pkt.src_port.unwrap_or(rng.gen_range(1024u16..=65535));
            sections.push(TreeSection {
                title: format!("User Datagram Protocol, Src Port: {}, Dst Port: 2152", sp),
                expanded: false,
                fields: vec![
                    tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
                    tf("Destination Port:", "2152", FieldColor::Yellow),
                ],
            });
            let msg_types = [(0xffu8,"G-PDU"),(16,"Create PDP Ctx Req"),(17,"Create PDP Ctx Resp"),(18,"Update PDP Ctx Req"),(26,"Error Indication")];
            let (mt, mt_name) = msg_types[rng.gen_range(0..msg_types.len())];
            let teid: u32 = rng.r#gen();
            sections.push(TreeSection {
                title: format!("GPRS Tunneling Protocol v1 (GTP) — {}", mt_name),
                expanded: true,
                fields: vec![
                    tf("Version:", "1", FieldColor::Cyan),
                    tf("PT:", "1 (GTP)", FieldColor::Default),
                    tf("Message Type:", &format!("0x{:02x} ({})", mt, mt_name), FieldColor::Yellow),
                    tf("Length:", &pkt.length.to_string(), FieldColor::Default),
                    tf("TEID:", &format!("0x{:08x}", teid), FieldColor::Cyan),
                    tf("Sequence Number:", &rng.r#gen::<u16>().to_string(), FieldColor::Default),
                ],
            });
        }

        "Radius" => {
            let sp = pkt.src_port.unwrap_or(rng.gen_range(1024u16..=65535));
            let dp = pkt.dst_port.unwrap_or(1812);
            sections.push(TreeSection {
                title: format!("User Datagram Protocol, Src Port: {}, Dst Port: {}", sp, dp),
                expanded: false,
                fields: vec![
                    tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
                    tf("Destination Port:", &dp.to_string(), FieldColor::Yellow),
                ],
            });
            let codes = [(1u8,"Access-Request"),(2,"Access-Accept"),(3,"Access-Reject"),(4,"Accounting-Request"),(5,"Accounting-Response"),(11,"Access-Challenge")];
            let (code, code_name) = codes[rng.gen_range(0..codes.len())];
            let id: u8 = rng.r#gen();
            sections.push(TreeSection {
                title: format!("RADIUS — {}", code_name),
                expanded: true,
                fields: vec![
                    tf("Code:", &format!("{} ({})", code, code_name), FieldColor::Yellow),
                    tf("ID:", &id.to_string(), FieldColor::Cyan),
                    tf("Length:", &pkt.length.to_string(), FieldColor::Default),
                    tf("Authenticator:", &format!("0x{:032x}", rng.r#gen::<u64>()), FieldColor::Default),
                    tf("User-Name:", "user@example.com", FieldColor::Green),
                    tf("NAS-IP-Address:", &pkt.src, FieldColor::Cyan),
                    tf("NAS-Port:", &rng.gen_range(1u32..=100).to_string(), FieldColor::Default),
                ],
            });
        }

        "DoIP" => {
            let sp = pkt.src_port.unwrap_or(rng.gen_range(1024u16..=65535));
            sections.push(TreeSection {
                title: format!("Transmission Control Protocol, Src Port: {}, Dst Port: 13400", sp),
                expanded: false,
                fields: vec![
                    tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
                    tf("Destination Port:", "13400", FieldColor::Yellow),
                ],
            });
            let payloads = [
                (0x0001u16,"Routing Activation Request"),
                (0x0002,"Routing Activation Response"),
                (0x8001,"Diagnostic Message"),
                (0x8002,"Diagnostic Message Positive Ack"),
                (0x8003,"Diagnostic Message Negative Ack"),
                (0x4001,"Vehicle Announcement"),
            ];
            let (pt, pt_name) = payloads[rng.gen_range(0..payloads.len())];
            let src_addr: u16 = rng.gen_range(0x0e00..=0x0eff);
            let tgt_addr: u16 = rng.gen_range(0x0001..=0x00ff);
            sections.push(TreeSection {
                title: format!("Diagnostic over IP (DoIP) — {}", pt_name),
                expanded: true,
                fields: vec![
                    tf("Protocol Version:", "0x02 (ISO 13400-2:2012)", FieldColor::Cyan),
                    tf("Inverse Version:", "0xfd", FieldColor::Default),
                    tf("Payload Type:", &format!("0x{:04x} ({})", pt, pt_name), FieldColor::Yellow),
                    tf("Payload Length:", &pkt.length.to_string(), FieldColor::Default),
                    tf("Source Address:", &format!("0x{:04x}", src_addr), FieldColor::Green),
                    tf("Target Address:", &format!("0x{:04x}", tgt_addr), FieldColor::Orange),
                ],
            });
        }

        "SOME/IP" => {
            let sp = pkt.src_port.unwrap_or(rng.gen_range(1024u16..=65535));
            let dp = pkt.dst_port.unwrap_or(30490);
            sections.push(TreeSection {
                title: format!("User Datagram Protocol, Src Port: {}, Dst Port: {}", sp, dp),
                expanded: false,
                fields: vec![
                    tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
                    tf("Destination Port:", &dp.to_string(), FieldColor::Yellow),
                ],
            });
            let service_id: u16 = rng.gen_range(0x0100..=0x0200);
            let method_id: u16 = rng.gen_range(0x0001..=0x000f);
            let msg_types = [(0x00u8,"REQUEST"),(0x01,"REQUEST_NO_RETURN"),(0x02,"NOTIFICATION"),(0x80,"RESPONSE"),(0x81,"ERROR")];
            let (mt, mt_name) = msg_types[rng.gen_range(0..msg_types.len())];
            let client_id: u16 = rng.r#gen();
            let session_id: u16 = rng.r#gen();
            sections.push(TreeSection {
                title: format!("SOME/IP — {} (Service 0x{:04x})", mt_name, service_id),
                expanded: true,
                fields: vec![
                    tf("Service ID:", &format!("0x{:04x}", service_id), FieldColor::Cyan),
                    tf("Method ID:", &format!("0x{:04x}", method_id), FieldColor::Yellow),
                    tf("Length:", &pkt.length.to_string(), FieldColor::Default),
                    tf("Client ID:", &format!("0x{:04x}", client_id), FieldColor::Default),
                    tf("Session ID:", &format!("0x{:04x}", session_id), FieldColor::Default),
                    tf("Interface Version:", "1", FieldColor::Default),
                    tf("Message Type:", &format!("0x{:02x} ({})", mt, mt_name), FieldColor::Green),
                    tf("Return Code:", "0x00 (E_OK)", FieldColor::Green),
                ],
            });
        }

        "MPLS" => {
            let label: u32 = rng.gen_range(16..=1048575);
            let tc: u8 = rng.gen_range(0..=7);
            sections.push(TreeSection {
                title: format!("MultiProtocol Label Switching (Label={})", label),
                expanded: true,
                fields: vec![
                    tf("Label:", &label.to_string(), FieldColor::Cyan),
                    tf("Traffic Class:", &tc.to_string(), FieldColor::Default),
                    tf("Bottom of Stack:", "1", FieldColor::Default),
                    tf("TTL:", &rng.gen_range(48u8..=128).to_string(), FieldColor::Default),
                ],
            });
        }

        "PPPoE" => {
            let code_names = ["PADI", "PADO", "PADR", "PADS", "PADT", "Session"];
            let cn = code_names[rng.gen_range(0..code_names.len())];
            sections.push(TreeSection {
                title: format!("Point-to-Point Protocol over Ethernet ({})", cn),
                expanded: true,
                fields: vec![
                    tf("Version:", "1", FieldColor::Default),
                    tf("Type:", "1", FieldColor::Default),
                    tf("Code:", cn, FieldColor::Yellow),
                    tf("Session ID:", &format!("0x{:04x}", rng.r#gen::<u16>()), FieldColor::Cyan),
                    tf("Payload Length:", &pkt.length.saturating_sub(6).to_string(), FieldColor::Default),
                ],
            });
        }

        "WoL" => {
            let mac = rand_mac(&mut rng);
            sections.push(TreeSection {
                title: "Wake on LAN (Magic Packet)".into(),
                expanded: true,
                fields: vec![
                    tf("Sync Stream:", "0xffffffffffff", FieldColor::Default),
                    tf("Target MAC:", &mac, FieldColor::Cyan),
                    tf("MAC Repetitions:", "16", FieldColor::Default),
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
