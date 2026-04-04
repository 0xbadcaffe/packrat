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
        | "Modbus" | "MQTT" | "MQTT-TLS" | "OPC-UA" | "DNP3" | "S7comm"
        | "EtherNet/IP" | "IEC-104"                                            => "6 (TCP)",
        "UDP" | "DNS" | "mDNS" | "DHCP" | "NTP" | "QUIC" | "SNMP"
        | "CoAP" | "CoAP-DTLS" | "BACnet"                                     => "17 (UDP)",
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

        _ => {}
    }

    sections
}

fn tf(key: &str, val: &str, color: FieldColor) -> TreeField {
    make_field(key, val, color)
}
