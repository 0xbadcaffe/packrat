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
const OT_IPS: &[&str] = &[
    "192.168.0.10", "192.168.0.20", "192.168.100.1",
    "10.10.1.5", "10.10.1.10", "10.10.1.100",
];
const DNS_NAMES: &[&str] = &[
    "google.com", "github.com", "api.stripe.com",
    "fonts.googleapis.com", "cdn.cloudflare.com",
    "s3.amazonaws.com", "app.slack.com", "discord.com",
];
const MQTT_TOPICS: &[&str] = &[
    "sensors/temperature", "sensors/pressure", "sensors/humidity",
    "actuators/valve", "actuators/pump", "actuators/relay",
    "plant/line1/status", "plant/line2/alarm", "device/plc01/health",
];
const PROTOS: &[&str] = &[
    "TCP", "UDP", "DNS", "HTTP", "HTTPS", "TLS", "ARP", "ICMP", "DHCP",
    "Modbus", "MQTT", "CoAP", "BACnet", "DNP3", "OPC-UA", "S7comm", "EtherNet/IP",
    "NTP", "PTP", "SIP", "FTP", "BGP", "WireGuard", "VXLAN", "GRE", "IGMP",
    "SMB", "RDP", "Kafka", "AMQP", "NATS", "Kerberos",
];
const WEIGHTS: &[u32] = &[26, 13, 18, 7, 10, 7, 3, 3, 1, 3, 3, 2, 1, 1, 1, 1, 1, 3, 1, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1];

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
        let b: u8 = rng.r#gen();
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
            let id: u16 = rng.r#gen();
            let seq: u16 = rng.gen_range(1..=100);
            (src, dst, None, None,
             format!("Echo request id=0x{:04x} seq={}", id, seq))
        }
        "DNS" => {
            let src = rand_ip(LOCAL_IPS, &mut rng).to_string();
            let dst = if rng.gen_bool(0.7) { "8.8.8.8" } else { "1.1.1.1" }.to_string();
            let name = DNS_NAMES[rng.gen_range(0..DNS_NAMES.len())];
            let tid: u16 = rng.r#gen();
            let info = if rng.gen_bool(0.5) {
                format!("Query 0x{:04x} A {}", tid, name)
            } else {
                format!("Response A {}.{}.{}.{}",
                    rng.gen_range(1..=254u8), rng.r#gen::<u8>(),
                    rng.r#gen::<u8>(), rng.gen_range(1..=254u8))
            };
            let sp: u16 = rng.gen_range(1024..=65535);
            (src, dst, Some(sp), Some(53u16), info)
        }
        "DHCP" => {
            let msg = ["Discover", "Request", "Offer", "ACK"][rng.gen_range(0..4)];
            let tid: u32 = rng.r#gen();
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
        "Modbus" => {
            let src = rand_ip(OT_IPS, &mut rng).to_string();
            let dst = rand_ip(OT_IPS, &mut rng).to_string();
            let fn_codes = [
                (1u8, "Read Coils"), (2, "Read Discrete Inputs"),
                (3, "Read Holding Registers"), (4, "Read Input Registers"),
                (5, "Write Single Coil"), (6, "Write Single Register"),
                (15, "Write Multiple Coils"), (16, "Write Multiple Registers"),
            ];
            let (fc, fc_name) = fn_codes[rng.gen_range(0..fn_codes.len())];
            let unit: u8 = rng.gen_range(1..=10);
            let addr: u16 = rng.gen_range(0..=1000);
            (src, dst, Some(rng.gen_range(1024u16..=65535)), Some(502),
             format!("FC{} {} unit={} addr=0x{:04x}", fc, fc_name, unit, addr))
        }
        "MQTT" => {
            let src = rand_ip(OT_IPS, &mut rng).to_string();
            let dst = rand_ip(OT_IPS, &mut rng).to_string();
            let topic = MQTT_TOPICS[rng.gen_range(0..MQTT_TOPICS.len())];
            let msg_types = [
                "CONNECT client=sensor_01", "CONNACK rc=0",
                "SUBSCRIBE", "SUBACK",
            ];
            let info = if rng.gen_bool(0.6) {
                format!("PUBLISH topic={} qos={} len={}", topic, rng.gen_range(0u8..=2), rng.gen_range(4u16..=64))
            } else {
                msg_types[rng.gen_range(0..msg_types.len())].to_string()
            };
            (src, dst, Some(rng.gen_range(1024u16..=65535)), Some(1883), info)
        }
        "CoAP" => {
            let src = rand_ip(OT_IPS, &mut rng).to_string();
            let dst = rand_ip(OT_IPS, &mut rng).to_string();
            let resources = ["/sensors/temperature", "/sensors/pressure", "/actuators/relay", "/status"];
            let methods = ["GET", "PUT", "POST", "DELETE"];
            let types = ["CON", "NON", "ACK"];
            let res = resources[rng.gen_range(0..resources.len())];
            let m = methods[rng.gen_range(0..methods.len())];
            let t = types[rng.gen_range(0..types.len())];
            let mid: u16 = rng.r#gen();
            (src, dst, Some(rng.gen_range(1024u16..=65535)), Some(5683),
             format!("{} {} {} mid=0x{:04x}", t, m, res, mid))
        }
        "BACnet" => {
            let src = rand_ip(OT_IPS, &mut rng).to_string();
            let dst = rand_ip(OT_IPS, &mut rng).to_string();
            let objs = ["AI:1", "AI:2", "AO:1", "BI:1", "AV:10", "BV:5"];
            let props = ["present-value", "object-name", "description", "units", "status-flags"];
            let obj = objs[rng.gen_range(0..objs.len())];
            let prop = props[rng.gen_range(0..props.len())];
            (src, dst, Some(rng.gen_range(1024u16..=65535)), Some(47808),
             format!("ReadProperty objectId={} propId={}", obj, prop))
        }
        "DNP3" => {
            let src = rand_ip(OT_IPS, &mut rng).to_string();
            let dst = rand_ip(OT_IPS, &mut rng).to_string();
            let fns = ["Read Class 0", "Read Class 1", "Read Class 2",
                       "Write", "Select", "Operate", "Direct Operate", "Unsolicited Response"];
            let fn_name = fns[rng.gen_range(0..fns.len())];
            let outstation: u16 = rng.gen_range(1..=10);
            (src, dst, Some(rng.gen_range(1024u16..=65535)), Some(20000),
             format!("{} outstation={}", fn_name, outstation))
        }
        "OPC-UA" => {
            let src = rand_ip(OT_IPS, &mut rng).to_string();
            let dst = rand_ip(OT_IPS, &mut rng).to_string();
            let services = ["ReadRequest", "WriteRequest", "Browse", "CreateSession",
                            "ActivateSession", "Subscribe", "Publish"];
            let svc = services[rng.gen_range(0..services.len())];
            let ns: u8 = rng.gen_range(1..=3);
            let node: u16 = rng.gen_range(1000..=9999);
            (src, dst, Some(rng.gen_range(1024u16..=65535)), Some(4840),
             format!("{} nodeId=ns={};i={}", svc, ns, node))
        }
        "S7comm" => {
            let src = rand_ip(OT_IPS, &mut rng).to_string();
            let dst = rand_ip(OT_IPS, &mut rng).to_string();
            let fns = ["Read Var", "Write Var", "Request Download", "Upload", "PLC Stop", "PLC Start"];
            let fn_name = fns[rng.gen_range(0..fns.len())];
            let db: u16 = rng.gen_range(1..=100);
            (src, dst, Some(rng.gen_range(1024u16..=65535)), Some(102),
             format!("{} DB{} offset=0x{:04x}", fn_name, db, rng.gen_range(0u16..=512)))
        }
        "EtherNet/IP" => {
            let src = rand_ip(OT_IPS, &mut rng).to_string();
            let dst = rand_ip(OT_IPS, &mut rng).to_string();
            let cmds = ["ListIdentity", "RegisterSession", "SendRRData", "SendUnitData"];
            let cmd = cmds[rng.gen_range(0..cmds.len())];
            (src, dst, Some(rng.gen_range(1024u16..=65535)), Some(44818),
             format!("{} session=0x{:08x}", cmd, rng.r#gen::<u32>()))
        }
        "NTP" => {
            let src = rand_ip(LOCAL_IPS, &mut rng).to_string();
            let ntp_servers = ["216.239.35.0", "129.6.15.28", "132.163.97.1", "time.cloudflare.com"];
            let dst = ntp_servers[rng.gen_range(0..ntp_servers.len())].to_string();
            let stratum: u8 = rng.gen_range(1..=4);
            let modes = ["client", "server", "broadcast"];
            let mode = modes[rng.gen_range(0..modes.len())];
            (src, dst, Some(rng.gen_range(1024u16..=65535)), Some(123),
             format!("NTP v4 {} stratum={}", mode, stratum))
        }
        "PTP" => {
            let src = rand_ip(LOCAL_IPS, &mut rng).to_string();
            let dst = rand_ip(LOCAL_IPS, &mut rng).to_string();
            let msg_types = ["Sync", "Delay_Req", "Follow_Up", "Delay_Resp", "Announce"];
            let msg = msg_types[rng.gen_range(0..msg_types.len())];
            let seq: u16 = rng.r#gen();
            (src, dst, Some(319u16), Some(319),
             format!("PTP {} seq={} domain=0", msg, seq))
        }
        "SIP" => {
            let src = rand_ip(LOCAL_IPS, &mut rng).to_string();
            let dst = rand_ip(LOCAL_IPS, &mut rng).to_string();
            let methods = ["INVITE", "BYE", "ACK", "REGISTER", "OPTIONS", "CANCEL", "REFER"];
            let m = methods[rng.gen_range(0..methods.len())];
            let ext: u16 = rng.gen_range(1000..=9999);
            (src, dst.clone(), Some(rng.gen_range(1024u16..=65535)), Some(5060),
             format!("{} sip:{}@{}", m, ext, dst))
        }
        "FTP" => {
            let src = rand_ip(LOCAL_IPS, &mut rng).to_string();
            let dst = rand_ip(REMOTE_IPS, &mut rng).to_string();
            let cmds = [
                "USER anonymous", "PASS secret@example.com", "LIST", "RETR file.txt",
                "STOR upload.bin", "PWD", "CWD /pub", "QUIT", "PASV", "PORT",
            ];
            let cmd = cmds[rng.gen_range(0..cmds.len())];
            (src, dst, Some(rng.gen_range(1024u16..=65535)), Some(21),
             format!("FTP Request: {}", cmd))
        }
        "BGP" => {
            let src = rand_ip(LOCAL_IPS, &mut rng).to_string();
            let dst = rand_ip(REMOTE_IPS, &mut rng).to_string();
            let types = ["OPEN", "UPDATE", "NOTIFICATION", "KEEPALIVE"];
            let t = types[rng.gen_range(0..types.len())];
            let asn: u32 = rng.gen_range(64512..=65534);
            (src, dst, Some(rng.gen_range(1024u16..=65535)), Some(179),
             format!("BGP {} AS={}", t, asn))
        }
        "WireGuard" => {
            let src = rand_ip(LOCAL_IPS, &mut rng).to_string();
            let dst = rand_ip(REMOTE_IPS, &mut rng).to_string();
            let types = ["Handshake Initiation", "Handshake Response", "Transport Data", "Cookie Reply"];
            let t = types[rng.gen_range(0..types.len())];
            (src, dst, Some(rng.gen_range(1024u16..=65535)), Some(51820),
             format!("WireGuard {}", t))
        }
        "VXLAN" => {
            let src = rand_ip(LOCAL_IPS, &mut rng).to_string();
            let dst = rand_ip(LOCAL_IPS, &mut rng).to_string();
            let vni: u32 = rng.gen_range(1..=16_777_215);
            (src, dst, Some(rng.gen_range(1024u16..=65535)), Some(4789),
             format!("VXLAN VNI={} encapsulated Ethernet", vni))
        }
        "GRE" => {
            let src = rand_ip(LOCAL_IPS, &mut rng).to_string();
            let dst = rand_ip(REMOTE_IPS, &mut rng).to_string();
            let encap = ["IPv4", "IPv6", "MPLS", "Ethernet"];
            let e = encap[rng.gen_range(0..encap.len())];
            (src, dst, None, None,
             format!("GRE Encapsulated {}", e))
        }
        "IGMP" => {
            let src = rand_ip(LOCAL_IPS, &mut rng).to_string();
            let mcast = format!("239.{}.{}.{}", rng.gen_range(1u8..=2), rng.r#gen::<u8>(), rng.gen_range(1u8..=254));
            let types = ["Membership Query", "Membership Report v3", "Leave Group"];
            let t = types[rng.gen_range(0..types.len())];
            (src, mcast, None, None,
             format!("IGMPv3 {} group={}", t, rand_ip(LOCAL_IPS, &mut rng)))
        }
        "SMB" => {
            let src = rand_ip(LOCAL_IPS, &mut rng).to_string();
            let dst = rand_ip(LOCAL_IPS, &mut rng).to_string();
            let cmds = ["Negotiate", "SessionSetup", "TreeConnect", "Create", "Read", "Write", "Close"];
            let cmd = cmds[rng.gen_range(0..cmds.len())];
            let session: u64 = rng.r#gen::<u64>() & 0xFFFFFFFFFFFF;
            (src, dst, Some(rng.gen_range(1024u16..=65535)), Some(445),
             format!("SMB2 {} session=0x{:012x}", cmd, session))
        }
        "RDP" => {
            let src = rand_ip(LOCAL_IPS, &mut rng).to_string();
            let dst = rand_ip(LOCAL_IPS, &mut rng).to_string();
            let pdus = ["X.224 Connection Request", "MCS Connect Initial", "Client Info", "Demand Active PDU", "Bitmap Update"];
            let pdu = pdus[rng.gen_range(0..pdus.len())];
            (src, dst, Some(rng.gen_range(1024u16..=65535)), Some(3389),
             format!("RDP {}", pdu))
        }
        "Kafka" => {
            let src = rand_ip(LOCAL_IPS, &mut rng).to_string();
            let dst = rand_ip(LOCAL_IPS, &mut rng).to_string();
            let apis = [("Produce",0u16), ("Fetch",1), ("Metadata",3), ("OffsetFetch",9), ("JoinGroup",11)];
            let (name, api_key) = apis[rng.gen_range(0..apis.len())];
            let corr: i32 = rng.r#gen();
            (src, dst, Some(rng.gen_range(1024u16..=65535)), Some(9092),
             format!("Kafka {} apiKey={} corr={}", name, api_key, corr))
        }
        "AMQP" => {
            let src = rand_ip(LOCAL_IPS, &mut rng).to_string();
            let dst = rand_ip(LOCAL_IPS, &mut rng).to_string();
            let methods = ["connection.start", "connection.open", "channel.open", "basic.publish", "basic.deliver", "queue.declare"];
            let m = methods[rng.gen_range(0..methods.len())];
            (src, dst, Some(rng.gen_range(1024u16..=65535)), Some(5672),
             format!("AMQP {}", m))
        }
        "NATS" => {
            let src = rand_ip(LOCAL_IPS, &mut rng).to_string();
            let dst = rand_ip(LOCAL_IPS, &mut rng).to_string();
            let ops = ["PUB", "SUB", "MSG", "PING", "PONG", "+OK"];
            let op = ops[rng.gen_range(0..ops.len())];
            let subjects = ["events.>", "orders.created", "users.login", "_INBOX.reply"];
            let subj = subjects[rng.gen_range(0..subjects.len())];
            (src, dst, Some(rng.gen_range(1024u16..=65535)), Some(4222),
             format!("NATS {} {}", op, subj))
        }
        "Kerberos" => {
            let src = rand_ip(LOCAL_IPS, &mut rng).to_string();
            let dst = rand_ip(LOCAL_IPS, &mut rng).to_string();
            let msgs = ["AS-REQ", "AS-REP", "TGS-REQ", "TGS-REP", "AP-REQ"];
            let m = msgs[rng.gen_range(0..msgs.len())];
            let users = ["administrator", "svc_backup", "john.doe", "svc_sql"];
            let u = users[rng.gen_range(0..users.len())];
            (src, dst, Some(rng.gen_range(1024u16..=65535)), Some(88),
             format!("Kerberos {} user={} realm=CORP.EXAMPLE.COM", m, u))
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
                let seq: u32 = rng.r#gen();
                let ack: u32 = rng.r#gen();
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
        vlan_id:       None,
        vlan_pcp:      None,
        vlan_dei:      None,
        outer_vlan_id: None,
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
        if i == 0 { format!("{:02x}", rng.r#gen::<u8>() & 0xfe) }
        else       { format!("{:02x}", rng.r#gen::<u8>()) }
    }).collect::<Vec<_>>().join(":")
}
