/// PCAP file replay — load a .pcap and feed packets into the capture pipeline.
use std::path::PathBuf;
use crate::net::packet::Packet;

pub struct ReplayState {
    pub path:       String,   // editable input
    pub speed:      f64,      // replay speed multiplier (1.0 = real-time, 0 = instant)
    pub packets:    Vec<Packet>,
    pub current:    usize,
    pub running:    bool,
    pub complete:   bool,
    pub error:      Option<String>,
    pub total:      usize,
    /// Accumulated fractional ticks for sub-1-packet/tick speeds
    tick_accum:     f64,
}

impl Default for ReplayState {
    fn default() -> Self {
        Self {
            path:      String::new(),
            speed:     1.0,
            packets:   Vec::new(),
            current:   0,
            running:   false,
            complete:  false,
            error:     None,
            total:     0,
            tick_accum: 0.0,
        }
    }
}

impl ReplayState {
    /// Load a PCAP file. Returns true on success.
    pub fn load(&mut self) -> bool {
        self.packets.clear();
        self.current = 0;
        self.complete = false;
        self.running = false;
        self.error = None;

        let path = PathBuf::from(self.path.trim());
        if !path.exists() {
            self.error = Some(format!("File not found: {}", self.path.trim()));
            return false;
        }

        match read_pcap(&path) {
            Ok(pkts) => {
                self.total = pkts.len();
                self.packets = pkts;
                true
            }
            Err(e) => {
                self.error = Some(e);
                false
            }
        }
    }

    pub fn start(&mut self) {
        if self.packets.is_empty() {
            self.error = Some("Load a PCAP file first".into());
            return;
        }
        self.running = true;
        self.current = 0;
        self.complete = false;
        self.tick_accum = 0.0;
    }

    pub fn stop(&mut self) { self.running = false; }

    pub fn speed_up(&mut self)   { self.speed = (self.speed * 2.0).min(64.0); }
    pub fn speed_down(&mut self) { self.speed = (self.speed / 2.0).max(0.125); }

    /// Called each app tick. Returns packets to inject (may be empty, may be many).
    pub fn tick(&mut self) -> Vec<Packet> {
        if !self.running || self.packets.is_empty() { return vec![]; }

        // How many packets to emit this tick?
        // At speed=1.0 and 10 ticks/sec, emit proportional to original rate.
        // Simplified: emit ceil(speed) packets per tick, or skip ticks for speed<1.
        let emit_count = if self.speed >= 1.0 {
            self.speed.ceil() as usize
        } else {
            self.tick_accum += self.speed;
            if self.tick_accum >= 1.0 {
                self.tick_accum -= 1.0;
                1
            } else {
                0
            }
        };

        let mut out = Vec::new();
        for _ in 0..emit_count {
            if self.current >= self.packets.len() {
                self.running = false;
                self.complete = true;
                break;
            }
            out.push(self.packets[self.current].clone());
            self.current += 1;
        }
        out
    }

    pub fn progress_pct(&self) -> u8 {
        if self.total == 0 { return 0; }
        ((self.current * 100) / self.total) as u8
    }
}

/// Minimal pcap reader — handles pcap (not pcapng) little-endian format.
/// Returns packets as Packet structs with simulated metadata derived from bytes.
pub fn read_pcap(path: &std::path::Path) -> Result<Vec<Packet>, String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).map_err(|e| e.to_string())?;

    if buf.len() < 24 {
        return Err("File too small to be a valid PCAP".into());
    }

    // Global header: magic(4), version_major(2), version_minor(2), thiszone(4),
    //               sigfigs(4), snaplen(4), network(4) = 24 bytes
    let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if magic != 0xa1b2c3d4 && magic != 0xd4c3b2a1 {
        return Err("Not a valid PCAP file (wrong magic number)".into());
    }
    let be = magic == 0xd4c3b2a1;

    let mut packets = Vec::new();
    let mut offset = 24usize;
    let mut counter = 1u64;
    let _start_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();

    while offset + 16 <= buf.len() {
        let read_u32 = |o: usize| -> u32 {
            let b = &buf[o..o+4];
            if be { u32::from_be_bytes([b[0],b[1],b[2],b[3]]) }
            else  { u32::from_le_bytes([b[0],b[1],b[2],b[3]]) }
        };

        let ts_sec  = read_u32(offset);
        let ts_usec = read_u32(offset + 4);
        let incl_len = read_u32(offset + 8) as usize;
        let _orig_len = read_u32(offset + 12);
        offset += 16;

        if offset + incl_len > buf.len() { break; }
        let raw = buf[offset..offset+incl_len].to_vec();
        offset += incl_len;

        let timestamp = ts_sec as f64 + ts_usec as f64 / 1_000_000.0;
        let pkt = bytes_to_packet(raw, counter, timestamp);
        packets.push(pkt);
        counter += 1;

        if packets.len() >= 100_000 { break; } // safety cap
    }

    if packets.is_empty() {
        Err("No packets found in PCAP".into())
    } else {
        Ok(packets)
    }
}

/// Convert raw Ethernet frame bytes into a Packet struct.
fn bytes_to_packet(raw: Vec<u8>, no: u64, timestamp: f64) -> Packet {
    let len = raw.len() as u16;

    // Ethernet dst/src MACs are bytes 0-11, EtherType at 12-13
    let ethertype = if raw.len() >= 14 {
        u16::from_be_bytes([raw[12], raw[13]])
    } else { 0 };

    // Handle 802.1Q VLAN (0x8100) and QinQ/802.1ad (0x88a8)
    let (vlan_id, vlan_pcp, vlan_dei, outer_vlan_id, ip_off) = {
        let mut off = 14usize;
        let mut outer: Option<u16> = None;
        let mut inner: Option<u16> = None;
        let mut pcp:   Option<u8>  = None;
        let mut dei:   Option<u8>  = None;
        let mut et = ethertype;
        while (et == 0x8100 || et == 0x88a8) && raw.len() >= off + 4 {
            let tci = u16::from_be_bytes([raw[off], raw[off + 1]]);
            let vid = tci & 0x0fff;
            let p   = ((tci >> 13) & 0x07) as u8;
            let d   = ((tci >> 12) & 0x01) as u8;
            et = u16::from_be_bytes([raw[off + 2], raw[off + 3]]);
            off += 4;
            if inner.is_some() {
                // already have one tag — this is a second tag (shouldn't happen in well-formed frames)
            } else if outer.is_some() {
                inner = Some(vid); pcp = Some(p); dei = Some(d);
            } else {
                outer = Some(vid); pcp = Some(p); dei = Some(d);
            }
        }
        // if only one tag: outer is the inner VLAN
        let (vid, oid) = if inner.is_some() {
            (inner, outer)
        } else {
            (outer, None)
        };
        (vid, pcp, dei, oid, off)
    };

    if raw.len() < ip_off + 20 {
        return Packet {
            no, timestamp, length: len, bytes: raw,
            vlan_id, vlan_pcp, vlan_dei, outer_vlan_id,
            src: "?".into(), dst: "?".into(),
            protocol: "RAW".into(), info: "short frame".into(),
            src_port: None, dst_port: None,
        };
    }

    // IPv4
    let ip = &raw[ip_off..];
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    let proto_byte = ip[9];
    let src = format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15]);
    let dst = format!("{}.{}.{}.{}", ip[16], ip[17], ip[18], ip[19]);

    let tp_off = ip_off + ihl;

    let (protocol, src_port, dst_port, info) = if raw.len() > tp_off + 4 {
        let tp = &raw[tp_off..];
        let sp = u16::from_be_bytes([tp[0], tp[1]]);
        let dp = u16::from_be_bytes([tp[2], tp[3]]);
        match proto_byte {
            6  => {
                let flags = if raw.len() > tp_off + 13 { raw[tp_off + 13] } else { 0 };
                let flag_str = fmt_tcp_flags(flags);
                let proto = port_to_proto(sp, dp, "TCP");
                (proto, Some(sp), Some(dp), format!("{} → {} [{}]", sp, dp, flag_str))
            }
            17 => {
                let proto = port_to_proto(sp, dp, "UDP");
                (proto, Some(sp), Some(dp), format!("{} → {}", sp, dp))
            }
            1  => ("ICMP".into(),   None, None, "ICMP".into()),
            2  => ("IGMP".into(),   None, None, "IGMP".into()),
            89 => ("OSPF".into(),   None, None, "OSPF".into()),
            50 => ("ESP".into(),    None, None, "ESP".into()),
            51 => ("AH".into(),     None, None, "AH".into()),
            _  => (format!("IP/{}", proto_byte), None, None, "".into()),
        }
    } else {
        ("IP".into(), None, None, "".into())
    };

    Packet {
        no, timestamp, src, dst, protocol, length: len, info,
        src_port, dst_port, vlan_id, vlan_pcp, vlan_dei, outer_vlan_id, bytes: raw,
    }
}

fn port_to_proto(sp: u16, dp: u16, fallback: &str) -> String {
    let well_known: &[(u16, &str)] = &[
        (80,"HTTP"),(443,"HTTPS"),(22,"SSH"),(21,"FTP"),(25,"SMTP"),
        (53,"DNS"),(67,"DHCP"),(68,"DHCP"),(123,"NTP"),(143,"IMAP"),
        (110,"POP3"),(3306,"MySQL"),(5432,"PostgreSQL"),(6379,"Redis"),
        (27017,"MongoDB"),(9200,"Elasticsearch"),(445,"SMB"),(389,"LDAP"),
        (3389,"RDP"),(5900,"VNC"),(8080,"HTTP"),(8443,"HTTPS"),
        (4789,"VXLAN"),(51820,"WireGuard"),(5060,"SIP"),(5061,"SIPS"),
        (1883,"MQTT"),(8883,"MQTT-TLS"),(4840,"OPC-UA"),(502,"Modbus"),
        (20000,"DNP3"),(47808,"BACnet"),(102,"S7comm"),(44818,"EtherNet/IP"),
        (179,"BGP"),(161,"SNMP"),(162,"SNMP"),(514,"Syslog"),
        (5353,"mDNS"),(5355,"LLMNR"),
    ];
    for &(port, name) in well_known {
        if dp == port || sp == port { return name.to_string(); }
    }
    fallback.to_string()
}

fn fmt_tcp_flags(f: u8) -> String {
    let mut s = String::new();
    if f & 0x02 != 0 { s.push_str("SYN "); }
    if f & 0x10 != 0 { s.push_str("ACK "); }
    if f & 0x01 != 0 { s.push_str("FIN "); }
    if f & 0x04 != 0 { s.push_str("RST "); }
    if f & 0x08 != 0 { s.push_str("PSH "); }
    if f & 0x20 != 0 { s.push_str("URG "); }
    if s.is_empty() { s.push_str("NONE"); }
    s.trim_end().to_string()
}
