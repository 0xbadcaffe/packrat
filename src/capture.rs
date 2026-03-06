/// Real packet capture backend using libpcap / Npcap.
///
/// Compiled only when built with `--features real-capture`.
/// Falls back to the simulated generator otherwise.
///
/// Usage:
///   cargo build --release --features real-capture
///   sudo ./target/release/packrat          # Linux / macOS
///   .\target\release\packrat.exe           # Windows (run as Administrator)

#[cfg(feature = "real-capture")]
pub mod live {
    use pcap::{Capture, Device, Active};
    use std::sync::{Arc, Mutex};
    use std::thread;

    use crate::packet::Packet;

    /// List all available network interfaces.
    pub fn list_devices() -> Vec<String> {
        Device::list()
            .unwrap_or_default()
            .into_iter()
            .map(|d| d.name)
            .collect()
    }

    /// Spawn a background thread that captures packets from `iface`
    /// and pushes them into `sink`.  Returns a handle you can drop to stop.
    pub fn start_capture(
        iface: &str,
        filter: Option<&str>,
        sink: Arc<Mutex<Vec<Packet>>>,
    ) -> thread::JoinHandle<()> {
        let iface = iface.to_string();
        let filter = filter.map(|s| s.to_string());

        thread::spawn(move || {
            let mut cap = Capture::from_device(iface.as_str())
                .expect("device not found")
                .promisc(true)
                .snaplen(65535)
                .timeout(100)     // ms — keeps the thread responsive
                .open()
                .expect("failed to open device (are you root / admin?)");

            // Apply a BPF filter if requested (e.g. "tcp port 80")
            if let Some(ref f) = filter {
                cap.filter(f, true).expect("invalid BPF filter");
            }

            let mut counter: u64 = 0;
            let start = std::time::Instant::now();

            while let Ok(raw) = cap.next_packet() {
                let ts = start.elapsed().as_secs_f64();
                let data = raw.data.to_vec();
                let len  = data.len() as u16;

                // Minimal Ethernet + IPv4 parse — extend as needed
                let (src, dst, protocol, src_port, dst_port, info) =
                    parse_packet(&data);

                let pkt = Packet {
                    no: counter + 1,
                    timestamp: ts,
                    src,
                    dst,
                    protocol,
                    length: len,
                    info,
                    src_port,
                    dst_port,
                    bytes: data,
                };

                counter += 1;
                if let Ok(mut v) = sink.lock() {
                    v.push(pkt);
                    // Cap memory usage
                    if v.len() > 50_000 {
                        v.remove(0);
                    }
                }
            }
        })
    }

    /// Lightweight packet parser — Ethernet → IPv4 → TCP/UDP/ICMP/DNS.
    fn parse_packet(data: &[u8]) -> (String, String, String, Option<u16>, Option<u16>, String) {
        let unknown = || (
            "?.?.?.?".into(), "?.?.?.?".into(),
            "RAW".into(), None, None, "unparseable frame".into()
        );

        if data.len() < 14 { return unknown(); }

        let ether_type = u16::from_be_bytes([data[12], data[13]]);

        // 0x0806 = ARP
        if ether_type == 0x0806 {
            if data.len() >= 42 {
                let src = fmt_ip(&data[28..32]);
                let dst = fmt_ip(&data[38..42]);
                return (src.clone(), dst.clone(), "ARP".into(), None, None,
                        format!("Who has {}? Tell {}", dst, src));
            }
            return unknown();
        }

        // 0x0800 = IPv4
        if ether_type != 0x0800 || data.len() < 34 { return unknown(); }

        let ip = &data[14..];
        let ihl  = ((ip[0] & 0x0f) * 4) as usize;
        let proto_num = ip[9];
        let src_ip = fmt_ip(&ip[12..16]);
        let dst_ip = fmt_ip(&ip[16..20]);

        if ip.len() < ihl { return unknown(); }
        let transport = &ip[ihl..];

        match proto_num {
            1 => {  // ICMP
                let info = if transport.len() >= 2 {
                    match transport[0] {
                        0  => "Echo reply".into(),
                        8  => "Echo request".into(),
                        3  => "Destination unreachable".into(),
                        11 => "Time exceeded".into(),
                        _  => format!("ICMP type={}", transport[0]),
                    }
                } else { "ICMP".into() };
                (src_ip, dst_ip, "ICMP".into(), None, None, info)
            }
            6 => {  // TCP
                if transport.len() < 20 { return (src_ip, dst_ip, "TCP".into(), None, None, "TCP (short)".into()); }
                let sp = u16::from_be_bytes([transport[0], transport[1]]);
                let dp = u16::from_be_bytes([transport[2], transport[3]]);
                let seq = u32::from_be_bytes([transport[4],transport[5],transport[6],transport[7]]);
                let flags = transport[13];
                let flag_str = fmt_tcp_flags(flags);
                let proto = match dp { 80|8080 => "HTTP", 443 => "HTTPS", _ => "TCP" };
                let info = format!("{} → {} [{}] Seq={}", sp, dp, flag_str, seq);
                (src_ip, dst_ip, proto.into(), Some(sp), Some(dp), info)
            }
            17 => { // UDP
                if transport.len() < 8 { return (src_ip, dst_ip, "UDP".into(), None, None, "UDP (short)".into()); }
                let sp = u16::from_be_bytes([transport[0], transport[1]]);
                let dp = u16::from_be_bytes([transport[2], transport[3]]);
                let proto = match (sp, dp) { (53,_)|(_,53) => "DNS", (67,_)|(_,67)|(_,68)|(68,_) => "DHCP", _ => "UDP" };
                let info = format!("{} → {} Len={}", sp, dp, transport.len() - 8);
                (src_ip, dst_ip, proto.into(), Some(sp), Some(dp), info)
            }
            _ => (src_ip, dst_ip, format!("IP({})", proto_num), None, None, "Unknown IP protocol".into())
        }
    }

    fn fmt_ip(b: &[u8]) -> String {
        if b.len() < 4 { return "0.0.0.0".into(); }
        format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
    }

    fn fmt_tcp_flags(f: u8) -> String {
        let mut v = Vec::new();
        if f & 0x02 != 0 { v.push("SYN"); }
        if f & 0x10 != 0 { v.push("ACK"); }
        if f & 0x08 != 0 { v.push("PSH"); }
        if f & 0x01 != 0 { v.push("FIN"); }
        if f & 0x04 != 0 { v.push("RST"); }
        if v.is_empty() { "NONE".into() } else { v.join(", ") }
    }
}

/// Stub — compiled when real-capture feature is NOT enabled.
#[cfg(not(feature = "real-capture"))]
pub mod live {
    pub fn list_devices() -> Vec<String> { vec![] }
}
