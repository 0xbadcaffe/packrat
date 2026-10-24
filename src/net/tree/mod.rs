// Build a protocol dissector tree for a packet (for the UI detail pane).
#![allow(dead_code, unused_parens)]
use crate::net::packet::{FieldColor, Packet, TreeField, TreeSection, make_field};

const DNS_NAMES: &[&str] = &[
    "google.com",
    "github.com",
    "api.stripe.com",
    "fonts.googleapis.com",
    "cdn.cloudflare.com",
];

// ─── Byte-parsing helpers ─────────────────────────────────────────────────────

fn parse_mac(b: &[u8], off: usize) -> String {
    if b.len() >= off + 6 {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[off],
            b[off + 1],
            b[off + 2],
            b[off + 3],
            b[off + 4],
            b[off + 5]
        )
    } else {
        "??:??:??:??:??:??".into()
    }
}

fn u8_at(b: &[u8], off: usize) -> u8 {
    b.get(off).copied().unwrap_or(0)
}

fn u16_be(b: &[u8], off: usize) -> u16 {
    if b.len() >= off + 2 {
        u16::from_be_bytes([b[off], b[off + 1]])
    } else {
        0
    }
}

fn u32_be(b: &[u8], off: usize) -> u32 {
    if b.len() >= off + 4 {
        u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
    } else {
        0
    }
}

fn u64_be(b: &[u8], off: usize) -> u64 {
    if b.len() >= off + 8 {
        u64::from_be_bytes([
            b[off],
            b[off + 1],
            b[off + 2],
            b[off + 3],
            b[off + 4],
            b[off + 5],
            b[off + 6],
            b[off + 7],
        ])
    } else {
        0
    }
}

/// Stable index from packet number — never changes on re-render.
fn stable(pkt_no: u64, max: usize) -> usize {
    if max == 0 {
        return 0;
    }
    (pkt_no.wrapping_mul(2654435761u64) as usize) % max
}

/// NTP fixed-point seconds (NTP epoch) → unix timestamp string.
fn ntp_ts(secs: u64) -> String {
    let unix = secs.saturating_sub(2_208_988_800);
    format!("{}.000000000", unix)
}

/// Format TCP flags byte as string.
fn fmt_tcp_flags(f: u8) -> String {
    let mut s = String::new();
    if f & 0x02 != 0 {
        s.push_str("SYN ");
    }
    if f & 0x10 != 0 {
        s.push_str("ACK ");
    }
    if f & 0x01 != 0 {
        s.push_str("FIN ");
    }
    if f & 0x04 != 0 {
        s.push_str("RST ");
    }
    if f & 0x08 != 0 {
        s.push_str("PSH ");
    }
    if f & 0x20 != 0 {
        s.push_str("URG ");
    }
    if s.is_empty() {
        s.push_str("NONE");
    }
    s.trim_end().to_string()
}

/// Stub shown for application-layer protocols that are not decoded in live-capture mode.
fn app_payload_stub() -> TreeSection {
    TreeSection {
        title: "Application Data".into(),
        expanded: false,
        fields: vec![tf(
            "Note:",
            "Protocol fields not decoded in live mode. Use simulated mode or a PCAP import to see decoded fields.",
            FieldColor::Default,
        )],
    }
}

pub fn build_tree(pkt: &Packet, is_simulated: bool) -> Vec<TreeSection> {
    if !is_simulated {
        let mut sections: Vec<TreeSection> = Vec::new();
        for field in crate::analysis::packet_fields::extract_fields(pkt) {
            if sections
                .last()
                .is_none_or(|section| section.title != field.layer)
            {
                sections.push(TreeSection {
                    title: field.layer.clone(),
                    fields: Vec::new(),
                    expanded: true,
                });
            }
            if let Some(section) = sections.last_mut() {
                section
                    .fields
                    .push(make_field(&field.label, &field.value, FieldColor::Default));
            }
        }
        return sections;
    }
    let raw = &pkt.bytes;
    let eth_extra = match (pkt.outer_vlan_id.is_some(), pkt.vlan_id.is_some()) {
        (true, _) => 8usize,     // QinQ: two 4-byte tags
        (false, true) => 4usize, // single tag
        (false, false) => 0usize,
    };
    let ip_off = 14 + eth_extra;
    let ihl = (u8_at(raw, ip_off) & 0x0F) as usize * 4;
    let tp_off = ip_off + ihl.max(20);
    let mut sections = base::base_layers(pkt);

    match pkt.protocol.as_str() {
        "ICMP" | "ICMPv6" => icmp_dns_dhcp::icmp(raw, tp_off, &mut sections),
        "DNS" | "mDNS" => icmp_dns_dhcp::dns(pkt, &mut sections),
        "DHCP" => icmp_dns_dhcp::dhcp(pkt, &mut sections),
        "NTP" => ntp_quic_tcp::ntp(pkt, &mut sections),
        "QUIC" => ntp_quic_tcp::quic(pkt, &mut sections),
        proto
            if matches!(
                proto,
                "TCP" | "HTTP" | "HTTPS" | "TLS" | "SSH" | "MySQL" | "Redis" | "PostgreSQL"
            ) =>
        {
            ntp_quic_tcp::tcp(pkt, raw, tp_off, &mut sections, proto)
        }
        proto if matches!(proto, "UDP" | "SNMP") => udp_modbus_mqtt::udp(pkt, &mut sections),
        "Modbus" => udp_modbus_mqtt::modbus(pkt, &mut sections),
        "MQTT" | "MQTT-TLS" => udp_modbus_mqtt::mqtt(pkt, &mut sections),
        "OPC-UA" => opc_ua_dnp3_coap::opc_ua(pkt, &mut sections),
        "DNP3" => opc_ua_dnp3_coap::dnp3(pkt, &mut sections),
        "CoAP" | "CoAP-DTLS" => opc_ua_dnp3_coap::coap(pkt, &mut sections),
        "BACnet" => bacnet_s7comm_ethernet_ip::bacnet(pkt, &mut sections),
        "S7comm" => bacnet_s7comm_ethernet_ip::s7comm(pkt, &mut sections),
        "EtherNet/IP" => bacnet_s7comm_ethernet_ip::ethernet_ip(pkt, &mut sections),
        "PTP" => ptp_sip::ptp(pkt, &mut sections),
        "SIP" | "SIPS" => ptp_sip::sip(pkt, &mut sections),
        "BGP" => bgp_ftp_telnet::bgp(pkt, &mut sections),
        "FTP" => bgp_ftp_telnet::ftp(pkt, &mut sections),
        "Telnet" => bgp_ftp_telnet::telnet(pkt, &mut sections),
        "LDAP" => ldap_dhcpv6_vxlan::ldap(pkt, &mut sections),
        "DHCPv6" => ldap_dhcpv6_vxlan::dhcpv6(pkt, &mut sections),
        "VXLAN" => ldap_dhcpv6_vxlan::vxlan(pkt, &mut sections),
        "WireGuard" => wireguard_gre_igmp_vrrp_esp::wireguard(pkt, &mut sections),
        "GRE" => wireguard_gre_igmp_vrrp_esp::gre(pkt, &mut sections),
        "IGMP" => wireguard_gre_igmp_vrrp_esp::igmp(pkt, &mut sections),
        "VRRP" => wireguard_gre_igmp_vrrp_esp::vrrp(pkt, &mut sections),
        "ESP" => wireguard_gre_igmp_vrrp_esp::esp(pkt, &mut sections),
        "AH" => ah_gtp_radius_doip::ah(pkt, &mut sections),
        "GTP" => ah_gtp_radius_doip::gtp(pkt, &mut sections),
        "Radius" => ah_gtp_radius_doip::radius(pkt, &mut sections),
        "DoIP" => ah_gtp_radius_doip::doip(pkt, &mut sections),
        "SOME/IP" => some_ip_mpls_pppoe_wol_smb::some_ip(pkt, &mut sections),
        "MPLS" => some_ip_mpls_pppoe_wol_smb::mpls(pkt, &mut sections),
        "PPPoE" => some_ip_mpls_pppoe_wol_smb::pppoe(pkt, &mut sections),
        "WoL" => some_ip_mpls_pppoe_wol_smb::wol(pkt, &mut sections),
        "SMB" => some_ip_mpls_pppoe_wol_smb::smb(pkt, &mut sections),
        "RDP" => rdp_kerberos_netbios_ssn::rdp(pkt, &mut sections),
        "Kerberos" => rdp_kerberos_netbios_ssn::kerberos(pkt, &mut sections),
        "NetBIOS-SSN" => rdp_kerberos_netbios_ssn::netbios_ssn(pkt, &mut sections),
        "RTSP" => rtsp_kafka_amqp::rtsp(pkt, &mut sections),
        "Kafka" => rtsp_kafka_amqp::kafka(pkt, &mut sections),
        "AMQP" => rtsp_kafka_amqp::amqp(pkt, &mut sections),
        "NATS" => nats_memcached_vnc::nats(pkt, &mut sections),
        "Memcached" => nats_memcached_vnc::memcached(pkt, &mut sections),
        "VNC" => nats_memcached_vnc::vnc(pkt, &mut sections),
        "Docker" => docker_prometheus_etcd::docker(pkt, &mut sections),
        "Prometheus" => docker_prometheus_etcd::prometheus(pkt, &mut sections),
        "etcd" => docker_prometheus_etcd::etcd(pkt, &mut sections),
        "NBNS" => nbns_tftp_stun::nbns(pkt, &mut sections),
        "TFTP" => nbns_tftp_stun::tftp(pkt, &mut sections),
        "STUN" => nbns_tftp_stun::stun(pkt, &mut sections),
        "SSDP" => ssdp_rip_rtp::ssdp(pkt, &mut sections),
        "RIP" => ssdp_rip_rtp::rip(pkt, &mut sections),
        "RTP" => ssdp_rip_rtp::rtp(pkt, &mut sections),
        "OSPF" => ospf_eigrp_pim::ospf(pkt, &mut sections),
        "EIGRP" => ospf_eigrp_pim::eigrp(pkt, &mut sections),
        "PIM" => ospf_eigrp_pim::pim(pkt, &mut sections),
        _ => {}
    }

    // ── Real-capture mode: strip fake application-layer sections ─────────────
    // Only the base protocol layers (Ethernet, IP, TCP/UDP, ICMP) read from real
    // bytes. Every application-layer section above that is synthesized from hash
    // functions for simulation purposes and must not be shown on real traffic.
    if !is_simulated {
        // Titles that come from real-byte parsing and are safe to show.
        const REAL_PREFIXES: &[&str] = &[
            "Frame ",
            "802.1Q",
            "Ethernet",
            "Address Resolution Protocol",
            "Internet Protocol",
            "Transmission Control Protocol",
            "User Datagram Protocol",
            "Internet Control Message Protocol",
        ];
        let before = sections.len();
        sections.retain(|s| REAL_PREFIXES.iter().any(|p| s.title.starts_with(p)));
        if sections.len() < before {
            sections.push(app_payload_stub());
        }
    }

    sections
}

fn tf(key: &str, val: &str, color: FieldColor) -> TreeField {
    make_field(key, val, color)
}

mod ah_gtp_radius_doip;
mod bacnet_s7comm_ethernet_ip;
mod base;
mod bgp_ftp_telnet;
mod docker_prometheus_etcd;
mod icmp_dns_dhcp;
mod ldap_dhcpv6_vxlan;
mod nats_memcached_vnc;
mod nbns_tftp_stun;
mod ntp_quic_tcp;
mod opc_ua_dnp3_coap;
mod ospf_eigrp_pim;
mod ptp_sip;
mod rdp_kerberos_netbios_ssn;
mod rtsp_kafka_amqp;
mod some_ip_mpls_pppoe_wol_smb;
mod ssdp_rip_rtp;
mod udp_modbus_mqtt;
mod wireguard_gre_igmp_vrrp_esp;
