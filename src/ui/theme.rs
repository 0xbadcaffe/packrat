use ratatui::style::Color;
use crate::net::packet::FieldColor;

pub const C_CYAN:    Color = Color::Rgb(95, 215, 215);
pub const C_GREEN:   Color = Color::Rgb(135, 215, 0);
pub const C_YELLOW:  Color = Color::Rgb(215, 175, 0);
pub const C_RED:     Color = Color::Rgb(215, 95, 95);
pub const C_MAGENTA: Color = Color::Rgb(175, 135, 215);
pub const C_ORANGE:  Color = Color::Rgb(215, 135, 95);
pub const C_FG:      Color = Color::Rgb(212, 212, 212);
pub const C_FG2:     Color = Color::Rgb(154, 154, 154);
pub const C_FG3:     Color = Color::Rgb(90, 90, 90);
pub const C_BG:      Color = Color::Rgb(28, 28, 28);
pub const C_BG2:     Color = Color::Rgb(36, 36, 36);
pub const C_BG3:     Color = Color::Rgb(44, 44, 44);
pub const C_SEL_BG:  Color = Color::Rgb(0, 95, 95);
pub const C_BORDER:  Color = Color::Rgb(68, 68, 68);

pub fn proto_color(proto: &str) -> Color {
    match proto {
        "TCP"                        => C_CYAN,
        "UDP"                        => C_GREEN,
        "DNS" | "mDNS"               => C_YELLOW,
        "HTTP"                       => C_ORANGE,
        "HTTPS" | "TLS"              => C_MAGENTA,
        "ARP"                        => C_FG2,
        "ICMP" | "ICMPv6"            => C_RED,
        "DHCP"                       => C_YELLOW,
        "SSH"                        => C_GREEN,
        "QUIC"                       => C_MAGENTA,
        "NTP"                        => C_FG2,
        // Industrial / OT
        "Modbus"                     => C_ORANGE,
        "MQTT" | "MQTT-TLS"          => C_GREEN,
        "OPC-UA"                     => C_MAGENTA,
        "CoAP" | "CoAP-DTLS"         => C_CYAN,
        "BACnet"                     => C_YELLOW,
        "DNP3" | "IEC-104"           => C_RED,
        "S7comm"                     => C_ORANGE,
        "EtherNet/IP"                => C_CYAN,
        // Network infrastructure
        "PTP"                        => C_CYAN,
        "BGP"                        => C_ORANGE,
        "FTP"                        => C_GREEN,
        "Telnet"                     => C_YELLOW,
        "SIP" | "SIPS"               => C_CYAN,
        "LDAP"                       => C_CYAN,
        "Radius"                     => C_ORANGE,
        "DoIP"                       => C_ORANGE,
        "SOME/IP"                    => C_MAGENTA,
        "GRE"                        => C_FG2,
        "GTP"                        => C_MAGENTA,
        "IGMP"                       => C_YELLOW,
        "VRRP"                       => C_RED,
        "ESP" | "AH"                 => C_MAGENTA,
        "MPLS"                       => C_FG2,
        "PPPoE"                      => C_FG2,
        "VXLAN"                      => C_CYAN,
        "WireGuard"                  => C_GREEN,
        "DHCPv6"                     => C_YELLOW,
        "WoL"                        => C_YELLOW,
        "STP"                        => C_YELLOW,
        "SMB"         => C_ORANGE,
        "RDP"         => C_MAGENTA,
        "Kerberos"    => C_YELLOW,
        "NetBIOS-SSN" => C_FG2,
        "RTSP"        => C_CYAN,
        "Kafka"       => C_GREEN,
        "AMQP"        => C_ORANGE,
        "NATS"        => C_CYAN,
        "Memcached"   => C_GREEN,
        "VNC"         => C_MAGENTA,
        "Docker"      => C_CYAN,
        "Prometheus"  => C_ORANGE,
        "etcd"        => C_GREEN,
        "NBNS"        => C_YELLOW,
        "TFTP"        => C_FG2,
        "STUN"        => C_CYAN,
        "SSDP"        => C_YELLOW,
        "RIP"         => C_ORANGE,
        "RTP"         => C_GREEN,
        "OSPF"        => C_ORANGE,
        "EIGRP"       => C_RED,
        "PIM"         => C_MAGENTA,
        _                            => C_FG,
    }
}

pub fn field_color(fc: &FieldColor) -> Color {
    match fc {
        FieldColor::Cyan    => C_CYAN,
        FieldColor::Green   => C_GREEN,
        FieldColor::Yellow  => C_YELLOW,
        FieldColor::Red     => C_RED,
        FieldColor::Magenta => C_MAGENTA,
        FieldColor::Orange  => C_ORANGE,
        FieldColor::Default => C_FG,
    }
}
