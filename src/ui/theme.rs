//! Theme system — runtime-switchable colour palettes.
#![allow(non_snake_case)]
//!
//! All UI code reads colours through the `C_*()` functions defined here.
//! Call `set_theme()` before each render pass (from `ui::draw`) to apply
//! the active theme.  The backing thread-local is set once per frame so
//! every widget in the same frame sees a coherent palette.

use std::cell::RefCell;
use ratatui::style::Color;
use crate::net::packet::FieldColor;

// ─── Palette ──────────────────────────────────────────────────────────────────

/// All semantic colour slots used by the UI.
#[derive(Debug, Clone)]
pub struct ThemePalette {
    pub bg:      Color,
    pub bg2:     Color,
    pub bg3:     Color,
    pub border:  Color,
    pub sel_bg:  Color,
    pub fg:      Color,
    pub fg2:     Color,
    pub fg3:     Color,
    pub cyan:    Color,
    pub green:   Color,
    pub yellow:  Color,
    pub red:     Color,
    pub magenta: Color,
    pub orange:  Color,
}

impl ThemePalette {
    // ── Built-in themes ───────────────────────────────────────────────────────

    pub fn dark_pro() -> Self {
        Self {
            bg:      Color::Rgb(28,  28,  28),
            bg2:     Color::Rgb(36,  36,  36),
            bg3:     Color::Rgb(44,  44,  44),
            border:  Color::Rgb(68,  68,  68),
            sel_bg:  Color::Rgb(0,   95,  95),
            fg:      Color::Rgb(212, 212, 212),
            fg2:     Color::Rgb(154, 154, 154),
            fg3:     Color::Rgb(90,  90,  90),
            cyan:    Color::Rgb(95,  215, 215),
            green:   Color::Rgb(135, 215, 0),
            yellow:  Color::Rgb(215, 175, 0),
            red:     Color::Rgb(215, 95,  95),
            magenta: Color::Rgb(175, 135, 215),
            orange:  Color::Rgb(215, 135, 95),
        }
    }

    pub fn white_classic() -> Self {
        Self {
            bg:      Color::Rgb(248, 248, 248),
            bg2:     Color::Rgb(240, 240, 240),
            bg3:     Color::Rgb(228, 228, 228),
            border:  Color::Rgb(192, 192, 192),
            sel_bg:  Color::Rgb(178, 208, 232),
            fg:      Color::Rgb(20,  20,  20),
            fg2:     Color::Rgb(74,  74,  74),
            fg3:     Color::Rgb(136, 136, 136),
            cyan:    Color::Rgb(0,   107, 107),
            green:   Color::Rgb(26,  122, 0),
            yellow:  Color::Rgb(139, 105, 20),
            red:     Color::Rgb(204, 34,  0),
            magenta: Color::Rgb(123, 61,  160),
            orange:  Color::Rgb(176, 69,  0),
        }
    }

    pub fn matrix_green() -> Self {
        Self {
            bg:      Color::Rgb(0,  0,   0),
            bg2:     Color::Rgb(6,  14,  6),
            bg3:     Color::Rgb(10, 22,  10),
            border:  Color::Rgb(20, 60,  20),
            sel_bg:  Color::Rgb(0,  50,  0),
            fg:      Color::Rgb(0,  204, 68),
            fg2:     Color::Rgb(0,  119, 34),
            fg3:     Color::Rgb(0,  51,  17),
            cyan:    Color::Rgb(0,  255, 136),
            green:   Color::Rgb(0,  221, 0),
            yellow:  Color::Rgb(136, 255, 0),
            red:     Color::Rgb(255, 51, 0),
            magenta: Color::Rgb(136, 255, 136),
            orange:  Color::Rgb(170, 255, 34),
        }
    }

    pub fn vscode_dark() -> Self {
        Self {
            bg:      Color::Rgb(30,  30,  30),
            bg2:     Color::Rgb(37,  37,  38),
            bg3:     Color::Rgb(45,  45,  45),
            border:  Color::Rgb(68,  68,  68),
            sel_bg:  Color::Rgb(38,  79,  120),
            fg:      Color::Rgb(212, 212, 212),
            fg2:     Color::Rgb(154, 154, 154),
            fg3:     Color::Rgb(106, 106, 106),
            cyan:    Color::Rgb(79,  193, 255),
            green:   Color::Rgb(106, 153, 85),
            yellow:  Color::Rgb(220, 220, 170),
            red:     Color::Rgb(244, 71,  71),
            magenta: Color::Rgb(197, 134, 192),
            orange:  Color::Rgb(206, 145, 120),
        }
    }

    pub fn vscode_light() -> Self {
        Self {
            bg:      Color::Rgb(255, 255, 255),
            bg2:     Color::Rgb(243, 243, 243),
            bg3:     Color::Rgb(232, 232, 232),
            border:  Color::Rgb(200, 200, 200),
            sel_bg:  Color::Rgb(173, 214, 255),
            fg:      Color::Rgb(0,   0,   0),
            fg2:     Color::Rgb(68,  68,  68),
            fg3:     Color::Rgb(138, 138, 138),
            cyan:    Color::Rgb(0,   112, 193),
            green:   Color::Rgb(9,   134, 88),
            yellow:  Color::Rgb(120, 83,  0),
            red:     Color::Rgb(205, 49,  49),
            magenta: Color::Rgb(175, 0,   219),
            orange:  Color::Rgb(163, 21,  21),
        }
    }
}

// ─── Theme registry ───────────────────────────────────────────────────────────

pub const THEME_NAMES: &[&str] = &[
    "Dark Pro",
    "White Classic",
    "Matrix Green",
    "VSCode Dark",
    "VSCode Light",
];

pub fn palette_by_name(name: &str) -> ThemePalette {
    match name {
        "White Classic" => ThemePalette::white_classic(),
        "Matrix Green"  => ThemePalette::matrix_green(),
        "VSCode Dark"   => ThemePalette::vscode_dark(),
        "VSCode Light"  => ThemePalette::vscode_light(),
        _               => ThemePalette::dark_pro(),   // default / "Dark Pro"
    }
}

// ─── Thread-local active palette ─────────────────────────────────────────────

thread_local! {
    static PALETTE: RefCell<ThemePalette> = RefCell::new(ThemePalette::dark_pro());
}

/// Set the active theme for this thread (call once at the top of each `draw()`).
pub fn set_theme(p: ThemePalette) {
    PALETTE.with(|cell| *cell.borrow_mut() = p);
}

// ─── Colour accessor functions ────────────────────────────────────────────────
// These replace the old `pub const C_*` values.
// The SCREAMING_SNAKE_CASE names are intentional (mirrors the old const names
// so all existing call-sites read identically).
pub fn C_CYAN()   -> Color { PALETTE.with(|p| p.borrow().cyan) }
pub fn C_GREEN()  -> Color { PALETTE.with(|p| p.borrow().green) }
pub fn C_YELLOW() -> Color { PALETTE.with(|p| p.borrow().yellow) }
pub fn C_RED()    -> Color { PALETTE.with(|p| p.borrow().red) }
pub fn C_MAGENTA()-> Color { PALETTE.with(|p| p.borrow().magenta) }
pub fn C_ORANGE() -> Color { PALETTE.with(|p| p.borrow().orange) }
pub fn C_FG()     -> Color { PALETTE.with(|p| p.borrow().fg) }
pub fn C_FG2()    -> Color { PALETTE.with(|p| p.borrow().fg2) }
pub fn C_FG3()    -> Color { PALETTE.with(|p| p.borrow().fg3) }
pub fn C_BG()     -> Color { PALETTE.with(|p| p.borrow().bg) }
pub fn C_BG2()    -> Color { PALETTE.with(|p| p.borrow().bg2) }
pub fn C_BG3()    -> Color { PALETTE.with(|p| p.borrow().bg3) }
pub fn C_SEL_BG() -> Color { PALETTE.with(|p| p.borrow().sel_bg) }
pub fn C_BORDER() -> Color { PALETTE.with(|p| p.borrow().border) }

// ─── Protocol / field colours ─────────────────────────────────────────────────

pub fn proto_color(proto: &str) -> Color {
    match proto {
        "TCP"                        => C_CYAN(),
        "UDP"                        => C_GREEN(),
        "DNS" | "mDNS"               => C_YELLOW(),
        "HTTP"                       => C_ORANGE(),
        "HTTPS" | "TLS"              => C_MAGENTA(),
        "ARP"                        => C_FG2(),
        "ICMP" | "ICMPv6"            => C_RED(),
        "DHCP"                       => C_YELLOW(),
        "SSH"                        => C_GREEN(),
        "QUIC"                       => C_MAGENTA(),
        "NTP"                        => C_FG2(),
        "Modbus"                     => C_ORANGE(),
        "MQTT" | "MQTT-TLS"          => C_GREEN(),
        "OPC-UA"                     => C_MAGENTA(),
        "CoAP" | "CoAP-DTLS"         => C_CYAN(),
        "BACnet"                     => C_YELLOW(),
        "DNP3" | "IEC-104"           => C_RED(),
        "S7comm"                     => C_ORANGE(),
        "EtherNet/IP"                => C_CYAN(),
        "PTP"                        => C_CYAN(),
        "BGP"                        => C_ORANGE(),
        "FTP"                        => C_GREEN(),
        "Telnet"                     => C_YELLOW(),
        "SIP" | "SIPS"               => C_CYAN(),
        "LDAP"                       => C_CYAN(),
        "Radius"                     => C_ORANGE(),
        "DoIP"                       => C_ORANGE(),
        "SOME/IP"                    => C_MAGENTA(),
        "GRE"                        => C_FG2(),
        "GTP"                        => C_MAGENTA(),
        "IGMP"                       => C_YELLOW(),
        "VRRP"                       => C_RED(),
        "ESP" | "AH"                 => C_MAGENTA(),
        "MPLS"                       => C_FG2(),
        "PPPoE"                      => C_FG2(),
        "VXLAN"                      => C_CYAN(),
        "WireGuard"                  => C_GREEN(),
        "DHCPv6"                     => C_YELLOW(),
        "WoL"                        => C_YELLOW(),
        "STP"                        => C_YELLOW(),
        "SMB"                        => C_ORANGE(),
        "RDP"                        => C_MAGENTA(),
        "Kerberos"                   => C_YELLOW(),
        "NetBIOS-SSN"                => C_FG2(),
        "RTSP"                       => C_CYAN(),
        "Kafka"                      => C_GREEN(),
        "AMQP"                       => C_ORANGE(),
        "NATS"                       => C_CYAN(),
        "Memcached"                  => C_GREEN(),
        "VNC"                        => C_MAGENTA(),
        "Docker"                     => C_CYAN(),
        "Prometheus"                 => C_ORANGE(),
        "etcd"                       => C_GREEN(),
        "NBNS"                       => C_YELLOW(),
        "TFTP"                       => C_FG2(),
        "STUN"                       => C_CYAN(),
        "SSDP"                       => C_YELLOW(),
        "RIP"                        => C_ORANGE(),
        "RTP"                        => C_GREEN(),
        "OSPF"                       => C_ORANGE(),
        "EIGRP"                      => C_RED(),
        "PIM"                        => C_MAGENTA(),
        _                            => C_FG(),
    }
}

pub fn field_color(fc: &FieldColor) -> Color {
    match fc {
        FieldColor::Cyan    => C_CYAN(),
        FieldColor::Green   => C_GREEN(),
        FieldColor::Yellow  => C_YELLOW(),
        FieldColor::Red     => C_RED(),
        FieldColor::Magenta => C_MAGENTA(),
        FieldColor::Orange  => C_ORANGE(),
        FieldColor::Default => C_FG(),
    }
}
