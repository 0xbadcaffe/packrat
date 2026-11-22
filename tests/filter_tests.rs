//! Tests for the display filter parser and evaluator.

use packrat_tui::analysis::display_filter::{self, EvalCtx};
#[cfg(feature = "terminal-ui")]
use packrat_tui::app::App;
use packrat_tui::net::packet::Packet;

fn pkt(proto: &str, src: &str, dst: &str, sport: Option<u16>, dport: Option<u16>,
       info: &str, len: u16) -> Packet {
    Packet { capture: None,
        no: 1,
        timestamp: 0.0,
        src: src.into(),
        dst: dst.into(),
        protocol: proto.into(),
        length: len,
        info: info.into(),
        src_port: sport,
        dst_port: dport,
        vlan_id: None,
        vlan_pcp: None,
        vlan_dei: None,
        outer_vlan_id: None,
        bytes: vec![0u8; len as usize],
    }
}

fn ctx<'a>(p: &'a Packet) -> EvalCtx<'a> {
    EvalCtx { pkt: p, marked: false, tags: &[] }
}

fn ctx_tagged<'a>(p: &'a Packet, tags: &'a [String]) -> EvalCtx<'a> {
    EvalCtx { pkt: p, marked: false, tags }
}

fn ctx_marked<'a>(p: &'a Packet) -> EvalCtx<'a> {
    EvalCtx { pkt: p, marked: true, tags: &[] }
}

#[test]
#[cfg(feature = "terminal-ui")]
fn app_ingest_uses_advanced_display_filter_for_new_packets() {
    let mut app = App::new_for_test();
    app.filter.input = "tcp.dstport == 443".into();
    app.rebuild_filtered();

    app.inject_packet(pkt("TCP", "10.0.0.1", "10.0.0.2", Some(50000), Some(80), "", 60));
    app.inject_packet(pkt("TCP", "10.0.0.1", "10.0.0.2", Some(50001), Some(443), "", 60));

    assert_eq!(app.packets.len(), 2);
    assert_eq!(app.filtered.len(), 1);
    assert_eq!(app.selected_packet().and_then(|p| p.dst_port), Some(443));
}

#[test]
#[cfg(feature = "terminal-ui")]
fn app_rebuild_bare_ip_filter_matches_addresses() {
    let mut app = App::new_for_test();
    app.inject_packet(pkt("TCP", "192.168.1.50", "203.0.113.7", Some(50000), Some(4444), "", 60));
    app.inject_packet(pkt("TCP", "192.168.1.50", "198.51.100.1", Some(50001), Some(443), "", 60));

    app.filter.input = "203.0.113.7".into();
    app.rebuild_filtered();

    assert_eq!(app.filtered.len(), 1);
    assert_eq!(app.selected_packet().map(|p| p.dst.as_str()), Some("203.0.113.7"));
}

// ── Parser: valid expressions ─────────────────────────────────────────────────

#[test]
fn parse_bare_proto() {
    assert!(display_filter::parse("tcp").is_ok());
    assert!(display_filter::parse("http").is_ok());
    assert!(display_filter::parse("dns").is_ok());
    assert!(display_filter::parse("ARP").is_ok());
}

#[test]
fn parse_not_proto() {
    assert!(display_filter::parse("not tcp").is_ok());
    assert!(display_filter::parse("!udp").is_ok());
}

#[test]
fn parse_and_or() {
    assert!(display_filter::parse("tcp and ip.src == 1.2.3.4").is_ok());
    assert!(display_filter::parse("tcp or udp").is_ok());
    assert!(display_filter::parse("tcp || udp").is_ok());
    assert!(display_filter::parse("tcp && dns").is_ok());
}

#[test]
fn parse_comparison_ops() {
    assert!(display_filter::parse("frame.len > 100").is_ok());
    assert!(display_filter::parse("frame.len >= 100").is_ok());
    assert!(display_filter::parse("frame.len < 100").is_ok());
    assert!(display_filter::parse("frame.len <= 100").is_ok());
    assert!(display_filter::parse("frame.len == 100").is_ok());
    assert!(display_filter::parse("frame.len != 100").is_ok());
}

#[test]
fn parse_contains() {
    assert!(display_filter::parse("dns.qname contains \"evil.com\"").is_ok());
    assert!(display_filter::parse("http.host ~ \"api\"").is_ok());
}

#[test]
fn parse_in_set() {
    assert!(display_filter::parse("tcp.dstport in [80,443,8080]").is_ok());
    let frames = display_filter::parse("frame.number in[65,117]").unwrap();
    let mut packet = pkt("TCP", "192.0.2.1", "192.0.2.2", None, None, "", 60);
    for (number, expected) in [(65, true), (117, true), (118, false)] {
        packet.no = number;
        assert_eq!(display_filter::eval(&frames, &ctx(&packet)), expected);
    }
    assert!(display_filter::parse("ip.src in [ \"192.0.2.1\", \"192.0.2.2\" ]").is_ok());
}

#[test]
fn set_filter_parsing_terminates_on_partial_and_invalid_input() {
    let (sender, receiver) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let expression = "frame.number in [65,117,177]";
        for end in 0..expression.len() {
            let _ = display_filter::parse(&expression[..end]);
        }
        assert!(display_filter::parse(expression).is_ok());
        for value in ["[", "[65", "[65,", "[word]", "[65 117]", "65]", "[65,]"] {
            let input = format!("frame.number in {value}");
            assert!(display_filter::parse(&input).is_err(), "{input}");
        }
        sender.send(()).unwrap();
    });
    receiver.recv_timeout(std::time::Duration::from_secs(2))
        .expect("set parser must return for every incomplete and malformed input");
    worker.join().unwrap();
}

#[test]
fn display_filter_bounds_input_tree_and_set_size() {
    let limit = display_filter::MAX_DISPLAY_FILTER_BYTES;
    assert!(display_filter::parse(&"t".repeat(limit)).is_ok());
    assert!(display_filter::parse(&"t".repeat(limit + 1)).unwrap_err().0.contains("bytes"));

    for nesting in [0, 16, 32] {
        assert!(display_filter::parse(&format!("{}tcp{}", "(".repeat(nesting), ")".repeat(nesting))).is_ok());
        assert!(display_filter::parse(&format!("{}tcp", "!".repeat(nesting))).is_ok());
    }
    for expression in [format!("{}tcp{}", "(".repeat(33), ")".repeat(33)), format!("{}tcp", "!".repeat(33))] {
        assert!(display_filter::parse(&expression).unwrap_err().0.contains("nesting"));
    }
    for op in [" and ", " or "] {
        let allowed = vec!["tcp"; 64].join(op);
        let expr = display_filter::parse(&allowed).unwrap();
        let packet = pkt("TCP", "192.0.2.1", "192.0.2.2", None, None, "", 60);
        assert!(display_filter::eval(&expr, &ctx(&packet)));
        assert!(display_filter::parse(&vec!["tcp"; 65].join(op)).unwrap_err().0.contains("terms"));
    }
    assert!(display_filter::parse(&format!("frame.number in [{}]", vec!["1"; 128].join(","))).is_ok());
    assert!(display_filter::parse(&format!("frame.number in [{}]", vec!["1"; 129].join(",")))
        .unwrap_err().0.contains("set has too many"));
}

#[test]
#[cfg(feature = "terminal-ui")]
fn display_filter_editor_routes_set_separators_before_settings_shortcut() {
    use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
    let key = |code| Event::Key(KeyEvent::new(code, KeyModifiers::NONE));
    let mut app = App::new_for_test();
    for no in 1..=3 {
        let mut packet = pkt("TCP", "192.0.2.1", "192.0.2.2", None, None, "", 60);
        packet.no = no;
        app.inject_packet(packet);
    }

    assert!(!packrat_tui::event::handle(&mut app, key(KeyCode::Char('/'))));
    assert!(app.filter.active);
    let expression = "frame.number in [1,3]";
    for ch in expression.chars() {
        assert!(!packrat_tui::event::handle(&mut app, key(KeyCode::Char(ch))));
        assert!(!app.settings_open);
    }
    assert!(!packrat_tui::event::handle(&mut app, key(KeyCode::Enter)));
    assert!(!app.filter.active);
    assert_eq!(app.filter.input, expression);
    assert_eq!(app.filtered.len(), 2);

    assert!(!packrat_tui::event::handle(&mut app, key(KeyCode::Char(','))));
    assert!(app.settings_open);
}

#[test]
#[cfg(feature = "terminal-ui")]
fn display_filter_editor_treats_printable_hotkeys_as_text() {
    use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
    let mut app = App::new_for_test();
    app.filter.active = true;

    for ch in ['?', 'P', '!', 'q'] {
        let key = KeyEvent::new(KeyCode::Char(ch), KeyModifiers::SHIFT);
        assert!(!packrat_tui::event::handle(&mut app, Event::Key(key)));
    }
    let ctrl_p = KeyEvent::new(KeyCode::Char('p'), KeyModifiers::CONTROL);
    assert!(!packrat_tui::event::handle(&mut app, Event::Key(ctrl_p)));
    assert_eq!(app.filter.input, "?P!q");
    assert!(!app.search_open);
    assert!(!app.project_manager_open);
}

#[test]
#[cfg(feature = "terminal-ui")]
fn display_filter_editor_keeps_oversized_input_out_of_capture_path() {
    use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
    let key = |code| Event::Key(KeyEvent::new(code, KeyModifiers::NONE));
    let mut app = App::new_for_test();
    app.filter.active = true;
    let limit = display_filter::MAX_DISPLAY_FILTER_BYTES;
    app.filter.input = "t".repeat(limit - 1);
    assert!(!packrat_tui::event::handle(&mut app, key(KeyCode::Char('\u{e9}'))));
    assert_eq!(app.filter.input.len(), limit - 1);
    assert!(!packrat_tui::event::handle(&mut app, key(KeyCode::Char('x'))));
    assert_eq!(app.filter.input.len(), limit);
    assert!(!packrat_tui::event::handle(&mut app, key(KeyCode::Backspace)));
    assert_eq!(app.filter.input.len(), limit - 1);
}

#[test]
fn parse_marked() {
    assert!(display_filter::parse("marked == true").is_ok());
    assert!(display_filter::parse("marked == false").is_ok());
    assert!(display_filter::parse("marked").is_ok());
}

#[test]
fn parse_tag() {
    assert!(display_filter::parse("tag == \"suspicious\"").is_ok());
}

#[test]
fn parse_parenthesised() {
    assert!(display_filter::parse("(tcp or udp) and frame.len > 100").is_ok());
}

#[test]
fn parse_error_empty() {
    assert!(display_filter::parse("").is_err());
}

#[test]
fn parse_error_unclosed_string() {
    assert!(display_filter::parse("dns.qname contains \"unclosed").is_err());
}

// ── Evaluator: protocol matching ──────────────────────────────────────────────

#[test]
fn eval_proto_match() {
    let p = pkt("TCP", "1.2.3.4", "5.6.7.8", Some(1234), Some(80), "", 60);
    let expr = display_filter::parse("tcp").unwrap();
    assert!(display_filter::eval(&expr, &ctx(&p)));
}

#[test]
fn eval_proto_no_match() {
    let p = pkt("UDP", "1.2.3.4", "5.6.7.8", None, Some(53), "", 60);
    let expr = display_filter::parse("tcp").unwrap();
    assert!(!display_filter::eval(&expr, &ctx(&p)));
}

#[test]
fn eval_proto_case_insensitive() {
    let p = pkt("HTTP", "1.0.0.1", "2.0.0.2", Some(49000), Some(80), "GET /index.html", 200);
    let expr_lower = display_filter::parse("http").unwrap();
    let expr_upper = display_filter::parse("HTTP").unwrap();
    assert!(display_filter::eval(&expr_lower, &ctx(&p)));
    assert!(display_filter::eval(&expr_upper, &ctx(&p)));
}

#[test]
fn eval_not() {
    let p = pkt("UDP", "1.0.0.1", "2.0.0.2", None, Some(53), "", 60);
    let expr = display_filter::parse("not tcp").unwrap();
    assert!(display_filter::eval(&expr, &ctx(&p)));
}

// ── Evaluator: IP comparisons ─────────────────────────────────────────────────

#[test]
fn eval_ip_src_eq() {
    let p = pkt("TCP", "192.168.1.50", "203.0.113.7", Some(50000), Some(4444), "", 118);
    let expr = display_filter::parse("ip.src == 192.168.1.50").unwrap();
    assert!(display_filter::eval(&expr, &ctx(&p)));
}

#[test]
fn eval_ip_src_ne() {
    let p = pkt("TCP", "192.168.1.1", "203.0.113.7", Some(50000), Some(4444), "", 118);
    let expr = display_filter::parse("ip.src == 192.168.1.50").unwrap();
    assert!(!display_filter::eval(&expr, &ctx(&p)));
}

#[test]
fn eval_ip_dst_eq() {
    let p = pkt("TCP", "192.168.1.50", "203.0.113.7", Some(50000), Some(4444), "", 118);
    let expr = display_filter::parse("ip.dst == 203.0.113.7").unwrap();
    assert!(display_filter::eval(&expr, &ctx(&p)));
}

// ── Evaluator: port comparisons ───────────────────────────────────────────────

#[test]
fn eval_dst_port_eq() {
    let p = pkt("TCP", "10.0.0.1", "10.0.0.2", Some(54321), Some(443), "", 100);
    let expr = display_filter::parse("tcp.dstport == 443").unwrap();
    assert!(display_filter::eval(&expr, &ctx(&p)));
}

#[test]
fn eval_port_in_set() {
    let p = pkt("TCP", "10.0.0.1", "10.0.0.2", Some(54321), Some(8080), "", 100);
    let expr = display_filter::parse("tcp.dstport in [80,443,8080]").unwrap();
    assert!(display_filter::eval(&expr, &ctx(&p)));
}

#[test]
fn eval_tcp_port_matches_source_port() {
    let p = pkt("TCP", "10.0.0.1", "10.0.0.2", Some(8080), Some(22), "", 100);
    let expr = display_filter::parse("tcp.port == 8080").unwrap();
    assert!(display_filter::eval(&expr, &ctx(&p)));
}

#[test]
fn eval_deep_vlan_fields() {
    let mut p = pkt("TCP", "10.0.0.1", "10.0.0.2", Some(1234), Some(443), "", 100);
    p.vlan_id = Some(20);
    p.vlan_pcp = Some(7);
    p.vlan_dei = Some(1);
    p.outer_vlan_id = Some(100);

    assert!(display_filter::eval(&display_filter::parse("vlan.id == 20").unwrap(), &ctx(&p)));
    assert!(display_filter::eval(&display_filter::parse("vlan.pcp >= 6").unwrap(), &ctx(&p)));
    assert!(display_filter::eval(&display_filter::parse("vlan.dei == 1").unwrap(), &ctx(&p)));
    assert!(display_filter::eval(&display_filter::parse("vlan.outer_id == 100").unwrap(), &ctx(&p)));
    assert!(display_filter::eval(&display_filter::parse("vlan.qinq == true").unwrap(), &ctx(&p)));
}

#[test]
fn eval_port_not_in_set() {
    let p = pkt("TCP", "10.0.0.1", "10.0.0.2", Some(54321), Some(22), "", 100);
    let expr = display_filter::parse("tcp.dstport in [80,443,8080]").unwrap();
    assert!(!display_filter::eval(&expr, &ctx(&p)));
}

// ── Evaluator: frame length ───────────────────────────────────────────────────

#[test]
fn eval_frame_len_gt() {
    let p = pkt("TCP", "1.0.0.1", "2.0.0.2", None, None, "", 512);
    let expr = display_filter::parse("frame.len > 100").unwrap();
    assert!(display_filter::eval(&expr, &ctx(&p)));
}

#[test]
fn eval_frame_len_lt_fails() {
    let p = pkt("TCP", "1.0.0.1", "2.0.0.2", None, None, "", 50);
    let expr = display_filter::parse("frame.len > 100").unwrap();
    assert!(!display_filter::eval(&expr, &ctx(&p)));
}

// ── Evaluator: info/contains ──────────────────────────────────────────────────

#[test]
fn eval_info_contains() {
    let p = pkt("DNS", "192.168.1.50", "8.8.8.8", Some(54321), Some(53),
                "Query A evil-tunnel.com", 120);
    let expr = display_filter::parse("dns.qname contains \"evil-tunnel\"").unwrap();
    assert!(display_filter::eval(&expr, &ctx(&p)));
}

#[test]
fn eval_info_contains_no_match() {
    let p = pkt("DNS", "192.168.1.50", "8.8.8.8", Some(54321), Some(53),
                "Query A google.com", 74);
    let expr = display_filter::parse("dns.qname contains \"evil-tunnel\"").unwrap();
    assert!(!display_filter::eval(&expr, &ctx(&p)));
}

// ── Evaluator: marked / tag ───────────────────────────────────────────────────

#[test]
fn eval_marked_true() {
    let p = pkt("TCP", "1.0.0.1", "2.0.0.2", None, None, "", 60);
    let expr = display_filter::parse("marked == true").unwrap();
    assert!(display_filter::eval(&expr, &ctx_marked(&p)));
    assert!(!display_filter::eval(&expr, &ctx(&p)));
}

#[test]
fn eval_tag_match() {
    let p = pkt("TCP", "1.0.0.1", "2.0.0.2", None, None, "", 60);
    let tags = vec!["suspicious".to_string(), "c2".to_string()];
    let expr = display_filter::parse("tag == \"suspicious\"").unwrap();
    assert!(display_filter::eval(&expr, &ctx_tagged(&p, &tags)));
}

#[test]
fn eval_tag_no_match() {
    let p = pkt("TCP", "1.0.0.1", "2.0.0.2", None, None, "", 60);
    let tags: Vec<String> = vec![];
    let expr = display_filter::parse("tag == \"suspicious\"").unwrap();
    assert!(!display_filter::eval(&expr, &ctx_tagged(&p, &tags)));
}

// ── Evaluator: compound expressions ──────────────────────────────────────────

#[test]
fn eval_and_both_true() {
    let p = pkt("TCP", "192.168.1.50", "203.0.113.7", Some(50000), Some(4444), "", 118);
    let expr = display_filter::parse("tcp and ip.dst == 203.0.113.7").unwrap();
    assert!(display_filter::eval(&expr, &ctx(&p)));
}

#[test]
fn eval_and_one_false() {
    let p = pkt("UDP", "192.168.1.50", "8.8.8.8", None, Some(53), "", 74);
    let expr = display_filter::parse("tcp and ip.dst == 8.8.8.8").unwrap();
    assert!(!display_filter::eval(&expr, &ctx(&p)));
}

#[test]
fn eval_or() {
    let p = pkt("DNS", "192.168.1.50", "8.8.8.8", None, Some(53), "", 74);
    let expr = display_filter::parse("tcp or dns").unwrap();
    assert!(display_filter::eval(&expr, &ctx(&p)));
}

#[test]
fn eval_nested_not_and() {
    let p = pkt("HTTP", "10.0.0.1", "10.0.0.2", Some(49000), Some(80), "", 200);
    let expr = display_filter::parse("not tcp and http").unwrap();
    assert!(display_filter::eval(&expr, &ctx(&p)));
}
