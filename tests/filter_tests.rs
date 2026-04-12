//! Tests for the display filter parser and evaluator.

use packrat_tui::analysis::display_filter::{self, EvalCtx};
use packrat_tui::net::packet::Packet;

fn pkt(proto: &str, src: &str, dst: &str, sport: Option<u16>, dport: Option<u16>,
       info: &str, len: u16) -> Packet {
    Packet {
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
        bytes: vec![],
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
