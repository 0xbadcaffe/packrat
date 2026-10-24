use super::*;
use crate::net::packet::Packet;

fn make_pkt(proto: &str, src: &str, dst: &str, sport: u16, dport: u16, len: u16) -> Packet {
    Packet {
        capture: None,
        no: 1,
        timestamp: 0.0,
        src: src.into(),
        dst: dst.into(),
        protocol: proto.into(),
        length: len,
        info: format!("{} → {}", src, dst),
        bytes: vec![0u8; len as usize],
        src_port: Some(sport),
        dst_port: Some(dport),
        vlan_id: None,
        vlan_pcp: None,
        vlan_dei: None,
        outer_vlan_id: None,
    }
}

#[test]
fn test_proto_filter() {
    let pkt = make_pkt("TCP", "1.2.3.4", "5.6.7.8", 1234, 80, 100);
    let ctx = EvalCtx {
        pkt: &pkt,
        marked: false,
        tags: &[],
    };
    assert!(eval(&parse("tcp").unwrap(), &ctx));
    assert!(!eval(&parse("udp").unwrap(), &ctx));
}

#[test]
fn test_field_cmp() {
    let pkt = make_pkt("TCP", "1.2.3.4", "5.6.7.8", 1234, 443, 200);
    let ctx = EvalCtx {
        pkt: &pkt,
        marked: false,
        tags: &[],
    };
    assert!(eval(&parse("ip.src == \"1.2.3.4\"").unwrap(), &ctx));
    assert!(eval(&parse("tcp.dstport == 443").unwrap(), &ctx));
    assert!(eval(&parse("frame.len > 100").unwrap(), &ctx));
    assert!(!eval(&parse("frame.len < 100").unwrap(), &ctx));
}

#[test]
fn test_boolean_logic() {
    let pkt = make_pkt("TCP", "1.2.3.4", "5.6.7.8", 1234, 80, 100);
    let ctx = EvalCtx {
        pkt: &pkt,
        marked: false,
        tags: &[],
    };
    assert!(eval(&parse("tcp and ip.src == \"1.2.3.4\"").unwrap(), &ctx));
    assert!(eval(&parse("not udp").unwrap(), &ctx));
    assert!(eval(&parse("udp or tcp").unwrap(), &ctx));
}

#[test]
fn test_in_filter() {
    let pkt = make_pkt("TCP", "1.2.3.4", "5.6.7.8", 1234, 443, 100);
    let ctx = EvalCtx {
        pkt: &pkt,
        marked: false,
        tags: &[],
    };
    assert!(eval(&parse("tcp.port in [80,443,8080]").unwrap(), &ctx));
    assert!(!eval(&parse("tcp.port in [80,8080]").unwrap(), &ctx));
}

#[test]
fn test_marked() {
    let pkt = make_pkt("TCP", "1.2.3.4", "5.6.7.8", 1234, 80, 100);
    let ctx_marked = EvalCtx {
        pkt: &pkt,
        marked: true,
        tags: &[],
    };
    let ctx_unmarked = EvalCtx {
        pkt: &pkt,
        marked: false,
        tags: &[],
    };
    assert!(eval(&parse("marked == true").unwrap(), &ctx_marked));
    assert!(!eval(&parse("marked == true").unwrap(), &ctx_unmarked));
}

#[test]
fn test_tag_filter() {
    let pkt = make_pkt("TCP", "1.2.3.4", "5.6.7.8", 1234, 80, 100);
    let tags = vec!["suspicious".to_string(), "c2".to_string()];
    let ctx = EvalCtx {
        pkt: &pkt,
        marked: false,
        tags: &tags,
    };
    assert!(eval(&parse("tag == \"suspicious\"").unwrap(), &ctx));
    assert!(!eval(&parse("tag == \"benign\"").unwrap(), &ctx));
}
