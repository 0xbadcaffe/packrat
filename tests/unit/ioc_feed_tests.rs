use super::*;

#[test]
fn plain_text_feed_distinguishes_ipv6_ipv4_and_domains() {
    let mut engine = IocEngine::default();
    engine.load_plain_text(
        "# indicators\n2001:0DB8::42\n192.0.2.20\nINDICATOR.TEST.\nhttp://example.test\n2001::invalid",
        "test.txt",
    );
    assert_eq!(engine.ioc_count(), 3);
    assert_eq!(engine.ips.len(), 2);
    let index = engine.ips[&"2001:db8::42".parse::<IpAddr>().unwrap()];
    assert_eq!(engine.iocs[index].kind, IocKind::Ip);
    assert_eq!(engine.iocs[index].source, "test.txt");
    assert_eq!(engine.iocs[engine.domains["indicator.test"]].kind, IocKind::Domain);
}
