use super::*;

#[test]
fn plain_text_feed_distinguishes_ipv6_ipv4_and_domains() {
    let mut engine = IocEngine::default();
    engine.load_file_entries(
        "# indicators\n2001:0DB8::42\n192.0.2.20\nINDICATOR.TEST.",
        "test.txt", false,
    ).unwrap();
    assert_eq!(engine.ioc_count(), 3);
    assert_eq!(engine.ips.len(), 2);
    let index = engine.ips[&"2001:db8::42".parse::<IpAddr>().unwrap()];
    assert_eq!(engine.iocs[index].kind, IocKind::Ip);
    assert_eq!(engine.iocs[index].source, "test.txt");
    assert_eq!(engine.iocs[engine.domains["indicator.test"]].kind, IocKind::Domain);
}

#[test]
fn successful_reload_replaces_file_indicators_without_losing_session_entries_or_hits() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path();
    let file = path.join("a.csv");
    let mut engine = IocEngine::default();
    engine.load_csv("ip,192.0.2.1,session", "session");
    std::fs::write(&file, "ip,192.0.2.2,old").unwrap();
    engine.reload_from_path(path).unwrap();
    engine.load_csv("ip,192.0.2.3,later", "session");
    let retained = engine.ips[&"192.0.2.2".parse::<IpAddr>().unwrap()];
    engine.remember_hit(IocHit {
        ioc: engine.iocs[retained].clone(), context: "src_ip".into(), pkt_no: 17, ts: 1.0,
    });
    std::fs::write(&file, "ip,192.0.2.4,new").unwrap();
    for _ in 0..2 { engine.reload_from_path(path).unwrap(); }
    let addresses = engine.ips.keys().map(ToString::to_string).collect::<HashSet<_>>();
    assert_eq!(addresses, ["192.0.2.1", "192.0.2.3", "192.0.2.4"].into_iter().map(str::to_owned).collect());
    assert_eq!(engine.ioc_count(), 3);
    assert_eq!(engine.hits[0].pkt_no, 17);
    assert_eq!(engine.hits[0].ioc.value, "192.0.2.2");
}

#[test]
fn failed_reload_keeps_the_active_file_feed_and_empty_directory_retires_it() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("ioc");
    let mut engine = IocEngine::default();
    engine.reload_from_path(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    let readable = path.join("a.txt");
    std::fs::write(&readable, "192.0.2.1").unwrap();
    engine.reload_from_path(&path).unwrap();
    std::fs::write(&readable, "192.0.2.2").unwrap();
    let unreadable = path.join("b.csv");
    std::fs::create_dir(&unreadable).unwrap();
    assert!(engine.reload_from_path(&path).unwrap_err().contains("b.csv"));
    assert_eq!(engine.iocs[0].value, "192.0.2.1");
    std::fs::remove_dir(&unreadable).unwrap();
    std::fs::remove_file(readable).unwrap();
    std::fs::remove_dir(&path).unwrap();
    assert!(engine.reload_from_path(&path).is_err());
    assert_eq!(engine.iocs[0].value, "192.0.2.1");
    std::fs::create_dir(&path).unwrap();
    engine.reload_from_path(&path).unwrap();
    assert_eq!(engine.ioc_count(), 0);
}

#[test]
fn malformed_file_entries_cannot_replace_a_valid_feed() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path();
    let csv = path.join("a.csv");
    let mut engine = IocEngine::default();
    std::fs::write(&csv, "ip,192.0.2.7,known entry").unwrap();
    engine.reload_from_path(path).unwrap();
    for (line, problem) in [
        ("ip,not-an-address", "invalid IP address"),
        ("domain,bad/name", "invalid domain name"),
        ("unknown,192.0.2.9", "unknown indicator type"),
        ("ip", "expected type,value"),
    ] {
        std::fs::write(&csv, format!("# staged\nip,192.0.2.8,replacement\n{line}\n")).unwrap();
        let error = engine.reload_from_path(path).unwrap_err();
        assert!(error.contains("a.csv:3:") && error.contains(problem), "{error}");
        assert_eq!(engine.iocs[0].value, "192.0.2.7");
        assert_eq!(engine.ioc_count(), 1);
    }
    std::fs::write(&csv, "ip,192.0.2.8,replacement, with commas").unwrap();
    let text = path.join("b.ioc");
    std::fs::write(&text, "# staged\n\nnot an indicator").unwrap();
    assert!(engine.reload_from_path(path).unwrap_err().contains("b.ioc:3:"));
    assert_eq!(engine.iocs[0].value, "192.0.2.7");
    std::fs::write(text, "# staged\n2001:db8::9").unwrap();
    engine.reload_from_path(path).unwrap();
    assert_eq!(engine.iocs[0].description, "replacement, with commas");
    assert_eq!(engine.ioc_count(), 2);
}
