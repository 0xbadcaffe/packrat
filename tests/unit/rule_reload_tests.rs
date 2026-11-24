use super::*;

fn rule(id: &str) -> Rule {
    Rule::new(id, id, Condition::Equals {
        field: "protocol".into(), value: "TCP".into(),
    }, vec![Action::Log { message: "Test detection".into() }])
}

fn write_rule<T: serde::Serialize>(path: &Path, name: &str, value: &T) {
    std::fs::write(path.join(name), serde_json::to_vec(value).unwrap()).unwrap();
}

#[test]
fn malformed_file_keeps_the_entire_active_ruleset_and_its_counters() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path();
    let mut engine = RuleEngine::default();
    let mut active = rule("active");
    active.hits = 8;
    engine.add_rule(active);
    write_rule(path, "01-good.json", &rule("replacement"));
    std::fs::write(path.join("02-broken.json"), b"{").unwrap();
    assert!(engine.reload_from_path(path).unwrap_err().contains("02-broken.json"));
    assert_eq!(engine.rules.len(), 1);
    assert_eq!(engine.rules[0].id, "active");
    assert_eq!(engine.rules[0].hits, 8);

    write_rule(path, "02-broken.json", &vec![rule("another")]);
    engine.reload_from_path(path).unwrap();
    assert_eq!(engine.rules.iter().map(|rule| rule.id.as_str()).collect::<Vec<_>>(), ["replacement", "another"]);
}

#[test]
fn duplicate_and_blank_rule_ids_do_not_replace_active_rules() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path();
    let mut engine = RuleEngine::default();
    engine.add_rule(rule("active"));
    write_rule(path, "a.json", &rule("same"));
    write_rule(path, "b.json", &vec![rule("same")]);
    let error = engine.reload_from_path(path).unwrap_err();
    assert!(error.contains("b.json") && error.contains("duplicate rule ID"));
    assert_eq!(engine.rules[0].id, "active");
    write_rule(path, "b.json", &rule("  "));
    assert!(engine.reload_from_path(path).unwrap_err().contains("blank rule ID"));
    assert_eq!(engine.rules[0].id, "active");
}

#[test]
fn missing_directory_is_distinct_from_an_intentionally_empty_directory() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("rules");
    let mut engine = RuleEngine::default();
    engine.reload_from_path(&path).unwrap();
    engine.add_rule(rule("active"));
    assert!(engine.reload_from_path(&path).is_err());
    assert_eq!(engine.rules[0].id, "active");
    std::fs::create_dir(&path).unwrap();
    engine.reload_from_path(&path).unwrap();
    assert!(engine.rules.is_empty());
}
