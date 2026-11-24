#[path = "support/packets.rs"]
mod packets;

use packrat_tui::analysis::rules::{Action, Condition, Rule};
use packrat_tui::engine::AnalysisCore;
use packrat_tui::model::evidence::Severity;

fn rule(id: &str, port: u16, actions: Vec<Action>) -> Rule {
    Rule::new(id, id, Condition::Num {
        field: "tcp.dstport".into(),
        op: packrat_tui::analysis::rules::CmpOp::Eq,
        value: u64::from(port),
    }, actions)
}

fn critical() -> Action {
    Action::Alert { message: "Review the matched packet".into(), severity: Severity::Critical }
}

fn log() -> Action {
    Action::Log { message: "Routine observation".into() }
}

#[test]
fn rule_alert_and_incident_still_arrive_after_history_fills() {
    let mut core = AnalysisCore::default();
    core.rule_engine.add_rule(rule("routine", 80, vec![log()]));
    core.rule_engine.add_rule(rule("review", 443, vec![critical()]));
    for no in 1..=1000 {
        core.analyze(&packets::tcp(no, 100, 0x10, b""));
    }
    assert_eq!(core.rule_engine.hits.len(), 1000);
    let mut packet = packets::tcp(1001, 100, 0x10, b"");
    packet.bytes[36..38].copy_from_slice(&443_u16.to_be_bytes());
    let packet = packrat_tui::net::parser::parse_ethernet(&packet.bytes, 1001, 1001.0);
    let analysis = core.analyze(&packet);
    let alert = core.alert_center.items.iter().find(|alert| alert.source == "RULE" && alert.title == "review").unwrap();
    assert_eq!(alert.packet_refs, [1001]);
    assert_eq!(analysis.incidents.len(), 1);
    assert!(!analysis.incidents[0].auto_contain_rule);
    assert_eq!(core.rule_engine.hits.len(), 1000);
    assert_eq!(core.rule_engine.hits[0].pkt_no, 2);
    assert_eq!(core.rule_engine.hits[999].pkt_no, 1001);
    assert_eq!(core.rule_engine.evicted_hit_count(), 1);
}

#[test]
fn rule_delivery_does_not_depend_on_which_actions_fit_in_history() {
    let mut core = AnalysisCore::default();
    core.rule_engine.add_rule(rule("first-review", 80, vec![critical()]));
    core.rule_engine.add_rule(rule("routine", 80, vec![log(); 1000]));
    core.rule_engine.add_rule(rule("last-review", 80, vec![critical()]));

    let analysis = core.analyze(&packets::tcp(1, 100, 0x10, b""));
    assert_eq!(analysis.incidents.len(), 2);
    for title in ["first-review", "last-review"] {
        assert!(core.alert_center.items.iter().any(|item| item.source == "RULE" && item.title == title && item.packet_refs == [1]));
    }
    assert_eq!(core.rule_engine.hits.len(), 1000);
    assert_eq!(core.rule_engine.hits[0].rule_id, "routine");
    assert_eq!(core.rule_engine.hits[999].rule_id, "last-review");
    assert_eq!(core.rule_engine.evicted_hit_count(), 2);
    core.clear();
    assert!(core.rule_engine.hits.is_empty());
    assert_eq!(core.rule_engine.evicted_hit_count(), 0);
    assert_eq!(core.rule_engine.rules.len(), 3);
    assert!(core.rule_engine.rules.iter().all(|rule| rule.hits == 0));
}
