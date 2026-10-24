#[path = "support/packets.rs"]
mod packets;

use packrat_tui::model::graph_types::GraphNodeKind;
use packrat_tui::{analysis::yara::parse_rules, engine::AnalysisCore};

fn load_rule(core: &mut AnalysisCore) {
    let (rules, errors) =
        parse_rules("rule pdf {\n strings:\n $a = \"%PDF\"\n condition:\n $a\n}\n");
    assert!(errors.is_empty());
    core.yara_engine.rules = rules;
}

#[test]
fn carving_and_scanning_run_on_a_worker_with_no_terminal() {
    std::thread::spawn(|| {
        let mut core = AnalysisCore::default();
        assert!(core.yara_engine.rules.is_empty());
        load_rule(&mut core);
        core.analyze(&packets::tcp(1, 100, 0x18, b"%PDF-1.7\nbody\n%%EOF"));
        core.carve_from_streams();
        assert_eq!(core.carved_objects.len(), 1);
        assert_eq!(core.scan_new_objects(), 1);
        assert_eq!(core.carved_objects[0].yara_hits, ["pdf"]);
        assert_eq!(
            core.operator_graph
                .nodes_by_kind(&GraphNodeKind::FileObject)
                .len(),
            1
        );
        core.carve_from_streams();
        assert_eq!(core.carved_objects.len(), 1);
    })
    .join()
    .unwrap();
}

#[test]
fn object_scanning_is_bounded_and_reload_clears_stale_labels() {
    let mut core = AnalysisCore::default();
    load_rule(&mut core);
    for index in 0..6 {
        core.carved_objects.extend(
            core.carver
                .carve(format!("%PDF-1.7\n{index}\n%%EOF").as_bytes(), "test"),
        );
    }
    assert_eq!(core.scan_new_objects(), 4);
    assert_eq!(core.yara_scan_cursor, 4);
    assert_eq!(core.scan_new_objects(), 2);
    assert_eq!(core.scan_new_objects(), 0);
    assert_eq!(core.yara_engine.total_matches(), 6);
    core.yara_engine.rules.clear();
    core.reset_object_scan();
    assert!(
        core.carved_objects
            .iter()
            .all(|object| object.yara_hits.is_empty())
    );
    assert_eq!(core.yara_engine.total_matches(), 0);
    assert_eq!(core.yara_scan_cursor, 0);
}

#[test]
fn clearing_a_capture_resets_carving_dedup_but_preserves_rules() {
    let mut core = AnalysisCore::default();
    load_rule(&mut core);
    let packet = packets::tcp(1, 100, 0x18, b"%PDF-1.7\nbody\n%%EOF");
    core.analyze(&packet);
    core.carve_from_streams();
    core.maintenance();
    assert_eq!(core.yara_scan_cursor, 1);
    core.clear();
    assert!(core.carved_objects.is_empty());
    assert_eq!(core.yara_engine.rules.len(), 1);
    assert_eq!(core.yara_scan_cursor, 0);
    core.analyze(&packet);
    core.carve_from_streams();
    assert_eq!(core.carved_objects.len(), 1);
}
