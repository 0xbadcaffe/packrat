#![cfg(feature = "terminal-ui")]

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use packrat_tui::{app::App, event, tabs::{Tab, Workspace}, ui};
use ratatui::{Terminal, backend::TestBackend};

fn screen(app: &App, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|frame| ui::draw(frame, app)).unwrap();
    let buffer = terminal.backend().buffer();
    let mut result = String::new();
    for y in 0..height {
        for x in 0..width { result.push_str(buffer[(x, y)].symbol()); }
        result.push('\n');
    }
    result
}

#[test]
fn three_workspaces_are_visible_in_small_and_large_terminals() {
    let app = App::new_for_test();
    for (width, height) in [(40, 12), (80, 24), (120, 40)] {
        let text = screen(&app, width, height);
        assert!(text.contains("1 Traffic"), "missing Traffic at {width}x{height}");
        assert!(text.contains("2 Investigation"), "missing Investigation at {width}x{height}");
        assert!(text.contains("3 Case"), "missing Case at {width}x{height}");
    }
}

#[test]
fn navigation_shows_workspace_and_view_shortcuts_on_one_row() {
    let mut app = App::new_for_test();
    let press = |app: &mut App, code, modifiers| {
        assert!(!event::handle(app, Event::Key(KeyEvent::new(code, modifiers))));
    };
    for (index, workspace) in [Workspace::Traffic, Workspace::Inspect, Workspace::Case].into_iter().enumerate() {
        press(&mut app, KeyCode::Char(char::from(b'1' + index as u8)), KeyModifiers::NONE);
        assert_eq!(app.active_tab, workspace.home());
        let wide = screen(&app, 180, 24);
        let views = wide.lines().nth(3).unwrap();
        assert!(views.starts_with(" 1 Traffic │ 2 Investigation │ 3 Case ║ "), "{views}");
        for (index, tab) in workspace.views().iter().enumerate() {
            assert!(views.contains(&format!("Alt+{} {}", index + 1, tab.label())), "{views}");
            press(&mut app, KeyCode::Char(char::from(b'1' + index as u8)), KeyModifiers::ALT);
            assert_eq!(app.active_tab, *tab);
        }
    }
}

#[test]
fn navigation_keeps_labels_whole_and_f2_reaches_hidden_views() {
    let mut app = App::new_for_test();
    app.select_workspace(Workspace::Inspect);
    let medium = screen(&app, 64, 12);
    assert_eq!(medium.lines().nth(3).unwrap().trim(),
        "1 Traffic │ 2 Investigation │ 3 Case ║ Alt+1 Investigate");
    let narrow = screen(&app, 28, 12);
    assert_eq!(narrow.lines().nth(3).unwrap().trim(), "1 Traffic │ 2 Investigation");
    assert!(narrow.contains("[F2 views]"));

    let press = |app: &mut App, code, modifiers| {
        assert!(!event::handle(app, Event::Key(KeyEvent::new(code, modifiers))));
    };
    press(&mut app, KeyCode::Char('2'), KeyModifiers::ALT);
    assert_eq!(app.active_tab, Tab::Analysis);
    press(&mut app, KeyCode::F(2), KeyModifiers::NONE);
    for _ in 0..6 {
        press(&mut app, KeyCode::Down, KeyModifiers::NONE);
    }
    assert!(screen(&app, 28, 12).contains("> Graph"));
    press(&mut app, KeyCode::Enter, KeyModifiers::NONE);
    assert_eq!(app.active_tab, Tab::OperatorGraph);
}

#[test]
fn view_drawer_keeps_selected_tool_visible_on_short_terminals() {
    let mut app = App::new_for_test();
    app.active_tab = Tab::Investigate;
    app.open_view_menu();
    for _ in 0..20 { app.view_menu_next(); }
    app.view_menu_prev();
    assert!(screen(&app, 80, 12).contains("Graph"));
    app.activate_view_menu_selection();
    assert_eq!(app.active_tab, Tab::OperatorGraph);
}

#[test]
fn about_in_each_workspace_shows_the_build_version_and_preserves_the_view() {
    let version = concat!("v", env!("CARGO_PKG_VERSION"));
    let mut app = App::new_for_test();
    let key = |app: &mut App, code| {
        assert!(!event::handle(app, Event::Key(KeyEvent::new(code, KeyModifiers::NONE))));
    };
    for workspace in [Workspace::Traffic, Workspace::Inspect, Workspace::Case] {
        app.select_workspace(workspace);
        let original_tab = app.active_tab;
        key(&mut app, if workspace == Workspace::Traffic { KeyCode::Tab } else { KeyCode::F(2) });
        assert!(screen(&app, 28, 9).contains("End: About"));
        key(&mut app, KeyCode::End);
        assert_eq!(app.view_menu_cursor, workspace.views().len());
        for (width, height) in [(28, 9), (40, 12), (80, 24)] {
            let menu = screen(&app, width, height);
            assert!(menu.contains(&format!("> About {version}")), "{menu}");
        }
        key(&mut app, KeyCode::Enter);
        assert!(app.about_open && !app.view_menu_open);
        assert_eq!(app.active_tab, original_tab);
        for (width, height) in [(28, 9), (80, 24)] {
            assert!(screen(&app, width, height).contains(&format!("Packrat {version}")));
        }
        key(&mut app, KeyCode::Esc);
        assert!(!app.about_open && app.view_menu_open);
        assert_eq!(app.view_menu_cursor, workspace.views().len());
        key(&mut app, KeyCode::Esc);
        assert!(!app.view_menu_open);
        assert_eq!(app.active_tab, original_tab);
    }
}

#[test]
fn selected_alert_shows_evidence_availability_and_keeps_the_action_visible() {
    let mut app = App::new_for_test();
    app.active_tab = Tab::Security;
    app.security_tab = packrat_tui::app::SecuritySubTab::Alerts;
    app.configure_core(|core| {
        core.alert_center.record(7, "IDS", "HIGH", "Horizontal host scan", "Distinct targets");
    });
    for (width, height) in [(80, 24), (140, 40)] {
        let text = screen(&app, width, height);
        assert!(text.contains("0/1 retained; 1 unavailable; capture ID not recorded"), "{text}");
        assert!(text.contains("V inspect  E export case"), "{text}");
    }
}

#[test]
fn alert_views_show_capture_time_separately_from_frame_and_review_order() {
    let mut app = App::new_for_test();
    app.active_tab = Tab::Security;
    app.configure_core(|core| {
        for (frame, time) in [(10, 9.5), (11, 3.25), (12, 0.0)] {
            core.alert_center.record_correlated(
                frame, time, "IDS", "HIGH", "Observation window", "detail", "same",
            );
        }
    });

    let expected = "first 3.250000 s, last 9.500000 s";
    let detail = screen(&app, 120, 32);
    assert!(detail.contains(expected) && detail.contains("3 hits"), "{detail}");
    assert!(app.investigate_selected_alert());
    let summary = screen(&app, 120, 40);
    assert!(summary.contains(expected) && summary.contains("Observations  3"), "{summary}");

    app.active_tab = Tab::Security;
    app.configure_core(|core| {
        core.alert_center.items[0].first_seen = 0.0;
        core.alert_center.items[0].last_seen = 0.0;
    });
    let detail = screen(&app, 120, 32);
    assert!(detail.contains("first not recorded, last not recorded"), "{detail}");
}

#[test]
fn long_selected_alert_scrolls_without_hiding_evidence_actions() {
    let mut app = App::new_for_test();
    app.active_tab = Tab::Security;
    app.configure_core(|core| {
        let detail = format!("BeginMarker {} EndMarker", "extended observation ".repeat(45));
        core.alert_center.record(7, "IDS", "HIGH", "Long observation", detail);
        core.alert_center.record(8, "IDS", "HIGH", "Second finding", "SecondDetail");
    });

    let press = |app: &mut App, code| {
        assert!(!event::handle(app, Event::Key(KeyEvent::new(code, KeyModifiers::NONE))));
    };
    for (width, height) in [(48, 18), (80, 24)] {
        let initial = screen(&app, width, height);
        assert!(initial.contains("IDS / Long observation") && !initial.contains("EndMarker"), "{initial}");
        let mut found_end = false;
        for _ in 0..40 {
            press(&mut app, KeyCode::PageDown);
            let page = screen(&app, width, height);
            assert!(page.contains("V inspect  E export case"), "{page}");
            found_end |= page.contains("EndMarker");
        }
        let end = screen(&app, width, height);
        assert!(!end.contains("IDS / Long observation"), "{end}");
        assert!(found_end, "end of finding was not reachable at {width}x{height}");
        press(&mut app, KeyCode::PageUp);
        assert_ne!(screen(&app, width, height), end);
        press(&mut app, KeyCode::Down);
        assert!(screen(&app, width, height).contains("IDS / Second finding"));
        press(&mut app, KeyCode::Up);
        assert!(screen(&app, width, height).contains("IDS / Long observation"));
    }
}

#[test]
fn alert_center_review_filter_keeps_resolved_history_accessible() {
    let mut app = App::new_for_test();
    app.active_tab = Tab::Security;
    app.configure_core(|core| {
        core.alert_center.record(1, "IDS", "HIGH", "ResolvedFinding", "detail");
        core.alert_center.record(2, "IDS", "HIGH", "OpenFinding", "detail");
        core.alert_center.set_disposition(1, None, packrat_tui::analysis::alert_center::AlertDisposition::Benign);
    });
    let filter = Event::Key(KeyEvent::new(KeyCode::Char('F'), KeyModifiers::SHIFT));
    assert!(!event::handle(&mut app, filter.clone()));
    let open = screen(&app, 80, 24);
    assert!(open.contains("F: Open") && open.contains("OpenFinding") && !open.contains("ResolvedFinding"));
    assert!(!event::handle(&mut app, filter.clone()));
    let resolved = screen(&app, 80, 24);
    assert!(resolved.contains("F: Resolved") && resolved.contains("ResolvedFinding") && !resolved.contains("OpenFinding"));
    assert!(!event::handle(&mut app, filter));
    let all = screen(&app, 80, 24);
    assert!(all.contains("F: All") && all.contains("ResolvedFinding") && all.contains("OpenFinding"));
}
