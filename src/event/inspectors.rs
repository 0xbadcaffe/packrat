use super::*;

// ─── Workbench tab ────────────────────────────────────────────────────────────

pub(super) fn handle_workbench(app: &mut App, key: KeyEvent) {
    if global_tab_switch(app, &key) {
        return;
    }

    const HEX_COLS: usize = 16;
    match key.code {
        KeyCode::Tab => {
            app.next_tab();
            return;
        }
        KeyCode::BackTab => {
            app.prev_tab();
            return;
        }
        KeyCode::Char('h') | KeyCode::Left => app.workbench.cursor_left(),
        KeyCode::Char('l') | KeyCode::Right => app.workbench.cursor_right(),
        KeyCode::Char('k') | KeyCode::Up => app.workbench.cursor_up(HEX_COLS),
        KeyCode::Char('j') | KeyCode::Down => app.workbench.cursor_down(HEX_COLS),
        KeyCode::Char(' ') => app.workbench.toggle_selection(),
        KeyCode::Esc => {
            app.workbench.sel_start = None;
        }
        // Go back to Packets tab to pick a different packet
        KeyCode::Char('p') => {
            app.active_tab = Tab::Packets;
        }
        _ => {}
    }
}

// ─── Protocol Autopsy overlay ────────────────────────────────────────────────

pub(super) fn handle_autopsy(app: &mut App, key: KeyEvent) {
    let Some(state) = app.autopsy_state.as_mut() else {
        return;
    };
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => {
            app.autopsy_state = None;
        }
        KeyCode::Tab => {
            let state = app.autopsy_state.as_mut().unwrap();
            state.active_pane = match state.active_pane {
                AutopsyPane::Tree => AutopsyPane::Stream,
                AutopsyPane::Stream => AutopsyPane::Tree,
            };
        }
        KeyCode::Down | KeyCode::Char('j') => match state.active_pane {
            AutopsyPane::Tree => {
                state.tree_scroll = state.tree_scroll.saturating_add(1);
            }
            AutopsyPane::Stream => {
                state.stream_scroll = state.stream_scroll.saturating_add(1);
            }
        },
        KeyCode::Up | KeyCode::Char('k') => match state.active_pane {
            AutopsyPane::Tree => {
                state.tree_scroll = state.tree_scroll.saturating_sub(1);
            }
            AutopsyPane::Stream => {
                state.stream_scroll = state.stream_scroll.saturating_sub(1);
            }
        },
        KeyCode::PageDown => match state.active_pane {
            AutopsyPane::Tree => {
                state.tree_scroll = state.tree_scroll.saturating_add(10);
            }
            AutopsyPane::Stream => {
                state.stream_scroll = state.stream_scroll.saturating_add(10);
            }
        },
        KeyCode::PageUp => match state.active_pane {
            AutopsyPane::Tree => {
                state.tree_scroll = state.tree_scroll.saturating_sub(10);
            }
            AutopsyPane::Stream => {
                state.stream_scroll = state.stream_scroll.saturating_sub(10);
            }
        },
        KeyCode::Char('g') => {
            state.tree_scroll = 0;
            state.stream_scroll = 0;
        }
        _ => {}
    }
}

// ─── Objects tab ─────────────────────────────────────────────────────────────

pub(super) fn handle_objects(app: &mut App, key: KeyEvent) {
    if global_tab_switch(app, &key) {
        return;
    }

    match key.code {
        // Sub-tab navigation
        KeyCode::Char('o') => {
            app.objects_subtab = ObjectsSubTab::Objects;
        }
        KeyCode::Char('y') => {
            app.objects_subtab = ObjectsSubTab::YaraRules;
        }
        KeyCode::Char('m') => {
            app.objects_subtab = ObjectsSubTab::YaraMatches;
        }
        KeyCode::Tab => {
            app.next_tab();
            return;
        }
        KeyCode::BackTab => {
            app.prev_tab();
            return;
        }
        KeyCode::Char('[') => {
            app.objects_subtab = match app.objects_subtab {
                ObjectsSubTab::Objects => ObjectsSubTab::YaraMatches,
                ObjectsSubTab::YaraRules => ObjectsSubTab::Objects,
                ObjectsSubTab::YaraMatches => ObjectsSubTab::YaraRules,
            };
        }
        KeyCode::Char(']') => {
            app.objects_subtab = match app.objects_subtab {
                ObjectsSubTab::Objects => ObjectsSubTab::YaraRules,
                ObjectsSubTab::YaraRules => ObjectsSubTab::YaraMatches,
                ObjectsSubTab::YaraMatches => ObjectsSubTab::Objects,
            };
        }

        // Scroll — different counter per sub-panel
        KeyCode::Down | KeyCode::Char('j') => match app.objects_subtab {
            ObjectsSubTab::Objects => {
                app.objects_scroll = app.objects_scroll.saturating_add(1);
            }
            ObjectsSubTab::YaraRules => {
                app.yara_rules_scroll = app.yara_rules_scroll.saturating_add(1);
            }
            ObjectsSubTab::YaraMatches => {
                app.yara_matches_scroll = app.yara_matches_scroll.saturating_add(1);
            }
        },
        KeyCode::Up | KeyCode::Char('k') => match app.objects_subtab {
            ObjectsSubTab::Objects => {
                app.objects_scroll = app.objects_scroll.saturating_sub(1);
            }
            ObjectsSubTab::YaraRules => {
                app.yara_rules_scroll = app.yara_rules_scroll.saturating_sub(1);
            }
            ObjectsSubTab::YaraMatches => {
                app.yara_matches_scroll = app.yara_matches_scroll.saturating_sub(1);
            }
        },
        KeyCode::Char('g') => {
            app.objects_scroll = 0;
            app.yara_rules_scroll = 0;
            app.yara_matches_scroll = 0;
        }

        // Actions
        KeyCode::Char('r') => {
            app.reload_yara_rules();
        }
        KeyCode::Char('s') => {
            app.yara_force_rescan();
        }
        KeyCode::Char('c') => {
            app.carve_from_streams();
        }
        KeyCode::Char('h') => {
            app.show_help = true;
        }

        _ => {}
    }
}
