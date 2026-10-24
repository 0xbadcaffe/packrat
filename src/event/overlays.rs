use super::*;

pub(super) fn handle_stream_overlay(app: &mut App, key: KeyEvent) {
    let searching = app
        .stream_overlay
        .as_ref()
        .is_some_and(|overlay| overlay.searching);
    if searching {
        let overlay = app.stream_overlay.as_mut().expect("stream overlay exists");
        match key.code {
            KeyCode::Esc => {
                overlay.searching = false;
                overlay.search_query.clear();
                overlay.refresh_matches();
            }
            KeyCode::Enter => overlay.searching = false,
            KeyCode::Backspace => {
                overlay.search_query.pop();
                overlay.refresh_matches();
            }
            KeyCode::Char(character) => {
                overlay.search_query.push(character);
                overlay.refresh_matches();
            }
            _ => {}
        }
        return;
    }
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => app.stream_overlay = None,
        KeyCode::Char('/') => {
            if let Some(overlay) = app.stream_overlay.as_mut() {
                overlay.searching = true;
            }
        }
        KeyCode::Char('n') => {
            if let Some(overlay) = app.stream_overlay.as_mut() {
                overlay.next_match();
            }
        }
        KeyCode::Char('N') => {
            if let Some(overlay) = app.stream_overlay.as_mut() {
                overlay.previous_match();
            }
        }
        KeyCode::Char('e') => app.export_stream_overlay(),
        _ => {}
    }
}

pub(super) fn handle_critical_alert(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Enter | KeyCode::Char('a') | KeyCode::Char('A') => {
            app.open_active_incident_analysis();
        }
        KeyCode::Char('c') | KeyCode::Char('C') => {
            app.set_status("Open incident analysis before acknowledging this alert.");
        }
        _ => {
            app.set_status(
                "Critical alert requires review. Press Enter to open incident analysis.",
            );
        }
    }
}

pub(super) fn handle_view_menu(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc | KeyCode::F(2) | KeyCode::BackTab => app.view_menu_open = false,
        KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => app.view_menu_next(),
        KeyCode::Up | KeyCode::Char('k') => app.view_menu_prev(),
        KeyCode::Enter | KeyCode::Char(' ') => app.activate_view_menu_selection(),
        KeyCode::Char('1') => app.select_workspace(Workspace::Traffic),
        KeyCode::Char('2') => app.select_workspace(Workspace::Inspect),
        KeyCode::Char('3') => app.select_workspace(Workspace::Case),
        KeyCode::Char('4') => {
            app.navigate_to(Tab::Scanner);
            app.view_menu_open = false;
        }
        KeyCode::Char('5') => app.select_workspace(Workspace::Case),
        _ => {}
    }
}

pub(super) fn handle_settings(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc | KeyCode::Char(',') | KeyCode::Char('q') => app.close_settings(),
        KeyCode::Down | KeyCode::Char('j') => {
            app.settings_cursor = (app.settings_cursor + 1).min(crate::app::SETTINGS_COUNT - 1);
        }
        KeyCode::Up | KeyCode::Char('k') => {
            app.settings_cursor = app.settings_cursor.saturating_sub(1);
        }
        KeyCode::Enter if app.settings_cursor == 0 => {
            app.close_settings();
            app.theme_picker_open = true;
            let cur = app.selected_theme_name.clone();
            app.theme_picker_cursor = THEME_NAMES.iter().position(|&n| n == cur).unwrap_or(0);
        }
        KeyCode::Enter => app.activate_settings_selection(),
        KeyCode::Left | KeyCode::Char('h') => app.adjust_settings_selection(false),
        KeyCode::Right | KeyCode::Char('l') => app.adjust_settings_selection(true),
        _ => {}
    }
}

pub(super) fn handle_strings_search(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.strings_search_active = false;
            app.strings_filter.clear();
        }
        KeyCode::Enter => {
            app.strings_search_active = false;
        }
        KeyCode::Backspace => {
            app.strings_filter.pop();
        }
        KeyCode::Char(c) => {
            app.strings_filter.push(c);
        }
        _ => {}
    }
}

// ─── Global command palette ───────────────────────────────────────────────────

pub(super) fn handle_search_palette(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.close_search();
        }
        KeyCode::Enter => {
            app.search_jump();
        }

        KeyCode::Down | KeyCode::Char('j') => {
            let max = app.search_results.len().saturating_sub(1);
            if app.search_selected < max {
                app.search_selected += 1;
            }
        }
        KeyCode::Up | KeyCode::Char('k') => {
            app.search_selected = app.search_selected.saturating_sub(1);
        }

        KeyCode::Backspace => {
            app.search_query.pop();
            app.search_selected = 0;
            app.run_search();
        }
        KeyCode::Char(c) => {
            app.search_query.push(c);
            app.search_selected = 0;
            app.run_search();
        }

        _ => {}
    }
}

pub(super) fn handle_pcap_import(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.pcap_import_editing = false;
            app.pcap_import_path.clear();
        }
        KeyCode::Enter => {
            let path = app.pcap_import_path.clone();
            app.pcap_import_editing = false;
            app.pcap_import_path.clear();
            app.load_pcap_instant(&path);
        }
        KeyCode::Backspace => {
            app.pcap_import_path.pop();
        }
        KeyCode::Char(c) => {
            app.pcap_import_path.push(c);
        }
        _ => {}
    }
}

pub(super) fn handle_iface_picker(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Down | KeyCode::Char('j') => app.iface_down(),
        KeyCode::Up | KeyCode::Char('k') => app.iface_up(),
        KeyCode::Char(' ') | KeyCode::Enter => app.confirm_iface(),
        _ => {}
    }
}
