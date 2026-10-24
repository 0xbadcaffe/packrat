use crate::analysis::operator_graph::GraphUiModeState;
use crate::app::{App, InvestigationView, ObjectsSubTab, SecuritySubTab};
use crate::model::project::ProjectSaveMode;
use crate::scan::{ScanField, ScanMode};
use crate::storage::project_store;
use crate::tabs::{Tab, Workspace};
use crate::ui::autopsy_overlay::AutopsyPane;
use crate::ui::project_manager::{PmField, PmTab};
use crate::ui::theme::THEME_NAMES;
use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};

/// Handle a crossterm event. Returns `true` if the app should quit.
pub fn handle(app: &mut App, event: Event) -> bool {
    let Event::Key(key) = event else {
        return false;
    };

    if app.alert_overlay_open {
        handle_critical_alert(app, key);
        return false;
    }

    if app.view_menu_open {
        handle_view_menu(app, key);
        return false;
    }

    // Only quit when not in a text-entry or modal mode — otherwise 'q' is a
    // valid character or should close the overlay rather than quitting the app.
    let in_text_mode = app.strings_search_active
        || app.filter.active
        || app.craft.editing
        || app.replay_editing
        || app.pcap_import_editing
        || app.scan_editing
        || app.traceroute.editing
        || app.notebook_editing
        || app.notebook_searching
        || app.hosts_searching
        || app.hosts_tagging
        || app.graph_ui.searching
        || app.search_open
        || app.header_searching
        || app.settings_open
        || app.show_help
        || app.stream_overlay.is_some()
        || app.packet_comparison.is_some()
        || app.autopsy_state.is_some()
        || (app.project_manager_open && app.project_manager.is_text_editing());

    if !in_text_mode && is_quit(&key) {
        return true;
    }

    // ── Global command palette ────────────────────────────────────────────────
    if app.search_open {
        handle_search_palette(app, key);
        return false;
    }

    if app.show_help {
        match key.code {
            KeyCode::Esc | KeyCode::Char('h') | KeyCode::Char('q') => {
                app.show_help = false;
                app.help_scroll = 0;
            }
            KeyCode::Down | KeyCode::Char('j') => {
                app.help_scroll = app.help_scroll.saturating_add(1)
            }
            KeyCode::Up | KeyCode::Char('k') => app.help_scroll = app.help_scroll.saturating_sub(1),
            KeyCode::PageDown => app.help_scroll = app.help_scroll.saturating_add(10),
            KeyCode::PageUp => app.help_scroll = app.help_scroll.saturating_sub(10),
            KeyCode::Home | KeyCode::Char('g') => app.help_scroll = 0,
            KeyCode::End | KeyCode::Char('G') => app.help_scroll = u16::MAX,
            _ => {}
        }
        return false;
    }

    if app.stream_overlay.is_some() {
        handle_stream_overlay(app, key);
        return false;
    }

    if app.packet_comparison.is_some() {
        if matches!(
            key.code,
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('=')
        ) {
            app.packet_comparison = None;
        }
        return false;
    }

    if app.autopsy_state.is_some() {
        handle_autopsy(app, key);
        return false;
    }

    if app.pcap_import_editing {
        handle_pcap_import(app, key);
        return false;
    }

    if app.project_manager_open {
        handle_project_manager(app, key);
        return false;
    }

    if app.settings_open {
        handle_settings(app, key);
        return false;
    }

    if app.theme_picker_open {
        handle_theme_picker(app, key);
        return false;
    }

    if !in_text_mode && matches!(key.code, KeyCode::Tab | KeyCode::F(2)) {
        app.open_view_menu();
        return false;
    }

    if !in_text_mode && key.code == KeyCode::Left && key.modifiers.contains(KeyModifiers::ALT) {
        app.navigate_back();
        return false;
    }

    if !in_text_mode && key.code == KeyCode::Esc && app.return_to_workspace_home() {
        return false;
    }

    if app.active_tab == Tab::Analysis
        && app.analysis_section == crate::app::INCIDENT_ANALYSIS_SECTION
        && key.code == KeyCode::Char('x')
    {
        app.approve_active_latch();
        return false;
    }

    if app.active_tab == Tab::Analysis
        && app.analysis_section == crate::app::INCIDENT_ANALYSIS_SECTION
        && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C'))
    {
        if let Err(message) = app.acknowledge_active_incident() {
            app.set_status(message);
        }
        return false;
    }

    if app.picking_iface {
        handle_iface_picker(app, key);
    } else if app.strings_search_active {
        handle_strings_search(app, key);
    } else if app.header_searching {
        handle_investigate(app, key);
    } else {
        // Open global search palette with '?'
        if key.code == KeyCode::Char('?') {
            app.open_search();
            return false;
        }

        if key.code == KeyCode::Char('p') && key.modifiers.contains(KeyModifiers::CONTROL) {
            app.open_search();
            return false;
        }

        if key.code == KeyCode::Char(',') {
            app.open_settings();
            return false;
        }

        // Project manager with 'P'
        if key.code == KeyCode::Char('P') {
            app.open_project_manager();
            return false;
        }

        // Quick-save project with Ctrl+S
        if key.code == KeyCode::Char('s') && key.modifiers.contains(KeyModifiers::CONTROL) {
            app.quick_save_project();
            return false;
        }

        // Theme picker with backslash
        if key.code == KeyCode::Char('\\') {
            app.theme_picker_open = true;
            // Position cursor on the currently selected theme
            let cur = app.selected_theme_name.clone();
            app.theme_picker_cursor = THEME_NAMES.iter().position(|&n| n == cur).unwrap_or(0);
            return false;
        }

        // Export case bundle with 'X' from any tab
        if key.code == KeyCode::Char('X') {
            app.export_case_bundle();
            return false;
        }

        if key.code == KeyCode::Char('!') {
            app.engage_guard_kill_switch();
            return false;
        }

        // Pin the active screen context to the cross-workspace investigation tray.
        if key.code == KeyCode::Char('M') {
            app.pin_current_context();
            return false;
        }

        // Reload IOC feeds with 'I' from any tab
        if key.code == KeyCode::Char('I') {
            app.reload_ioc_feeds();
            return false;
        }

        // Diff baseline snapshot with 'B' from any tab
        if key.code == KeyCode::Char('B') {
            app.diff_snapshot_baseline();
            return false;
        }

        // PCAP instant import with 'L' from any tab
        if key.code == KeyCode::Char('L') {
            app.pcap_import_editing = true;
            return false;
        }

        match app.active_tab {
            Tab::Craft => handle_craft(app, key),
            Tab::Traceroute => handle_traceroute(app, key),
            Tab::Security => handle_security(app, key),
            Tab::Scanner => handle_scanner(app, key),
            Tab::Hosts => handle_hosts(app, key),
            Tab::Notebook => handle_notebook(app, key),
            Tab::Workbench => handle_workbench(app, key),
            Tab::Objects => handle_objects(app, key),
            Tab::Rules => handle_rules(app, key),
            Tab::Diff => handle_diff(app, key),
            Tab::TlsAnalysis => handle_tls(app, key),
            Tab::OperatorGraph => handle_graph(app, key),
            Tab::Investigate => handle_investigate(app, key),
            _ => handle_main(app, key),
        }
    }
    false
}

fn is_quit(key: &KeyEvent) -> bool {
    key.code == KeyCode::Char('q')
        || (key.code == KeyCode::Char('c') && key.modifiers == KeyModifiers::CONTROL)
}

fn global_tab_switch(app: &mut App, key: &KeyEvent) -> bool {
    match key.code {
        KeyCode::Char('1') => {
            app.select_workspace(Workspace::Traffic);
            true
        }
        KeyCode::Char('2') => {
            app.select_workspace(Workspace::Inspect);
            true
        }
        KeyCode::Char('3') => {
            app.select_workspace(Workspace::Case);
            true
        }
        KeyCode::Char('4') => {
            app.navigate_to(Tab::Scanner);
            true
        }
        KeyCode::Char('5') => {
            app.select_workspace(Workspace::Case);
            true
        }
        KeyCode::Char('H') => {
            app.navigate_to(Tab::Hosts);
            true
        }
        KeyCode::Char('S') => {
            app.navigate_to(Tab::Security);
            true
        }
        KeyCode::Char('N') => {
            app.navigate_to(Tab::Notebook);
            true
        }
        KeyCode::Char('T') => {
            app.navigate_to(Tab::TlsAnalysis);
            true
        }
        KeyCode::Char('O') => {
            app.navigate_to(Tab::Objects);
            true
        }
        KeyCode::Char('R') => {
            app.navigate_to(Tab::Rules);
            true
        }
        KeyCode::Char('W') => {
            app.navigate_to(Tab::Workbench);
            true
        }
        KeyCode::Char('G') => {
            app.navigate_to(Tab::OperatorGraph);
            true
        }
        KeyCode::Char('D') => {
            app.navigate_to(Tab::Diff);
            true
        }
        KeyCode::Char(',') => {
            app.open_settings();
            true
        }
        _ => false,
    }
}

mod overlays;
use overlays::*;
mod tools;
use tools::*;
mod security;
use security::*;
mod casework;
use casework::*;
mod inspectors;
use inspectors::*;
mod graph;
use graph::*;
mod packets;
use packets::*;
mod analysis;
use analysis::*;
mod preferences;
use preferences::*;
