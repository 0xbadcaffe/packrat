use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use crate::app::{App, ObjectsSubTab, SecuritySubTab};
use crate::analysis::operator_graph::GraphUiModeState;
use crate::scan::{ScanField, ScanMode};
use crate::tabs::Tab;

/// Handle a crossterm event. Returns `true` if the app should quit.
pub fn handle(app: &mut App, event: Event) -> bool {
    let Event::Key(key) = event else { return false; };

    // Only quit when not in a text-entry mode — otherwise 'q' is a valid character.
    let in_text_mode = app.strings_search_active
        || app.filter.active
        || app.craft.editing
        || app.replay_editing
        || app.scan_editing
        || app.traceroute.editing
        || app.notebook_editing
        || app.hosts_searching
        || app.graph_ui.searching
        || app.search_open;

    if !in_text_mode && is_quit(&key) { return true; }

    // ── Global command palette ────────────────────────────────────────────────
    if app.search_open {
        handle_search_palette(app, key);
        return false;
    }

    if app.show_help {
        if matches!(key.code, KeyCode::Esc | KeyCode::Char('h') | KeyCode::Char('q')) {
            app.show_help = false;
        }
        return false;
    }

    if app.stream_overlay.is_some() {
        if matches!(key.code, KeyCode::Esc | KeyCode::Char('q')) {
            app.stream_overlay = None;
        }
        return false;
    }

    if app.picking_iface {
        handle_iface_picker(app, key);
    } else if app.strings_search_active {
        handle_strings_search(app, key);
    } else {
        // Open global search palette with '?'
        if key.code == KeyCode::Char('?') {
            app.open_search();
            return false;
        }

        match app.active_tab {
            Tab::Craft         => handle_craft(app, key),
            Tab::Traceroute    => handle_traceroute(app, key),
            Tab::Security      => handle_security(app, key),
            Tab::Scanner       => handle_scanner(app, key),
            Tab::Hosts         => handle_hosts(app, key),
            Tab::Notebook      => handle_notebook(app, key),
            Tab::Workbench     => handle_workbench(app, key),
            Tab::Objects       => handle_objects(app, key),
            Tab::OperatorGraph => handle_graph(app, key),
            _                  => handle_main(app, key),
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
        KeyCode::Char('1') => { app.active_tab = Tab::Packets;     true }
        KeyCode::Char('2') => { app.active_tab = Tab::Analysis;    true }
        KeyCode::Char('3') => { app.active_tab = Tab::Strings;     true }
        KeyCode::Char('4') => { app.active_tab = Tab::Dynamic;     true }
        KeyCode::Char('5') => { app.active_tab = Tab::Visualize;   true }
        KeyCode::Char('6') => { app.active_tab = Tab::Flows;       true }
        KeyCode::Char('7') => { app.active_tab = Tab::Craft;       true }
        KeyCode::Char('8') => { app.active_tab = Tab::Traceroute;  true }
        KeyCode::Char('9') => { app.active_tab = Tab::Security;    true }
        KeyCode::Char('0') => { app.active_tab = Tab::Scanner;     true }
        KeyCode::Char('H') => { app.active_tab = Tab::Hosts;       true }
        KeyCode::Char('N') => { app.active_tab = Tab::Notebook;    true }
        KeyCode::Char('T') => { app.active_tab = Tab::TlsAnalysis; true }
        KeyCode::Char('O') => { app.active_tab = Tab::Objects;     true }
        KeyCode::Char('R') => { app.active_tab = Tab::Rules;       true }
        KeyCode::Char('W') => { app.active_tab = Tab::Workbench;       true }
        KeyCode::Char('G') => { app.active_tab = Tab::OperatorGraph;   true }
        _ => false,
    }
}

fn handle_strings_search(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc       => { app.strings_search_active = false; app.strings_filter.clear(); }
        KeyCode::Enter     => { app.strings_search_active = false; }
        KeyCode::Backspace => { app.strings_filter.pop(); }
        KeyCode::Char(c)   => { app.strings_filter.push(c); }
        _ => {}
    }
}

// ─── Global command palette ───────────────────────────────────────────────────

fn handle_search_palette(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => { app.close_search(); }
        KeyCode::Enter => { app.search_jump(); }

        KeyCode::Down | KeyCode::Char('j') => {
            let max = app.search_results.len().saturating_sub(1);
            if app.search_selected < max { app.search_selected += 1; }
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

fn handle_iface_picker(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Down | KeyCode::Char('j') => app.iface_down(),
        KeyCode::Up   | KeyCode::Char('k') => app.iface_up(),
        KeyCode::Char(' ') | KeyCode::Enter => app.confirm_iface(),
        _ => {}
    }
}

// ─── Craft tab ────────────────────────────────────────────────────────────────

fn handle_craft(app: &mut App, key: KeyEvent) {
    if app.craft.editing {
        match key.code {
            KeyCode::Esc | KeyCode::Enter => app.craft.stop_edit(),
            KeyCode::Backspace            => app.craft.pop_char(),
            KeyCode::Tab                  => { app.craft.stop_edit(); app.craft.focus_next(); }
            KeyCode::BackTab              => { app.craft.stop_edit(); app.craft.focus_prev(); }
            KeyCode::Char(c)              => app.craft.push_char(c),
            _ => {}
        }
        return;
    }

    if global_tab_switch(app, &key) { return; }

    match key.code {
        KeyCode::Tab     => app.craft.focus_next(),
        KeyCode::BackTab => app.craft.focus_prev(),
        KeyCode::Down | KeyCode::Char('j') => app.craft.focus_next(),
        KeyCode::Up   | KeyCode::Char('k') => app.craft.focus_prev(),
        KeyCode::Enter | KeyCode::Char('e') => app.craft.start_edit(),
        KeyCode::Char(' ') | KeyCode::Char('x') => app.craft_inject(),
        // Flood mode — F toggles, < / > adjust rate
        KeyCode::Char('f') => {
            app.craft.flooding = !app.craft.flooding;
            if app.craft.flooding {
                app.craft.flood_sent = 0;
                app.craft.flood_accum = 0.0;
            }
        }
        KeyCode::Char('<') => app.craft.flood_rate_down(),
        KeyCode::Char('>') => app.craft.flood_rate_up(),
        KeyCode::Char('C') => {
            app.craft.result = None;
            app.craft.flooding = false;
            app.craft.flood_sent = 0;
        }
        KeyCode::Char('i') => app.switch_interface(),
        KeyCode::Char('h') => app.show_help = true,
        _ => {}
    }
}

// ─── Traceroute tab ───────────────────────────────────────────────────────────

fn handle_traceroute(app: &mut App, key: KeyEvent) {
    // While editing the target — all chars go to the field, no tab switching.
    if app.traceroute.editing {
        match key.code {
            KeyCode::Esc               => { app.traceroute.editing = false; }
            KeyCode::Enter             => {
                app.traceroute.editing = false;
                if !app.traceroute.running { app.traceroute.start(); }
            }
            KeyCode::Backspace         => { app.traceroute.target.pop(); }
            KeyCode::Char(c)           => { app.traceroute.target.push(c); }
            _ => {}
        }
        return;
    }

    if global_tab_switch(app, &key) { return; }

    match key.code {
        KeyCode::Tab                            => app.next_tab(),
        // Enter/e starts editing the target field
        KeyCode::Enter | KeyCode::Char('e')     => { app.traceroute.editing = true; }
        // Space starts/stops the trace when target is set
        KeyCode::Char(' ') | KeyCode::Char('x') => {
            if app.traceroute.running { app.traceroute.running = false; }
            else if !app.traceroute.target.is_empty() { app.traceroute.start(); }
            else { app.traceroute.editing = true; }
        }
        KeyCode::Esc                            => app.traceroute.clear(),
        KeyCode::Down | KeyCode::Char('j')      => app.traceroute.scroll_down(),
        KeyCode::Up   | KeyCode::Char('k')      => app.traceroute.scroll_up(),
        _ => {}
    }
}

// ─── Security tab ─────────────────────────────────────────────────────────────

fn handle_security(app: &mut App, key: KeyEvent) {
    // Replay editing intercepts all keys — must check before global_tab_switch
    // so that typing digits in the file path doesn't jump to another tab.
    if matches!(app.security_tab, SecuritySubTab::Replay) && app.replay_editing {
        match key.code {
            KeyCode::Esc | KeyCode::Enter => {
                if matches!(key.code, KeyCode::Enter) { app.replay.load(); }
                app.replay_editing = false;
            }
            KeyCode::Backspace => { app.replay.path.pop(); }
            KeyCode::Char(c)   => { app.replay.path.push(c); }
            _ => {}
        }
        return;
    }

    if global_tab_switch(app, &key) { return; }

    match key.code {
        // Sub-tab cycling with [ / ]
        KeyCode::Char('[') | KeyCode::BackTab => app.security_subtab_prev(),
        KeyCode::Char(']') | KeyCode::Tab     => app.security_subtab_next(),
        // Direct sub-tab keys
        KeyCode::Char('a') => app.security_tab = SecuritySubTab::Ids,
        KeyCode::Char('c') => app.security_tab = SecuritySubTab::Credentials,
        KeyCode::Char('o') => app.security_tab = SecuritySubTab::OsFingerprint,
        KeyCode::Char('w') => app.security_tab = SecuritySubTab::ArpWatch,
        KeyCode::Char('d') => app.security_tab = SecuritySubTab::DnsTunnel,
        KeyCode::Char('u') => app.security_tab = SecuritySubTab::HttpAnalytics,
        KeyCode::Char('t') => app.security_tab = SecuritySubTab::TlsWeakness,
        KeyCode::Char('b') => app.security_tab = SecuritySubTab::BruteForce,
        KeyCode::Char('v') => app.security_tab = SecuritySubTab::VulnHits,
        KeyCode::Char('p') => app.security_tab = SecuritySubTab::Replay,
        // Navigation
        KeyCode::Down | KeyCode::Char('j') => {
            app.security_scroll = app.security_scroll.saturating_add(1);
        }
        KeyCode::Up | KeyCode::Char('k') => {
            app.security_scroll = app.security_scroll.saturating_sub(1);
        }
        KeyCode::Char('g') => app.security_scroll = 0,
        KeyCode::Char('G') => app.security_scroll = 9999,
        KeyCode::Char('C') => {
            app.security.clear(); app.credentials.clear(); app.security_scroll = 0;
        }
        // Replay sub-tab controls
        KeyCode::Char('e') if matches!(app.security_tab, SecuritySubTab::Replay) => {
            app.replay_editing = true;
        }
        KeyCode::Enter if matches!(app.security_tab, SecuritySubTab::Replay) => {
            app.replay.load();
        }
        KeyCode::Char(' ') if matches!(app.security_tab, SecuritySubTab::Replay) => {
            if app.replay.running { app.replay.stop(); }
            else { app.replay.start(); }
        }
        KeyCode::Char('<') if matches!(app.security_tab, SecuritySubTab::Replay) => {
            app.replay.speed_down();
        }
        KeyCode::Char('>') if matches!(app.security_tab, SecuritySubTab::Replay) => {
            app.replay.speed_up();
        }
        KeyCode::Char('h') => app.show_help = true,
        _ => {}
    }
}

// ─── Scanner tab ──────────────────────────────────────────────────────────────

fn handle_scanner(app: &mut App, key: KeyEvent) {
    if app.scan_editing {
        match key.code {
            KeyCode::Esc | KeyCode::Enter => { app.scan_editing = false; }
            KeyCode::Backspace => {
                match app.scan.focused_field {
                    ScanField::Target    => { app.scan.target.pop(); }
                    ScanField::PortStart => { app.scan.port_range_start.pop(); }
                    ScanField::PortEnd   => { app.scan.port_range_end.pop(); }
                    ScanField::Mode      => {}
                }
            }
            KeyCode::Char(c) => {
                match app.scan.focused_field {
                    ScanField::Target    => app.scan.target.push(c),
                    ScanField::PortStart => app.scan.port_range_start.push(c),
                    ScanField::PortEnd   => app.scan.port_range_end.push(c),
                    ScanField::Mode      => {}
                }
            }
            _ => {}
        }
        return;
    }

    if global_tab_switch(app, &key) { return; }

    match key.code {
        KeyCode::Tab | KeyCode::Down | KeyCode::Char('j') => {
            app.scan.focused_field = match app.scan.focused_field {
                ScanField::Target    => ScanField::PortStart,
                ScanField::PortStart => ScanField::PortEnd,
                ScanField::PortEnd   => ScanField::Mode,
                ScanField::Mode      => ScanField::Target,
            };
        }
        KeyCode::BackTab | KeyCode::Up | KeyCode::Char('k') => {
            app.scan.focused_field = match app.scan.focused_field {
                ScanField::Target    => ScanField::Mode,
                ScanField::PortStart => ScanField::Target,
                ScanField::PortEnd   => ScanField::PortStart,
                ScanField::Mode      => ScanField::PortEnd,
            };
        }
        KeyCode::Enter | KeyCode::Char('e') => {
            if app.scan.focused_field == ScanField::Mode {
                // Cycle mode
                app.scan.scan_mode = match app.scan.scan_mode {
                    ScanMode::TcpConnect => ScanMode::Syn,
                    ScanMode::Syn        => ScanMode::Udp,
                    ScanMode::Udp        => ScanMode::TcpConnect,
                };
            } else {
                app.scan_editing = true;
            }
        }
        KeyCode::Char('m') => {
            app.scan.scan_mode = match app.scan.scan_mode {
                ScanMode::TcpConnect => ScanMode::Syn,
                ScanMode::Syn        => ScanMode::Udp,
                ScanMode::Udp        => ScanMode::TcpConnect,
            };
        }
        KeyCode::Char(' ') | KeyCode::Char('x') => {
            if app.scan.running {
                app.scan.running = false;
            } else {
                app.scan.start();
            }
        }
        KeyCode::Esc => { app.scan.running = false; }
        KeyCode::Char('C') => { app.scan.clear(); app.scanner_scroll = 0; }
        KeyCode::PageDown => {
            app.scanner_scroll = app.scanner_scroll.saturating_add(20);
        }
        KeyCode::PageUp => {
            app.scanner_scroll = app.scanner_scroll.saturating_sub(20);
        }
        KeyCode::Char('h') => app.show_help = true,
        _ => {}
    }
}

// ─── Hosts tab ────────────────────────────────────────────────────────────────

fn handle_hosts(app: &mut App, key: KeyEvent) {
    if app.hosts_searching {
        match key.code {
            KeyCode::Esc | KeyCode::Enter => { app.hosts_searching = false; }
            KeyCode::Backspace => { app.hosts_search.pop(); }
            KeyCode::Char(c)   => { app.hosts_search.push(c); }
            _ => {}
        }
        return;
    }

    if global_tab_switch(app, &key) { return; }

    match key.code {
        KeyCode::Char('s') | KeyCode::Char('/') => { app.hosts_searching = true; }
        KeyCode::Down | KeyCode::Char('j') => { app.hosts_scroll = app.hosts_scroll.saturating_add(1); }
        KeyCode::Up   | KeyCode::Char('k') => { app.hosts_scroll = app.hosts_scroll.saturating_sub(1); }
        KeyCode::Char('g') => { app.hosts_scroll = 0; }
        KeyCode::Char('C') => { app.hosts_search.clear(); app.hosts_scroll = 0; }
        KeyCode::Char('c') => { app.hosts.clear(); }
        KeyCode::Char('h') => { app.show_help = true; }
        _ => {}
    }
}

// ─── Notebook tab ─────────────────────────────────────────────────────────────

fn handle_notebook(app: &mut App, key: KeyEvent) {
    if app.notebook_editing {
        match key.code {
            KeyCode::Esc => {
                app.notebook_editing = false;
                app.notebook_input.clear();
            }
            KeyCode::Enter => {
                if !app.notebook_input.is_empty() {
                    let text = app.notebook_input.clone();
                    app.notebook.add(text, None);
                    app.notebook_input.clear();
                }
                app.notebook_editing = false;
            }
            KeyCode::Backspace => { app.notebook_input.pop(); }
            KeyCode::Char(c)   => { app.notebook_input.push(c); }
            _ => {}
        }
        return;
    }

    if global_tab_switch(app, &key) { return; }

    match key.code {
        KeyCode::Char('n')   => { app.notebook_editing = true; }
        KeyCode::Down | KeyCode::Char('j') => { app.notebook_scroll = app.notebook_scroll.saturating_add(1); }
        KeyCode::Up   | KeyCode::Char('k') => { app.notebook_scroll = app.notebook_scroll.saturating_sub(1); }
        KeyCode::Char('g')   => { app.notebook_scroll = 0; }
        KeyCode::Char('d')   => {
            // Delete the note at scroll position
            let notes = app.notebook.all();
            if let Some(note) = notes.get(app.notebook_scroll) {
                let id = note.id;
                app.notebook.delete(id);
            }
        }
        KeyCode::Char('h')   => { app.show_help = true; }
        _ => {}
    }
}

// ─── Workbench tab ────────────────────────────────────────────────────────────

fn handle_workbench(app: &mut App, key: KeyEvent) {
    if global_tab_switch(app, &key) { return; }

    const HEX_COLS: usize = 16;
    match key.code {
        KeyCode::Char('h') | KeyCode::Left  => app.workbench.cursor_left(),
        KeyCode::Char('l') | KeyCode::Right => app.workbench.cursor_right(),
        KeyCode::Char('k') | KeyCode::Up    => app.workbench.cursor_up(HEX_COLS),
        KeyCode::Char('j') | KeyCode::Down  => app.workbench.cursor_down(HEX_COLS),
        KeyCode::Char(' ')                  => app.workbench.toggle_selection(),
        KeyCode::Esc                        => { app.workbench.sel_start = None; }
        // Go back to Packets tab to pick a different packet
        KeyCode::Char('p')                  => { app.active_tab = Tab::Packets; }
        _ => {}
    }
}

// ─── Objects tab ─────────────────────────────────────────────────────────────

fn handle_objects(app: &mut App, key: KeyEvent) {
    if global_tab_switch(app, &key) { return; }

    match key.code {
        // Sub-tab navigation
        KeyCode::Char('o') => { app.objects_subtab = ObjectsSubTab::Objects; }
        KeyCode::Char('y') => { app.objects_subtab = ObjectsSubTab::YaraRules; }
        KeyCode::Char('m') => { app.objects_subtab = ObjectsSubTab::YaraMatches; }
        KeyCode::Char('[') | KeyCode::BackTab => {
            app.objects_subtab = match app.objects_subtab {
                ObjectsSubTab::Objects     => ObjectsSubTab::YaraMatches,
                ObjectsSubTab::YaraRules   => ObjectsSubTab::Objects,
                ObjectsSubTab::YaraMatches => ObjectsSubTab::YaraRules,
            };
        }
        KeyCode::Char(']') | KeyCode::Tab => {
            app.objects_subtab = match app.objects_subtab {
                ObjectsSubTab::Objects     => ObjectsSubTab::YaraRules,
                ObjectsSubTab::YaraRules   => ObjectsSubTab::YaraMatches,
                ObjectsSubTab::YaraMatches => ObjectsSubTab::Objects,
            };
        }

        // Scroll — different counter per sub-panel
        KeyCode::Down | KeyCode::Char('j') => {
            match app.objects_subtab {
                ObjectsSubTab::Objects     => { app.objects_scroll = app.objects_scroll.saturating_add(1); }
                ObjectsSubTab::YaraRules   => { app.yara_rules_scroll = app.yara_rules_scroll.saturating_add(1); }
                ObjectsSubTab::YaraMatches => { app.yara_matches_scroll = app.yara_matches_scroll.saturating_add(1); }
            }
        }
        KeyCode::Up | KeyCode::Char('k') => {
            match app.objects_subtab {
                ObjectsSubTab::Objects     => { app.objects_scroll = app.objects_scroll.saturating_sub(1); }
                ObjectsSubTab::YaraRules   => { app.yara_rules_scroll = app.yara_rules_scroll.saturating_sub(1); }
                ObjectsSubTab::YaraMatches => { app.yara_matches_scroll = app.yara_matches_scroll.saturating_sub(1); }
            }
        }
        KeyCode::Char('g') => {
            app.objects_scroll = 0;
            app.yara_rules_scroll = 0;
            app.yara_matches_scroll = 0;
        }

        // Actions
        KeyCode::Char('r') => { app.reload_yara_rules(); }
        KeyCode::Char('s') => { app.yara_force_rescan(); }
        KeyCode::Char('c') => { app.carve_from_streams(); }
        KeyCode::Char('h') => { app.show_help = true; }

        _ => {}
    }
}

// ─── Operator Graph tab ───────────────────────────────────────────────────────

fn handle_graph(app: &mut App, key: KeyEvent) {
    // Search input mode
    if app.graph_ui.searching {
        match key.code {
            KeyCode::Esc   => { app.graph_ui.searching = false; }
            KeyCode::Enter => { app.graph_ui.searching = false; }
            KeyCode::Backspace => { app.graph_ui.search.pop(); }
            KeyCode::Char(c)   => { app.graph_ui.search.push(c); }
            _ => {}
        }
        return;
    }

    if global_tab_switch(app, &key) { return; }

    match key.code {
        // Mode cycling
        KeyCode::Tab => {
            app.graph_ui.mode = app.graph_ui.mode.next();
        }

        // Node list navigation
        KeyCode::Down | KeyCode::Char('j') => {
            match app.graph_ui.mode {
                GraphUiModeState::Neighborhood | GraphUiModeState::Adjacency => {
                    app.graph_ui.list_scroll = app.graph_ui.list_scroll.saturating_add(1);
                }
                GraphUiModeState::Paths => {
                    let max = app.operator_graph.paths.len().saturating_sub(1);
                    if app.graph_ui.path_selected < max {
                        app.graph_ui.path_selected += 1;
                    }
                }
                GraphUiModeState::Clusters => {
                    let max = app.operator_graph.clusters.len().saturating_sub(1);
                    if app.graph_ui.cluster_selected < max {
                        app.graph_ui.cluster_selected += 1;
                    }
                }
                GraphUiModeState::Evidence => {
                    app.graph_ui.evidence_scroll = app.graph_ui.evidence_scroll.saturating_add(1);
                }
            }
        }
        KeyCode::Up | KeyCode::Char('k') => {
            match app.graph_ui.mode {
                GraphUiModeState::Neighborhood | GraphUiModeState::Adjacency => {
                    app.graph_ui.list_scroll = app.graph_ui.list_scroll.saturating_sub(1);
                }
                GraphUiModeState::Paths => {
                    app.graph_ui.path_selected = app.graph_ui.path_selected.saturating_sub(1);
                }
                GraphUiModeState::Clusters => {
                    app.graph_ui.cluster_selected = app.graph_ui.cluster_selected.saturating_sub(1);
                }
                GraphUiModeState::Evidence => {
                    app.graph_ui.evidence_scroll = app.graph_ui.evidence_scroll.saturating_sub(1);
                }
            }
        }

        // Select node
        KeyCode::Enter => {
            match app.graph_ui.mode {
                GraphUiModeState::Neighborhood | GraphUiModeState::Adjacency => {
                    // Select the highlighted node in the list
                    let filter = app.graph_ui.filter.clone();
                    let search = app.graph_ui.search.clone();
                    let snapshot = app.operator_graph.filtered_snapshot(&filter);
                    let visible: Vec<_> = {
                        let q = search.to_lowercase();
                        snapshot.node_ids.iter().filter_map(|&id| {
                            app.operator_graph.get_node(id)
                        }).filter(|n| {
                            q.is_empty() || n.label.to_lowercase().contains(&q)
                        }).collect()
                    };
                    let scroll = app.graph_ui.list_scroll;
                    if let Some(node) = visible.get(scroll) {
                        let id = node.id;
                        if let Some(prev) = app.graph_ui.selected_node {
                            app.graph_ui.pivot_history.push(prev);
                        }
                        app.graph_ui.selected_node = Some(id);
                        app.graph_ui.neighbor_scroll = 0;
                        app.graph_ui.detail_scroll = 0;
                    }
                }
                GraphUiModeState::Paths => {
                    // Jump to first node of selected path
                    if let Some(path) = app.operator_graph.paths.get(app.graph_ui.path_selected) {
                        if let Some(&node_id) = path.nodes.first() {
                            app.graph_ui.selected_node = Some(node_id);
                            app.graph_ui.mode = GraphUiModeState::Neighborhood;
                        }
                    }
                }
                GraphUiModeState::Clusters => {
                    // Jump to first member of selected cluster
                    if let Some(cluster) = app.operator_graph.clusters.get(app.graph_ui.cluster_selected) {
                        if let Some(&node_id) = cluster.members.first() {
                            app.graph_ui.selected_node = Some(node_id);
                            app.graph_ui.mode = GraphUiModeState::Neighborhood;
                        }
                    }
                }
                _ => {}
            }
        }

        // Navigate back (pivot history)
        KeyCode::Backspace => {
            if let Some(prev) = app.graph_ui.pivot_history.pop() {
                app.graph_ui.selected_node = Some(prev);
            }
        }

        // Jump to paths/clusters mode
        KeyCode::Char('A') => { app.graph_ui.mode = GraphUiModeState::Adjacency; }
        KeyCode::Char('P') | KeyCode::Char('a') => { app.graph_ui.mode = GraphUiModeState::Paths; }
        KeyCode::Char('C') => { app.graph_ui.mode = GraphUiModeState::Clusters; }
        KeyCode::Char('E') => { app.graph_ui.mode = GraphUiModeState::Evidence; }

        // Compute pivots for selected node
        KeyCode::Char('p') => {
            if let Some(node_id) = app.graph_ui.selected_node {
                app.operator_graph.recompute_pivots(node_id);
            }
        }

        // Search
        KeyCode::Char('/') => {
            app.graph_ui.searching = true;
        }

        // Export
        KeyCode::Char('x') => {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default().as_secs();
            let path = format!("packrat_graph_{}.json", ts);
            let _ = crate::storage::graph_store::export_json(&app.operator_graph, &path);
        }

        KeyCode::Char('h') => { app.show_help = true; }

        _ => {}
    }
}

// ─── Main handler ─────────────────────────────────────────────────────────────

fn handle_main(app: &mut App, key: KeyEvent) {
    if app.filter.active {
        match key.code {
            KeyCode::Esc | KeyCode::Enter => {
                app.filter.active = false;
                app.rebuild_filtered();
            }
            KeyCode::Backspace => { app.filter.input.pop(); app.rebuild_filtered(); }
            KeyCode::Char(c)   => { app.filter.input.push(c); app.rebuild_filtered(); }
            _ => {}
        }
        return;
    }

    if global_tab_switch(app, &key) { return; }

    match key.code {
        KeyCode::Tab => app.next_tab(),
        KeyCode::Char('i') => app.switch_interface(),

        KeyCode::Down | KeyCode::Char('j') => {
            if matches!(app.active_tab, Tab::Strings) && !app.capturing {
                let list_len = app.strings_list_len();
                app.strings_move_down(list_len);
            } else {
                app.move_down();
            }
        }
        KeyCode::Up | KeyCode::Char('k') => {
            if matches!(app.active_tab, Tab::Strings) && !app.capturing {
                app.strings_move_up();
            } else {
                app.move_up();
            }
        }
        KeyCode::Enter => {
            if matches!(app.active_tab, Tab::Strings) && !app.capturing {
                app.strings_select();
            } else if matches!(app.active_tab, Tab::Flows) {
                app.flows_jump_to_packets();
            } else if matches!(app.active_tab, Tab::Packets) {
                // Open selected packet in the protocol workbench
                if let Some(pkt) = app.selected_packet() {
                    let pkt = pkt.clone();
                    app.workbench.load_packet(&pkt);
                    app.active_tab = Tab::Workbench;
                }
            }
        }
        KeyCode::Esc => {
            if matches!(app.active_tab, Tab::Strings) { app.strings_deselect(); }
        }
        KeyCode::Char('g') => app.move_top(),
        KeyCode::Char('G') => app.move_bottom(),
        KeyCode::PageDown   => app.page_down(),
        KeyCode::PageUp     => app.page_up(),

        KeyCode::Char(' ') => app.toggle_capture(),
        KeyCode::Char('C') => app.clear_packets(),
        KeyCode::Char('w') => app.toggle_recording(),

        KeyCode::Char('/') => {
            if matches!(app.active_tab, Tab::Strings) {
                app.strings_search_active = true;
            } else {
                app.filter.active = true;
            }
        }

        KeyCode::Char('h') => app.show_help = true,
        KeyCode::Char('r') => app.reload_lua_plugins(),

        KeyCode::Char('b') if matches!(app.active_tab, Tab::Flows) => app.flows_sort_bytes(),
        KeyCode::Char('p') if matches!(app.active_tab, Tab::Flows) => app.flows_sort_packets(),
        KeyCode::Char('t') if matches!(app.active_tab, Tab::Flows) => app.flows_sort_time(),
        KeyCode::Char('s') if matches!(app.active_tab, Tab::Flows) => app.flows_sort_beacon(),
        KeyCode::Char('f') if matches!(app.active_tab, Tab::Flows) => app.flows_open_stream(),

        _ => {}
    }
}
