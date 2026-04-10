use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use crate::app::{App, SecuritySubTab};
use crate::scan::{ScanField, ScanMode};
use crate::tabs::Tab;

/// Handle a crossterm event. Returns `true` if the app should quit.
pub fn handle(app: &mut App, event: Event) -> bool {
    let Event::Key(key) = event else { return false; };

    if is_quit(&key) { return true; }

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
        match app.active_tab {
            Tab::Craft      => handle_craft(app, key),
            Tab::Traceroute => handle_traceroute(app, key),
            Tab::Security   => handle_security(app, key),
            Tab::Scanner    => handle_scanner(app, key),
            _               => handle_main(app, key),
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
        KeyCode::Char('1') => { app.active_tab = Tab::Packets;    true }
        KeyCode::Char('2') => { app.active_tab = Tab::Analysis;   true }
        KeyCode::Char('3') => { app.active_tab = Tab::Strings;    true }
        KeyCode::Char('4') => { app.active_tab = Tab::Dynamic;    true }
        KeyCode::Char('5') => { app.active_tab = Tab::Visualize;  true }
        KeyCode::Char('6') => { app.active_tab = Tab::Flows;      true }
        KeyCode::Char('7') => { app.active_tab = Tab::Craft;      true }
        KeyCode::Char('8') => { app.active_tab = Tab::Traceroute; true }
        KeyCode::Char('9') => { app.active_tab = Tab::Security;   true }
        KeyCode::Char('0') => { app.active_tab = Tab::Scanner;    true }
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
    if global_tab_switch(app, &key) { return; }
    match key.code {
        KeyCode::Tab       => app.next_tab(),
        KeyCode::Backspace => { app.traceroute.target.pop(); }
        KeyCode::Enter     => {
            if app.traceroute.running { app.traceroute.running = false; }
            else { app.traceroute.start(); }
        }
        KeyCode::Esc => app.traceroute.clear(),
        KeyCode::Down | KeyCode::Char('j') => app.traceroute.scroll_down(),
        KeyCode::Up   | KeyCode::Char('k') => app.traceroute.scroll_up(),
        KeyCode::Char(c) => { app.traceroute.target.push(c); }
        _ => {}
    }
}

// ─── Security tab ─────────────────────────────────────────────────────────────

fn handle_security(app: &mut App, key: KeyEvent) {
    if global_tab_switch(app, &key) { return; }

    // Replay editing
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
