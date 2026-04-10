use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
use crate::app::App;
use crate::tabs::Tab;

/// Handle a crossterm event. Returns `true` if the app should quit.
pub fn handle(app: &mut App, event: Event) -> bool {
    let Event::Key(key) = event else { return false; };

    // Universal quit
    if is_quit(&key) {
        return true;
    }

    // Help overlay dismisses with Esc or h
    if app.show_help {
        if matches!(key.code, KeyCode::Esc | KeyCode::Char('h') | KeyCode::Char('q')) {
            app.show_help = false;
        }
        return false;
    }

    // Stream overlay dismisses with Esc
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
    } else if matches!(app.active_tab, Tab::Craft) {
        handle_craft(app, key);
    } else if matches!(app.active_tab, Tab::Traceroute) {
        handle_traceroute(app, key);
    } else {
        handle_main(app, key);
    }
    false
}

fn is_quit(key: &KeyEvent) -> bool {
    key.code == KeyCode::Char('q')
        || (key.code == KeyCode::Char('c') && key.modifiers == KeyModifiers::CONTROL)
}

fn handle_strings_search(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.strings_search_active = false;
            app.strings_filter.clear();
        }
        KeyCode::Enter => {
            app.strings_search_active = false;
        }
        KeyCode::Backspace => { app.strings_filter.pop(); }
        KeyCode::Char(c) => { app.strings_filter.push(c); }
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

    match key.code {
        // Global tab keys — switch to tab 1–8 or cycle
        KeyCode::Char('1') => app.active_tab = Tab::Packets,
        KeyCode::Char('2') => app.active_tab = Tab::Analysis,
        KeyCode::Char('3') => app.active_tab = Tab::Strings,
        KeyCode::Char('4') => app.active_tab = Tab::Dynamic,
        KeyCode::Char('5') => app.active_tab = Tab::Visualize,
        KeyCode::Char('6') => app.active_tab = Tab::Flows,
        KeyCode::Char('7') => app.active_tab = Tab::Craft,
        KeyCode::Char('8') => app.active_tab = Tab::Traceroute,
        KeyCode::Tab        => { app.craft.focus_next(); }
        KeyCode::BackTab    => { app.craft.focus_prev(); }
        KeyCode::Down | KeyCode::Char('j') => app.craft.focus_next(),
        KeyCode::Up   | KeyCode::Char('k') => app.craft.focus_prev(),
        // Enter or 'e' starts editing the focused field
        KeyCode::Enter | KeyCode::Char('e') => app.craft.start_edit(),
        // Space or 'x' injects the packet
        KeyCode::Char(' ') | KeyCode::Char('x') => app.craft_inject(),
        // 'C' clears result message
        KeyCode::Char('C') => app.craft.result = None,
        KeyCode::Char('i') => app.switch_interface(),
        KeyCode::Char('h') => app.show_help = true,
        _ => {}
    }
}

// ─── Traceroute tab ───────────────────────────────────────────────────────────

fn handle_traceroute(app: &mut App, key: KeyEvent) {
    match key.code {
        // Global tab keys
        KeyCode::Char('1') => app.active_tab = Tab::Packets,
        KeyCode::Char('2') => app.active_tab = Tab::Analysis,
        KeyCode::Char('3') => app.active_tab = Tab::Strings,
        KeyCode::Char('4') => app.active_tab = Tab::Dynamic,
        KeyCode::Char('5') => app.active_tab = Tab::Visualize,
        KeyCode::Char('6') => app.active_tab = Tab::Flows,
        KeyCode::Char('7') => app.active_tab = Tab::Craft,
        KeyCode::Char('8') => app.active_tab = Tab::Traceroute,
        KeyCode::Tab        => app.next_tab(),
        // Target input — always active
        KeyCode::Backspace  => { app.traceroute.target.pop(); }
        KeyCode::Enter      => {
            if app.traceroute.running {
                // Stop in-progress
                app.traceroute.running = false;
            } else {
                app.traceroute.start();
            }
        }
        KeyCode::Esc        => app.traceroute.clear(),
        KeyCode::Down | KeyCode::Char('j') => app.traceroute.scroll_down(),
        KeyCode::Up   | KeyCode::Char('k') => app.traceroute.scroll_up(),
        KeyCode::Char(c)    => {
            // Normal printable chars go to the target input
            app.traceroute.target.push(c);
        }
        _ => {}
    }
}

// ─── Main handler (all other tabs) ────────────────────────────────────────────

fn handle_main(app: &mut App, key: KeyEvent) {
    // Filter input mode intercepts most keys
    if app.filter.active {
        match key.code {
            KeyCode::Esc | KeyCode::Enter => {
                app.filter.active = false;
                app.rebuild_filtered();
            }
            KeyCode::Backspace => {
                app.filter.input.pop();
                app.rebuild_filtered();
            }
            KeyCode::Char(c) => {
                app.filter.input.push(c);
                app.rebuild_filtered();
            }
            _ => {}
        }
        return;
    }

    match key.code {
        // Tabs
        KeyCode::Char('1') => app.active_tab = Tab::Packets,
        KeyCode::Char('2') => app.active_tab = Tab::Analysis,
        KeyCode::Char('3') => app.active_tab = Tab::Strings,
        KeyCode::Char('4') => app.active_tab = Tab::Dynamic,
        KeyCode::Char('5') => app.active_tab = Tab::Visualize,
        KeyCode::Char('6') => app.active_tab = Tab::Flows,
        KeyCode::Char('7') => app.active_tab = Tab::Craft,
        KeyCode::Char('8') => app.active_tab = Tab::Traceroute,
        KeyCode::Tab       => app.next_tab(),

        // Interface switch (back to picker)
        KeyCode::Char('i') => app.switch_interface(),

        // Navigation — strings tab gets its own j/k/Enter/Esc when capture is stopped
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
            if matches!(app.active_tab, Tab::Strings) {
                app.strings_deselect();
            }
        }
        KeyCode::Char('g') => app.move_top(),
        KeyCode::Char('G') => app.move_bottom(),
        KeyCode::PageDown  => app.page_down(),
        KeyCode::PageUp    => app.page_up(),

        // Capture
        KeyCode::Char(' ') => app.toggle_capture(),
        KeyCode::Char('C') => app.clear_packets(),

        // PCAP export recording
        KeyCode::Char('w') => app.toggle_recording(),

        // Filter — on Strings tab '/' activates string search; elsewhere packet filter
        KeyCode::Char('/') => {
            if matches!(app.active_tab, Tab::Strings) {
                app.strings_search_active = true;
            } else {
                app.filter.active = true;
            }
        }

        // Help popup
        KeyCode::Char('h') => app.show_help = true,

        // Hot-reload Lua plugins
        KeyCode::Char('r') => app.reload_lua_plugins(),

        KeyCode::Char('b') if matches!(app.active_tab, Tab::Flows) => app.flows_sort_bytes(),
        KeyCode::Char('p') if matches!(app.active_tab, Tab::Flows) => app.flows_sort_packets(),
        KeyCode::Char('t') if matches!(app.active_tab, Tab::Flows) => app.flows_sort_time(),
        KeyCode::Char('s') if matches!(app.active_tab, Tab::Flows) => app.flows_sort_beacon(),
        KeyCode::Char('f') if matches!(app.active_tab, Tab::Flows) => app.flows_open_stream(),

        _ => {}
    }
}
