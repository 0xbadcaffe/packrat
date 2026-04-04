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
        KeyCode::Char('6') => app.active_tab = Tab::Topology,
        KeyCode::Char('7') => app.active_tab = Tab::Flows,
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

        KeyCode::Char('b') if matches!(app.active_tab, Tab::Flows) => app.flows_sort_bytes(),
        KeyCode::Char('p') if matches!(app.active_tab, Tab::Flows) => app.flows_sort_packets(),
        KeyCode::Char('t') if matches!(app.active_tab, Tab::Flows) => app.flows_sort_time(),
        KeyCode::Char('s') if matches!(app.active_tab, Tab::Flows) => app.flows_sort_beacon(),
        KeyCode::Char('f') if matches!(app.active_tab, Tab::Flows) => app.flows_open_stream(),

        _ => {}
    }
}
