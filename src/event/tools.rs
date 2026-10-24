use super::*;

// ─── Craft tab ────────────────────────────────────────────────────────────────

pub(super) fn handle_craft(app: &mut App, key: KeyEvent) {
    if app.craft.editing {
        match key.code {
            KeyCode::Esc | KeyCode::Enter => app.craft.stop_edit(),
            KeyCode::Backspace => app.craft.pop_char(),
            KeyCode::Char(c) => app.craft.push_char(c),
            _ => {}
        }
        return;
    }

    if global_tab_switch(app, &key) {
        return;
    }

    match key.code {
        KeyCode::Tab => {
            app.next_tab();
            return;
        }
        KeyCode::BackTab => {
            app.prev_tab();
            return;
        }
        KeyCode::Down | KeyCode::Char('j') => app.craft.focus_next(),
        KeyCode::Up | KeyCode::Char('k') => app.craft.focus_prev(),
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

pub(super) fn handle_traceroute(app: &mut App, key: KeyEvent) {
    // While editing the target — all chars go to the field, no tab switching.
    if app.traceroute.editing {
        match key.code {
            KeyCode::Esc => {
                app.traceroute.editing = false;
            }
            KeyCode::Enter => {
                app.traceroute.editing = false;
                if !app.traceroute.running {
                    app.traceroute.start();
                }
            }
            KeyCode::Backspace => {
                app.traceroute.target.pop();
            }
            KeyCode::Char(c) => {
                app.traceroute.target.push(c);
            }
            _ => {}
        }
        return;
    }

    if global_tab_switch(app, &key) {
        return;
    }

    match key.code {
        KeyCode::Tab => app.next_tab(),
        // Enter/e starts editing the target field
        KeyCode::Enter | KeyCode::Char('e') => {
            app.traceroute.editing = true;
        }
        // Space starts/stops the trace when target is set
        KeyCode::Char(' ') | KeyCode::Char('x') => {
            if app.traceroute.running {
                app.traceroute.running = false;
            } else if !app.traceroute.target.is_empty() {
                app.traceroute.start();
            } else {
                app.traceroute.editing = true;
            }
        }
        KeyCode::Esc => app.traceroute.clear(),
        KeyCode::Down | KeyCode::Char('j') => app.traceroute.scroll_down(),
        KeyCode::Up | KeyCode::Char('k') => app.traceroute.scroll_up(),
        _ => {}
    }
}

// ─── Scanner tab ──────────────────────────────────────────────────────────────

pub(super) fn handle_scanner(app: &mut App, key: KeyEvent) {
    if app.scan_editing {
        match key.code {
            KeyCode::Esc | KeyCode::Enter => {
                app.scan_editing = false;
            }
            KeyCode::Backspace => match app.scan.focused_field {
                ScanField::Target => {
                    app.scan.target.pop();
                }
                ScanField::PortStart => {
                    app.scan.port_range_start.pop();
                }
                ScanField::PortEnd => {
                    app.scan.port_range_end.pop();
                }
                ScanField::Mode => {}
            },
            KeyCode::Char(c) => match app.scan.focused_field {
                ScanField::Target => app.scan.target.push(c),
                ScanField::PortStart => app.scan.port_range_start.push(c),
                ScanField::PortEnd => app.scan.port_range_end.push(c),
                ScanField::Mode => {}
            },
            _ => {}
        }
        return;
    }

    if global_tab_switch(app, &key) {
        return;
    }

    match key.code {
        KeyCode::Tab => {
            app.next_tab();
            return;
        }
        KeyCode::BackTab => {
            app.prev_tab();
            return;
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.scan.focused_field = match app.scan.focused_field {
                ScanField::Target => ScanField::PortStart,
                ScanField::PortStart => ScanField::PortEnd,
                ScanField::PortEnd => ScanField::Mode,
                ScanField::Mode => ScanField::Target,
            };
        }
        KeyCode::Up | KeyCode::Char('k') => {
            app.scan.focused_field = match app.scan.focused_field {
                ScanField::Target => ScanField::Mode,
                ScanField::PortStart => ScanField::Target,
                ScanField::PortEnd => ScanField::PortStart,
                ScanField::Mode => ScanField::PortEnd,
            };
        }
        KeyCode::Enter | KeyCode::Char('e') => {
            if app.scan.focused_field == ScanField::Mode {
                // Cycle mode
                app.scan.scan_mode = match app.scan.scan_mode {
                    ScanMode::TcpConnect => ScanMode::Syn,
                    ScanMode::Syn => ScanMode::Udp,
                    ScanMode::Udp => ScanMode::TcpConnect,
                };
            } else {
                app.scan_editing = true;
            }
        }
        KeyCode::Char('m') => {
            app.scan.scan_mode = match app.scan.scan_mode {
                ScanMode::TcpConnect => ScanMode::Syn,
                ScanMode::Syn => ScanMode::Udp,
                ScanMode::Udp => ScanMode::TcpConnect,
            };
        }
        KeyCode::Char(' ') | KeyCode::Char('x') => {
            if app.scan.running {
                app.scan.running = false;
            } else {
                app.scan.start();
            }
        }
        KeyCode::Esc => {
            app.scan.running = false;
        }
        KeyCode::Char('C') => {
            app.scan.clear();
            app.scanner_scroll = 0;
        }
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
