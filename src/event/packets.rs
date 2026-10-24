use super::*;

// ─── Main handler ─────────────────────────────────────────────────────────────

pub(super) fn handle_investigate(app: &mut App, key: KeyEvent) {
    if app.header_searching {
        match key.code {
            KeyCode::Esc | KeyCode::Enter => app.close_header_search(),
            KeyCode::Backspace => app.pop_header_search(),
            KeyCode::Char(c) => app.update_header_search(c),
            _ => {}
        }
        return;
    }

    if app.investigation_view == InvestigationView::Decode {
        match key.code {
            KeyCode::Char('/') => app.start_header_search(),
            KeyCode::Char('j') | KeyCode::Down => app.header_cursor_down(),
            KeyCode::Char('k') | KeyCode::Up => app.header_cursor_up(),
            KeyCode::Char('g') => app.header_cursor_home(),
            KeyCode::Char('G') => app.header_cursor_end(),
            KeyCode::Enter => app.jump_selected_header_to_bytes(),
            KeyCode::Char('f') => app.apply_selected_header_filter(),
            KeyCode::Char('c') => app.clear_header_search(),
            KeyCode::Char('s') => app.open_active_investigation_stream_overlay(),
            KeyCode::Char('=') => app.open_packet_comparison(),
            KeyCode::Char('n') => app.worklist_next_packet(),
            KeyCode::Char('p') => app.worklist_prev_packet(),
            KeyCode::Char('[') => app.investigation_prev_view(),
            KeyCode::Char(']') => app.investigation_next_view(),
            KeyCode::Char('w') => app.toggle_worklist(),
            KeyCode::Char('d') | KeyCode::Delete => app.remove_active_worklist_packet(),
            KeyCode::Char('l') => app.active_tab = Tab::Packets,
            KeyCode::Esc => app.close_worklist(),
            KeyCode::Tab | KeyCode::F(2) => app.open_view_menu(),
            _ => {
                global_tab_switch(app, &key);
            }
        }
        return;
    }

    if app.investigation_view == InvestigationView::Bytes {
        match key.code {
            KeyCode::Char('h') | KeyCode::Left => app.byte_cursor_left(),
            KeyCode::Char('l') | KeyCode::Right => app.byte_cursor_right(),
            KeyCode::Char('j') | KeyCode::Down => app.byte_cursor_down(),
            KeyCode::Char('k') | KeyCode::Up => app.byte_cursor_up(),
            KeyCode::Char('g') => app.byte_cursor_home(),
            KeyCode::Char('G') => app.byte_cursor_end(),
            KeyCode::Char('n') => app.worklist_next_packet(),
            KeyCode::Char('p') => app.worklist_prev_packet(),
            KeyCode::Char('[') => app.investigation_prev_view(),
            KeyCode::Char(']') => app.investigation_next_view(),
            KeyCode::Char('w') => app.toggle_worklist(),
            KeyCode::Char('d') | KeyCode::Delete => app.remove_active_worklist_packet(),
            KeyCode::Char('s') => app.open_active_investigation_stream_overlay(),
            KeyCode::Char('=') => app.open_packet_comparison(),
            KeyCode::Char('v') => app.active_tab = Tab::Packets,
            KeyCode::Esc => app.close_worklist(),
            KeyCode::Tab | KeyCode::F(2) => app.open_view_menu(),
            _ => {
                global_tab_switch(app, &key);
            }
        }
        return;
    }

    if global_tab_switch(app, &key) {
        return;
    }

    match key.code {
        KeyCode::Char('[') => app.investigation_prev_view(),
        KeyCode::Char(']') => app.investigation_next_view(),
        KeyCode::Char('n') | KeyCode::Down => app.worklist_next_packet(),
        KeyCode::Char('p') | KeyCode::Up => app.worklist_prev_packet(),
        KeyCode::Char('j') => app.investigation_scroll_down(),
        KeyCode::Char('k') => app.investigation_scroll_up(),
        KeyCode::Char('w') => app.toggle_worklist(),
        KeyCode::Char('d') | KeyCode::Delete => app.remove_active_worklist_packet(),
        KeyCode::Char('l') => app.active_tab = Tab::Packets,
        KeyCode::Char('s') => app.open_active_investigation_stream_overlay(),
        KeyCode::Char('=') => app.open_packet_comparison(),
        KeyCode::Esc => app.close_worklist(),
        KeyCode::Char('g') => app.investigation_scroll = 0,
        KeyCode::Tab | KeyCode::F(2) => app.open_view_menu(),
        _ => {}
    }
}

pub(super) fn handle_main(app: &mut App, key: KeyEvent) {
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

    if global_tab_switch(app, &key) {
        return;
    }

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
                app.open_selected_packet_investigation();
            }
        }
        KeyCode::Esc => {
            if matches!(app.active_tab, Tab::Strings) {
                app.strings_deselect();
            }
        }
        KeyCode::Char('g') => app.move_top(),
        KeyCode::Char('G') => app.move_bottom(),
        KeyCode::PageDown => app.page_down(),
        KeyCode::PageUp => app.page_up(),

        KeyCode::Char(' ') => app.toggle_capture(),
        KeyCode::Char('C') | KeyCode::Char('c')
            if matches!(
                app.active_tab,
                Tab::Packets
                    | Tab::Analysis
                    | Tab::Strings
                    | Tab::Dynamic
                    | Tab::Visualize
                    | Tab::Flows
            ) =>
        {
            app.clear_packets()
        }
        KeyCode::Char('m') if matches!(app.active_tab, Tab::Packets) => {
            app.mark_selected_packet_for_investigation()
        }
        KeyCode::Char('w') if matches!(app.active_tab, Tab::Packets) => app.toggle_worklist(),

        KeyCode::Char('/') => {
            if matches!(app.active_tab, Tab::Strings) {
                app.strings_search_active = true;
            } else {
                app.filter.active = true;
            }
        }

        KeyCode::Char('h') => app.show_help = true,
        KeyCode::Char('r') => app.reload_lua_plugins(),
        KeyCode::Char('a') if matches!(app.active_tab, Tab::Packets) => app.open_autopsy(),

        KeyCode::Char('b') if matches!(app.active_tab, Tab::Flows) => app.flows_sort_bytes(),
        KeyCode::Char('p') if matches!(app.active_tab, Tab::Flows) => app.flows_sort_packets(),
        KeyCode::Char('t') if matches!(app.active_tab, Tab::Flows) => app.flows_sort_time(),
        KeyCode::Char('s') if matches!(app.active_tab, Tab::Flows) => app.flows_sort_beacon(),
        KeyCode::Char('f') if matches!(app.active_tab, Tab::Flows) => app.flows_open_stream(),

        _ => {}
    }
}
