use super::*;

#[tokio::test]
async fn investigate_headers_searches_tcp_fields_without_global_palette() {
    let mut app = App::new_for_test();
    app.inject_packet(tcp_packet(1));
    app.selected = Some(0);
    event::handle(&mut app, key(KeyCode::Enter));
    app.investigation_view = InvestigationView::Decode;

    event::handle(&mut app, key(KeyCode::Char('/')));
    event::handle(&mut app, key(KeyCode::Char('t')));
    event::handle(&mut app, key(KeyCode::Char('c')));
    event::handle(&mut app, key(KeyCode::Char('p')));
    event::handle(&mut app, key(KeyCode::Char('.')));
    event::handle(&mut app, key(KeyCode::Char('s')));
    event::handle(&mut app, key(KeyCode::Char('e')));
    event::handle(&mut app, key(KeyCode::Char('q')));
    event::handle(&mut app, key(KeyCode::Enter));

    assert!(!app.search_open);
    assert!(!app.header_searching);
    assert_eq!(app.visible_packet_header_fields()[0].path, "tcp.seq");
    assert_eq!(app.visible_packet_header_fields()[0].value, "16909060");
}

#[tokio::test]
async fn investigate_header_jumps_to_keyboard_byte_interpreter() {
    let mut app = App::new_for_test();
    app.inject_packet(tcp_packet(1));
    app.selected = Some(0);
    event::handle(&mut app, key(KeyCode::Enter));
    app.investigation_view = InvestigationView::Decode;

    event::handle(&mut app, key(KeyCode::Char('/')));
    for character in "tcp.seq".chars() {
        event::handle(&mut app, key(KeyCode::Char(character)));
    }
    event::handle(&mut app, key(KeyCode::Enter));
    let expected_offset = app.visible_packet_header_fields()[0].offset.unwrap();
    event::handle(&mut app, key(KeyCode::Enter));

    assert_eq!(app.investigation_view, InvestigationView::Bytes);
    assert_eq!(app.byte_cursor, expected_offset);

    event::handle(&mut app, key(KeyCode::Char('l')));
    assert_eq!(app.byte_cursor, expected_offset + 1);
    event::handle(&mut app, key(KeyCode::Char('g')));
    assert_eq!(app.byte_cursor, 0);
    event::handle(&mut app, key(KeyCode::Char('G')));
    assert_eq!(
        app.byte_cursor,
        app.active_investigation_packet().unwrap().bytes.len() - 1
    );
}

#[tokio::test]
async fn investigate_derived_header_without_offset_stays_in_headers() {
    let mut app = App::new_for_test();
    app.inject_packet(tcp_packet(1));
    app.selected = Some(0);
    event::handle(&mut app, key(KeyCode::Enter));
    app.investigation_view = InvestigationView::Decode;

    assert_eq!(app.visible_packet_header_fields()[0].path, "frame.number");
    assert_eq!(app.visible_packet_header_fields()[0].offset, None);
    event::handle(&mut app, key(KeyCode::Enter));

    assert_eq!(app.investigation_view, InvestigationView::Decode);
    assert!(
        app.status_msg
            .as_deref()
            .unwrap_or_default()
            .contains("no byte offset")
    );
}

#[tokio::test]
async fn investigate_s_opens_follow_stream_for_active_packet() {
    let mut app = App::new_for_test();
    app.inject_packet(tcp_payload_packet(1, b"GET /admin HTTP/1.1\r\n\r\n"));
    app.selected = Some(0);
    event::handle(&mut app, key(KeyCode::Enter));
    app.investigation_view = InvestigationView::Flow;

    event::handle(&mut app, key(KeyCode::Char('s')));

    let Some(overlay) = &app.stream_overlay else {
        panic!("stream overlay did not open");
    };
    assert_eq!(overlay.segments.len(), 1);
    assert!(overlay.segments[0].1.starts_with(b"GET /admin"));
}

#[tokio::test]
async fn investigate_equals_compares_active_packet_with_next_worklist_packet() {
    let mut app = App::new_for_test();
    app.inject_packet(tcp_packet(1));
    let mut second = tcp_packet(2);
    second.bytes[38..42].copy_from_slice(&99_u32.to_be_bytes());
    app.inject_packet(second);
    app.selected = Some(0);
    event::handle(&mut app, key(KeyCode::Enter));
    app.active_tab = Tab::Packets;
    app.selected = Some(1);
    event::handle(&mut app, key(KeyCode::Char('m')));
    app.worklist.prev();
    app.active_tab = Tab::Investigate;

    event::handle(&mut app, key(KeyCode::Char('=')));
    let comparison = app.packet_comparison.as_ref().expect("comparison overlay");
    assert_eq!((comparison.left_no, comparison.right_no), (1, 2));
    assert!(
        comparison
            .field_differences
            .iter()
            .any(|difference| difference.path == "tcp.seq")
    );

    event::handle(&mut app, key(KeyCode::Esc));
    assert!(app.packet_comparison.is_none());
    assert_eq!(app.worklist.active_packet_no(), Some(1));
}

#[tokio::test]
async fn theme_picker_esc_closes() {
    let mut app = App::new_for_test();
    app.theme_picker_open = true;
    event::handle(&mut app, key(KeyCode::Esc));
    assert!(!app.theme_picker_open);
}

#[tokio::test]
async fn theme_picker_j_moves_cursor_down() {
    let mut app = App::new_for_test();
    app.theme_picker_open = true;
    app.theme_picker_cursor = 0;
    event::handle(&mut app, key(KeyCode::Char('j')));
    assert_eq!(app.theme_picker_cursor, 1);
}

#[tokio::test]
async fn theme_picker_k_moves_cursor_up() {
    let mut app = App::new_for_test();
    app.theme_picker_open = true;
    app.theme_picker_cursor = 2;
    event::handle(&mut app, key(KeyCode::Char('k')));
    assert_eq!(app.theme_picker_cursor, 1);
}

#[tokio::test]
async fn theme_picker_k_clamps_at_zero() {
    let mut app = App::new_for_test();
    app.theme_picker_open = true;
    app.theme_picker_cursor = 0;
    event::handle(&mut app, key(KeyCode::Char('k')));
    assert_eq!(app.theme_picker_cursor, 0);
}

#[tokio::test]
async fn shift_p_opens_project_manager() {
    let mut app = App::new_for_test();
    event::handle(&mut app, shift('P'));
    assert!(app.project_manager_open);
}

#[tokio::test]
async fn project_manager_esc_closes() {
    let mut app = App::new_for_test();
    app.project_manager_open = true;
    event::handle(&mut app, key(KeyCode::Esc));
    assert!(!app.project_manager_open);
}

#[tokio::test]
async fn help_key_opens_help() {
    let mut app = App::new_for_test();
    // 'h' opens help from most tabs — use Craft where it's explicitly handled
    app.active_tab = Tab::Craft;
    event::handle(&mut app, key(KeyCode::Char('h')));
    assert!(app.show_help);
}

#[tokio::test]
async fn help_esc_closes_help() {
    let mut app = App::new_for_test();
    app.show_help = true;
    event::handle(&mut app, key(KeyCode::Esc));
    assert!(!app.show_help);
}

#[tokio::test]
async fn help_h_closes_help() {
    let mut app = App::new_for_test();
    app.show_help = true;
    event::handle(&mut app, key(KeyCode::Char('h')));
    assert!(!app.show_help);
}

#[tokio::test]
async fn notebook_n_enters_edit_mode() {
    let mut app = nb_app();
    event::handle(&mut app, key(KeyCode::Char('n')));
    assert!(app.notebook_editing);
}

#[tokio::test]
async fn notebook_edit_chars_go_to_input() {
    let mut app = nb_app();
    app.notebook_editing = true;
    event::handle(&mut app, key(KeyCode::Char('H')));
    event::handle(&mut app, key(KeyCode::Char('i')));
    assert_eq!(app.notebook_input, "Hi");
}

#[tokio::test]
async fn notebook_edit_backspace_deletes_char() {
    let mut app = nb_app();
    app.notebook_editing = true;
    app.notebook_input = "Hello".to_string();
    event::handle(&mut app, key(KeyCode::Backspace));
    assert_eq!(app.notebook_input, "Hell");
}

#[tokio::test]
async fn notebook_edit_enter_saves_note() {
    let mut app = nb_app();
    app.notebook_editing = true;
    app.notebook_input = "My note".to_string();
    event::handle(&mut app, key(KeyCode::Enter));
    assert!(!app.notebook_editing);
    assert!(app.notebook_input.is_empty());
    assert_eq!(app.notebook.len(), 1);
    assert_eq!(app.notebook.all()[0].text, "My note");
}

#[tokio::test]
async fn notebook_edit_enter_empty_does_not_save() {
    let mut app = nb_app();
    app.notebook_editing = true;
    // input is empty
    event::handle(&mut app, key(KeyCode::Enter));
    assert!(!app.notebook_editing);
    assert_eq!(app.notebook.len(), 0);
}

#[tokio::test]
async fn notebook_edit_esc_cancels() {
    let mut app = nb_app();
    app.notebook_editing = true;
    app.notebook_input = "Typed but cancelled".to_string();
    event::handle(&mut app, key(KeyCode::Esc));
    assert!(!app.notebook_editing);
    assert!(app.notebook_input.is_empty());
    assert_eq!(app.notebook.len(), 0);
}

#[tokio::test]
async fn notebook_slash_enters_search() {
    let mut app = nb_app();
    event::handle(&mut app, key(KeyCode::Char('/')));
    assert!(app.notebook_searching);
    assert!(app.notebook_search.is_empty());
}

#[tokio::test]
async fn notebook_search_chars_accumulate() {
    let mut app = nb_app();
    app.notebook_searching = true;
    event::handle(&mut app, key(KeyCode::Char('d')));
    event::handle(&mut app, key(KeyCode::Char('n')));
    event::handle(&mut app, key(KeyCode::Char('s')));
    assert_eq!(app.notebook_search, "dns");
}

#[tokio::test]
async fn notebook_search_backspace() {
    let mut app = nb_app();
    app.notebook_searching = true;
    app.notebook_search = "dnss".to_string();
    event::handle(&mut app, key(KeyCode::Backspace));
    assert_eq!(app.notebook_search, "dns");
}
