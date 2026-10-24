use packrat_tui::{app::App, tabs::Tab, ui};
use ratatui::{Terminal, backend::TestBackend};

fn screen(app: &App, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|frame| ui::draw(frame, app)).unwrap();
    let buffer = terminal.backend().buffer();
    let mut result = String::new();
    for y in 0..height {
        for x in 0..width { result.push_str(buffer[(x, y)].symbol()); }
        result.push('\n');
    }
    result
}

#[test]
fn three_workspaces_are_visible_in_small_and_large_terminals() {
    let app = App::new_for_test();
    for (width, height) in [(40, 12), (80, 24), (120, 40)] {
        let text = screen(&app, width, height);
        assert!(text.contains("1 Traffic"), "missing Traffic at {width}x{height}");
        assert!(text.contains("2 Investigation"), "missing Investigation at {width}x{height}");
        assert!(text.contains("3 Case"), "missing Case at {width}x{height}");
    }
}

#[test]
fn view_drawer_keeps_selected_tool_visible_on_short_terminals() {
    let mut app = App::new_for_test();
    app.active_tab = Tab::Investigate;
    app.open_view_menu();
    for _ in 0..20 { app.view_menu_next(); }
    assert!(screen(&app, 80, 12).contains("Graph"));
    app.activate_view_menu_selection();
    assert_eq!(app.active_tab, Tab::OperatorGraph);
}
