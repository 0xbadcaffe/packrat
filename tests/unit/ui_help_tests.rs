use super::*;
use ratatui::{Terminal, backend::TestBackend};

fn rendered_help(width: u16, height: u16, scroll: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = App::new_for_test();
    app.help_scroll = scroll;
    terminal.draw(|frame| draw(frame, &app)).unwrap();
    terminal.backend().buffer().content.iter()
        .map(|cell| cell.symbol())
        .collect::<String>()
}

#[test]
fn help_renders_and_scrolls_at_small_terminal_size() {
    let top = rendered_help(80, 24, 0);
    assert!(top.contains("Navigation"));
    let bottom = rendered_help(80, 24, u16::MAX);
    assert!(bottom.contains("General"));
    assert!(bottom.contains("Quit"));
}

#[test]
fn help_renders_at_wide_terminal_size() {
    let output = rendered_help(160, 48, 0);
    assert!(output.contains("Keyboard Reference"));
    assert!(output.contains("Capture & Recording"));
}
