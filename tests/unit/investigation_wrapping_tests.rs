use super::*;
use ratatui::{Terminal, backend::TestBackend};

#[test]
fn scroll_can_reach_the_end_of_one_wrapped_investigation_row() {
    let mut terminal = Terminal::new(TestBackend::new(22, 5)).unwrap();
    let mut render = |offset| {
        terminal.draw(|frame| {
            let area = frame.area();
            let line = Line::from(vec![Span::styled("recorded-trigger ", heading()), Span::raw(
                "recorded-flow-row retained-flow-row evidence-marker",
            )]);
            frame.render_widget(wrapped_panel(vec![line], "Summary", offset, area), area);
        }).unwrap();
        terminal.backend().to_string()
    };
    let first = render(0);
    assert!(first.contains("recorded-trigger"));
    assert!(!first.contains("marker"));
    let next = render(1);
    assert!(!next.contains("recorded-trigger"));
    assert!(next.contains("evidence-marker"));
    assert_eq!(render(usize::MAX), next);
}
