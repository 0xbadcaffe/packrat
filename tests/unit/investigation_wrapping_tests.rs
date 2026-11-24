use super::*;
use ratatui::{Terminal, backend::TestBackend};

#[test]
fn scroll_can_reach_the_end_of_one_wrapped_investigation_row() {
    let mut terminal = Terminal::new(TestBackend::new(22, 5)).unwrap();
    let mut app = crate::app::App::new_for_test();
    let mut render = |app: &crate::app::App| {
        terminal
            .draw(|frame| {
                let area = frame.area();
                let line = Line::from(vec![
                    Span::styled("recorded-trigger ", heading()),
                    Span::raw("recorded-flow-row retained-flow-row evidence-marker"),
                ]);
                render_wrapped_panel(frame, app, vec![line], "Summary", area);
            })
            .unwrap();
        terminal.backend().to_string()
    };
    let first = render(&app);
    assert!(first.contains("recorded-trigger"));
    assert!(!first.contains("marker"));
    app.investigation_scroll_down();
    let next = render(&app);
    assert!(!next.contains("recorded-trigger"));
    assert!(next.contains("evidence-marker"));
    app.investigation_scroll = usize::MAX;
    assert_eq!(render(&app), next);
    app.investigation_scroll_up();
    assert_eq!(render(&app), first);
    for _ in 0..5 {
        app.investigation_scroll_down();
        assert_eq!(render(&app), next);
    }
    app.investigation_scroll_up();
    assert_eq!(render(&app), first);
}
