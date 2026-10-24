use crate::app::App;
use super::*;
use ratatui::{Terminal, backend::TestBackend};

#[test]
fn preferences_render_at_compact_and_normal_sizes() {
    for (width, height) in [(60, 18), (96, 26)] {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        let app = App::new_for_test();
        terminal.draw(|frame| draw(frame, &app.try_view().unwrap().unwrap(), frame.area())).unwrap();
        let output = terminal.backend().buffer().content.iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(output.contains("Preferences"));
        assert!(output.contains("Theme"));
        assert!(output.contains("Guard"));
    }
}
