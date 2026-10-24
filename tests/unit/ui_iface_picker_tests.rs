use super::*;
use ratatui::{Terminal, backend::TestBackend};

fn render(width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = App::new_for_test();
    app.iface_list = vec!["eth0".into(), "simulated".into()];
    terminal.draw(|frame| {
        let area = frame.area();
        draw(frame, &app, area);
    }).unwrap();
    terminal.backend().buffer().content.iter()
        .map(|cell| cell.symbol())
        .collect::<String>()
}

#[test]
fn selector_keeps_banner_interface_and_controls_visible() {
    let normal = render(100, 24);
    assert!(normal.contains("🐀"));
    assert!(normal.contains("____"));
    assert!(normal.contains("network evidence console"));
    assert!(normal.contains("eth0"));
    assert!(normal.contains("start capture"));

    let compact = render(60, 14);
    assert!(compact.contains("🐀"));
    assert!(compact.contains("PACKRAT //"));
    assert!(compact.contains("eth0"));
    assert!(compact.contains("start capture"));

    let medium = render(80, 24);
    assert!(medium.contains("🐀"));
    assert!(medium.contains("____"));
    assert!(medium.contains("eth0"));

    let tall_and_narrow = render(28, 24);
    assert!(tall_and_narrow.contains("PACKRAT"));
    assert!(!tall_and_narrow.contains("PACKRAT //"));
    assert!(tall_and_narrow.contains("eth0"));
}

#[test]
fn matrix_rain_is_bounded_animated_and_has_bright_heads() {
    let first: Vec<_> = (0..24).map(|column| matrix_rain_cell(column, 3, 0)).collect();
    let later: Vec<_> = (0..24).map(|column| matrix_rain_cell(column, 3, 6)).collect();
    assert_ne!(first, later);
    assert!(first.iter().flatten().any(|(_, tone)| *tone == RainTone::Head));
    assert!(first.iter().flatten().all(|(glyph, _)| glyph.is_ascii()));
}
