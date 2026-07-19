use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
};

use crate::app::App;
use crate::ui::theme::*;

const MATRIX_HEAD: Color = Color::Rgb(190, 255, 210);
const MATRIX_BRIGHT: Color = Color::Rgb(0, 255, 136);
const MATRIX_GREEN: Color = Color::Rgb(0, 221, 0);
const MATRIX_DIM: Color = Color::Rgb(0, 119, 34);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RainTone {
    Head,
    Trail,
    Tail,
}

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let show_full_banner =
        area.height >= 17 && area.width >= crate::ui::ascii::FULL_STARTUP_MIN_WIDTH;
    let banner_height = if show_full_banner { 9 } else { 3 };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(banner_height), // banner
            Constraint::Length(2),  // header
            Constraint::Min(0),     // list
            Constraint::Length(1),  // hint
        ])
        .split(area);

    draw_banner(f, app, chunks[0]);
    draw_header(f, chunks[1]);
    draw_list(f, app, chunks[2]);
    draw_hint(f, chunks[3]);
}

fn draw_banner(f: &mut Frame, app: &App, area: Rect) {
    if area.height < 8 || area.width < crate::ui::ascii::FULL_STARTUP_MIN_WIDTH {
        let mark = if area.width >= crate::ui::ascii::COMPACT_STARTUP_MARK.len() as u16 {
            crate::ui::ascii::COMPACT_STARTUP_MARK
        } else {
            crate::ui::ascii::NARROW_STARTUP_MARK
        };
        let banner = Paragraph::new(vec![
            Line::raw(""),
            Line::from(vec![
                Span::raw(format!("{}  ", crate::ui::ascii::PACKRAT_EMOJI)),
                Span::styled(
                    mark,
                    Style::default().fg(MATRIX_BRIGHT).add_modifier(Modifier::BOLD),
                ),
            ]),
        ]).style(Style::default().bg(Color::Black));
        f.render_widget(banner, area);
        return;
    }
    let tick = app.animation_tick();
    let title_suffix = format!(
        "  PACKRAT // network evidence console  v{}",
        env!("CARGO_PKG_VERSION")
    );
    let title_width = 2 + title_suffix.len();
    let mut title = vec![
        Span::raw(format!("{}  ", crate::ui::ascii::PACKRAT_EMOJI)),
        Span::styled("PACKRAT", Style::default().fg(MATRIX_BRIGHT).add_modifier(Modifier::BOLD)),
        Span::styled(
            format!(" // network evidence console  v{}", env!("CARGO_PKG_VERSION")),
            Style::default().fg(MATRIX_DIM),
        ),
    ];
    append_matrix_rain(&mut title, title_width, area.width, 0, tick);
    let mut banner = vec![Line::from(title)];

    banner.push(matrix_banner_line("", Style::default(), area.width, 1, tick, true));
    banner.extend(
        crate::ui::ascii::STARTUP_MARK[..5]
            .iter()
            .enumerate()
            .map(|(index, line)| {
                matrix_banner_line(
                    line,
                    Style::default().fg(MATRIX_BRIGHT).add_modifier(Modifier::BOLD),
                    area.width,
                    index + 2,
                    tick,
                    true,
                )
            }),
    );
    banner.push(matrix_banner_line("", Style::default(), area.width, 7, tick, true));
    banner.push(matrix_banner_line(
        crate::ui::ascii::STARTUP_MARK[5],
        Style::default().fg(MATRIX_GREEN).add_modifier(Modifier::BOLD),
        area.width,
        8,
        tick,
        false,
    ));
    f.render_widget(Paragraph::new(banner).style(Style::default().bg(Color::Black)), area);
}

fn matrix_banner_line(
    content: &str,
    style: Style,
    area_width: u16,
    row: usize,
    tick: u32,
    fill_spaces: bool,
) -> Line<'static> {
    if fill_spaces {
        let bytes = content.as_bytes();
        let mut spans = Vec::with_capacity(usize::from(area_width));
        for column in 0..usize::from(area_width) {
            if let Some(&glyph) = bytes.get(column).filter(|&&glyph| glyph != b' ') {
                spans.push(Span::styled((glyph as char).to_string(), style));
            } else if let Some((glyph, tone)) = matrix_rain_cell(column, row, tick) {
                spans.push(Span::styled(glyph.to_string(), rain_style(tone)));
            } else {
                spans.push(Span::raw(" "));
            }
        }
        return Line::from(spans);
    }

    let mut spans = vec![Span::styled(content.to_owned(), style)];
    append_matrix_rain(&mut spans, content.len(), area_width, row, tick);
    Line::from(spans)
}

fn append_matrix_rain(
    spans: &mut Vec<Span<'static>>,
    content_width: usize,
    area_width: u16,
    row: usize,
    tick: u32,
) {
    let rain_start = usize::from(crate::ui::ascii::FULL_STARTUP_MIN_WIDTH);
    spans.push(Span::raw(" ".repeat(rain_start.saturating_sub(content_width))));
    let rain_width = usize::from(area_width).saturating_sub(rain_start);
    for column in 0..rain_width {
        let Some((glyph, tone)) = matrix_rain_cell(column, row, tick) else {
            spans.push(Span::raw(" "));
            continue;
        };
        spans.push(Span::styled(glyph.to_string(), rain_style(tone)));
    }
}

fn rain_style(tone: RainTone) -> Style {
    let color = match tone {
        RainTone::Head => MATRIX_HEAD,
        RainTone::Trail => MATRIX_GREEN,
        RainTone::Tail => MATRIX_DIM,
    };
    Style::default().fg(color)
}

fn matrix_rain_cell(column: usize, row: usize, tick: u32) -> Option<(char, RainTone)> {
    // Packrat-local drop schedule; no third-party screensaver code or assets.
    const GLYPHS: &[u8] = b"01:+=-*<>[]{}";
    let cycle = 12 + column % 7;
    let speed = 1 + column % 3;
    let head = ((tick as usize * speed / 2) + column * 5 + column / 3) % cycle;
    let distance = (head + cycle - row % cycle) % cycle;
    let tone = match distance {
        0 => RainTone::Head,
        1 => RainTone::Trail,
        2 | 3 => RainTone::Tail,
        _ => return None,
    };
    let glyph = GLYPHS[(column * 11 + row * 7 + tick as usize / 2) % GLYPHS.len()] as char;
    Some((glyph, tone))
}

#[cfg(test)]
mod tests {
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
}

fn draw_header(f: &mut Frame, area: Rect) {
    let header = Paragraph::new(Line::from(vec![
        Span::styled("  Select network interface", Style::default().fg(C_CYAN()).add_modifier(Modifier::BOLD)),
        Span::styled("  ─────────────────────────────────", Style::default().fg(C_BORDER())),
    ])).style(Style::default().bg(C_BG()));
    f.render_widget(header, area);
}

fn draw_list(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app.iface_list.iter().enumerate().map(|(i, name)| {
        let is_sel = i == app.iface_sel;
        let label = if name == "simulated" {
            format!("  {}  (built-in, no root required)", name)
        } else {
            format!("  {}", name)
        };
        if is_sel {
            ListItem::new(label)
                .style(Style::default().fg(Color::Black).bg(C_CYAN()).add_modifier(Modifier::BOLD))
        } else {
            ListItem::new(label).style(Style::default().fg(C_FG2()).bg(C_BG()))
        }
    }).collect();

    let list = List::new(items)
        .block(Block::default()
            .borders(Borders::LEFT)
            .border_style(Style::default().fg(C_BORDER())))
        .style(Style::default().bg(C_BG()));
    f.render_widget(list, area);
}

fn draw_hint(f: &mut Frame, area: Rect) {
    let hint = Line::from(vec![
        Span::styled("  j/k", Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD)),
        Span::styled(" navigate   ", Style::default().fg(C_FG3())),
        Span::styled("Space/Enter", Style::default().fg(C_GREEN()).add_modifier(Modifier::BOLD)),
        Span::styled(" start capture   ", Style::default().fg(C_FG3())),
        Span::styled("q", Style::default().fg(C_RED()).add_modifier(Modifier::BOLD)),
        Span::styled(" quit", Style::default().fg(C_FG3())),
    ]);
    f.render_widget(Paragraph::new(hint).style(Style::default().bg(C_BG2())), area);
}
