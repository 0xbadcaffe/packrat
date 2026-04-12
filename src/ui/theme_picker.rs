//! Theme picker overlay — browse and apply built-in themes at runtime.

use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, List, ListItem, Paragraph},
};

use crate::app::App;
use crate::ui::theme::{self, ThemePalette, THEME_NAMES, C_BG2, C_CYAN, C_FG, C_FG3, C_YELLOW};

pub fn draw(f: &mut Frame, app: &App) {
    let area = f.area();
    // Centered overlay — 40% width, 60% height, centered
    let w = (area.width * 2 / 5).max(48);
    let h = (THEME_NAMES.len() as u16 + 8).min(area.height - 4);
    let x = area.x + (area.width - w) / 2;
    let y = area.y + (area.height - h) / 2;
    let popup = Rect { x, y, width: w, height: h };

    f.render_widget(Clear, popup);

    let cursor = app.theme_picker_cursor;

    let items: Vec<ListItem> = THEME_NAMES.iter().enumerate().map(|(i, &name)| {
        let is_current  = name == app.selected_theme_name;
        let is_selected = i == cursor;
        // Render a colour swatch row for each theme
        let palette = theme::palette_by_name(name);
        let swatch = make_swatch(&palette);

        let name_style = if is_selected {
            Style::default().fg(C_CYAN()).add_modifier(Modifier::BOLD)
        } else if is_current {
            Style::default().fg(C_YELLOW())
        } else {
            Style::default().fg(C_FG())
        };

        let prefix = if is_selected {
            "▶ "
        } else if is_current {
            "✓ "
        } else {
            "  "
        };

        Line::from({
            let mut spans = vec![
                Span::styled(prefix, Style::default().fg(C_CYAN())),
                Span::styled(name, name_style),
                Span::raw("  "),
            ];
            spans.extend(swatch);
            spans
        }).into()
    }).collect();

    let list = List::new(items)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(C_YELLOW()))
            .title(Span::styled(
                " Themes  [j/k] scroll  [Enter] apply  [Esc] close ",
                Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD),
            )));
    f.render_widget(list, popup);

    // Status line at bottom — show current theme
    let status_rect = Rect {
        x: popup.x + 1,
        y: popup.y + popup.height - 2,
        width: popup.width - 2,
        height: 1,
    };
    let status = Paragraph::new(format!(" Active: {}  (changes saved automatically)", app.selected_theme_name))
        .style(Style::default().fg(C_FG3()).bg(C_BG2()));
    f.render_widget(status, status_rect);
}

/// Build 8 coloured square spans representing the theme palette.
fn make_swatch(p: &ThemePalette) -> Vec<Span<'static>> {
    let colors: [Color; 8] = [p.cyan, p.green, p.yellow, p.red, p.magenta, p.orange, p.fg2, p.border];
    colors.iter().map(|&c| {
        Span::styled("█", Style::default().fg(c))
    }).collect()
}
