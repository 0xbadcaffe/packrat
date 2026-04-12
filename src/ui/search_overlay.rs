//! Global command palette overlay.
//!
//! A floating search box centered on the screen. Triggered by `?` from any tab.
//! Results span all data sources: packets, hosts, IOC hits, rule hits, YARA matches.

use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph},
};
use crate::app::App;
use crate::ui::theme::*;

pub fn draw(f: &mut Frame, app: &App) {
    let area = f.area();

    // Center a popup: 70% width, up to 24 rows tall
    let width  = (area.width as f32 * 0.70) as u16;
    let height = 24u16.min(area.height.saturating_sub(4));
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    let popup = Rect { x, y, width, height };

    f.render_widget(Clear, popup);

    // Split: top row is the input bar, rest is results
    let inner_y      = popup.y + 1;       // inside border
    let inner_width  = popup.width.saturating_sub(2);
    let inner_height = popup.height.saturating_sub(2);

    let input_rect = Rect {
        x: popup.x + 1,
        y: inner_y,
        width: inner_width,
        height: 1,
    };
    let sep_rect = Rect {
        x: popup.x + 1,
        y: inner_y + 1,
        width: inner_width,
        height: 1,
    };
    let list_rect = Rect {
        x: popup.x + 1,
        y: inner_y + 2,
        width: inner_width,
        height: inner_height.saturating_sub(2),
    };

    // Outer block (border + title)
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_CYAN()))
        .title(Span::styled(
            " Search  [Esc] close  [↑↓/jk] navigate  [Enter] jump ",
            Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD),
        ));
    f.render_widget(block, popup);

    // Input line
    let cursor = format!(" > {}█", app.search_query);
    let input = Paragraph::new(Line::from(
        Span::styled(cursor, Style::default().fg(C_CYAN()).add_modifier(Modifier::BOLD))
    )).style(Style::default().bg(C_BG2()));
    f.render_widget(input, input_rect);

    // Separator
    let sep_line = "─".repeat(inner_width as usize);
    let sep = Paragraph::new(Line::from(
        Span::styled(sep_line, Style::default().fg(C_BORDER()))
    ));
    f.render_widget(sep, sep_rect);

    // Results list
    let results = &app.search_results;
    let selected = app.search_selected;

    // Scroll so selected is visible
    let list_h = list_rect.height as usize;
    let scroll = if selected >= list_h { selected - list_h + 1 } else { 0 };

    let items: Vec<ListItem> = results.iter()
        .skip(scroll)
        .enumerate()
        .map(|(i, r)| {
            let abs_idx = i + scroll;
            let is_sel = abs_idx == selected;

            let source_color = source_color(r.source);
            let bg = if is_sel { C_SEL_BG() } else { C_BG() };

            let label_style = if is_sel {
                Style::default().fg(C_FG()).bg(C_SEL_BG()).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(C_FG2()).bg(C_BG())
            };

            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{:<12}", r.source),
                    Style::default().fg(source_color).bg(bg)
                        .add_modifier(if is_sel { Modifier::BOLD } else { Modifier::empty() }),
                ),
                Span::styled(
                    format!("{:<36}", truncate(&r.label, 35)),
                    label_style,
                ),
                Span::styled(
                    truncate(&r.detail, (inner_width as usize).saturating_sub(50)),
                    Style::default().fg(C_FG3()).bg(bg),
                ),
            ]))
        })
        .collect();

    let count_hint = if results.is_empty() {
        if app.search_query.is_empty() {
            " Start typing to search across all data…".to_string()
        } else {
            " No results".to_string()
        }
    } else {
        format!(" {} result(s)", results.len())
    };

    let list = List::new(items)
        .block(Block::default()
            .title(Span::styled(count_hint, Style::default().fg(C_FG3()))))
        .style(Style::default().bg(C_BG()));
    f.render_widget(list, list_rect);
}

fn source_color(source: &str) -> ratatui::style::Color {
    match source {
        "Packet"   => C_CYAN(),
        "Host"     => C_GREEN(),
        "IOC Hit"  => C_RED(),
        "Rule Hit" => C_ORANGE(),
        "YARA"     => C_RED(),
        "Object"   => C_MAGENTA(),
        _          => C_FG2(),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if max == 0 { return String::new(); }
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let end = s.char_indices().nth(max.saturating_sub(1))
            .map(|(i, _)| i)
            .unwrap_or(s.len());
        format!("{}…", &s[..end])
    }
}
