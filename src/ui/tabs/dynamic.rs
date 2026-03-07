use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, List, ListItem},
};

use crate::app::App;
use crate::dynamic::EntryKind;
use crate::ui::helpers::truncate;
use crate::ui::theme::*;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let inner_h = area.height.saturating_sub(2) as usize;
    let total = app.dyn_log.len();
    let offset = if total > inner_h { total - inner_h } else { 0 };

    let items: Vec<ListItem> = app.dyn_log.iter().skip(offset).map(|e| {
        let (kind_str, kind_color) = match e.kind {
            EntryKind::Syscall => ("syscall", C_CYAN),
            EntryKind::Signal  => ("signal ", C_RED),
            EntryKind::Network => ("netpkt ", C_GREEN),
        };
        let ret_color = if e.retval.starts_with('-') { C_RED } else { C_FG2 };
        ListItem::new(Line::from(vec![
            Span::styled(format!("{:>8.4}s ", e.ts), Style::default().fg(C_FG3)),
            Span::styled(format!("{:<9}", kind_str), Style::default().fg(kind_color).add_modifier(Modifier::BOLD)),
            Span::styled(format!("{:<14}", e.name), Style::default().fg(Color::White)),
            Span::styled(truncate(&e.args, 55), Style::default().fg(C_FG2)),
            Span::styled(format!(" = {}", e.retval), Style::default().fg(ret_color)),
        ]))
    }).collect();

    let list = List::new(items)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(C_BORDER))
            .title(Span::styled(
                " Dynamic Trace — syscalls / signals / network ",
                Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD),
            )))
        .style(Style::default().bg(C_BG));
    f.render_widget(list, area);
}
