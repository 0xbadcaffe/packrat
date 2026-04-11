use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
};
use crate::app::App;
use crate::ui::theme::*;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // input box
            Constraint::Min(0),    // notes list
            Constraint::Length(1), // status
        ])
        .split(area);

    // Note input
    let input_display = if app.notebook_editing {
        format!("{}_", app.notebook_input)
    } else {
        "<press n to add note>".into()
    };
    let input_color = if app.notebook_editing { C_CYAN } else { C_FG3 };
    let border_color = if app.notebook_editing { C_CYAN } else { C_BORDER };
    let input_box = Paragraph::new(input_display)
        .style(Style::default().fg(input_color))
        .block(Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color))
            .title(Span::styled(
                " Analyst Notebook ",
                Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD),
            )));
    f.render_widget(input_box, chunks[0]);

    // Notes list
    let notes = app.notebook.all();
    let scroll = app.notebook_scroll;
    let items: Vec<ListItem> = notes.iter().skip(scroll).map(|note| {
        let ts = format_ts(note.timestamp);
        let tags = if note.tags.is_empty() {
            String::new()
        } else {
            format!(" [{}]", note.tags.join(", "))
        };
        let ev = note.evidence.as_ref()
            .map(|e| format!(" @ {e}"))
            .unwrap_or_default();
        ListItem::new(vec![
            Line::from(vec![
                Span::styled(ts, Style::default().fg(C_FG3)),
                Span::styled(ev, Style::default().fg(C_CYAN)),
                Span::styled(tags, Style::default().fg(C_YELLOW)),
            ]),
            Line::from(vec![
                Span::styled("  ", Style::default()),
                Span::styled(note.text.clone(), Style::default().fg(C_FG)),
            ]),
        ])
    }).collect();

    let list = List::new(items)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_BORDER))
            .title(Span::styled(
                format!(" {} notes ", notes.len()),
                Style::default().fg(C_FG3),
            )));
    f.render_widget(list, chunks[1]);

    // Status
    let status = Paragraph::new(Line::from(vec![
        Span::styled(
            " [n] add note  [d] delete  [/] search  [j/k] scroll  [Esc] cancel",
            Style::default().fg(C_FG3),
        ),
    ])).style(Style::default().bg(C_BG2));
    f.render_widget(status, chunks[2]);
}

fn format_ts(ts: f64) -> String {
    let secs = ts as u64;
    let h = (secs / 3600) % 24;
    let m = (secs / 60) % 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02} ")
}
