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
            Constraint::Length(3), // input / search box
            Constraint::Min(0),    // notes list
            Constraint::Length(1), // status
        ])
        .split(area);

    draw_input_box(f, app, chunks[0]);
    draw_notes_list(f, app, chunks[1]);
    draw_status_bar(f, app, chunks[2]);
}

fn draw_input_box(f: &mut Frame, app: &App, area: Rect) {
    if app.notebook_searching {
        let display = format!("{}▌", app.notebook_search);
        let count = app.notebook.search(&app.notebook_search).len();
        let hit_str = if app.notebook_search.is_empty() {
            String::new()
        } else {
            format!("  {} hit{}", count, if count == 1 { "" } else { "s" })
        };
        let p = Paragraph::new(Line::from(vec![
            Span::styled(display, Style::default().fg(C_CYAN)),
            Span::styled(hit_str, Style::default().fg(C_GREEN)),
        ]))
        .block(Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_CYAN))
            .title(Span::styled(
                " Search Notes  [Enter] confirm  [Esc] clear ",
                Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD),
            )));
        f.render_widget(p, area);
        return;
    }

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
    f.render_widget(input_box, area);
}

fn draw_notes_list(f: &mut Frame, app: &App, area: Rect) {
    // Decide which notes to show — unify to Vec<&Note>
    let notes: Vec<&crate::analysis::notebook::Note> =
        if !app.notebook_search.is_empty() || app.notebook_searching {
            app.notebook.search(&app.notebook_search)
        } else {
            app.notebook.all().iter().collect()
        };

    let scroll = app.notebook_scroll;
    let items: Vec<ListItem> = notes.iter().enumerate().skip(scroll).map(|(i, note)| {
        let ts = format_ts(note.timestamp);
        let tags = if note.tags.is_empty() {
            String::new()
        } else {
            format!(" [{}]", note.tags.join(", "))
        };
        let ev = note.evidence.as_ref()
            .map(|e| format!(" @ {e}"))
            .unwrap_or_default();
        let selected = i == scroll;
        let text_color = if selected { C_FG } else { C_FG2 };
        ListItem::new(vec![
            Line::from(vec![
                Span::styled(ts, Style::default().fg(C_FG3)),
                Span::styled(ev, Style::default().fg(C_CYAN)),
                Span::styled(tags, Style::default().fg(C_YELLOW)),
            ]),
            Line::from(vec![
                Span::styled("  ", Style::default()),
                Span::styled(note.text.clone(), Style::default().fg(text_color)),
            ]),
        ])
    }).collect();

    let total = app.notebook.len();
    let shown = notes.len();
    let title = if !app.notebook_search.is_empty() || app.notebook_searching {
        format!(" {shown} / {total} notes ")
    } else {
        format!(" {total} notes ")
    };

    let list = List::new(items)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_BORDER))
            .title(Span::styled(title, Style::default().fg(C_FG3))));
    f.render_widget(list, area);
}

fn draw_status_bar(f: &mut Frame, _app: &App, area: Rect) {
    let status = Paragraph::new(Line::from(vec![
        Span::styled(
            " [n] add note  [d] delete  [/] search  [j/k] scroll  [g/G] top/bottom  [Esc] cancel",
            Style::default().fg(C_FG3),
        ),
    ])).style(Style::default().bg(C_BG2));
    f.render_widget(status, area);
}

fn format_ts(ts: f64) -> String {
    let secs = ts as u64;
    let h = (secs / 3600) % 24;
    let m = (secs / 60) % 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02} ")
}
