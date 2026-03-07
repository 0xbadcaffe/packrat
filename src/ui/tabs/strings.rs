use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::Span,
    widgets::{Block, BorderType, Borders, Cell, Row, Table},
};

use crate::app::App;
use crate::ui::theme::*;

const MIN_LEN: usize = 4;

struct ExtractedString {
    offset: String,
    length: usize,
    value: String,
    kind: &'static str,
    sensitive: bool,
}

/// Extract printable ASCII runs (len >= MIN_LEN) from packet bytes.
fn extract_strings(app: &App) -> Vec<ExtractedString> {
    let mut out = Vec::new();
    for pkt in app.packets.iter().take(500) {
        let bytes = &pkt.bytes;
        let mut run_start = 0;
        let mut in_run = false;
        for (i, &b) in bytes.iter().enumerate() {
            let printable = b >= 32 && b < 127;
            if printable {
                if !in_run { run_start = i; in_run = true; }
            } else if in_run {
                in_run = false;
                let s = &bytes[run_start..i];
                if s.len() >= MIN_LEN {
                    let val = String::from_utf8_lossy(s).into_owned();
                    let (kind, sensitive) = classify(&val);
                    out.push(ExtractedString {
                        offset: format!("{}:{:04x}", pkt.no, run_start),
                        length: val.len(),
                        value: val,
                        kind,
                        sensitive,
                    });
                }
            }
        }
        // flush trailing run
        if in_run {
            let s = &bytes[run_start..];
            if s.len() >= MIN_LEN {
                let val = String::from_utf8_lossy(s).into_owned();
                let (kind, sensitive) = classify(&val);
                out.push(ExtractedString {
                    offset: format!("{}:{:04x}", pkt.no, run_start),
                    length: val.len(),
                    value: val,
                    kind,
                    sensitive,
                });
            }
        }
    }
    out
}

fn classify(s: &str) -> (&'static str, bool) {
    let l = s.to_lowercase();
    if l.contains("password") || l.contains("passwd") || l.contains("secret") || l.contains("shadow") {
        return ("sensitive", true);
    }
    if l.contains("begin rsa") || l.contains("begin private") || l.contains("ssh-rsa") || l.contains("api_key") {
        return ("key", true);
    }
    if l.starts_with("exec(") || l.contains("/bin/sh") || l.contains("/bin/bash") || l.contains("system(") {
        return ("shell", true);
    }
    if l.starts_with("get ") || l.starts_with("post ") || l.starts_with("put ") || l.starts_with("http/") {
        return ("http", false);
    }
    if l.starts_with("content-") || l.starts_with("authorization:") || l.starts_with("user-agent:") || l.starts_with("accept") {
        return ("http", false);
    }
    if l.starts_with("select ") || l.starts_with("insert ") || l.starts_with("update ") || l.starts_with("delete ") {
        return ("sql", false);
    }
    if l.starts_with("eyj") {
        return ("jwt", false);
    }
    if l.starts_with('/') || l.contains(".so") || l.contains(".conf") || l.contains("/etc/") || l.contains("/proc/") {
        return ("path", false);
    }
    // IP address pattern: digits and dots
    if s.len() <= 15 && s.chars().all(|c| c.is_ascii_digit() || c == '.') && s.contains('.') {
        return ("ip", false);
    }
    // Domain-like: only alphanumeric, dots, hyphens and contains a dot
    if s.len() <= 64 && s.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-') && s.contains('.') {
        return ("domain", false);
    }
    ("ascii", false)
}

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let all = extract_strings(app);

    let filt: Vec<&ExtractedString> = if app.strings_filter.is_empty() {
        all.iter().collect()
    } else {
        let q = app.strings_filter.to_lowercase();
        all.iter()
            .filter(|s| s.value.to_lowercase().contains(&q) || s.kind.contains(&*q))
            .collect()
    };

    let header = Row::new(vec![
        Cell::from("Pkt:Off").style(Style::default().fg(C_FG2)),
        Cell::from("Len").style(Style::default().fg(C_FG2)),
        Cell::from("String").style(Style::default().fg(C_FG2)),
        Cell::from("Type").style(Style::default().fg(C_FG2)),
    ]).style(Style::default().bg(C_BG3)).height(1);

    let rows: Vec<Row> = filt.iter().map(|s| {
        let (val_color, type_color) =
            if s.sensitive { (C_RED, C_RED) } else { (C_GREEN, C_FG3) };
        Row::new(vec![
            Cell::from(s.offset.clone()).style(Style::default().fg(C_FG3)),
            Cell::from(s.length.to_string()).style(Style::default().fg(C_YELLOW)),
            Cell::from(s.value.clone()).style(Style::default().fg(val_color)),
            Cell::from(s.kind).style(Style::default().fg(type_color)),
        ])
    }).collect();

    use ratatui::layout::Constraint;
    let widths = [
        Constraint::Length(12),
        Constraint::Length(6),
        Constraint::Min(0),
        Constraint::Length(10),
    ];

    let title = if app.packets.is_empty() {
        " Strings — no packets captured ".to_string()
    } else {
        format!(" Strings [{} found in {} pkts] ", filt.len(), app.packets.len().min(500))
    };

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(C_BORDER))
            .title(Span::styled(title, Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD))))
        .style(Style::default().bg(C_BG));

    f.render_widget(table, area);
}
