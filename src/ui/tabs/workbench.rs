use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};
use crate::app::App;
use crate::ui::theme::*;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),  // info bar
            Constraint::Min(0),     // hex + annotations split
            Constraint::Length(1),  // status
        ])
        .split(area);

    // Info bar
    let info_str = if app.workbench.is_empty() {
        "No packet loaded — press Enter on a packet to open in workbench".into()
    } else {
        format!("  {} — {} bytes — cursor: 0x{:04x} ({}) ",
            app.workbench.source_info,
            app.workbench.len(),
            app.workbench.cursor,
            app.workbench.cursor,
        )
    };
    let info = Paragraph::new(info_str)
        .style(Style::default().fg(C_YELLOW).bg(C_BG2).add_modifier(Modifier::BOLD));
    f.render_widget(info, chunks[0]);

    let content_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Ratio(2, 3), Constraint::Ratio(1, 3)])
        .split(chunks[1]);

    draw_hex_view(f, app, content_chunks[0]);
    draw_annotations(f, app, content_chunks[1]);

    // Status
    let status_text = if app.workbench.is_empty() {
        " Go to  1 Packets  tab, select a packet, press  Enter  to open it here"
    } else {
        " [hjkl] cursor  [Space] select range  [Esc] clear sel  [p] back to packets"
    };
    let status = Paragraph::new(Line::from(vec![
        Span::styled(status_text, Style::default().fg(C_FG3)),
    ])).style(Style::default().bg(C_BG2));
    f.render_widget(status, chunks[2]);
}

fn draw_hex_view(f: &mut Frame, app: &App, area: Rect) {
    let wb = &app.workbench;
    let cols: usize = 16;
    let scroll = wb.scroll;
    let cursor = wb.cursor;
    let sel_start = wb.sel_start;

    let mut lines: Vec<Line> = Vec::new();
    let bytes = &wb.bytes;
    let total_rows = (bytes.len() + cols - 1) / cols;
    let visible_rows = area.height.saturating_sub(2) as usize;

    for row in scroll..(scroll + visible_rows).min(total_rows) {
        let start = row * cols;
        let end = (start + cols).min(bytes.len());
        let row_bytes = &bytes[start..end];

        let mut spans: Vec<Span> = Vec::new();
        // Offset
        spans.push(Span::styled(format!("{:08x}  ", start), Style::default().fg(C_FG3)));

        // Hex bytes
        for (i, &b) in row_bytes.iter().enumerate() {
            let abs_idx = start + i;
            let in_sel = if let Some(ss) = sel_start {
                (abs_idx >= ss.min(cursor)) && (abs_idx <= ss.max(cursor))
            } else {
                abs_idx == cursor
            };
            let is_annotated = wb.annotations.iter().any(|a| abs_idx >= a.offset && abs_idx < a.offset + a.length);
            let style = if in_sel {
                Style::default().fg(C_BG).bg(C_CYAN)
            } else if is_annotated {
                Style::default().fg(C_YELLOW)
            } else {
                Style::default().fg(C_FG2)
            };
            spans.push(Span::styled(format!("{b:02x} "), style));
            if i == 7 { spans.push(Span::raw(" ")); }
        }
        // Pad if short row
        let pad = cols - row_bytes.len();
        for _ in 0..pad { spans.push(Span::raw("   ")); }
        spans.push(Span::raw("  "));

        // ASCII
        for (i, &b) in row_bytes.iter().enumerate() {
            let abs_idx = start + i;
            let in_sel = if let Some(ss) = sel_start {
                (abs_idx >= ss.min(cursor)) && (abs_idx <= ss.max(cursor))
            } else {
                abs_idx == cursor
            };
            let ch = if b >= 0x20 && b < 0x7f { b as char } else { '.' };
            let style = if in_sel {
                Style::default().fg(C_BG).bg(C_CYAN)
            } else if b >= 0x20 && b < 0x7f {
                Style::default().fg(C_GREEN)
            } else {
                Style::default().fg(C_FG3)
            };
            spans.push(Span::styled(ch.to_string(), style));
        }
        lines.push(Line::from(spans));
    }

    let hex_view = Paragraph::new(lines)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_BORDER))
            .title(Span::styled(" Hex View ", Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD))))
        .style(Style::default().bg(C_BG));
    f.render_widget(hex_view, area);
}

fn draw_annotations(f: &mut Frame, app: &App, area: Rect) {
    let wb = &app.workbench;
    let mut lines: Vec<Line> = Vec::new();

    // Current byte info
    if let Some(b) = wb.current_byte() {
        lines.push(Line::from(vec![
            Span::styled("Byte: ", Style::default().fg(C_FG3)),
            Span::styled(format!("0x{b:02x} ({b}) '{}'",
                if b >= 0x20 && b < 0x7f { b as char } else { '.' }),
                Style::default().fg(C_CYAN),
            ),
        ]));
    }

    if let Some(ann) = wb.annotation_at_cursor() {
        lines.push(Line::from(Span::styled("─ annotation ─", Style::default().fg(C_FG3))));
        lines.push(Line::from(vec![
            Span::styled("Field: ", Style::default().fg(C_FG3)),
            Span::styled(ann.name.clone(), Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  Value: ", Style::default().fg(C_FG3)),
            Span::styled(ann.value.clone(), Style::default().fg(C_GREEN)),
        ]));
        lines.push(Line::from(vec![
            Span::styled(format!("  Offset: 0x{:04x} len:{}", ann.offset, ann.length),
                Style::default().fg(C_FG3)),
        ]));
    }

    lines.push(Line::from(Span::styled("─ annotations ─", Style::default().fg(C_FG3))));
    for ann in &wb.annotations {
        let slice = &wb.bytes[ann.offset..(ann.offset + ann.length).min(wb.bytes.len())];
        let val = &ann.value[..ann.value.len().min(24)];
        lines.push(Line::from(vec![
            Span::styled(format!("+{:04x} {:<14} ", ann.offset, ann.name),
                Style::default().fg(C_YELLOW)),
            Span::styled(val.to_string(), Style::default().fg(C_FG2)),
        ]));
        let _ = slice; // used above via ann.value
    }

    if !wb.notes.is_empty() {
        lines.push(Line::from(Span::styled("─ notes ─", Style::default().fg(C_FG3))));
        lines.push(Line::from(Span::styled(wb.notes.clone(), Style::default().fg(C_FG))));
    }

    let panel = Paragraph::new(lines)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_BORDER))
            .title(Span::styled(" Inspector ", Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD))))
        .style(Style::default().bg(C_BG))
        .wrap(Wrap { trim: false });
    f.render_widget(panel, area);
}
