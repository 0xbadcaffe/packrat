use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};
use crate::app::App;
use crate::ui::theme::*;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),   // summary
            Constraint::Min(0),      // details
            Constraint::Length(1),   // status bar
        ])
        .split(area);

    draw_summary(f, app, chunks[0]);
    draw_details(f, app, chunks[1]);
    draw_status_bar(f, app, chunks[2]);
}

fn draw_summary(f: &mut Frame, app: &App, area: Rect) {
    let content = if app.diff_baseline.is_empty() {
        Line::from(vec![
            Span::styled(
                " No baseline set. Press ",
                Style::default().fg(C_FG3),
            ),
            Span::styled("[B]", Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
            Span::styled(
                " to snapshot the current capture as baseline, then ",
                Style::default().fg(C_FG3),
            ),
            Span::styled("[D]", Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
            Span::styled(" to compute the diff.", Style::default().fg(C_FG3)),
        ])
    } else if let Some(result) = &app.diff_engine.result {
        let added   = result.only_in_b.len();
        let removed = result.only_in_a.len();
        Line::from(vec![
            Span::styled(" Baseline: ", Style::default().fg(C_FG3)),
            Span::styled(
                format!("{} pkts", result.total_a),
                Style::default().fg(C_CYAN),
            ),
            Span::styled("  →  Current: ", Style::default().fg(C_FG3)),
            Span::styled(
                format!("{} pkts", result.total_b),
                Style::default().fg(C_CYAN),
            ),
            Span::styled("    ", Style::default()),
            Span::styled(
                format!("+{added}"),
                Style::default().fg(C_GREEN).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" new  ", Style::default().fg(C_FG3)),
            Span::styled(
                format!("-{removed}"),
                Style::default().fg(C_RED).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" removed", Style::default().fg(C_FG3)),
        ])
    } else {
        Line::from(vec![
            Span::styled(
                format!(" Baseline: {} pkts — press ", app.diff_baseline.len()),
                Style::default().fg(C_FG3),
            ),
            Span::styled("[D]", Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
            Span::styled(" to compute diff against current capture.", Style::default().fg(C_FG3)),
        ])
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_BORDER))
        .title(Span::styled(
            " Differential Analysis ",
            Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD),
        ));
    f.render_widget(Paragraph::new(content).block(block).style(Style::default().bg(C_BG)), area);
}

fn draw_details(f: &mut Frame, app: &App, area: Rect) {
    let Some(result) = &app.diff_engine.result else {
        let msg = Paragraph::new(Line::from(vec![
            Span::styled(
                " No diff results yet.",
                Style::default().fg(C_FG3),
            ),
        ])).block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(C_BORDER)))
          .style(Style::default().bg(C_BG));
        f.render_widget(msg, area);
        return;
    };

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Ratio(1, 3),
            Constraint::Ratio(1, 3),
            Constraint::Ratio(1, 3),
        ])
        .split(area);

    draw_proto_delta(f, result, app.diff_scroll, cols[0]);
    draw_host_delta(f, result, app.diff_scroll, cols[1]);
    draw_port_delta(f, result, app.diff_scroll, cols[2]);
}

fn draw_proto_delta(
    f: &mut Frame,
    result: &crate::analysis::diff::PacketDiff,
    scroll: usize,
    area: Rect,
) {
    let header = Row::new(vec![
        Cell::from("Protocol").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("Baseline").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("Current").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("Δ").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
    ]).style(Style::default().bg(C_BG2)).height(1);

    let mut entries: Vec<(&String, &(u64, u64))> = result.proto_delta.iter().collect();
    entries.sort_by(|a, b| b.1.1.cmp(&a.1.1));

    let rows: Vec<Row> = entries.iter().skip(scroll).map(|(proto, (a, b))| {
        let delta = *b as i64 - *a as i64;
        let delta_str = if delta > 0 { format!("+{delta}") } else { format!("{delta}") };
        let delta_style = if delta > 0 {
            Style::default().fg(C_GREEN)
        } else if delta < 0 {
            Style::default().fg(C_RED)
        } else {
            Style::default().fg(C_FG3)
        };
        Row::new(vec![
            Cell::from(proto.as_str()).style(Style::default().fg(C_CYAN)),
            Cell::from(a.to_string()).style(Style::default().fg(C_FG2)),
            Cell::from(b.to_string()).style(Style::default().fg(C_FG2)),
            Cell::from(delta_str).style(delta_style),
        ])
    }).collect();

    let table = Table::new(rows, [
        Constraint::Min(12),
        Constraint::Length(9),
        Constraint::Length(9),
        Constraint::Length(7),
    ])
    .header(header)
    .block(Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_BORDER))
        .title(Span::styled(" Protocol Δ ", Style::default().fg(C_YELLOW))))
    .style(Style::default().bg(C_BG));
    f.render_widget(table, area);
}

fn draw_host_delta(
    f: &mut Frame,
    result: &crate::analysis::diff::PacketDiff,
    scroll: usize,
    area: Rect,
) {
    let header = Row::new(vec![
        Cell::from("Host").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("Base B↑").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("Curr B↑").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
    ]).style(Style::default().bg(C_BG2)).height(1);

    let mut entries: Vec<(&String, &(u64, u64))> = result.host_delta.iter().collect();
    entries.sort_by(|a, b| b.1.1.cmp(&a.1.1));

    let rows: Vec<Row> = entries.iter().skip(scroll).map(|(ip, (a, b))| {
        let delta = *b as i64 - *a as i64;
        let style = if delta > 0 { Style::default().fg(C_GREEN) }
                    else if delta < 0 { Style::default().fg(C_RED) }
                    else { Style::default().fg(C_FG2) };
        Row::new(vec![
            Cell::from(ip.as_str()).style(Style::default().fg(C_CYAN)),
            Cell::from(crate::ui::fmt_bytes(*a)).style(Style::default().fg(C_FG2)),
            Cell::from(crate::ui::fmt_bytes(*b)).style(style),
        ])
    }).collect();

    let table = Table::new(rows, [
        Constraint::Min(16),
        Constraint::Length(9),
        Constraint::Length(9),
    ])
    .header(header)
    .block(Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_BORDER))
        .title(Span::styled(" Host Δ ", Style::default().fg(C_YELLOW))))
    .style(Style::default().bg(C_BG));
    f.render_widget(table, area);
}

fn draw_port_delta(
    f: &mut Frame,
    result: &crate::analysis::diff::PacketDiff,
    scroll: usize,
    area: Rect,
) {
    let header = Row::new(vec![
        Cell::from("Port").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("Baseline").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("Current").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("Δ").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
    ]).style(Style::default().bg(C_BG2)).height(1);

    let mut entries: Vec<(&u16, &(u64, u64))> = result.port_delta.iter().collect();
    entries.sort_by(|a, b| b.1.1.cmp(&a.1.1));

    let rows: Vec<Row> = entries.iter().skip(scroll).map(|(port, (a, b))| {
        let delta = *b as i64 - *a as i64;
        let delta_str = if delta > 0 { format!("+{delta}") } else { format!("{delta}") };
        let delta_style = if delta > 0 { Style::default().fg(C_GREEN) }
                          else if delta < 0 { Style::default().fg(C_RED) }
                          else { Style::default().fg(C_FG3) };
        Row::new(vec![
            Cell::from(port.to_string()).style(Style::default().fg(C_CYAN)),
            Cell::from(a.to_string()).style(Style::default().fg(C_FG2)),
            Cell::from(b.to_string()).style(Style::default().fg(C_FG2)),
            Cell::from(delta_str).style(delta_style),
        ])
    }).collect();

    let table = Table::new(rows, [
        Constraint::Length(6),
        Constraint::Length(9),
        Constraint::Length(9),
        Constraint::Min(7),
    ])
    .header(header)
    .block(Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_BORDER))
        .title(Span::styled(" Port Δ ", Style::default().fg(C_YELLOW))))
    .style(Style::default().bg(C_BG));
    f.render_widget(table, area);
}

fn draw_status_bar(f: &mut Frame, app: &App, area: Rect) {
    let baseline_str = if app.diff_baseline.is_empty() {
        "no baseline".to_string()
    } else {
        format!("{} pkts baseline", app.diff_baseline.len())
    };
    let bar = Paragraph::new(Line::from(vec![
        Span::styled(format!(" {baseline_str}  "), Style::default().fg(C_FG3)),
        Span::styled("[B]", Style::default().fg(C_YELLOW)),
        Span::styled(" set baseline  ", Style::default().fg(C_FG3)),
        Span::styled("[D]", Style::default().fg(C_YELLOW)),
        Span::styled(" compute diff  ", Style::default().fg(C_FG3)),
        Span::styled("[j/k]", Style::default().fg(C_YELLOW)),
        Span::styled(" scroll  ", Style::default().fg(C_FG3)),
        Span::styled("[X]", Style::default().fg(C_YELLOW)),
        Span::styled(" clear", Style::default().fg(C_FG3)),
    ])).style(Style::default().bg(C_BG2));
    f.render_widget(bar, area);
}
