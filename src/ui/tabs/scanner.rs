use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};

use crate::app::App;
use crate::scan::{PortState, ScanField, ScanMode};
use crate::ui::theme::*;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(7), Constraint::Min(0)])
        .split(area);

    draw_form(f, app, chunks[0]);
    draw_results(f, app, chunks[1]);
}

fn draw_form(f: &mut Frame, app: &App, area: Rect) {
    let scan = &app.scan;

    let focused_color = |field: ScanField| -> ratatui::style::Color {
        if scan.focused_field == field { C_CYAN } else { C_FG2 }
    };
    let val_color = |field: ScanField| -> ratatui::style::Color {
        if scan.focused_field == field { C_YELLOW } else { C_FG }
    };

    let mode_str = match scan.scan_mode {
        ScanMode::TcpConnect => "TCP Connect",
        ScanMode::Syn        => "SYN (simulated)",
        ScanMode::Udp        => "UDP (simulated)",
    };

    let progress = if scan.running && scan.total_ports > 0 {
        let pct = (scan.current_port as usize * 100 / scan.total_ports as usize).min(100);
        let bar_w = area.width.saturating_sub(24) as usize;
        let filled = (bar_w * pct / 100).min(bar_w);
        format!("[{}{}] {}% (port {})", "█".repeat(filled), "░".repeat(bar_w - filled), pct, scan.current_port)
    } else if scan.complete {
        format!("Done — {} open / {} total", scan.open_count(), scan.total_ports)
    } else {
        "idle".into()
    };

    let lines = vec![
        Line::from(vec![
            Span::styled(" Target:    ", Style::default().fg(focused_color(ScanField::Target))),
            Span::styled(if scan.target.is_empty() { "<type target>" } else { &scan.target },
                         Style::default().fg(val_color(ScanField::Target))),
        ]),
        Line::from(vec![
            Span::styled(" Port range:", Style::default().fg(C_FG2)),
            Span::styled(&scan.port_range_start, Style::default().fg(val_color(ScanField::PortStart))),
            Span::styled(" – ", Style::default().fg(C_FG3)),
            Span::styled(&scan.port_range_end, Style::default().fg(val_color(ScanField::PortEnd))),
            Span::styled("  [Tab] focus next field  [Enter/e] edit  [Space/x] start scan", Style::default().fg(C_FG3)),
        ]),
        Line::from(vec![
            Span::styled(" Mode:      ", Style::default().fg(focused_color(ScanField::Mode))),
            Span::styled(mode_str, Style::default().fg(val_color(ScanField::Mode))),
            Span::styled("  [m] cycle mode", Style::default().fg(C_FG3)),
        ]),
        Line::from(vec![
            Span::styled(" Progress:  ", Style::default().fg(C_FG2)),
            Span::styled(&progress, Style::default().fg(if scan.running { C_GREEN } else { C_FG2 })),
        ]),
        if let Some(e) = &scan.error {
            Line::from(Span::styled(format!(" Error: {}", e), Style::default().fg(C_RED)))
        } else {
            Line::from(Span::styled(
                " [Tab] next field  [Enter/e] edit  [Space/x] start  [Esc] cancel  [C] clear",
                Style::default().fg(C_FG3),
            ))
        },
    ];

    f.render_widget(
        Paragraph::new(lines)
            .block(Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(C_BORDER))
                .title(Span::styled(
                    " Port Scanner  (simulated — real with --features real-capture) ",
                    Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD),
                )))
            .style(Style::default().bg(C_BG)),
        area,
    );
}

fn draw_results(f: &mut Frame, app: &App, area: Rect) {
    let scan = &app.scan;
    let scroll = app.scanner_scroll;
    let visible = area.height.saturating_sub(3) as usize;

    let header = Row::new(vec![
        Cell::from(Span::styled("Port", Style::default().fg(C_FG3).add_modifier(Modifier::BOLD))),
        Cell::from(Span::styled("State", Style::default().fg(C_FG3).add_modifier(Modifier::BOLD))),
        Cell::from(Span::styled("Service", Style::default().fg(C_FG3).add_modifier(Modifier::BOLD))),
        Cell::from(Span::styled("Banner", Style::default().fg(C_FG3).add_modifier(Modifier::BOLD))),
    ]).height(1);

    let rows: Vec<Row> = scan.results.iter()
        .enumerate()
        .skip(scroll)
        .take(visible)
        .map(|(i, entry)| {
            let is_sel = i == scan.selected;
            let bg = if is_sel { C_SEL_BG } else { C_BG };

            let (state_str, state_color) = match entry.state {
                PortState::Open     => ("open",     C_GREEN),
                PortState::Closed   => ("closed",   C_FG3),
                PortState::Filtered => ("filtered", C_YELLOW),
                PortState::Unknown  => ("?",        C_FG3),
            };

            Row::new(vec![
                Cell::from(Span::styled(entry.port.to_string(), Style::default().fg(C_CYAN).bg(bg))),
                Cell::from(Span::styled(state_str, Style::default().fg(state_color).bg(bg))),
                Cell::from(Span::styled(entry.service, Style::default().fg(C_FG2).bg(bg))),
                Cell::from(Span::styled(
                    entry.banner.as_deref().unwrap_or(""),
                    Style::default().fg(C_FG3).bg(bg),
                )),
            ])
            .height(1)
            .style(Style::default().bg(bg))
        })
        .collect();

    let open_count = scan.open_count();
    let total = scan.results.len();
    let title = format!(" Results — {}/{} ports  ({} open) ", total, scan.total_ports, open_count);

    let table = Table::new(
        std::iter::once(header).chain(rows).collect::<Vec<_>>(),
        [Constraint::Length(7), Constraint::Length(10), Constraint::Length(18), Constraint::Min(0)],
    )
    .block(Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_BORDER))
        .title(Span::styled(title, Style::default().fg(C_FG2))))
    .style(Style::default().bg(C_BG));

    f.render_widget(table, area);
}
