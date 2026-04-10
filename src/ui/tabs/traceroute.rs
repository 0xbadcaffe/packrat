use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};

use crate::app::App;
use crate::traceroute::HopResult;
use crate::ui::theme::*;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // input bar
            Constraint::Min(0),     // results table
            Constraint::Length(1),  // hint bar
        ])
        .split(area);

    draw_input(f, app, chunks[0]);
    draw_results(f, app, chunks[1]);
    draw_hints(f, app, chunks[2]);
}

fn draw_input(f: &mut Frame, app: &App, area: Rect) {
    let tr = &app.traceroute;
    let status = if tr.running {
        Span::styled("  ● running…", Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD))
    } else if tr.complete {
        Span::styled("  ✓ done", Style::default().fg(C_GREEN))
    } else if tr.error.is_some() {
        Span::styled(
            format!("  ✗ {}", tr.error.as_deref().unwrap_or("")),
            Style::default().fg(C_RED),
        )
    } else {
        Span::raw("")
    };

    let target_display = if tr.editing {
        format!("{}_", tr.target)
    } else if tr.target.is_empty() {
        "<press e or Enter to type target>".into()
    } else {
        tr.target.clone()
    };
    let target_color = if tr.editing { C_YELLOW } else if tr.target.is_empty() { C_FG3 } else { C_CYAN };
    let line = Line::from(vec![
        Span::styled(" Target: ", Style::default().fg(C_FG2)),
        Span::styled(target_display, Style::default().fg(target_color).add_modifier(Modifier::BOLD)),
        status,
    ]);

    let title = if tr.editing {
        " Traceroute  [Enter] confirm  [Esc] cancel "
    } else {
        " Traceroute  [e/Enter] edit target  [Space/x] run  [Esc] clear "
    };

    f.render_widget(
        Paragraph::new(line)
            .block(Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(if tr.editing { C_CYAN } else { C_BORDER }))
                .title(Span::styled(
                    title,
                    Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD),
                ))),
        area,
    );
}

fn draw_results(f: &mut Frame, app: &App, area: Rect) {
    let tr = &app.traceroute;

    let header = Row::new(vec![
        Cell::from(Span::styled("Hop", Style::default().fg(C_FG3).add_modifier(Modifier::BOLD))),
        Cell::from(Span::styled("IP Address", Style::default().fg(C_FG3).add_modifier(Modifier::BOLD))),
        Cell::from(Span::styled("RTT", Style::default().fg(C_FG3).add_modifier(Modifier::BOLD))),
        Cell::from(Span::styled("Hostname", Style::default().fg(C_FG3).add_modifier(Modifier::BOLD))),
    ]).height(1);

    let visible = area.height.saturating_sub(3) as usize;
    let scroll = tr.selected.saturating_sub(visible.saturating_sub(1));

    let rows: Vec<Row> = tr.hops.iter().enumerate().skip(scroll).map(|(i, hop)| {
        let is_sel = i == tr.selected;
        let bg = if is_sel { C_SEL_BG } else { C_BG };

        let (ip_style, rtt_str, rtt_color) = match &hop.result {
            HopResult::Reply { rtt_ms } => {
                let color = if *rtt_ms < 10.0 { C_GREEN }
                    else if *rtt_ms < 50.0  { C_YELLOW }
                    else                    { C_RED };
                (Style::default().fg(C_CYAN).bg(bg),
                 format!("{:.2} ms", rtt_ms),
                 color)
            }
            HopResult::Timeout => {
                (Style::default().fg(C_FG3).bg(bg),
                 "* * *".into(),
                 C_FG3)
            }
        };

        let is_dest = hop.ip == tr.target_ip.map(|ip| ip.to_string()).unwrap_or_default();
        let hop_color = if is_dest { C_GREEN } else { C_FG2 };

        Row::new(vec![
            Cell::from(Span::styled(
                format!("{:>3}", hop.ttl),
                Style::default().fg(hop_color).bg(bg),
            )),
            Cell::from(Span::styled(&hop.ip, ip_style)),
            Cell::from(Span::styled(rtt_str, Style::default().fg(rtt_color).bg(bg))),
            Cell::from(Span::styled(
                hop.hostname.as_deref().unwrap_or(""),
                Style::default().fg(C_FG3).bg(bg),
            )),
        ])
        .height(1)
        .style(Style::default().bg(bg))
    }).collect();

    let title = if tr.hops.is_empty() && !tr.running {
        " Results  (type a host/IP above and press Enter) "
    } else {
        " Results "
    };

    let table = Table::new(
        std::iter::once(header).chain(rows).collect::<Vec<_>>(),
        [
            Constraint::Length(4),
            Constraint::Length(17),
            Constraint::Length(12),
            Constraint::Min(0),
        ],
    )
    .block(Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_BORDER))
        .title(Span::styled(title, Style::default().fg(C_FG2))))
    .style(Style::default().bg(C_BG));

    f.render_widget(table, area);

    // "Running" animation dots
    if tr.running {
        let dots = ".".repeat((tr.next_hop_ttl as usize % 4) + 1);
        let anim = Rect {
            x: area.x + area.width.saturating_sub(12),
            y: area.y,
            width: 10,
            height: 1,
        };
        f.render_widget(
            Paragraph::new(Span::styled(
                format!("probing{}", dots),
                Style::default().fg(C_CYAN),
            )),
            anim,
        );
    }
}

fn draw_hints(f: &mut Frame, app: &App, area: Rect) {
    let tr = &app.traceroute;
    let hop_count = tr.hops.len();
    let status = if tr.running {
        format!("hop {}/∞  probing…", tr.next_hop_ttl)
    } else if tr.complete {
        format!("{} hops to {}", hop_count, tr.target)
    } else {
        "[e/Enter] edit target  [Space/x] run  [Esc] clear  [j/k] scroll  [1-0] tab  [q] quit".into()
    };

    f.render_widget(
        Paragraph::new(Span::styled(
            format!(" {}", status),
            Style::default().fg(C_FG3),
        ))
        .style(Style::default().bg(C_BG2)),
        area,
    );
}
