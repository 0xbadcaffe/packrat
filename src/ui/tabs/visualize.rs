use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

use crate::app::App;
use crate::ui::theme::*;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);
    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[0]);
    let bot = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[1]);

    draw_proto_bars(f, app, top[0]);
    draw_sparkline(f, app, top[1]);
    draw_top_ips(f, app, bot[0]);
    draw_geo(f, app, bot[1]);
}

fn draw_proto_bars(f: &mut Frame, app: &App, area: Rect) {
    let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for p in &app.packets { *counts.entry(p.protocol.as_str()).or_default() += 1; }
    let total = app.packets.len().max(1);
    let mut sorted: Vec<_> = counts.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1));

    let mut lines: Vec<Line> = vec![Line::raw("")];
    for (proto, count) in sorted.iter().take(9) {
        let pct = (**count as f64 / total as f64) * 100.0;
        let bar_w = (pct / 100.0 * 20.0) as usize;
        lines.push(Line::from(vec![
            Span::styled("█".repeat(bar_w), Style::default().fg(proto_color(proto))),
            Span::styled(format!(" {:<7} {:.1}%", proto, pct), Style::default().fg(C_FG2)),
        ]));
    }

    let p = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(C_BORDER))
            .title(Span::styled(" Protocol Distribution ", Style::default().fg(C_CYAN))))
        .style(Style::default().bg(C_BG));
    f.render_widget(p, area);
}

fn draw_sparkline(f: &mut Frame, app: &App, area: Rect) {
    let w = area.width.saturating_sub(4) as usize;
    let data = &app.rate_history;
    let max = data.iter().max().copied().unwrap_or(1).max(1);

    let bars = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let samples: Vec<u32> = if data.len() > w {
        data[data.len() - w..].to_vec()
    } else {
        let mut v = vec![0u32; w - data.len()];
        v.extend_from_slice(data);
        v
    };

    let spark: String = samples.iter().map(|&v| {
        let idx = ((v as f64 / max as f64) * 7.0) as usize;
        bars[idx.min(7)]
    }).collect();

    let lines = vec![
        Line::raw(""),
        Line::from(vec![Span::styled(format!(" max: {}/s", max), Style::default().fg(C_FG3))]),
        Line::raw(""),
        Line::from(vec![Span::styled(spark, Style::default().fg(C_CYAN))]),
        Line::raw(""),
        Line::from(vec![Span::styled(format!(" current: {}/s", app.current_rate()), Style::default().fg(C_GREEN))]),
    ];

    let p = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(C_BORDER))
            .title(Span::styled(" Traffic Rate (pkts/s) ", Style::default().fg(C_CYAN))))
        .style(Style::default().bg(C_BG));
    f.render_widget(p, area);
}

fn draw_top_ips(f: &mut Frame, app: &App, area: Rect) {
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for p in &app.packets { *counts.entry(p.src.clone()).or_default() += 1; }
    let mut sorted: Vec<_> = counts.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1));
    let max = sorted.first().map(|(_, c)| **c).unwrap_or(1);

    let mut lines: Vec<Line> = vec![Line::raw("")];
    for (ip, count) in sorted.iter().take(10) {
        let bar_w = (**count as f64 / max as f64 * 18.0) as usize;
        lines.push(Line::from(vec![
            Span::styled(format!(" {:<16}", ip), Style::default().fg(C_CYAN)),
            Span::styled("█".repeat(bar_w), Style::default().fg(C_GREEN)),
            Span::styled(format!(" {}", count), Style::default().fg(C_FG3)),
        ]));
    }

    let p = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(C_BORDER))
            .title(Span::styled(" Top Source IPs ", Style::default().fg(C_CYAN))))
        .style(Style::default().bg(C_BG));
    f.render_widget(p, area);
}

fn draw_geo(f: &mut Frame, app: &App, area: Rect) {
    const GEO: &[(&str, &str, &str)] = &[
        ("8.8.8.8",        "US", "Mountain View, US"),
        ("1.1.1.1",        "AU", "Sydney, AU"),
        ("151.101.64.81",  "US", "San Francisco, US"),
        ("142.250.80.46",  "US", "Kansas City, US"),
        ("104.21.55.33",   "US", "San Jose, US"),
        ("172.217.14.206", "US", "Mountain View, US"),
        ("13.107.42.14",   "IE", "Dublin, IE"),
        ("52.84.17.200",   "US", "Ashburn, US"),
        ("34.120.208.123", "BE", "Brussels, BE"),
    ];

    let mut remote_counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for p in &app.packets {
        if GEO.iter().any(|(ip, _, _)| *ip == p.dst.as_str()) {
            *remote_counts.entry(p.dst.as_str()).or_default() += 1;
        }
    }
    let mut sorted: Vec<_> = remote_counts.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1));

    let mut lines: Vec<Line> = vec![Line::raw("")];
    for (ip, count) in sorted.iter().take(10) {
        if let Some((_, cc, loc)) = GEO.iter().find(|(gip, _, _)| gip == *ip) {
            lines.push(Line::from(vec![
                Span::styled(format!(" [{}]", cc), Style::default().fg(C_YELLOW)),
                Span::styled(format!(" {:<16}", ip), Style::default().fg(C_CYAN)),
                Span::styled(format!("{:<20}", loc), Style::default().fg(C_FG2)),
                Span::styled(format!(" {}p", count), Style::default().fg(C_GREEN)),
            ]));
        }
    }

    let p = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(C_BORDER))
            .title(Span::styled(" Remote Endpoints ", Style::default().fg(C_CYAN))))
        .style(Style::default().bg(C_BG));
    f.render_widget(p, area);
}
