use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, List, ListItem, Paragraph, Wrap},
};

use crate::app::App;
use crate::ui::helpers::{fmt_bytes, truncate};
use crate::ui::theme::*;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(22), Constraint::Min(0)])
        .split(area);

    draw_nav(f, app, chunks[0]);
    draw_content(f, app, chunks[1]);
}

fn draw_nav(f: &mut Frame, app: &App, area: Rect) {
    let sections = nav_sections();
    let icons = ["◈", "⬡", "⊞", "⊡", "◉", "≡", "◆", "⊗", "⚑"];
    let items: Vec<ListItem> = sections.iter().enumerate().map(|(i, &name)| {
        let style = if i == app.analysis_section {
            Style::default().fg(Color::White).bg(C_SEL_BG)
        } else {
            Style::default().fg(C_FG2)
        };
        ListItem::new(Line::from(vec![
            Span::styled(format!(" {} ", icons[i]), Style::default().fg(C_YELLOW)),
            Span::styled(name, style),
        ]))
    }).collect();

    let list = List::new(items)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(C_BORDER))
            .title(Span::styled(" Sections ", Style::default().fg(C_CYAN))))
        .style(Style::default().bg(C_BG));
    f.render_widget(list, area);
}

fn draw_content(f: &mut Frame, app: &App, area: Rect) {
    let title = nav_sections()[app.analysis_section];
    let content = build_content(app, app.analysis_section);
    let p = Paragraph::new(content)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(C_BORDER))
            .title(Span::styled(format!(" {} ", title), Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD))))
        .style(Style::default().bg(C_BG))
        .wrap(Wrap { trim: false });
    f.render_widget(p, area);
}

fn nav_sections() -> [&'static str; 9] {
    ["General Info", "Protocol Stats", "Top Talkers", "Conversations", "IP Endpoints", "Port Summary",
     "Magic Bytes", "XOR Analysis", "Anomaly Report"]
}

fn build_content(app: &App, section: usize) -> Vec<Line<'static>> {
    let mut lines: Vec<Line> = Vec::new();
    match section {
        0 => {
            let dur = app.packets.back().map(|p| p.timestamp).unwrap_or(0.0);
            let avg = if app.packets.is_empty() { 0 } else { app.total_bytes as usize / app.packets.len() };
            let rows: Vec<(&str, String)> = vec![
                ("Total Packets",    app.packets.len().to_string()),
                ("Total Bytes",      fmt_bytes(app.total_bytes)),
                ("Capture Duration", format!("{:.3}s", dur)),
                ("Avg Packet Size",  format!("{} bytes", avg)),
                ("Packets/sec",      app.current_rate().to_string()),
                ("Interface",        app.selected_iface.clone()),
                ("Snaplen",          "65535".into()),
                ("Link Type",        "Ethernet".into()),
                ("Recording",        if app.recording { format!("yes → {}", app.pcap_path) } else { "no".into() }),
            ];
            lines.push(Line::raw(""));
            for (k, v) in rows {
                lines.push(Line::from(vec![
                    Span::styled(format!("  {:<22}", k), Style::default().fg(C_FG2)),
                    Span::styled(v, Style::default().fg(C_CYAN)),
                ]));
            }
        }
        1 => {
            let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
            for p in &app.packets { *counts.entry(p.protocol.as_str()).or_default() += 1; }
            let total = app.packets.len().max(1);
            let mut sorted: Vec<_> = counts.iter().collect();
            sorted.sort_by(|a, b| b.1.cmp(a.1));

            lines.push(Line::raw(""));
            lines.push(Line::from(vec![Span::styled(
                format!("  {:<10} {:<8} {:<7} {}", "Protocol", "Count", "%", "Distribution"),
                Style::default().fg(C_FG2),
            )]));
            lines.push(Line::raw("  ".to_string() + &"─".repeat(60)));
            for (proto, count) in &sorted {
                let pct = (**count as f64 / total as f64) * 100.0;
                let bar_w = (pct / 100.0 * 30.0) as usize;
                lines.push(Line::from(vec![
                    Span::styled(format!("  {:<10}", proto), Style::default().fg(proto_color(proto))),
                    Span::styled(format!("{:<8}", count), Style::default().fg(C_CYAN)),
                    Span::styled(format!("{:<7.1}%", pct), Style::default().fg(C_FG2)),
                    Span::styled("█".repeat(bar_w), Style::default().fg(C_CYAN)),
                ]));
            }
        }
        2 => {
            let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
            for p in &app.packets { *counts.entry(p.src.clone()).or_default() += 1; }
            let mut sorted: Vec<_> = counts.iter().collect();
            sorted.sort_by(|a, b| b.1.cmp(a.1));
            let max = sorted.first().map(|(_, c)| **c).unwrap_or(1);

            lines.push(Line::raw(""));
            lines.push(Line::from(vec![Span::styled(
                format!("  {:<18} {:<8} {}", "Source IP", "Pkts", "Distribution"),
                Style::default().fg(C_FG2),
            )]));
            lines.push(Line::raw("  ".to_string() + &"─".repeat(60)));
            for (ip, count) in sorted.iter().take(15) {
                let bar_w = (**count as f64 / max as f64 * 25.0) as usize;
                lines.push(Line::from(vec![
                    Span::styled(format!("  {:<18}", ip), Style::default().fg(C_CYAN)),
                    Span::styled(format!("{:<8}", count), Style::default().fg(C_FG2)),
                    Span::styled("█".repeat(bar_w), Style::default().fg(C_GREEN)),
                ]));
            }
        }
        3 => {
            let mut convs: std::collections::HashMap<String, (usize, u64)> =
                std::collections::HashMap::new();
            for p in &app.packets {
                let mut pair = vec![p.src.as_str(), p.dst.as_str()];
                pair.sort();
                let key = format!("{} ↔ {} [{}]", pair[0], pair[1], p.protocol);
                let e = convs.entry(key).or_insert((0, 0));
                e.0 += 1;
                e.1 += p.length as u64;
            }
            let mut sorted: Vec<_> = convs.iter().collect();
            sorted.sort_by(|a, b| b.1.0.cmp(&a.1.0));

            lines.push(Line::raw(""));
            lines.push(Line::from(vec![Span::styled(
                format!("  {:<38} {:<8} {}", "Conversation", "Pkts", "Bytes"),
                Style::default().fg(C_FG2),
            )]));
            lines.push(Line::raw("  ".to_string() + &"─".repeat(60)));
            for (conv, (pkts, bytes)) in sorted.iter().take(20) {
                lines.push(Line::from(vec![
                    Span::styled(format!("  {:<38}", truncate(conv, 38)), Style::default().fg(C_FG)),
                    Span::styled(format!("{:<8}", pkts), Style::default().fg(C_CYAN)),
                    Span::styled(fmt_bytes(*bytes), Style::default().fg(C_GREEN)),
                ]));
            }
        }
        4 => {
            let mut eps: std::collections::HashMap<String, (usize, u64)> =
                std::collections::HashMap::new();
            for p in &app.packets {
                let e = eps.entry(p.src.clone()).or_insert((0, 0));
                e.0 += 1;
                e.1 += p.length as u64;
            }
            let mut sorted: Vec<_> = eps.iter().collect();
            sorted.sort_by(|a, b| b.1.0.cmp(&a.1.0));

            lines.push(Line::raw(""));
            lines.push(Line::from(vec![Span::styled(
                format!("  {:<18} {:<8} {}", "IP Address", "Pkts", "Bytes"),
                Style::default().fg(C_FG2),
            )]));
            lines.push(Line::raw("  ".to_string() + &"─".repeat(40)));
            for (ip, (pkts, bytes)) in sorted.iter().take(20) {
                lines.push(Line::from(vec![
                    Span::styled(format!("  {:<18}", ip), Style::default().fg(C_CYAN)),
                    Span::styled(format!("{:<8}", pkts), Style::default().fg(C_FG2)),
                    Span::styled(fmt_bytes(*bytes), Style::default().fg(C_GREEN)),
                ]));
            }
        }
        5 => {
            let port_name = |p: u16| match p {
                80    => "HTTP",    443  => "HTTPS",   53   => "DNS",
                22    => "SSH",     25   => "SMTP",    587  => "SMTP-sub",
                3306  => "MySQL",   5432 => "Postgres", 6379 => "Redis",
                8080  => "HTTP-Alt",9200 => "Elastic",  123  => "NTP",
                5353  => "mDNS",   _    => "Unknown",
            };
            let mut ports: std::collections::HashMap<u16, usize> = std::collections::HashMap::new();
            for p in &app.packets {
                if let Some(dp) = p.dst_port { *ports.entry(dp).or_default() += 1; }
            }
            let mut sorted: Vec<_> = ports.iter().collect();
            sorted.sort_by(|a, b| b.1.cmp(a.1));

            lines.push(Line::raw(""));
            lines.push(Line::from(vec![Span::styled(
                format!("  {:<8} {:<16} {}", "Port", "Service", "Count"),
                Style::default().fg(C_FG2),
            )]));
            lines.push(Line::raw("  ".to_string() + &"─".repeat(35)));
            for (port, count) in sorted.iter().take(20) {
                lines.push(Line::from(vec![
                    Span::styled(format!("  {:<8}", port), Style::default().fg(C_YELLOW)),
                    Span::styled(format!("{:<16}", port_name(**port)), Style::default().fg(C_FG2)),
                    Span::styled(count.to_string(), Style::default().fg(C_CYAN)),
                ]));
            }
        }
        6 => {
            // Magic Bytes
            lines.push(Line::raw(""));
            lines.push(Line::from(vec![Span::styled(
                format!("  {:<8} {:<12} {}", "Pkt#", "Magic", "Offset / Details"),
                Style::default().fg(C_FG2),
            )]));
            lines.push(Line::raw("  ".to_string() + &"─".repeat(55)));
            let mut found = false;
            for pkt in app.packets.iter().take(500) {
                let ind = crate::net::inspector::inspect(pkt);
                for m in &ind.magic {
                    found = true;
                    lines.push(Line::from(vec![
                        Span::styled(format!("  {:<8}", pkt.no), Style::default().fg(C_FG3)),
                        Span::styled(format!("{:<12}", m.name), Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
                        Span::styled(
                            format!("at byte offset {}  proto={}  {} bytes",
                                m.offset, pkt.protocol, pkt.length),
                            Style::default().fg(C_FG2),
                        ),
                    ]));
                }
            }
            if !found {
                lines.push(Line::raw(""));
                lines.push(Line::from(Span::styled(
                    "  No file magic signatures detected in captured packets.",
                    Style::default().fg(C_FG3),
                )));
            }
        }
        7 => {
            // XOR Analysis
            lines.push(Line::raw(""));
            lines.push(Line::from(vec![Span::styled(
                "  Single-byte XOR obfuscation detection (score = printable bytes after XOR)",
                Style::default().fg(C_FG2),
            )]));
            lines.push(Line::raw("  ".to_string() + &"─".repeat(55)));
            let mut found = false;
            for pkt in app.packets.iter().take(500) {
                let ind = crate::net::inspector::inspect(pkt);
                if let Some(xor) = ind.xor {
                    found = true;
                    lines.push(Line::from(vec![
                        Span::styled(format!("  pkt #{:<6}", pkt.no), Style::default().fg(C_FG3)),
                        Span::styled(
                            format!("key=0x{:02x} ({:3})", xor.key, xor.key),
                            Style::default().fg(C_ORANGE).add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            format!("  score={:.0}%  proto={}  len={}",
                                xor.score * 100.0, pkt.protocol, pkt.length),
                            Style::default().fg(C_FG3),
                        ),
                    ]));
                }
            }
            if !found {
                lines.push(Line::raw(""));
                lines.push(Line::from(Span::styled(
                    "  No XOR obfuscation candidates detected.",
                    Style::default().fg(C_FG3),
                )));
            }
        }
        8 => {
            // Anomaly Report
            lines.push(Line::raw(""));
            lines.push(Line::from(Span::styled(
                "  ⚑ Anomaly Report — non-standard ports, tunneling, beacons, scans",
                Style::default().fg(C_FG2),
            )));
            lines.push(Line::raw("  ".to_string() + &"─".repeat(55)));
            let mut found = false;
            // Per-packet anomalies
            for pkt in app.packets.iter().take(500) {
                let ind = crate::net::inspector::inspect(pkt);
                for anomaly in &ind.anomalies {
                    found = true;
                    lines.push(Line::from(vec![
                        Span::styled(format!("  pkt #{:<6}", pkt.no), Style::default().fg(C_FG3)),
                        Span::styled(format!("⚑ {}", anomaly), Style::default().fg(C_RED)),
                    ]));
                }
            }
            // Flow-level anomalies (beacon / scan)
            for flow in app.flow_tracker.sorted_flows(&app.flows_sort) {
                if flow.flags.beacon {
                    found = true;
                    let n = flow.intervals.len() as f64;
                    let mean = if n > 0.0 {
                        flow.intervals.iter().sum::<f64>() / n
                    } else { 0.0 };
                    lines.push(Line::from(vec![
                        Span::styled("  ⚑ BEACON ", Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
                        Span::styled(
                            format!("{}:{} ↔ {}:{}  ~{:.1}s interval  {} pkts",
                                flow.key.ep1.0, flow.key.ep1.1,
                                flow.key.ep2.0, flow.key.ep2.1,
                                mean, flow.packets),
                            Style::default().fg(C_FG2),
                        ),
                    ]));
                }
                if flow.flags.scan {
                    found = true;
                    lines.push(Line::from(vec![
                        Span::styled("  ⚑ SCAN   ", Style::default().fg(C_RED).add_modifier(Modifier::BOLD)),
                        Span::styled(
                            format!("{}  → ≥5 distinct destinations",
                                flow.key.ep1.0),
                            Style::default().fg(C_FG2),
                        ),
                    ]));
                }
            }
            if !found {
                lines.push(Line::raw(""));
                lines.push(Line::from(Span::styled(
                    "  No anomalies detected.",
                    Style::default().fg(C_FG3),
                )));
            }
        }
        _ => {}
    }
    lines
}
