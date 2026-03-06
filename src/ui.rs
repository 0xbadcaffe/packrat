use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, BorderType, Cell, List, ListItem, Paragraph, Row,
        Table, Tabs, Wrap,
    },
};

use crate::app::{App, Tab};
use crate::packet::FieldColor;
use crate::dynamic::EntryKind;

// ─── Color palette matching binsider ───
const C_CYAN:    Color = Color::Rgb(95, 215, 215);
const C_GREEN:   Color = Color::Rgb(135, 215, 0);
const C_YELLOW:  Color = Color::Rgb(215, 175, 0);
const C_RED:     Color = Color::Rgb(215, 95, 95);
const C_MAGENTA: Color = Color::Rgb(175, 135, 215);
const C_ORANGE:  Color = Color::Rgb(215, 135, 95);
const C_FG:      Color = Color::Rgb(212, 212, 212);
const C_FG2:     Color = Color::Rgb(154, 154, 154);
const C_FG3:     Color = Color::Rgb(90, 90, 90);
const C_BG:      Color = Color::Rgb(28, 28, 28);
const C_BG2:     Color = Color::Rgb(36, 36, 36);
const C_BG3:     Color = Color::Rgb(44, 44, 44);
const C_SEL_BG:  Color = Color::Rgb(0, 95, 95);
const C_BORDER:  Color = Color::Rgb(68, 68, 68);

fn proto_color(proto: &str) -> Color {
    match proto {
        "TCP"   => C_CYAN,
        "UDP"   => C_GREEN,
        "DNS"   => C_YELLOW,
        "HTTP"  => C_ORANGE,
        "HTTPS" => C_MAGENTA,
        "TLS"   => C_MAGENTA,
        "ARP"   => C_FG2,
        "ICMP"  => C_RED,
        "DHCP"  => C_YELLOW,
        _       => C_FG,
    }
}

fn field_color(fc: &FieldColor) -> Color {
    match fc {
        FieldColor::Cyan    => C_CYAN,
        FieldColor::Green   => C_GREEN,
        FieldColor::Yellow  => C_YELLOW,
        FieldColor::Red     => C_RED,
        FieldColor::Magenta => C_MAGENTA,
        FieldColor::Orange  => C_ORANGE,
        FieldColor::Default => C_FG,
    }
}

pub fn draw(f: &mut Frame, app: &mut App) {
    let area = f.area();

    // Overall vertical layout: titlebar | tabs | workspace | statusbar
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // title
            Constraint::Length(1), // filter
            Constraint::Length(2), // tabs
            Constraint::Min(0),    // workspace
            Constraint::Length(1), // statusbar
        ])
        .split(area);

    draw_titlebar(f, app, chunks[0]);
    draw_filterbar(f, app, chunks[1]);
    draw_tabs(f, app, chunks[2]);
    draw_workspace(f, app, chunks[3]);
    draw_statusbar(f, app, chunks[4]);
}

fn draw_titlebar(f: &mut Frame, app: &App, area: Rect) {
    let cap_str = if app.capturing { "● capturing" } else { "○ idle" };
    let cap_color = if app.capturing { C_GREEN } else { C_FG3 };
    let line = Line::from(vec![
        Span::styled(" 🐀 packrat ", Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Span::styled("─ packet analyzer  ", Style::default().fg(C_FG3)),
        Span::styled(cap_str, Style::default().fg(cap_color)),
        Span::styled(format!("  interface: eth0 (simulated)  {} pkts",
            app.packets.len()), Style::default().fg(C_FG3)),
    ]);
    let p = Paragraph::new(line).style(Style::default().bg(C_BG2));
    f.render_widget(p, area);
}

fn draw_filterbar(f: &mut Frame, app: &App, area: Rect) {
    let filter_display = if app.filter_mode {
        format!("{}_", app.filter_input)
    } else if app.filter_input.is_empty() {
        String::from("<press / to filter>")
    } else {
        app.filter_input.clone()
    };
    let filter_color = if app.filter_mode { C_CYAN } else if app.filter_input.is_empty() { C_FG3 } else { C_YELLOW };

    let line = Line::from(vec![
        Span::styled(" Display filter: ", Style::default().fg(C_FG2)),
        Span::styled(filter_display, Style::default().fg(filter_color)),
        Span::styled("  [Space] start/stop  [C] clear  [/] filter  [q] quit", Style::default().fg(C_FG3)),
    ]);
    let p = Paragraph::new(line).style(Style::default().bg(C_BG2));
    f.render_widget(p, area);
}

fn draw_tabs(f: &mut Frame, app: &App, area: Rect) {
    let titles = vec![
        Line::from(vec![Span::styled("1 ", Style::default().fg(C_YELLOW)), Span::raw("Packets")]),
        Line::from(vec![Span::styled("2 ", Style::default().fg(C_YELLOW)), Span::raw("Analysis")]),
        Line::from(vec![Span::styled("3 ", Style::default().fg(C_YELLOW)), Span::raw("Strings")]),
        Line::from(vec![Span::styled("4 ", Style::default().fg(C_YELLOW)), Span::raw("Dynamic")]),
        Line::from(vec![Span::styled("5 ", Style::default().fg(C_YELLOW)), Span::raw("Visualize")]),
    ];
    let tabs = Tabs::new(titles)
        .select(app.active_tab.index())
        .style(Style::default().fg(C_FG2).bg(C_BG2))
        .highlight_style(Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD))
        .divider("│")
        .block(Block::default().borders(Borders::BOTTOM).border_style(Style::default().fg(C_BORDER)));
    f.render_widget(tabs, area);
}

fn draw_workspace(f: &mut Frame, app: &mut App, area: Rect) {
    match app.active_tab {
        Tab::Packets   => draw_packets_tab(f, app, area),
        Tab::Analysis  => draw_analysis_tab(f, app, area),
        Tab::Strings   => draw_strings_tab(f, app, area),
        Tab::Dynamic   => draw_dynamic_tab(f, app, area),
        Tab::Visualize => draw_visualize_tab(f, app, area),
    }
}

// ─── TAB 1: PACKETS ───────────────────────────────────────────
fn draw_packets_tab(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(38), Constraint::Min(0)])
        .split(area);

    draw_packet_list(f, app, chunks[0]);

    let bottom = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(42), Constraint::Min(0)])
        .split(chunks[1]);

    draw_protocol_tree(f, app, bottom[0]);
    draw_hex_dump(f, app, bottom[1]);
}

fn draw_packet_list(f: &mut Frame, app: &App, area: Rect) {
    if app.picking_iface || app.packets.is_empty() {
        let rat = vec![
            Line::raw(""),
            Line::raw(""),
            Line::from(vec![
                Span::styled("        ", Style::default().fg(Color::LightMagenta).add_modifier(Modifier::BOLD)),
                Span::styled("        ", Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD)),
                Span::styled("        ", Style::default().fg(Color::LightCyan).add_modifier(Modifier::BOLD)),
                Span::styled(" __    ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::styled("        ", Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD)),
                Span::styled("        ", Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD)),
                Span::styled("  __   ", Style::default().fg(Color::LightBlue).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled("______  ", Style::default().fg(Color::LightMagenta).add_modifier(Modifier::BOLD)),
                Span::styled("_____   ", Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD)),
                Span::styled("  ____  ", Style::default().fg(Color::LightCyan).add_modifier(Modifier::BOLD)),
                Span::styled("|  | __", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::styled("_______ ", Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD)),
                Span::styled("_____   ", Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD)),
                Span::styled("_/  |_ ", Style::default().fg(Color::LightBlue).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled("\\____ \\ ", Style::default().fg(Color::LightMagenta).add_modifier(Modifier::BOLD)),
                Span::styled("\\__  \\  ", Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD)),
                Span::styled("_/ ___\\ ", Style::default().fg(Color::LightCyan).add_modifier(Modifier::BOLD)),
                Span::styled("|  |/ /", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::styled("\\_  __ \\", Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD)),
                Span::styled("\\__  \\  ", Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD)),
                Span::styled("\\   __\\", Style::default().fg(Color::LightBlue).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled("|  |_> >", Style::default().fg(Color::LightMagenta).add_modifier(Modifier::BOLD)),
                Span::styled(" / __ \\_", Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD)),
                Span::styled("\\  \\___ ", Style::default().fg(Color::LightCyan).add_modifier(Modifier::BOLD)),
                Span::styled("|    < ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::styled(" |  | \\/", Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD)),
                Span::styled(" / __ \\_", Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD)),
                Span::styled(" |  |  ", Style::default().fg(Color::LightBlue).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled("|   __/ ", Style::default().fg(Color::LightMagenta).add_modifier(Modifier::BOLD)),
                Span::styled("(____  /", Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD)),
                Span::styled(" \\___  >", Style::default().fg(Color::LightCyan).add_modifier(Modifier::BOLD)),
                Span::styled("|__|_ \\", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::styled(" |__|   ", Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD)),
                Span::styled("(____  /", Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD)),
                Span::styled(" |__|  ", Style::default().fg(Color::LightBlue).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled("|__|    ", Style::default().fg(Color::LightMagenta).add_modifier(Modifier::BOLD)),
                Span::styled("     \\/ ", Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD)),
                Span::styled("     \\/ ", Style::default().fg(Color::LightCyan).add_modifier(Modifier::BOLD)),
                Span::styled("     \\/", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::styled("        ", Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD)),
                Span::styled("     \\/ ", Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD)),
                Span::styled("       ", Style::default().fg(Color::LightBlue).add_modifier(Modifier::BOLD)),
            ]),
            Line::raw(""),
            Line::from(vec![Span::styled("     packet analyzer  v0.1.0", Style::default().fg(C_FG3))]),
            Line::raw(""),
        ];
        // Build iface picker lines separately so we can append them
        let mut lines = rat;
        if app.picking_iface {
            lines.push(Line::from(vec![
                Span::styled("  Select network interface", Style::default().fg(C_FG2)),
            ]));
            lines.push(Line::raw("  ") );
            for (i, iface) in app.iface_list.iter().enumerate() {
                let is_sel = i == app.iface_sel;
                let marker = if is_sel { " ▶ " } else { "   " };
                let (bg, fg) = if is_sel {
                    (C_SEL_BG, Color::White)
                } else {
                    (C_BG, C_FG2)
                };
                let tag = if iface == "simulated" { "  (built-in)" } else { "" };
                lines.push(Line::from(vec![
                    Span::styled(format!("{}{}{}", marker, iface, tag),
                        Style::default().fg(fg).bg(bg).add_modifier(if is_sel { Modifier::BOLD } else { Modifier::empty() })),
                ]));
            }
            lines.push(Line::raw(""));
            lines.push(Line::from(vec![
                Span::styled("  j/k", Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
                Span::styled(" navigate   ", Style::default().fg(C_FG2)),
                Span::styled("Space/Enter", Style::default().fg(C_GREEN).add_modifier(Modifier::BOLD)),
                Span::styled(" start capture   ", Style::default().fg(C_FG2)),
                Span::styled("q", Style::default().fg(C_RED).add_modifier(Modifier::BOLD)),
                Span::styled(" quit", Style::default().fg(C_FG2)),
            ]));
        } else {
            lines.push(Line::from(vec![Span::styled("     Press ", Style::default().fg(C_FG2)), Span::styled("Space", Style::default().fg(C_GREEN).add_modifier(Modifier::BOLD)), Span::styled(" to start capture", Style::default().fg(C_FG2))]));
            lines.push(Line::from(vec![Span::styled("     Press ", Style::default().fg(C_FG2)), Span::styled("q",     Style::default().fg(C_RED).add_modifier(Modifier::BOLD)),   Span::styled(" to quit", Style::default().fg(C_FG2))]));
        }
        let rat = lines;
        let splash = Paragraph::new(rat)
            .block(Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Plain)
                .border_style(Style::default().fg(C_BORDER))
                .title(Span::styled(" 🐀 packrat ", Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD))))
            .style(Style::default().bg(C_BG));
        f.render_widget(splash, area);
        return;
    }

    let header = Row::new(vec![
        Cell::from("No.").style(Style::default().fg(C_FG2)),
        Cell::from("Time").style(Style::default().fg(C_FG2)),
        Cell::from("Source").style(Style::default().fg(C_FG2)),
        Cell::from("Destination").style(Style::default().fg(C_FG2)),
        Cell::from("Protocol").style(Style::default().fg(C_FG2)),
        Cell::from("Len").style(Style::default().fg(C_FG2)),
        Cell::from("Info").style(Style::default().fg(C_FG2)),
    ]).style(Style::default().bg(C_BG3))
      .height(1);

    let visible_h = area.height.saturating_sub(3) as usize;
    let total = app.filtered.len();
    let sel = app.selected.unwrap_or(0);
    let offset = if sel >= visible_h { sel - visible_h + 1 } else { 0 };

    let rows: Vec<Row> = app.filtered.iter().enumerate()
        .skip(offset).take(visible_h)
        .filter_map(|(fi, &pi)| app.packets.get(pi).map(|p| (fi, p)))
        .map(|(fi, p)| {
            let selected = app.selected == Some(fi);
            let bg = if selected { C_SEL_BG } else { C_BG };
            let fg = if selected { Color::White } else { C_FG };
            let proto_fg = if selected { Color::White } else { proto_color(&p.protocol) };

            Row::new(vec![
                Cell::from(p.no.to_string()).style(Style::default().fg(C_FG3).bg(bg)),
                Cell::from(format!("{:.4}", p.timestamp)).style(Style::default().fg(C_FG2).bg(bg)),
                Cell::from(p.src.clone()).style(Style::default().fg(fg).bg(bg)),
                Cell::from(p.dst.clone()).style(Style::default().fg(fg).bg(bg)),
                Cell::from(p.protocol.clone()).style(Style::default().fg(proto_fg).bg(bg).add_modifier(Modifier::BOLD)),
                Cell::from(p.length.to_string()).style(Style::default().fg(C_FG2).bg(bg)),
                Cell::from(truncate(&p.info, 60)).style(Style::default().fg(C_FG2).bg(bg)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(6),
        Constraint::Length(9),
        Constraint::Length(15),
        Constraint::Length(15),
        Constraint::Length(8),
        Constraint::Length(5),
        Constraint::Min(0),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(C_BORDER))
            .title(Span::styled(
                format!(" Packets [{}/{}] ", app.filtered.len(), app.packets.len()),
                Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD)
            )))
        .style(Style::default().bg(C_BG));

    f.render_widget(table, area);
}

fn draw_protocol_tree(f: &mut Frame, app: &mut App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(Style::default().fg(C_BORDER))
        .title(Span::styled(" Protocol Tree ", Style::default().fg(C_GREEN).add_modifier(Modifier::BOLD)))
        .style(Style::default().bg(C_BG));

    if let Some(pkt) = app.selected_packet() {
        let sections = pkt.build_tree();
        let mut items: Vec<ListItem> = Vec::new();

        for sec in &sections {
            // Section header
            items.push(ListItem::new(Line::from(vec![
                Span::styled("▼ ", Style::default().fg(C_YELLOW)),
                Span::styled(truncate(&sec.title, (area.width as usize).saturating_sub(6)), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            ])));

            if sec.expanded {
                for field in &sec.fields {
                    let key_w = 20usize;
                    let key = pad_right(&field.key, key_w);
                    items.push(ListItem::new(Line::from(vec![
                        Span::styled("  ", Style::default()),
                        Span::styled(key, Style::default().fg(C_FG2)),
                        Span::styled(" ", Style::default()),
                        Span::styled(field.val.clone(), Style::default().fg(field_color(&field.color))),
                    ])));
                }
            }
        }

        let list = List::new(items)
            .block(block)
            .style(Style::default().bg(C_BG));
        f.render_widget(list, area);
    } else {
        let p = Paragraph::new("No packet selected.\n\nPress Space to start capture,\nthen j/k to navigate.")
            .style(Style::default().fg(C_FG3))
            .block(block);
        f.render_widget(p, area);
    }
}

fn draw_hex_dump(f: &mut Frame, app: &mut App, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(Style::default().fg(C_BORDER))
        .title(Span::styled(" Hex Dump ", Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)))
        .style(Style::default().bg(C_BG));

    if let Some(pkt) = app.selected_packet() {
        let bytes = &pkt.bytes;
        let bytes_per_row = 16usize;
        let inner_w = area.width.saturating_sub(2) as usize;
        let mut lines: Vec<Line> = Vec::new();

        for (row_i, chunk) in bytes.chunks(bytes_per_row).enumerate() {
            let offset = row_i * bytes_per_row;
            let mut spans: Vec<Span> = Vec::new();

            // Offset
            spans.push(Span::styled(
                format!("{:04x}  ", offset),
                Style::default().fg(C_FG3),
            ));

            // Hex bytes
            for (i, &b) in chunk.iter().enumerate() {
                let color = if b == 0 { C_FG3 }
                    else if b >= 32 && b < 127 { C_GREEN }
                    else { C_CYAN };
                spans.push(Span::styled(format!("{:02x}", b), Style::default().fg(color)));
                spans.push(Span::raw(" "));
                if i == 7 { spans.push(Span::raw(" ")); }
            }
            // Pad
            for i in chunk.len()..bytes_per_row {
                spans.push(Span::raw("   "));
                if i == 7 { spans.push(Span::raw(" ")); }
            }
            spans.push(Span::raw(" │ "));

            // ASCII
            for &b in chunk.iter() {
                let (ch, color) = if b >= 32 && b < 127 {
                    (b as char, C_GREEN)
                } else {
                    ('.', C_FG3)
                };
                spans.push(Span::styled(ch.to_string(), Style::default().fg(color)));
            }

            lines.push(Line::from(spans));
        }

        let info_line = Line::from(vec![
            Span::styled(format!(" {} bytes │ {} rows ", pkt.length, lines.len()), Style::default().fg(C_FG3)),
        ]);

        let mut all_lines = vec![info_line, Line::raw("")];
        all_lines.extend(lines);

        let p = Paragraph::new(all_lines)
            .block(block)
            .style(Style::default().bg(C_BG));
        f.render_widget(p, area);
    } else {
        let p = Paragraph::new("No packet selected.")
            .style(Style::default().fg(C_FG3))
            .block(block);
        f.render_widget(p, area);
    }
}

// ─── TAB 2: ANALYSIS ──────────────────────────────────────────
fn draw_analysis_tab(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(22), Constraint::Min(0)])
        .split(area);

    // Left nav
    let sections = ["General Info", "Protocol Stats", "Top Talkers", "Conversations", "IP Endpoints", "Port Summary"];
    let items: Vec<ListItem> = sections.iter().enumerate().map(|(i, &name)| {
        let style = if i == app.analysis_section {
            Style::default().fg(Color::White).bg(C_SEL_BG)
        } else {
            Style::default().fg(C_FG2)
        };
        ListItem::new(Line::from(vec![
            Span::styled(format!(" {} ", ["◈","⬡","⊞","⊡","◉","≡"][i]), Style::default().fg(C_YELLOW)),
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
    f.render_widget(list, chunks[0]);

    // Right content
    let title = sections[app.analysis_section];
    let content = build_analysis_content(app, app.analysis_section);
    let p = Paragraph::new(content)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(C_BORDER))
            .title(Span::styled(format!(" {} ", title), Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD))))
        .style(Style::default().bg(C_BG))
        .wrap(Wrap { trim: false });
    f.render_widget(p, chunks[1]);
}

fn build_analysis_content<'a>(app: &App, section: usize) -> Vec<Line<'a>> {
    let mut lines: Vec<Line> = Vec::new();
    match section {
        0 => { // General
            let dur = app.packets.last().map(|p| p.timestamp).unwrap_or(0.0);
            let avg = if app.packets.is_empty() { 0 } else { app.total_bytes as usize / app.packets.len() };
            let rows: Vec<(&str, String)> = vec![
                ("Total Packets",     app.packets.len().to_string()),
                ("Total Bytes",       fmt_bytes(app.total_bytes)),
                ("Capture Duration",  format!("{:.3}s", dur)),
                ("Avg Packet Size",   format!("{} bytes", avg)),
                ("Packets/sec",       app.current_rate().to_string()),
                ("Interface",         "eth0 (simulated)".into()),
                ("Snaplen",           "65535".into()),
                ("Link Type",         "Ethernet".into()),
            ];
            lines.push(Line::raw(""));
            for (k, v) in rows {
                lines.push(Line::from(vec![
                    Span::styled(format!("  {:<22}", k), Style::default().fg(C_FG2)),
                    Span::styled(v, Style::default().fg(C_CYAN)),
                ]));
            }
        }
        1 => { // Protocol stats
            let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
            for p in &app.packets { *counts.entry(p.protocol.as_str()).or_default() += 1; }
            let total = app.packets.len().max(1);
            let mut sorted: Vec<_> = counts.iter().collect();
            sorted.sort_by(|a,b| b.1.cmp(a.1));

            lines.push(Line::raw(""));
            lines.push(Line::from(vec![
                Span::styled(format!("  {:<10} {:<8} {:<7} {}", "Protocol", "Count", "%", "Distribution"),
                    Style::default().fg(C_FG2))
            ]));
            lines.push(Line::raw("  " .to_string() + &"─".repeat(60)));

            for (proto, count) in &sorted {
                let pct = (**count as f64 / total as f64) * 100.0;
                let bar_w = (pct / 100.0 * 30.0) as usize;
                let bar = "█".repeat(bar_w);
                lines.push(Line::from(vec![
                    Span::styled(format!("  {:<10}", proto), Style::default().fg(proto_color(proto))),
                    Span::styled(format!("{:<8}", count), Style::default().fg(C_CYAN)),
                    Span::styled(format!("{:<7.1}%", pct), Style::default().fg(C_FG2)),
                    Span::styled(bar, Style::default().fg(C_CYAN)),
                ]));
            }
        }
        2 => { // Top talkers
            let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
            for p in &app.packets {
                *counts.entry(p.src.clone()).or_default() += 1;
            }
            let mut sorted: Vec<_> = counts.iter().collect();
            sorted.sort_by(|a,b| b.1.cmp(a.1));
            let max = sorted.first().map(|(_,c)| *c).unwrap_or(&1);

            lines.push(Line::raw(""));
            lines.push(Line::from(vec![
                Span::styled(format!("  {:<18} {:<8} {}", "Source IP", "Pkts", "Distribution"),
                    Style::default().fg(C_FG2))
            ]));
            lines.push(Line::raw("  ".to_string() + &"─".repeat(60)));
            for (ip, count) in sorted.iter().take(15) {
                let bar_w = (**count as f64 / *max as f64 * 25.0) as usize;
                lines.push(Line::from(vec![
                    Span::styled(format!("  {:<18}", ip), Style::default().fg(C_CYAN)),
                    Span::styled(format!("{:<8}", count), Style::default().fg(C_FG2)),
                    Span::styled("█".repeat(bar_w), Style::default().fg(C_GREEN)),
                ]));
            }
        }
        3 => { // Conversations
            let mut convs: std::collections::HashMap<String, (usize,u64)> = std::collections::HashMap::new();
            for p in &app.packets {
                let mut pair = vec![p.src.as_str(), p.dst.as_str()];
                pair.sort();
                let key = format!("{} ↔ {} [{}]", pair[0], pair[1], p.protocol);
                let e = convs.entry(key).or_insert((0, 0));
                e.0 += 1; e.1 += p.length as u64;
            }
            let mut sorted: Vec<_> = convs.iter().collect();
            sorted.sort_by(|a,b| b.1.0.cmp(&a.1.0));

            lines.push(Line::raw(""));
            lines.push(Line::from(vec![
                Span::styled(format!("  {:<38} {:<8} {}", "Conversation", "Pkts", "Bytes"),
                    Style::default().fg(C_FG2))
            ]));
            lines.push(Line::raw("  ".to_string() + &"─".repeat(60)));
            for (conv, (pkts, bytes)) in sorted.iter().take(20) {
                lines.push(Line::from(vec![
                    Span::styled(format!("  {:<38}", truncate(conv, 38)), Style::default().fg(C_FG)),
                    Span::styled(format!("{:<8}", pkts), Style::default().fg(C_CYAN)),
                    Span::styled(fmt_bytes(*bytes), Style::default().fg(C_GREEN)),
                ]));
            }
        }
        4 => { // IP Endpoints
            let mut eps: std::collections::HashMap<String, (usize,u64)> = std::collections::HashMap::new();
            for p in &app.packets {
                let e = eps.entry(p.src.clone()).or_insert((0,0));
                e.0 += 1; e.1 += p.length as u64;
            }
            let mut sorted: Vec<_> = eps.iter().collect();
            sorted.sort_by(|a,b| b.1.0.cmp(&a.1.0));

            lines.push(Line::raw(""));
            lines.push(Line::from(vec![
                Span::styled(format!("  {:<18} {:<8} {}", "IP Address", "Pkts", "Bytes"),
                    Style::default().fg(C_FG2))
            ]));
            lines.push(Line::raw("  ".to_string() + &"─".repeat(40)));
            for (ip, (pkts, bytes)) in sorted.iter().take(20) {
                lines.push(Line::from(vec![
                    Span::styled(format!("  {:<18}", ip), Style::default().fg(C_CYAN)),
                    Span::styled(format!("{:<8}", pkts), Style::default().fg(C_FG2)),
                    Span::styled(fmt_bytes(*bytes), Style::default().fg(C_GREEN)),
                ]));
            }
        }
        5 => { // Port summary
            let port_names = |p: u16| -> &str {
                match p { 80=>"HTTP",443=>"HTTPS",53=>"DNS",22=>"SSH",25=>"SMTP",
                           3306=>"MySQL",5432=>"PostgreSQL",6379=>"Redis",
                           8080=>"HTTP-Alt",9200=>"Elasticsearch",_=>"Unknown" }
            };
            let mut ports: std::collections::HashMap<u16, usize> = std::collections::HashMap::new();
            for p in &app.packets {
                if let Some(dp) = p.dst_port { *ports.entry(dp).or_default() += 1; }
            }
            let mut sorted: Vec<_> = ports.iter().collect();
            sorted.sort_by(|a,b| b.1.cmp(a.1));

            lines.push(Line::raw(""));
            lines.push(Line::from(vec![
                Span::styled(format!("  {:<8} {:<16} {}", "Port", "Service", "Count"),
                    Style::default().fg(C_FG2))
            ]));
            lines.push(Line::raw("  ".to_string() + &"─".repeat(35)));
            for (port, count) in sorted.iter().take(20) {
                lines.push(Line::from(vec![
                    Span::styled(format!("  {:<8}", port), Style::default().fg(C_YELLOW)),
                    Span::styled(format!("{:<16}", port_names(**port)), Style::default().fg(C_FG2)),
                    Span::styled(count.to_string(), Style::default().fg(C_CYAN)),
                ]));
            }
        }
        _ => {}
    }
    lines
}

// ─── TAB 3: STRINGS ───────────────────────────────────────────
fn draw_strings_tab(f: &mut Frame, app: &mut App, area: Rect) {
    let all = crate::strings::all_strings();
    let filt: Vec<_> = if app.strings_filter.is_empty() {
        all.iter().collect()
    } else {
        let f = app.strings_filter.to_lowercase();
        all.iter().filter(|s| s.value.to_lowercase().contains(&f) || s.kind.label().contains(&f)).collect()
    };

    let header = Row::new(vec![
        Cell::from("Offset").style(Style::default().fg(C_FG2)),
        Cell::from("Len").style(Style::default().fg(C_FG2)),
        Cell::from("String").style(Style::default().fg(C_FG2)),
        Cell::from("Type").style(Style::default().fg(C_FG2)),
    ]).style(Style::default().bg(C_BG3)).height(1);

    let rows: Vec<Row> = filt.iter().map(|s| {
        let (val_color, type_color) = if s.kind.is_sensitive() {
            (C_RED, C_RED)
        } else {
            (C_GREEN, C_FG3)
        };
        Row::new(vec![
            Cell::from(s.offset.clone()).style(Style::default().fg(C_FG3)),
            Cell::from(s.length.to_string()).style(Style::default().fg(C_YELLOW)),
            Cell::from(s.value.clone()).style(Style::default().fg(val_color)),
            Cell::from(s.kind.label()).style(Style::default().fg(type_color)),
        ])
    }).collect();

    let widths = [
        Constraint::Length(12),
        Constraint::Length(6),
        Constraint::Min(0),
        Constraint::Length(14),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(C_BORDER))
            .title(Span::styled(
                format!(" Strings [{} shown] — / to filter ", filt.len()),
                Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD),
            )))
        .style(Style::default().bg(C_BG));

    f.render_widget(table, area);
}

// ─── TAB 4: DYNAMIC ───────────────────────────────────────────
fn draw_dynamic_tab(f: &mut Frame, app: &mut App, area: Rect) {
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
            .title(Span::styled(" Dynamic Trace — syscalls / signals / network ", Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD))))
        .style(Style::default().bg(C_BG));
    f.render_widget(list, area);
}

// ─── TAB 5: VISUALIZE ─────────────────────────────────────────
fn draw_visualize_tab(f: &mut Frame, app: &mut App, area: Rect) {
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

    draw_viz_proto(f, app, top[0]);
    draw_viz_spark(f, app, top[1]);
    draw_viz_top_ips(f, app, bot[0]);
    draw_viz_geo(f, app, bot[1]);
}

fn draw_viz_proto(f: &mut Frame, app: &App, area: Rect) {
    let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for p in &app.packets { *counts.entry(p.protocol.as_str()).or_default() += 1; }
    let total = app.packets.len().max(1);
    let mut sorted: Vec<_> = counts.iter().collect();
    sorted.sort_by(|a,b| b.1.cmp(a.1));

    let mut lines: Vec<Line> = vec![Line::raw("")];
    for (proto, count) in sorted.iter().take(9) {
        let pct = (**count as f64 / total as f64) * 100.0;
        let bar_w = (pct / 100.0 * 20.0) as usize;
        lines.push(Line::from(vec![
            Span::styled("█".repeat(bar_w), Style::default().fg(proto_color(proto))),
            Span::styled(format!(" {:<6} {:.1}% ({})", proto, pct, count), Style::default().fg(C_FG2)),
        ]));
    }

    let p = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(C_BORDER))
            .title(Span::styled(" Protocol Distribution ", Style::default().fg(C_CYAN))))
        .style(Style::default().bg(C_BG));
    f.render_widget(p, area);
}

fn draw_viz_spark(f: &mut Frame, app: &App, area: Rect) {
    let w = area.width.saturating_sub(4) as usize;
    let data = &app.rate_history;
    let max = *data.iter().max().unwrap_or(&1);
    let max = max.max(1);
    let inner_h = area.height.saturating_sub(3) as usize;

    // Build a simple bar chart using block chars
    let bars = ['▁','▂','▃','▄','▅','▆','▇','█'];
    let samples: Vec<u32> = if data.len() > w {
        data[data.len()-w..].to_vec()
    } else {
        let mut v = vec![0u32; w - data.len()];
        v.extend_from_slice(data);
        v
    };

    let spark_line: String = samples.iter().map(|&v| {
        let idx = ((v as f64 / max as f64) * 7.0) as usize;
        bars[idx.min(7)]
    }).collect();

    let mut lines: Vec<Line> = vec![
        Line::raw(""),
        Line::from(vec![Span::styled(format!(" max: {}/s", max), Style::default().fg(C_FG3))]),
        Line::raw(""),
        Line::from(vec![Span::styled(spark_line, Style::default().fg(C_CYAN))]),
        Line::raw(""),
        Line::from(vec![Span::styled(format!(" current: {}/s", app.current_rate()), Style::default().fg(C_GREEN))]),
    ];

    let p = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(C_BORDER))
            .title(Span::styled(" Traffic Rate (pkts/s) ", Style::default().fg(C_CYAN))))
        .style(Style::default().bg(C_BG));
    f.render_widget(p, area);
}

fn draw_viz_top_ips(f: &mut Frame, app: &App, area: Rect) {
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for p in &app.packets { *counts.entry(p.src.clone()).or_default() += 1; }
    let mut sorted: Vec<_> = counts.iter().collect();
    sorted.sort_by(|a,b| b.1.cmp(a.1));
    let max = sorted.first().map(|(_,c)| *c).unwrap_or(&1);

    let mut lines: Vec<Line> = vec![Line::raw("")];
    for (ip, count) in sorted.iter().take(10) {
        let bar_w = (**count as f64 / *max as f64 * 18.0) as usize;
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

fn draw_viz_geo(f: &mut Frame, app: &App, area: Rect) {
    const GEO: &[(&str, &str, &str)] = &[
        ("8.8.8.8",          "🇺🇸", "Mountain View, US"),
        ("1.1.1.1",          "🇦🇺", "Sydney, AU"),
        ("151.101.64.81",    "🇺🇸", "San Francisco, US"),
        ("142.250.80.46",    "🇺🇸", "Kansas City, US"),
        ("104.21.55.33",     "🇺🇸", "San Jose, US"),
        ("172.217.14.206",   "🇺🇸", "Mountain View, US"),
        ("13.107.42.14",     "🇮🇪", "Dublin, IE"),
        ("52.84.17.200",     "🇺🇸", "Ashburn, US"),
        ("34.120.208.123",   "🇧🇪", "Brussels, BE"),
        ("185.125.190.17",   "🇩🇪", "Frankfurt, DE"),
    ];

    let mut remote_counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for p in &app.packets {
        if GEO.iter().any(|(ip,_,_)| *ip == p.dst.as_str()) {
            *remote_counts.entry(p.dst.as_str()).or_default() += 1;
        }
    }
    let mut sorted: Vec<_> = remote_counts.iter().collect();
    sorted.sort_by(|a,b| b.1.cmp(a.1));

    let mut lines: Vec<Line> = vec![Line::raw("")];
    for (ip, count) in sorted.iter().take(10) {
        if let Some((_,flag,loc)) = GEO.iter().find(|(gip,_,_)| gip == *ip) {
            lines.push(Line::from(vec![
                Span::styled(format!(" {}", flag), Style::default()),
                Span::styled(format!(" {:<16}", ip), Style::default().fg(C_CYAN)),
                Span::styled(format!("{:<20}", loc), Style::default().fg(C_FG2)),
                Span::styled(format!(" {}p", count), Style::default().fg(C_YELLOW)),
            ]));
        }
    }

    let p = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(C_BORDER))
            .title(Span::styled(" Remote Endpoints (Geo) ", Style::default().fg(C_CYAN))))
        .style(Style::default().bg(C_BG));
    f.render_widget(p, area);
}

// ─── STATUS BAR ───────────────────────────────────────────────
fn draw_statusbar(f: &mut Frame, app: &App, area: Rect) {
    let cap_indicator = if app.capturing {
        Span::styled("● LIVE ", Style::default().fg(C_GREEN).add_modifier(Modifier::BOLD))
    } else {
        Span::styled("○ IDLE ", Style::default().fg(C_FG3))
    };

    let line = Line::from(vec![
        Span::styled(" ", Style::default()),
        cap_indicator,
        Span::styled("│ ", Style::default().fg(C_FG3)),
        Span::styled(format!("pkts:{} ", app.filtered.len()), Style::default().fg(C_FG2)),
        Span::styled(format!("total:{} ", app.packets.len()), Style::default().fg(C_FG2)),
        Span::styled(format!("bytes:{} ", fmt_bytes(app.total_bytes)), Style::default().fg(C_FG2)),
        Span::styled(format!("rate:{}/s ", app.current_rate()), Style::default().fg(C_GREEN)),
        Span::styled("│ ", Style::default().fg(C_FG3)),
        Span::styled("j/k:nav  g/G:top/bot  Space:cap  /:filter  1-5:tabs  q:quit",
            Style::default().fg(C_FG3)),
    ]);
    let p = Paragraph::new(line).style(Style::default().bg(C_BG2));
    f.render_widget(p, area);
}

// ─── HELPERS ──────────────────────────────────────────────────
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() }
    else { format!("{}…", &s[..max.saturating_sub(1)]) }
}

fn pad_right(s: &str, width: usize) -> String {
    if s.len() >= width { s[..width].to_string() }
    else { format!("{:<width$}", s, width = width) }
}

fn fmt_bytes(b: u64) -> String {
    if b < 1024 { format!("{}B", b) }
    else if b < 1_048_576 { format!("{:.1}K", b as f64 / 1024.0) }
    else { format!("{:.1}M", b as f64 / 1_048_576.0) }
}
