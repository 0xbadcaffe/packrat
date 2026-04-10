use std::collections::HashMap;

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Cell, Paragraph, Row, Table},
};

use crate::app::App;
use crate::ui::theme::*;

const MIN_LEN: usize = 4;

// ─── Data model ──────────────────────────────────────────────────────────────

/// A string extracted from a packet payload.
pub struct ExtractedString {
    /// Formatted "pkt_no:hex_offset" label.
    pub offset_label: String,
    /// The originating packet frame number (for lookup).
    pub pkt_no: u64,
    pub length:   usize,
    pub entropy:  f64,
    pub value:    String,
    pub kind:     &'static str,
    pub sensitive: bool,
}

// ─── Shannon entropy ─────────────────────────────────────────────────────────

fn shannon_entropy(s: &str) -> f64 {
    if s.len() < 2 { return 0.0; }
    let len = s.len() as f64;
    let mut counts = [0u32; 256];
    for b in s.bytes() { counts[b as usize] += 1; }
    counts.iter()
        .filter(|&&c| c > 0)
        .map(|&c| { let p = c as f64 / len; -p * p.log2() })
        .sum()
}

// ─── Classification dictionary ────────────────────────────────────────────────

fn classify(s: &str) -> (&'static str, bool) {
    let l = s.to_lowercase();

    // Security-sensitive
    if l.contains("password") || l.contains("passwd") || l.contains("secret")
        || l.contains("shadow") || l.contains("credential") || l.contains("private_key")
    { return ("sensitive", true); }
    if l.contains("begin rsa") || l.contains("begin private") || l.contains("ssh-rsa")
        || l.contains("api_key") || l.contains("api-key") || l.contains("token=")
    { return ("key", true); }
    if l.starts_with("exec(") || l.contains("/bin/sh") || l.contains("/bin/bash")
        || l.contains("system(") || l.contains("cmd.exe") || l.contains("powershell")
    { return ("shell", true); }

    // OT / ICS / Industrial
    if l.contains("modbus") || l.contains("bacnet") || l.contains("profibus")
        || l.contains("profinet") || l.contains("ethernetip") || l.contains("coap")
        || l.contains("opcua") || l.contains("opc-ua") || l.contains("dnp3")
    { return ("ot-proto", false); }
    if l.contains("holding register") || l.contains("coil") || l.contains("discrete input")
        || l.contains("function code") || l.contains("unit id") || l.contains("transaction id")
    { return ("ot-field", false); }
    if l.contains("plc") || l.contains(" hmi") || l.contains("scada") || l.contains(" rtu")
        || l.contains(" dcs") || l.contains("outstation") || l.contains("setpoint")
    { return ("ot-sys", false); }
    if l.contains("siemens") || l.contains("schneider") || l.contains("rockwell")
        || l.contains("omron") || l.contains("mitsubishi") || l.contains("honeywell")
        || l.contains("emerson") || l.contains("abb")
    { return ("ot-vendor", false); }
    if l.contains("sensors/") || l.contains("actuators/") || l.contains("plant/")
        || l.contains("connack") || l.contains("publish") || l.contains("subscribe")
    { return ("mqtt", false); }

    // Network / application
    if l.starts_with("get ") || l.starts_with("post ") || l.starts_with("put ")
        || l.starts_with("delete ") || l.starts_with("http/")
    { return ("http", false); }
    if l.starts_with("content-") || l.starts_with("authorization:") || l.starts_with("host:")
        || l.starts_with("user-agent:") || l.starts_with("accept") || l.starts_with("cookie:")
    { return ("http-hdr", false); }
    if l.starts_with("select ") || l.starts_with("insert ") || l.starts_with("update ")
        || l.starts_with("delete from") || l.starts_with("drop ")
    { return ("sql", false); }
    if l.starts_with("eyj") { return ("jwt", false); }

    if s.len() >= 16
        && s.chars().all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=')
        && s.ends_with('=')
    { return ("base64", false); }

    if l.starts_with('/') || l.contains("c:\\") || l.contains("/etc/") || l.contains("/proc/")
        || l.contains(".conf") || l.contains(".dll") || l.contains(".so")
    { return ("path", false); }

    if s.len() <= 15
        && s.chars().all(|c| c.is_ascii_digit() || c == '.')
        && s.matches('.').count() == 3
    { return ("ip", false); }

    if s.len() <= 64
        && s.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-')
        && s.contains('.')
    { return ("domain", false); }

    if l.contains("error") || l.contains("fail") || l.contains("exception")
        || l.contains("timeout") || l.contains("refused") || l.contains("denied")
    { return ("error", false); }

    if l.contains("version") || l.contains("firmware") || l.contains("build")
        || l.contains("release") || l.contains("copyright")
    { return ("version", false); }

    ("ascii", false)
}

// ─── Extraction ───────────────────────────────────────────────────────────────

pub fn extract_strings(app: &App) -> Vec<ExtractedString> {
    let mut out = Vec::new();
    for pkt in app.packets.iter().take(500) {
        let bytes = &pkt.bytes;
        let mut run_start = 0;
        let mut in_run = false;
        for (i, &b) in bytes.iter().enumerate() {
            if b >= 32 && b < 127 {
                if !in_run { run_start = i; in_run = true; }
            } else if in_run {
                in_run = false;
                push_string(&mut out, pkt.no, run_start, &bytes[run_start..i]);
            }
        }
        if in_run {
            push_string(&mut out, pkt.no, run_start, &bytes[run_start..]);
        }
    }
    out
}

fn push_string(out: &mut Vec<ExtractedString>, pkt_no: u64, offset: usize, raw: &[u8]) {
    if raw.len() < MIN_LEN { return; }
    let val = String::from_utf8_lossy(raw).into_owned();
    let (kind, sensitive) = classify(&val);
    let entropy = shannon_entropy(&val);
    out.push(ExtractedString {
        offset_label: format!("{}:{:04x}", pkt_no, offset),
        pkt_no,
        length: val.len(),
        entropy,
        value: val,
        kind,
        sensitive,
    });
}

// ─── Colors ───────────────────────────────────────────────────────────────────

pub fn entropy_color(e: f64) -> ratatui::style::Color {
    if e < 2.5 { C_GREEN } else if e < 4.5 { C_YELLOW } else { C_RED }
}

pub fn kind_color(kind: &str, sensitive: bool) -> ratatui::style::Color {
    if sensitive { return C_RED; }
    match kind {
        "sensitive" | "key" | "shell"                      => C_RED,
        "http" | "http-hdr"                                => C_ORANGE,
        "sql"                                              => C_YELLOW,
        "jwt" | "base64"                                   => C_MAGENTA,
        "ot-proto" | "ot-field" | "ot-sys"
        | "ot-vendor" | "mqtt"                             => C_CYAN,
        "path"                                             => C_FG2,
        "domain" | "ip"                                    => C_GREEN,
        "error"                                            => C_RED,
        "version"                                          => C_FG2,
        _                                                  => C_FG,
    }
}

// ─── Draw ─────────────────────────────────────────────────────────────────────

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let all = extract_strings(app);

    // Apply search filter
    let filt: Vec<&ExtractedString> = if app.strings_filter.is_empty() {
        all.iter().collect()
    } else {
        let q = app.strings_filter.to_lowercase();
        all.iter()
            .filter(|s| s.value.to_lowercase().contains(&q) || s.kind.contains(q.as_str()))
            .collect()
    };

    // Stats
    let sensitive_n = filt.iter().filter(|s| s.sensitive).count();
    let avg_entr = if filt.is_empty() { 0.0 } else {
        filt.iter().map(|s| s.entropy).sum::<f64>() / filt.len() as f64
    };
    let mut cat_counts: HashMap<&str, usize> = HashMap::new();
    for s in &filt { *cat_counts.entry(s.kind).or_insert(0) += 1; }
    let top_cat = cat_counts.iter().max_by_key(|(_, c)| *c).map(|(k, _)| *k).unwrap_or("-");

    let outer_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(Style::default().fg(C_BORDER))
        .title(Span::styled(
            format!(" Strings [{} found · {} sensitive · avg entropy {:.1} · top: {}] ",
                filt.len(), sensitive_n, avg_entr, top_cat),
            Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD),
        ));

    let inner = outer_block.inner(area);
    f.render_widget(outer_block, area);

    let search_height = if app.strings_search_active || !app.strings_filter.is_empty() { 1u16 } else { 0 };

    let show_detail = !app.capturing && app.strings_selected.is_some();

    // ── Vertical layout ──
    // [stats bar] [optional search] [list] [optional detail panel]
    let (list_pct, detail_pct) = if show_detail { (35, 65) } else { (100, 0) };

    let vchunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),                       // stats bar
            Constraint::Length(search_height),           // search (collapsible)
            Constraint::Percentage(list_pct),            // string list
            Constraint::Percentage(detail_pct),          // detail (tree + hex)
        ])
        .split(inner);

    // ── Stats bar ──
    let nav_hint = if !app.capturing && !filt.is_empty() {
        "  [j/k] navigate  [Enter] inspect packet  [Esc] close"
    } else if app.capturing {
        "  [stop capture to inspect]"
    } else { "" };

    let stats_line = Line::from(vec![
        Span::styled(" strings: ", Style::default().fg(C_FG3)),
        Span::styled(filt.len().to_string(), Style::default().fg(C_FG)),
        Span::styled("  sensitive: ", Style::default().fg(C_FG3)),
        Span::styled(sensitive_n.to_string(),
            Style::default().fg(if sensitive_n > 0 { C_RED } else { C_FG })),
        Span::styled("  avg entropy: ", Style::default().fg(C_FG3)),
        Span::styled(format!("{:.1}", avg_entr), Style::default().fg(entropy_color(avg_entr))),
        Span::styled("  top: ", Style::default().fg(C_FG3)),
        Span::styled(top_cat, Style::default().fg(kind_color(top_cat, false))),
        Span::styled(nav_hint, Style::default().fg(C_FG3)),
    ]);
    f.render_widget(
        Paragraph::new(stats_line).style(Style::default().bg(C_BG2)),
        vchunks[0],
    );

    // ── Search bar ──
    if search_height > 0 {
        let search_text = if app.strings_search_active {
            format!(" search: {}_", app.strings_filter)
        } else {
            format!(" search: {}  [Esc to clear]", app.strings_filter)
        };
        let search_color = if app.strings_search_active { C_CYAN } else { C_YELLOW };
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(search_text, Style::default().fg(search_color))))
                .style(Style::default().bg(C_BG2)),
            vchunks[1],
        );
    }

    // ── String list ──
    draw_string_list(f, app, &filt, vchunks[2]);

    // ── Detail panel (protocol tree + hex dump, like Packets tab) ──
    if show_detail {
        draw_detail_panel(f, app, &filt, vchunks[3]);
    }
}

// ─── String list ─────────────────────────────────────────────────────────────

fn draw_string_list(f: &mut Frame, app: &App, filt: &[&ExtractedString], area: Rect) {
    // -3 = top border (1) + header row (1) + bottom border (1)
    let visible = area.height.saturating_sub(3) as usize;
    let total   = filt.len();
    let can_nav = !app.capturing;

    // Derive scroll purely from selection so it's always correct regardless of
    // terminal height. Keep the selected row in the lower third of the view
    // (scroll only when selection goes out of bounds).
    let scroll = match app.strings_selected {
        Some(sel) if sel < app.strings_scroll           => sel,
        Some(sel) if sel >= app.strings_scroll + visible => sel + 1 - visible,
        _                                                => app.strings_scroll,
    }.min(total.saturating_sub(visible));

    let header = Row::new(vec![
        Cell::from("Pkt:Off").style(Style::default().fg(C_FG2)),
        Cell::from("Len").style(Style::default().fg(C_FG2)),
        Cell::from("Entr").style(Style::default().fg(C_FG2)),
        Cell::from("Type").style(Style::default().fg(C_FG2)),
        Cell::from("String").style(Style::default().fg(C_FG2)),
    ])
    .style(Style::default().bg(C_BG3))
    .height(1);

    let rows: Vec<Row> = filt.iter().enumerate()
        .skip(scroll)
        .take(visible)
        .map(|(i, s)| {
            let selected = can_nav && app.strings_selected == Some(i);
            let bg = if selected { C_SEL_BG } else { C_BG };
            let kc = kind_color(s.kind, s.sensitive);
            let val_fg = if selected {
                ratatui::style::Color::White
            } else if s.sensitive {
                C_RED
            } else {
                C_FG
            };
            Row::new(vec![
                Cell::from(s.offset_label.clone()).style(Style::default().fg(C_FG3).bg(bg)),
                Cell::from(s.length.to_string()).style(Style::default().fg(C_FG2).bg(bg)),
                Cell::from(format!("{:.1}", s.entropy)).style(Style::default().fg(entropy_color(s.entropy)).bg(bg)),
                Cell::from(s.kind).style(Style::default().fg(kc).bg(bg).add_modifier(
                    if s.sensitive { Modifier::BOLD } else { Modifier::empty() }
                )),
                Cell::from(s.value.clone()).style(Style::default().fg(val_fg).bg(bg)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(11),
        Constraint::Length(5),
        Constraint::Length(5),
        Constraint::Length(10),
        Constraint::Min(0),
    ];

    let sel_label = if can_nav && !filt.is_empty() {
        let sel_num = app.strings_selected.map(|i| i + 1).unwrap_or(0);
        let end = (scroll + visible).min(total);
        format!(" Strings [{}/{}  showing {}-{}] ", sel_num, total, scroll + 1, end)
    } else {
        format!(" Strings [{}] ", total)
    };

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(C_BORDER))
            .title(Span::styled(sel_label, Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD))))
        .style(Style::default().bg(C_BG));

    f.render_widget(table, area);
}

// ─── Detail panel — full protocol tree + hex dump ────────────────────────────

fn draw_detail_panel(f: &mut Frame, app: &App, filt: &[&ExtractedString], area: Rect) {
    let sel_idx = match app.strings_selected {
        Some(i) => i,
        None => return,
    };
    let entry = match filt.get(sel_idx) {
        Some(s) => *s,
        None => return,
    };
    let pkt = match app.packet_by_no(entry.pkt_no) {
        Some(p) => p,
        None => {
            f.render_widget(
                Paragraph::new("  Packet no longer in buffer.")
                    .style(Style::default().fg(C_FG3).bg(C_BG)),
                area,
            );
            return;
        }
    };

    // One-line header showing the matched string and its context.
    let vchunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .split(area);

    let preview = if entry.value.len() > 70 {
        format!("{}…", &entry.value[..69])
    } else {
        entry.value.clone()
    };
    let header_line = Line::from(vec![
        Span::styled(" ↳ ", Style::default().fg(C_FG3)),
        Span::styled(preview, Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Span::styled(
            format!("  ({} · {} · pkt #{})", entry.kind, entry.offset_label, pkt.no),
            Style::default().fg(C_FG3),
        ),
        Span::styled("  [Esc] close", Style::default().fg(C_FG3)),
    ]);
    f.render_widget(
        Paragraph::new(header_line).style(Style::default().bg(C_BG2)),
        vchunks[0],
    );

    // Protocol tree (left) + hex dump (right) — same layout as Packets tab.
    super::packets::draw_packet_detail(f, app, pkt, vchunks[1]);
}
