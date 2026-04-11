use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};
use crate::app::{App, ObjectsSubTab};
use crate::ui::theme::*;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // sub-tab bar
            Constraint::Min(0),    // content
            Constraint::Length(1), // status bar
        ])
        .split(area);

    draw_subtab_bar(f, app, chunks[0]);

    match app.objects_subtab {
        ObjectsSubTab::Objects     => draw_objects_panel(f, app, chunks[1]),
        ObjectsSubTab::YaraRules   => draw_rules_panel(f, app, chunks[1]),
        ObjectsSubTab::YaraMatches => draw_matches_panel(f, app, chunks[1]),
    }

    draw_status(f, app, chunks[2]);
}

// ─── Sub-tab bar ──────────────────────────────────────────────────────────────

fn draw_subtab_bar(f: &mut Frame, app: &App, area: Rect) {
    let tabs: &[(&str, ObjectsSubTab, &str)] = &[
        ("[o] ", ObjectsSubTab::Objects,     "Objects"),
        ("[y] ", ObjectsSubTab::YaraRules,   "YARA Rules"),
        ("[m] ", ObjectsSubTab::YaraMatches, "YARA Matches"),
    ];

    let mut spans: Vec<Span> = Vec::new();
    for (key, tab, label) in tabs {
        let active = &app.objects_subtab == tab;
        let key_style = if active {
            Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(C_FG3)
        };
        let label_style = if active {
            Style::default().fg(C_FG).add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
        } else {
            Style::default().fg(C_FG3)
        };
        spans.push(Span::styled(*key, key_style));
        spans.push(Span::styled(*label, label_style));
        spans.push(Span::raw("  "));
    }

    f.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(C_BG2)),
        area,
    );
}

// ─── Objects panel ────────────────────────────────────────────────────────────

fn draw_objects_panel(f: &mut Frame, app: &App, area: Rect) {
    let objects = &app.carved_objects;

    let header = Row::new(vec![
        Cell::from("ID").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("Type").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("Size").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("Source").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("SHA256").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("YARA Hits").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
    ]).style(Style::default().bg(C_BG2)).height(1);

    let scan_pct = if objects.is_empty() { 0 } else {
        app.yara_scan_cursor * 100 / objects.len()
    };
    let scanning_badge = if app.yara_scan_cursor < objects.len() && !app.yara_engine.rules.is_empty() {
        format!(" [scanning…{scan_pct}%]")
    } else {
        String::new()
    };

    let scroll = app.objects_scroll;
    let rows: Vec<Row> = objects.iter().skip(scroll).map(|obj| {
        let yara = if obj.yara_hits.is_empty() {
            "-".into()
        } else {
            obj.yara_hits.join(", ")
        };
        let yara_style = if obj.yara_hits.is_empty() {
            Style::default().fg(C_FG3)
        } else {
            Style::default().fg(C_RED).add_modifier(Modifier::BOLD)
        };
        Row::new(vec![
            Cell::from(format!("#{}", obj.id)).style(Style::default().fg(C_FG3)),
            Cell::from(obj.kind.clone()).style(Style::default().fg(C_CYAN)),
            Cell::from(obj.size_str()).style(Style::default().fg(C_FG2)),
            Cell::from(obj.source.clone()).style(Style::default().fg(C_FG2)),
            Cell::from(obj.sha256[..12.min(obj.sha256.len())].to_string())
                .style(Style::default().fg(C_FG3)),
            Cell::from(yara).style(yara_style),
        ])
    }).collect();

    let empty_hint = if objects.is_empty() {
        " No carved objects yet — use [c] to carve from reassembled streams"
    } else {
        ""
    };

    let table = Table::new(rows, [
        Constraint::Length(6),
        Constraint::Length(20),
        Constraint::Length(9),
        Constraint::Length(36),
        Constraint::Length(14),
        Constraint::Min(20),
    ])
    .header(header)
    .block(Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_BORDER))
        .title(Span::styled(
            format!(" Carved Objects — {}{}{} ",
                objects.len(),
                scanning_badge,
                empty_hint,
            ),
            Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD),
        )))
    .style(Style::default().bg(C_BG));
    f.render_widget(table, area);
}

// ─── YARA Rules panel ─────────────────────────────────────────────────────────

fn draw_rules_panel(f: &mut Frame, app: &App, area: Rect) {
    let engine = &app.yara_engine;

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(4)])
        .split(area);

    // Rules list
    let scroll = app.yara_rules_scroll;
    let rows: Vec<Row> = engine.rules.iter().skip(scroll).map(|r| {
        Row::new(vec![
            Cell::from(r.name.clone()).style(Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD)),
            Cell::from(r.tags.join(", ")).style(Style::default().fg(C_FG3)),
            Cell::from(format!("{} string(s)", r.string_count())).style(Style::default().fg(C_FG2)),
            Cell::from(r.description.clone()).style(Style::default().fg(C_FG2)),
        ])
    }).collect();

    let header = Row::new(vec![
        Cell::from("Rule").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("Tags").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("Strings").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("Description").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
    ]).style(Style::default().bg(C_BG2)).height(1);

    let no_rules_hint = if engine.rules.is_empty() {
        format!(" No rules loaded — drop .yar/.yara files into {} and press [r] to reload",
            engine.rule_dir_str())
    } else {
        String::new()
    };

    let table = Table::new(rows, [
        Constraint::Length(28),
        Constraint::Length(20),
        Constraint::Length(12),
        Constraint::Min(20),
    ])
    .header(header)
    .block(Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_BORDER))
        .title(Span::styled(
            format!(" YARA Rules — {}{} ", engine.rules.len(), no_rules_hint),
            Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD),
        )))
    .style(Style::default().bg(C_BG));
    f.render_widget(table, chunks[0]);

    // Load errors / rule dir info box
    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(vec![
        Span::styled("Rule dir: ", Style::default().fg(C_FG3)),
        Span::styled(engine.rule_dir_str(), Style::default().fg(C_FG2)),
    ]));
    if engine.load_errors.is_empty() {
        lines.push(Line::from(Span::styled("  No load errors.", Style::default().fg(C_GREEN))));
    } else {
        for e in engine.load_errors.iter().take(3) {
            lines.push(Line::from(vec![
                Span::styled("  ERR ", Style::default().fg(C_RED).add_modifier(Modifier::BOLD)),
                Span::styled(e.clone(), Style::default().fg(C_FG2)),
            ]));
        }
        if engine.load_errors.len() > 3 {
            lines.push(Line::from(Span::styled(
                format!("  … and {} more error(s)", engine.load_errors.len() - 3),
                Style::default().fg(C_FG3),
            )));
        }
    }
    let info = Paragraph::new(lines)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_BORDER))
            .title(Span::styled(" Load Log ", Style::default().fg(C_FG3))))
        .style(Style::default().bg(C_BG));
    f.render_widget(info, chunks[1]);
}

// ─── YARA Matches panel ───────────────────────────────────────────────────────

fn draw_matches_panel(f: &mut Frame, app: &App, area: Rect) {
    let engine = &app.yara_engine;
    let scroll = app.yara_matches_scroll;

    let header = Row::new(vec![
        Cell::from("Target").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("Rule").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("Pattern").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("Offset").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("Preview (hex)").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
    ]).style(Style::default().bg(C_BG2)).height(1);

    // Flatten all matches across all scan results
    let all_matches: Vec<(&str, &crate::analysis::yara::YaraMatch)> = engine.results.iter()
        .flat_map(|r| r.matches.iter().map(move |m| (r.target_label.as_str(), m)))
        .collect();

    let total = all_matches.len();

    let rows: Vec<Row> = all_matches.iter().skip(scroll).map(|(label, m)| {
        Row::new(vec![
            Cell::from(*label).style(Style::default().fg(C_CYAN)),
            Cell::from(m.rule_name.clone()).style(Style::default().fg(C_RED).add_modifier(Modifier::BOLD)),
            Cell::from(m.pattern_name.clone()).style(Style::default().fg(C_FG2)),
            Cell::from(format!("0x{:X}", m.offset)).style(Style::default().fg(C_FG3)),
            Cell::from(m.hex_preview()).style(Style::default().fg(C_FG3)),
        ])
    }).collect();

    let no_matches_hint = if total == 0 {
        if engine.rules.is_empty() {
            " No rules loaded — see [y] YARA Rules panel"
        } else {
            " No matches yet — use [s] to force rescan or [c] to carve new objects"
        }
    } else { "" };

    let table = Table::new(rows, [
        Constraint::Length(20),
        Constraint::Length(24),
        Constraint::Length(12),
        Constraint::Length(10),
        Constraint::Min(20),
    ])
    .header(header)
    .block(Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_BORDER))
        .title(Span::styled(
            format!(" YARA Matches — {}{} ", total, no_matches_hint),
            Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD),
        )))
    .style(Style::default().bg(C_BG));
    f.render_widget(table, area);
}

// ─── Status bar ───────────────────────────────────────────────────────────────

fn draw_status(f: &mut Frame, app: &App, area: Rect) {
    let common = " [o/y/m] panels  [j/k] scroll  [r] reload rules  [s] rescan  [c] carve";
    let extra = match app.objects_subtab {
        ObjectsSubTab::Objects     => "  [e] export",
        ObjectsSubTab::YaraRules   => "",
        ObjectsSubTab::YaraMatches => "",
    };
    let status = Paragraph::new(Line::from(Span::styled(
        format!("{common}{extra}"),
        Style::default().fg(C_FG3),
    ))).style(Style::default().bg(C_BG2));
    f.render_widget(status, area);
}
