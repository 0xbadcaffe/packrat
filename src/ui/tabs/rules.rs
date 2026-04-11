use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::Span,
    widgets::{Block, Borders, Cell, Row, Table},
};
use crate::app::App;
use crate::ui::theme::*;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Ratio(1, 2),
            Constraint::Ratio(1, 2),
        ])
        .split(area);

    draw_rules_table(f, app, chunks[0]);
    draw_hits_table(f, app, chunks[1]);
}

fn draw_rules_table(f: &mut Frame, app: &App, area: Rect) {
    let rules = &app.rule_engine.rules;

    let header = Row::new(vec![
        Cell::from("ID").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("Name").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("Enabled").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("Hits").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
    ]).style(Style::default().bg(C_BG2)).height(1);

    let scroll = app.rules_scroll;
    let rows: Vec<Row> = rules.iter().skip(scroll).map(|r| {
        let en_style = if r.enabled {
            Style::default().fg(C_GREEN)
        } else {
            Style::default().fg(C_FG3)
        };
        let hit_style = if r.hits > 0 {
            Style::default().fg(C_RED).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(C_FG2)
        };
        Row::new(vec![
            Cell::from(r.id.clone()).style(Style::default().fg(C_FG3)),
            Cell::from(r.name.clone()).style(Style::default().fg(C_CYAN)),
            Cell::from(if r.enabled { "yes" } else { "no" }).style(en_style),
            Cell::from(r.hits.to_string()).style(hit_style),
        ])
    }).collect();

    let table = Table::new(rows, [
        Constraint::Length(16),
        Constraint::Min(30),
        Constraint::Length(8),
        Constraint::Length(8),
    ])
    .header(header)
    .block(Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_BORDER))
        .title(Span::styled(
            format!(" Rules — {} defined ", rules.len()),
            Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD),
        )))
    .style(Style::default().bg(C_BG));
    f.render_widget(table, area);
}

fn draw_hits_table(f: &mut Frame, app: &App, area: Rect) {
    let hits = &app.rule_engine.hits;

    let header = Row::new(vec![
        Cell::from("Rule").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("Pkt#").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("Action").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Cell::from("Message").style(Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
    ]).style(Style::default().bg(C_BG2)).height(1);

    let rows: Vec<Row> = hits.iter().rev().take(area.height.saturating_sub(4) as usize).map(|h| {
        let action_str = match &h.action {
            crate::analysis::rules::Action::Alert { severity, .. } => format!("ALERT/{severity:?}"),
            crate::analysis::rules::Action::Tag { tag } => format!("TAG:{tag}"),
            crate::analysis::rules::Action::Log { .. } => "LOG".into(),
        };
        Row::new(vec![
            Cell::from(h.rule_name.clone()).style(Style::default().fg(C_CYAN)),
            Cell::from(format!("#{}", h.pkt_no)).style(Style::default().fg(C_FG3)),
            Cell::from(action_str).style(Style::default().fg(C_RED)),
            Cell::from(h.message.clone()).style(Style::default().fg(C_FG2)),
        ])
    }).collect();

    let table = Table::new(rows, [
        Constraint::Length(22),
        Constraint::Length(8),
        Constraint::Length(16),
        Constraint::Min(20),
    ])
    .header(header)
    .block(Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_BORDER))
        .title(Span::styled(
            format!(" Rule Hits — {} ", hits.len()),
            Style::default().fg(C_RED).add_modifier(Modifier::BOLD),
        )))
    .style(Style::default().bg(C_BG));
    f.render_widget(table, area);
}
