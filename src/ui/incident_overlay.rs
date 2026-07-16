//! Operator acknowledgement overlay for critical passive-detection incidents.

use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap},
};

use crate::app::App;
use crate::ui::theme::*;

pub fn draw(f: &mut Frame, app: &App) {
    let Some(incident) = app.incidents.active() else { return; };
    let area = f.area();
    let popup = Rect::new(
        area.x.saturating_add(2),
        area.y.saturating_add(4),
        area.width.saturating_sub(4),
        area.height.saturating_sub(4).min(11),
    );

    if popup.width == 0 || popup.height == 0 { return; }
    f.render_widget(Clear, popup);

    let lines = vec![
        Line::from(Span::styled(
            crate::ui::ascii::INCIDENT_MARK,
            Style::default().fg(C_BG()).bg(C_RED()).add_modifier(Modifier::BOLD),
        )),
        Line::from(vec![
            Span::styled(" CRITICAL ", Style::default().fg(C_BG()).bg(C_RED()).add_modifier(Modifier::BOLD)),
            Span::styled(format!("  Incident #{}  {}", incident.id, incident.detector), Style::default().fg(C_RED()).add_modifier(Modifier::BOLD)),
        ]),
        Line::raw(""),
        Line::from(vec![
            Span::styled(" Source: ", Style::default().fg(C_FG2())),
            Span::styled(incident.source.to_string(), Style::default().fg(C_YELLOW())),
            Span::styled("  Attacker: ", Style::default().fg(C_FG2())),
            Span::styled(&incident.attacker, Style::default().fg(C_RED())),
            Span::styled("  Target: ", Style::default().fg(C_FG2())),
            Span::styled(&incident.target, Style::default().fg(C_CYAN())),
        ]),
        Line::from(Span::styled(&incident.summary, Style::default().fg(C_FG()))),
        Line::from(vec![
            Span::styled(" Retained evidence: ", Style::default().fg(C_FG2())),
            Span::styled(format!("{} packets", incident.packet_history.len()), Style::default().fg(C_YELLOW())),
            Span::styled("  Passive response: traffic capture continues; no enforcement is active.", Style::default().fg(C_FG2())),
        ]),
        Line::raw(""),
        Line::from(Span::styled(
            " Enter / A  review incident analysis    C  unavailable until review",
            Style::default().fg(C_CYAN()).add_modifier(Modifier::BOLD),
        )),
    ];

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(C_RED()).bg(C_BG2()))
        .style(Style::default().bg(C_BG2()))
        .title(Span::styled(" PENETRATION ALERT - OPERATOR REVIEW REQUIRED ", Style::default().fg(C_RED()).add_modifier(Modifier::BOLD)));
    f.render_widget(
        Paragraph::new(lines).block(block).style(Style::default().bg(C_BG2())).wrap(Wrap { trim: true }),
        popup,
    );
}
