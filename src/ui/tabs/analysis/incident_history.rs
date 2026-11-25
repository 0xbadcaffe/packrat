use ratatui::{
    style::{Modifier, Style},
    text::{Line, Span},
};

use crate::app::AppView as App;
use crate::ui::helpers::truncate;
use crate::ui::theme::*;

pub(super) fn content(app: &App) -> Vec<Line<'static>> {
    let mut lines = vec![Line::raw("")];
    let incident = app.core.incidents.active().or_else(|| app.core.incidents.incidents.last());
    let Some(incident) = incident else {
        lines.push(Line::from(Span::styled(
            "  No critical incidents have been retained in this capture session.",
            Style::default().fg(C_FG3()),
        )));
        return lines;
    };

    let mut rows = vec![
        ("Incident", format!("#{}  {}", incident.id, incident.status)),
        ("Detection source", incident.source.to_string()),
        ("Detector", incident.detector.clone()),
        ("Summary", incident.summary.clone()),
        ("Attacker", incident.attacker.clone()),
        ("Target", incident.target.clone()),
        ("Capture ID", incident.capture_id.clone().unwrap_or_else(|| "Not recorded".into())),
        ("Observation path", incident.observation_path.map_or_else(|| "Not recorded".into(), |path| path.to_string())),
        ("Packet window", format!("#{} - #{}", incident.first_packet, incident.last_packet)),
        ("Retained packets", incident.packet_history.len().to_string()),
    ];
    let impact = crate::analysis::impact::correlate(incident, &app.core.endpoint_evidence);
    if impact.conflicting_endpoint_report_ids > 0 {
        rows.push(("Impact", format!("Conflicting report IDs omitted: {}", impact.conflicting_endpoint_report_ids)));
    }
    if impact.invalid_endpoint_reports > 0 {
        rows.push(("Impact", format!("Invalid reports omitted: {}", impact.invalid_endpoint_reports)));
    }
    for entry in impact.evidence.iter().filter(|entry| entry.category != "network_activity") {
        rows.push(("Impact", format!("{}: {:?} - {}. {}", entry.category, entry.confidence, entry.subject, entry.explanation)));
    }
    if let Some(action) = app.traffic_latch.actions.iter()
        .find(|action| action.incident_id == incident.id)
    {
        rows.push(("TrafficLatch", format!("{} - {}", action.status, action.detail)));
    }
    for (label, value) in rows {
        lines.push(Line::from(vec![
            Span::styled(format!("  {label:<18}"), Style::default().fg(C_FG2())),
            Span::styled(value, Style::default().fg(C_CYAN())),
        ]));
    }
    if incident.status == crate::analysis::incident::IncidentStatus::PendingReview {
        lines.push(Line::from(Span::styled(
            "\n  Press C to acknowledge this reviewed alert. The retained evidence remains available.",
            Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD),
        )));
    }
    if app.traffic_latch.actions.iter().any(|action| {
        action.incident_id == incident.id
            && action.status == crate::analysis::traffic_latch::LatchStatus::PendingApproval
    }) {
        lines.push(Line::from(Span::styled(
            "  Press x to apply the expiring, reviewed TrafficLatch action.",
            Style::default().fg(C_RED()).add_modifier(Modifier::BOLD),
        )));
    }
    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        "  Recent attacker conversation traffic",
        Style::default().fg(C_FG2()).add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::raw("  Pkt      Time       Source                Target                Proto   Info"));
    lines.push(Line::raw("  ".to_string() + &"─".repeat(82)));
    for packet in incident.packet_history.iter().rev().take(25).rev() {
        lines.push(Line::from(vec![
            Span::styled(format!("  #{:<7}", packet.no), Style::default().fg(C_FG3())),
            Span::styled(format!("{:<11.3}", packet.timestamp), Style::default().fg(C_FG3())),
            Span::styled(format!("{:<22}", truncate(&packet.src, 22)), Style::default().fg(C_RED())),
            Span::styled(format!("{:<22}", truncate(&packet.dst, 22)), Style::default().fg(C_CYAN())),
            Span::styled(format!("{:<8}", truncate(&packet.protocol, 8)), Style::default().fg(C_YELLOW())),
            Span::styled(truncate(&packet.info, 34), Style::default().fg(C_FG2())),
        ]));
    }
    lines
}
