use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::{app::AppView as App, tabs::Tab, ui::theme::*};

pub(super) fn draw(f: &mut Frame, app: &App, area: Rect) {
    if app.filter.flow.is_some() {
        let clear = if app.active_tab == Tab::Packets { "  [Esc] clear" } else { "" };
        let label = format!(" Filter: Selected flow  |  {} matched{clear} ", app.filtered.len());
        f.render_widget(Paragraph::new(label).style(Style::default().fg(C_YELLOW()).bg(C_BG2())), area);
        return;
    }
    let has_error = app.display_filter.has_error();
    let filter_display = if app.filter.active {
        format!("{}_", app.filter.input)
    } else if app.filter.input.is_empty() {
        "<press / for packet inspection filter: tcp, ip.src==x, dns and port==53>".into()
    } else {
        app.filter.input.clone()
    };
    let filter_color = if has_error { C_RED() }
        else if app.filter.active { C_CYAN() }
        else if app.filter.input.is_empty() { C_FG3() }
        else { C_YELLOW() };

    let error_span = if let Some(ref e) = app.display_filter.error {
        Span::styled(format!("  ✗ {e}"), Style::default().fg(C_RED()))
    } else if !app.filter.input.is_empty() && !has_error {
        Span::styled(
            format!("  ✓ {} matched", app.filtered.len()),
            Style::default().fg(C_GREEN()),
        )
    } else {
        Span::styled(
            if app.offline_review() { "  [?] search  [h] help" } else { "  [L] load pcap  [B] baseline  [?] search  [h] help" },
            Style::default().fg(C_FG3()),
        )
    };

    let line = Line::from(vec![
        Span::styled(" Filter: ", Style::default().fg(C_FG2())),
        Span::styled(filter_display, Style::default().fg(filter_color)),
        error_span,
    ]);
    f.render_widget(Paragraph::new(line).style(Style::default().bg(C_BG2())), area);
}
