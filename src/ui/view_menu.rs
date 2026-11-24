//! Workspace-local view drawer.

use ratatui::{
    Frame,
    layout::{Alignment, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, List, ListItem, Paragraph},
};

use crate::app::AppView as App;
use crate::tabs::Tab;
use crate::ui::theme::*;

const VERSION: &str = concat!("v", env!("CARGO_PKG_VERSION"));

pub fn draw(f: &mut Frame, app: &App) {
    let workspace = app.active_tab.workspace();
    let views = workspace.views();
    let area = f.area();
    let width = area.width.saturating_sub(4).min(68);
    let height = (views.len() as u16 + 5).min(area.height.saturating_sub(4));
    let popup = Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    );
    if popup.width == 0 || popup.height == 0 { return; }

    f.render_widget(Clear, popup);
    let visible = popup.height.saturating_sub(2) as usize;
    let start = app.view_menu_cursor.saturating_add(1).saturating_sub(visible);
    let entries = views.iter().copied().map(Some).chain(std::iter::once(None));
    let items = entries.enumerate().skip(start).take(visible).map(|(index, view)| {
        let selected = index == app.view_menu_cursor;
        let current = view == Some(app.active_tab);
        let marker = if selected { ">" } else if current { "*" } else { " " };
        let (label, description) = match view {
            Some(tab) => (format!(" {marker} {:<14}", tab.label()), view_description(tab)),
            None => (format!(" {marker} About "), VERSION),
        };
        let label_style = if selected {
            Style::default().fg(C_CYAN()).bg(C_SEL_BG()).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(C_FG())
        };
        ListItem::new(Line::from(vec![
            Span::styled(label, label_style),
            Span::styled(description, Style::default().fg(C_FG2())),
        ])).style(if selected { Style::default().bg(C_SEL_BG()) } else { Style::default() })
    });

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(C_CYAN()))
            .style(Style::default().bg(C_BG2()))
            .title(Span::styled(
                format!(" {} Views  [j/k] choose  [Enter] open  [Esc] close ", workspace.label()),
                Style::default().fg(C_CYAN()).add_modifier(Modifier::BOLD),
            ))
            .title_bottom(" End: About "),
    );
    f.render_widget(list, popup);
}

pub fn draw_about(f: &mut Frame) {
    let area = f.area();
    let width = area.width.min(36);
    let height = area.height.min(5);
    let popup = Rect::new(
        area.x + (area.width - width) / 2,
        area.y + (area.height - height) / 2,
        width,
        height,
    );
    let body = Paragraph::new(vec![
        Line::styled(format!("Packrat {VERSION}"), Style::default().fg(C_FG()).add_modifier(Modifier::BOLD)),
        Line::styled("Network analyzer", Style::default().fg(C_FG2())),
    ])
    .alignment(Alignment::Center)
    .block(Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(C_CYAN()))
        .style(Style::default().bg(C_BG2()))
        .title(" About ")
        .title_bottom(" Esc: back "));
    f.render_widget(Clear, popup);
    f.render_widget(body, popup);
}

fn view_description(view: Tab) -> &'static str {
    match view {
        Tab::Packets => "packet list and protocol decode",
        Tab::Investigate => "worklist-driven packet investigation",
        Tab::Flows => "conversations, volume, beacon scoring",
        Tab::Hosts => "host inventory and tags",
        Tab::TlsAnalysis => "TLS, JA4, ECH, key logs, and QUIC",
        Tab::Analysis => "traffic and incident summaries",
        Tab::Strings => "searchable payload strings",
        Tab::Visualize => "traffic distribution views",
        Tab::Workbench => "byte-level protocol inspection",
        Tab::Objects => "carved objects and YARA results",
        Tab::Diff => "baseline comparison",
        Tab::Security => "detections and network controls",
        Tab::Rules => "local detection policy",
        Tab::OperatorGraph => "evidence and attack paths",
        Tab::Scanner => "service discovery",
        Tab::Traceroute => "network path inspection",
        Tab::Craft => "controlled packet construction",
        Tab::Notebook => "case notes",
        Tab::Dynamic => "runtime event timeline",
    }
}
