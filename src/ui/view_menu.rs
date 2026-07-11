//! Workspace-local view drawer.

use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, List, ListItem},
};

use crate::app::App;
use crate::tabs::Tab;
use crate::ui::theme::*;

pub fn draw(f: &mut Frame, app: &App) {
    let workspace = app.active_tab.workspace();
    let views = workspace.views();
    let area = f.area();
    let width = area.width.saturating_sub(4).min(68);
    let height = (views.len() as u16 + 4).min(area.height.saturating_sub(4));
    let popup = Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    );
    if popup.width == 0 || popup.height == 0 { return; }

    f.render_widget(Clear, popup);
    let items = views.iter().enumerate().map(|(index, view)| {
        let selected = index == app.view_menu_cursor;
        let current = *view == app.active_tab;
        let marker = if selected { ">" } else if current { "*" } else { " " };
        let label_style = if selected {
            Style::default().fg(C_CYAN()).bg(C_SEL_BG()).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(C_FG())
        };
        ListItem::new(Line::from(vec![
            Span::styled(format!(" {marker} {:<14}", view.label()), label_style),
            Span::styled(view_description(*view), Style::default().fg(C_FG2())),
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
            )),
    );
    f.render_widget(list, popup);
}

fn view_description(view: Tab) -> &'static str {
    match view {
        Tab::Packets => "packet list and protocol decode",
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
