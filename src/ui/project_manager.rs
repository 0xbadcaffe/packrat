//! Project manager overlay — create, open, and manage named projects.

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, List, ListItem, Paragraph},
};

use crate::app::App;
use crate::model::project::{ProjectSaveMode, RecentProject};
use crate::ui::theme::*;

// ─── State ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum PmTab {
    Recent,
    New,
    Open,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PmField {
    Name,
    Desc,
    Path,
    Mode,
}

#[derive(Debug)]
pub struct ProjectManagerState {
    pub tab:          PmTab,
    pub recent:       Vec<RecentProject>,
    pub recent_cursor: usize,
    // New project form
    pub new_name:     String,
    pub new_desc:     String,
    pub new_path:     String,
    pub new_mode:     ProjectSaveMode,
    pub active_field: PmField,
    pub editing:      bool,
    // Open project form
    pub open_path:    String,
    pub open_editing: bool,
    // Status / error line
    pub status:       Option<String>,
}

impl Default for ProjectManagerState {
    fn default() -> Self {
        Self {
            tab:           PmTab::Recent,
            recent:        Vec::new(),
            recent_cursor: 0,
            new_name:      String::new(),
            new_desc:      String::new(),
            new_path:      String::new(),
            new_mode:      ProjectSaveMode::Lightweight,
            active_field:  PmField::Name,
            editing:       false,
            open_path:     String::new(),
            open_editing:  false,
            status:        None,
        }
    }
}

impl ProjectManagerState {
    pub fn is_text_editing(&self) -> bool {
        self.editing || self.open_editing
    }
}

// ─── Draw ────────────────────────────────────────────────────────────────────

pub fn draw(f: &mut Frame, app: &App) {
    let area = f.area();
    let popup = Rect {
        x: area.width / 8,
        y: area.height / 8,
        width: area.width * 3 / 4,
        height: area.height * 3 / 4,
    };
    f.render_widget(Clear, popup);

    let pm = &app.project_manager;

    // Tab labels
    let tab_labels = vec![
        if pm.tab == PmTab::Recent { " [Recent] " } else { "  Recent  " },
        if pm.tab == PmTab::New    { " [New]    " } else { "  New     " },
        if pm.tab == PmTab::Open   { " [Open]   " } else { "  Open    " },
    ];

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // header / tab bar
            Constraint::Min(0),     // body
            Constraint::Length(1),  // status / hint bar
        ])
        .split(popup);

    // ── Header ────────────────────────────────────────────────────────────────
    let tab_spans: Vec<Span> = tab_labels.iter().map(|&label| {
        let is_active = label.contains('[');
        if is_active {
            Span::styled(label, Style::default().fg(C_CYAN()).add_modifier(Modifier::BOLD))
        } else {
            Span::styled(label, Style::default().fg(C_FG3()))
        }
    }).collect();

    let title_line = Line::from({
        let mut spans = vec![
            Span::styled(" Project Manager ", Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD)),
            Span::styled("  │  ", Style::default().fg(C_BORDER())),
        ];
        spans.extend(tab_spans);
        spans
    });

    let header = Paragraph::new(title_line)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(C_YELLOW())));
    f.render_widget(header, chunks[0]);

    // ── Body ──────────────────────────────────────────────────────────────────
    match pm.tab {
        PmTab::Recent => draw_recent(f, app, chunks[1]),
        PmTab::New    => draw_new(f, app, chunks[1]),
        PmTab::Open   => draw_open(f, app, chunks[1]),
    }

    // ── Status bar ────────────────────────────────────────────────────────────
    let hint = if let Some(ref msg) = pm.status {
        Span::styled(format!(" {msg}"), Style::default().fg(C_YELLOW()).add_modifier(Modifier::BOLD))
    } else {
        match pm.tab {
            PmTab::Recent => Span::styled(
                " [Tab] switch panel  [j/k] scroll  [Enter] open  [Del] remove  [Esc] close",
                Style::default().fg(C_FG3()),
            ),
            PmTab::New => Span::styled(
                " [Tab] next field  [Space] toggle mode  [Enter] create  [Esc] close",
                Style::default().fg(C_FG3()),
            ),
            PmTab::Open => Span::styled(
                " [Enter] open  [Esc] close",
                Style::default().fg(C_FG3()),
            ),
        }
    };
    let status_line = Paragraph::new(Line::from(vec![hint]))
        .style(Style::default().bg(C_BG2()));
    f.render_widget(status_line, chunks[2]);
}

fn draw_recent(f: &mut Frame, app: &App, area: Rect) {
    let pm = &app.project_manager;
    let cursor = pm.recent_cursor;

    let project_label = if let Some(ref name) = app.current_project_name {
        format!(" Recent Projects  [current: {}] ", name)
    } else {
        " Recent Projects ".to_string()
    };

    if pm.recent.is_empty() {
        let msg = Paragraph::new(vec![
            Line::raw(""),
            Line::from(Span::styled(
                "  No recent projects. Use [New] to create one.",
                Style::default().fg(C_FG3()),
            )),
        ])
        .block(Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_BORDER()))
            .title(Span::styled(project_label, Style::default().fg(C_FG3()))));
        f.render_widget(msg, area);
        return;
    }

    let visible = area.height.saturating_sub(2) as usize;
    let scroll = if cursor < visible { 0 } else { cursor - visible + 1 };

    let items: Vec<ListItem> = pm.recent.iter().enumerate().skip(scroll).map(|(i, r)| {
        let selected = i == cursor;
        let name_style = if selected {
            Style::default().fg(C_CYAN()).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(C_FG())
        };
        let mode_color = match r.save_mode {
            ProjectSaveMode::Lightweight => C_GREEN(),
            ProjectSaveMode::Portable    => C_YELLOW(),
        };
        let desc = r.description.as_deref().unwrap_or("");
        ListItem::new(vec![
            Line::from(vec![
                Span::styled(if selected { "▶ " } else { "  " }, Style::default().fg(C_CYAN())),
                Span::styled(&r.name, name_style),
                Span::styled(format!("  {}", r.last_opened_display()), Style::default().fg(C_FG3())),
                Span::styled(format!("  {}", r.save_mode), Style::default().fg(mode_color)),
            ]),
            Line::from(vec![
                Span::raw("    "),
                Span::styled(&r.path, Style::default().fg(C_FG3())),
            ]),
            if !desc.is_empty() {
                Line::from(vec![
                    Span::raw("    "),
                    Span::styled(desc, Style::default().fg(C_FG2())),
                ])
            } else {
                Line::raw("")
            },
        ])
    }).collect();

    let list = List::new(items)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(C_BORDER()))
            .title(Span::styled(project_label, Style::default().fg(C_FG3()))));
    f.render_widget(list, area);
}

fn draw_new(f: &mut Frame, app: &App, area: Rect) {
    let pm = &app.project_manager;

    let outer = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_BORDER()))
        .title(Span::styled(" New Project ", Style::default().fg(C_FG3())));
    let inner = outer.inner(area);
    f.render_widget(outer, area);

    let fields = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(0),
        ])
        .split(inner);

    let name_active = pm.active_field == PmField::Name;
    let desc_active = pm.active_field == PmField::Desc;
    let path_active = pm.active_field == PmField::Path;
    let mode_active = pm.active_field == PmField::Mode;

    draw_field(f, " Name ", &pm.new_name, name_active && pm.editing, name_active, fields[0]);
    draw_field(f, " Description ", &pm.new_desc, desc_active && pm.editing, desc_active, fields[1]);
    draw_field(f, " Path ", &pm.new_path, path_active && pm.editing, path_active, fields[2]);

    // Mode selector
    let mode_color = if mode_active { C_CYAN() } else { C_FG2() };
    let mode_str = match pm.new_mode {
        ProjectSaveMode::Lightweight => "  ● Lightweight  ○ Portable  [Space to toggle]",
        ProjectSaveMode::Portable    => "  ○ Lightweight  ● Portable  [Space to toggle]",
    };
    let mode_widget = Paragraph::new(mode_str)
        .style(Style::default().fg(mode_color))
        .block(Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(if mode_active { C_CYAN() } else { C_BORDER() }))
            .title(Span::styled(" Save Mode ", Style::default().fg(C_FG3()))));
    f.render_widget(mode_widget, fields[3]);
}

fn draw_field(f: &mut Frame, label: &str, value: &str, editing: bool, focused: bool, area: Rect) {
    let display = if editing { format!("{value}_") } else { value.to_string() };
    let text_color = if editing { C_CYAN() } else if focused { C_FG() } else { C_FG2() };
    let border_color = if focused { C_CYAN() } else { C_BORDER() };
    let widget = Paragraph::new(display)
        .style(Style::default().fg(text_color))
        .block(Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color))
            .title(Span::styled(label, Style::default().fg(C_FG3()))));
    f.render_widget(widget, area);
}

fn draw_open(f: &mut Frame, app: &App, area: Rect) {
    let pm = &app.project_manager;

    let outer = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_BORDER()))
        .title(Span::styled(" Open Project File ", Style::default().fg(C_FG3())));
    let inner = outer.inner(area);
    f.render_widget(outer, area);

    let path_area = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(inner)[0];

    draw_field(f, " Path (.packrat.json) ", &pm.open_path, pm.open_editing, true, path_area);
}
