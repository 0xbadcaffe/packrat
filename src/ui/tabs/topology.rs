use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, List, ListItem, Paragraph},
};
use std::collections::HashMap;
use std::f64::consts::PI;

use crate::app::App;
use crate::topology::NodeInfo;
use crate::ui::helpers::fmt_bytes;
use crate::ui::theme::*;

/// Fewer nodes → much less visual clutter.
const MAX_GRAPH_NODES: usize = 8;

type Grid = Vec<Vec<Option<(char, ratatui::style::Color)>>>;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let vchunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(65), Constraint::Percentage(35)])
        .split(area);

    draw_graph(f, app, vchunks[0]);

    let hchunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(vchunks[1]);

    draw_nodes(f, app, hchunks[0]);
    draw_edges(f, app, hchunks[1]);
}

// ─── helpers ─────────────────────────────────────────────────────────────────

fn node_label(ip: &str) -> String {
    let p: Vec<&str> = ip.split('.').collect();
    if p.len() == 4 { format!("{}.{}", p[2], p[3]) } else { ip.chars().take(9).collect() }
}

/// Circular layout in normalised [0,1]×[0,1] space, top-dead-centre first.
fn compute_layout<'a>(nodes: &[(&'a str, &NodeInfo)]) -> HashMap<String, (f64, f64)> {
    let n = nodes.len();
    if n == 0 { return HashMap::new(); }
    let (cx, cy, r) = (0.5, 0.5, if n == 1 { 0.0 } else { 0.35 });
    nodes.iter().enumerate().map(|(i, (ip, _))| {
        let angle = 2.0 * PI * i as f64 / n as f64 - PI / 2.0;
        (ip.to_string(), (cx + r * angle.cos(), cy + r * angle.sin()))
    }).collect()
}

fn set_cell(grid: &mut Grid, x: i32, y: i32, ch: char, color: ratatui::style::Color) {
    let (rows, cols) = (grid.len() as i32, grid.first().map(|r| r.len()).unwrap_or(0) as i32);
    if x < 0 || y < 0 || x >= cols || y >= rows { return; }
    let (x, y) = (x as usize, y as usize);
    // Resolve junctions so crossing edges look clean.
    let resolved = match (grid[y][x].map(|(c, _)| c), ch) {
        (Some('─'), '│') | (Some('│'), '─') => '┼',
        (Some(existing), _) if existing != ' ' => return, // don't clobber occupied cells
        _ => ch,
    };
    grid[y][x] = Some((resolved, color));
}

/// Draw a line between attachment points using `─` `│` and `·` for diagonals.
/// Using `·` (mid-dot) instead of `╱` `╲` avoids the ugly `////` repetition.
fn draw_line(grid: &mut Grid, x0: i32, y0: i32, x1: i32, y1: i32, color: ratatui::style::Color) {
    let (dx, dy) = ((x1 - x0).abs(), (y1 - y0).abs());
    let (sx, sy) = (if x0 < x1 { 1 } else { -1 }, if y0 < y1 { 1 } else { -1 });

    // Pick a single character for the whole segment based on dominant direction.
    let ch = if dx == 0 { '│' } else if dy == 0 { '─' } else { '·' };

    let mut err = dx - dy;
    let (mut x, mut y) = (x0, y0);
    loop {
        set_cell(grid, x, y, ch, color);
        if x == x1 && y == y1 { break; }
        let e2 = 2 * err;
        if e2 > -dy { err -= dy; x += sx; }
        if e2 <  dx { err += dx; y += sy; }
    }
}

fn write_label(grid: &mut Grid, col: i32, row: i32, text: &str, color: ratatui::style::Color) {
    let (rows, cols) = (grid.len() as i32, grid.first().map(|r| r.len()).unwrap_or(0) as i32);
    if row < 0 || row >= rows { return; }
    for (i, ch) in text.chars().enumerate() {
        let c = col + i as i32;
        if c < 0 || c >= cols { break; }
        grid[row as usize][c as usize] = Some((ch, color));
    }
}

// ─── graph renderer ───────────────────────────────────────────────────────────

fn draw_graph(f: &mut Frame, app: &App, area: Rect) {
    let top_nodes = app.topology.top_nodes(MAX_GRAPH_NODES);
    let top_edges = app.topology.top_edges(64);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(Style::default().fg(C_BORDER))
        .title(Span::styled(
            format!(" Graph [{} nodes · {} flows] ", app.topology.nodes.len(), app.topology.edges.len()),
            Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD),
        ));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let (w, h) = (inner.width as usize, inner.height as usize);
    if w < 4 || h < 2 { return; }

    if top_nodes.is_empty() {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled("  No traffic observed yet.", Style::default().fg(C_FG3))))
                .style(Style::default().bg(C_BG)),
            inner,
        );
        return;
    }

    let mut grid: Grid = vec![vec![None; w]; h];
    let layout = compute_layout(&top_nodes);
    let max_pkts = top_edges.iter().map(|(_, _, e)| e.packets).max().unwrap_or(1);

    // Pre-compute label widths so edges attach to label sides, not label centres.
    let label_half: HashMap<String, i32> = top_nodes.iter().map(|(ip, _)| {
        let l = format!("[{}]", node_label(ip)).len() as i32;
        (ip.to_string(), l / 2)
    }).collect();

    // ── edges ──
    for (src, dst, info) in &top_edges {
        let (pos_src, pos_dst) = match (layout.get(*src), layout.get(*dst)) {
            (Some(a), Some(b)) => (a, b),
            _ => continue,
        };

        // Map normalised positions to grid coordinates.
        let gx = |nx: f64| (nx * (w.saturating_sub(1)) as f64).round() as i32;
        let gy = |ny: f64| ((1.0 - ny) * (h.saturating_sub(1)) as f64).round() as i32;

        let (sx, sy) = (gx(pos_src.0), gy(pos_src.1));
        let (dx, dy) = (gx(pos_dst.0), gy(pos_dst.1));

        // Attach the edge to the left or right side of the label, not the centre.
        let half_src = label_half.get(*src).copied().unwrap_or(0);
        let half_dst = label_half.get(*dst).copied().unwrap_or(0);
        let (ax, ay) = if dx >= sx { (sx + half_src + 1, sy) } else { (sx - half_src - 1, sy) };
        let (bx, by) = if dx >= sx { (dx - half_dst - 1, dy) } else { (dx + half_dst + 1, dy) };

        let color = proto_color(&info.protocol);
        draw_line(&mut grid, ax, ay, bx, by, color);

        // Show flow count near midpoint only for top flows.
        if info.packets * 4 >= max_pkts {
            let (mx, my) = ((ax + bx) / 2, (ay + by) / 2);
            let label = format!("{}", info.packets);
            write_label(&mut grid, mx - label.len() as i32 / 2, my, &label, color);
        }
    }

    // ── node labels (drawn last, always on top) ──
    for (ip, _) in &top_nodes {
        if let Some(&(nx, ny)) = layout.get(*ip) {
            let gx = (nx * (w.saturating_sub(1)) as f64).round() as i32;
            let gy = ((1.0 - ny) * (h.saturating_sub(1)) as f64).round() as i32;
            let label = format!("[{}]", node_label(ip));
            let lx = gx - label.len() as i32 / 2;
            write_label(&mut grid, lx, gy, &label, C_CYAN);
        }
    }

    // ── render grid as styled Lines ──
    let lines: Vec<Line> = grid.into_iter().map(|row| {
        let mut spans: Vec<Span> = Vec::new();
        let mut buf = String::new();
        let mut cur: Option<ratatui::style::Color> = None;
        for cell in row {
            let (ch, col) = cell.unwrap_or((' ', C_BG));
            if Some(col) == cur {
                buf.push(ch);
            } else {
                if !buf.is_empty() {
                    spans.push(Span::styled(buf.clone(), Style::default().fg(cur.unwrap_or(C_BG))));
                    buf.clear();
                }
                buf.push(ch);
                cur = Some(col);
            }
        }
        if !buf.is_empty() {
            spans.push(Span::styled(buf, Style::default().fg(cur.unwrap_or(C_BG))));
        }
        Line::from(spans)
    }).collect();

    f.render_widget(Paragraph::new(lines).style(Style::default().bg(C_BG)), inner);
}

// ─── node list ────────────────────────────────────────────────────────────────

fn draw_nodes(f: &mut Frame, app: &App, area: Rect) {
    let top_nodes = app.topology.top_nodes(50);
    let mut items: Vec<ListItem> = Vec::new();
    if top_nodes.is_empty() {
        items.push(ListItem::new(Line::from(Span::styled("  No traffic observed yet.", Style::default().fg(C_FG3)))));
    }
    for (ip, info) in &top_nodes {
        let total_pkts = info.tx_packets + info.rx_packets;
        let total_bytes = info.tx_bytes + info.rx_bytes;
        items.push(ListItem::new(Line::from(vec![
            Span::styled(format!(" {:<18}", ip), Style::default().fg(C_CYAN)),
            Span::styled(format!("{:<7}", total_pkts), Style::default().fg(C_FG2)),
            Span::styled(fmt_bytes(total_bytes), Style::default().fg(C_GREEN)),
        ])));
        items.push(ListItem::new(Line::from(Span::styled(
            format!("   tx:{:<6} rx:{:<6}", info.tx_packets, info.rx_packets),
            Style::default().fg(C_FG3),
        ))));
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(Style::default().fg(C_BORDER))
        .title(Span::styled(
            format!(" Nodes [{}] ", app.topology.nodes.len()),
            Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD),
        ));

    let inner = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(area);

    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            format!(" {:<18} {:<7} {}", "IP Address", "Pkts", "Bytes"),
            Style::default().fg(C_FG2),
        ))).block(block.clone()).style(Style::default().bg(C_BG)),
        inner[0],
    );
    f.render_widget(
        List::new(items)
            .block(Block::default()
                .borders(Borders::LEFT | Borders::RIGHT | Borders::BOTTOM)
                .border_style(Style::default().fg(C_BORDER)))
            .style(Style::default().bg(C_BG)),
        inner[1],
    );
}

// ─── flow list ────────────────────────────────────────────────────────────────

fn draw_edges(f: &mut Frame, app: &App, area: Rect) {
    let top_edges = app.topology.top_edges(30);
    let mut items: Vec<ListItem> = Vec::new();
    if top_edges.is_empty() {
        items.push(ListItem::new(Line::from(Span::styled("  No flows observed yet.", Style::default().fg(C_FG3)))));
    }
    for (src, dst, info) in &top_edges {
        items.push(ListItem::new(Line::from(vec![
            Span::styled(format!(" {}", src), Style::default().fg(C_CYAN)),
            Span::styled(" → ", Style::default().fg(C_FG3)),
            Span::styled(dst.to_string(), Style::default().fg(C_GREEN)),
        ])));
        items.push(ListItem::new(Line::from(Span::styled(
            format!("   [{:<6}] {:>6} pkts  {}", info.protocol, info.packets, fmt_bytes(info.bytes)),
            Style::default().fg(C_FG3),
        ))));
    }
    f.render_widget(
        List::new(items)
            .block(Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Plain)
                .border_style(Style::default().fg(C_BORDER))
                .title(Span::styled(
                    format!(" Flows [{}] ", app.topology.edges.len()),
                    Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD),
                )))
            .style(Style::default().bg(C_BG)),
        area,
    );
}
