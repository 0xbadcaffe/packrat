use super::*;

pub(super) fn draw_headers(f: &mut Frame, app: &App, area: Rect) {
    let fields = app.visible_packet_header_fields();
    let selected = app.header_cursor.min(fields.len().saturating_sub(1));
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(5)])
        .split(area);

    let visible_rows = chunks[0].height.saturating_sub(3) as usize;
    let start = if visible_rows == 0 {
        0
    } else if selected >= visible_rows {
        selected + 1 - visible_rows
    } else {
        0
    };

    let rows: Vec<Row> = fields
        .iter()
        .enumerate()
        .skip(start)
        .take(visible_rows.max(1))
        .map(|(index, field)| {
            let style = if index == selected {
                Style::default()
                    .fg(C_BG())
                    .bg(C_CYAN())
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(C_FG())
            };
            Row::new(vec![
                Cell::from(field.layer.clone()),
                Cell::from(field.path.clone()),
                Cell::from(field.label.clone()),
                Cell::from(field.value.clone()),
            ])
            .style(style)
        })
        .collect();

    let title = if app.header_searching {
        format!(" Headers  search: {}_ ", app.header_search)
    } else if app.header_search.is_empty() {
        " Headers  / search  j/k move  Enter bytes  f filter  c clear ".into()
    } else {
        format!(" Headers  filter: {}  / edit  c clear ", app.header_search)
    };

    let table = Table::new(
        rows,
        [
            Constraint::Length(12),
            Constraint::Length(24),
            Constraint::Length(24),
            Constraint::Min(12),
        ],
    )
    .header(
        Row::new(["Layer", "Path", "Field", "Value"])
            .style(Style::default().fg(C_FG2()).add_modifier(Modifier::BOLD)),
    )
    .block(panel_owned(title));
    f.render_widget(table, chunks[0]);

    let detail = fields
        .get(selected)
        .map(header_detail_lines)
        .unwrap_or_else(|| {
            vec![
                Line::from("No header fields match the current search."),
                Line::from("Press c to clear search or / to enter a new query."),
            ]
        });
    f.render_widget(
        Paragraph::new(detail)
            .block(panel("Selected Field"))
            .wrap(Wrap { trim: false }),
        chunks[1],
    );
}

pub(super) fn draw_bytes(f: &mut Frame, app: &App, packet: &Packet, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(6), Constraint::Min(0)])
        .split(area);
    let bytes = &packet.bytes;
    let cursor = app.byte_cursor.min(bytes.len().saturating_sub(1));
    let byte = bytes.get(cursor).copied();
    let u16_be = bytes
        .get(cursor..cursor + 2)
        .map(|slice| u16::from_be_bytes([slice[0], slice[1]]));
    let u16_le = bytes
        .get(cursor..cursor + 2)
        .map(|slice| u16::from_le_bytes([slice[0], slice[1]]));
    let u32_be = bytes
        .get(cursor..cursor + 4)
        .map(|slice| u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]));
    let window_end = (cursor + 16).min(bytes.len());
    let entropy = if cursor < window_end {
        crate::net::inspector::shannon_entropy(&bytes[cursor..window_end])
    } else {
        0.0
    };
    let ascii = byte
        .map(|value| {
            if value.is_ascii_graphic() || value == b' ' {
                (value as char).to_string()
            } else {
                ".".into()
            }
        })
        .unwrap_or_else(|| "-".into());

    let interpretation = vec![
        Line::from(format!(
            "Offset: {cursor} (0x{cursor:04x})  Packet: #{}  Length: {}",
            packet.no,
            bytes.len()
        )),
        Line::from(format!(
            "u8: {}  i8: {}  bits: {}  ASCII: {ascii}",
            byte.map(|value| value.to_string())
                .unwrap_or_else(|| "-".into()),
            byte.map(|value| (value as i8).to_string())
                .unwrap_or_else(|| "-".into()),
            byte.map(|value| format!("{value:08b}"))
                .unwrap_or_else(|| "-".into()),
        )),
        Line::from(format!(
            "u16 BE/LE: {} / {}  u32 BE: {}  entropy[next {}]: {entropy:.3}",
            u16_be
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".into()),
            u16_le
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".into()),
            u32_be
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".into()),
            window_end.saturating_sub(cursor),
        )),
    ];
    f.render_widget(
        Paragraph::new(interpretation)
            .block(panel("Byte Interpreter  h/l byte  j/k row  g/G ends"))
            .wrap(Wrap { trim: false }),
        chunks[0],
    );

    let visible_rows = chunks[1].height.saturating_sub(2) as usize;
    let selected_row = cursor / 16;
    let total_rows = bytes.len().div_ceil(16);
    let start_row = selected_row
        .saturating_sub(visible_rows.saturating_sub(1) / 2)
        .min(total_rows.saturating_sub(visible_rows));
    let mut lines = Vec::new();
    for row_index in start_row..(start_row + visible_rows).min(total_rows) {
        let offset = row_index * 16;
        let chunk = &bytes[offset..(offset + 16).min(bytes.len())];
        let mut spans = vec![Span::styled(
            format!("{offset:04x}  "),
            Style::default().fg(C_FG3()),
        )];
        for index in 0..16 {
            if let Some(value) = chunk.get(index) {
                let absolute = offset + index;
                let style = if absolute == cursor {
                    Style::default()
                        .fg(C_BG())
                        .bg(C_CYAN())
                        .add_modifier(Modifier::BOLD)
                } else if value.is_ascii_graphic() {
                    Style::default().fg(C_GREEN())
                } else {
                    Style::default().fg(C_CYAN())
                };
                spans.push(Span::styled(format!("{value:02x}"), style));
                spans.push(Span::raw(if index == 7 { "  " } else { " " }));
            } else {
                spans.push(Span::raw(if index == 7 { "    " } else { "   " }));
            }
        }
        spans.push(Span::styled(" | ", Style::default().fg(C_FG3())));
        for (index, value) in chunk.iter().enumerate() {
            let absolute = offset + index;
            let character = if value.is_ascii_graphic() || *value == b' ' {
                *value as char
            } else {
                '.'
            };
            let style = if absolute == cursor {
                Style::default()
                    .fg(C_BG())
                    .bg(C_CYAN())
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(C_FG2())
            };
            spans.push(Span::styled(character.to_string(), style));
        }
        lines.push(Line::from(spans));
    }
    f.render_widget(
        Paragraph::new(lines).block(panel("Hex and ASCII  Enter on Headers jumps here")),
        chunks[1],
    );
}
