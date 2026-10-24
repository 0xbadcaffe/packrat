use super::*;

pub(super) fn draw_flow(f: &mut Frame, app: &App, packet: &Packet, area: Rect) {
    let key = FlowKey::from_packet(packet);
    let rows: Vec<Row> = app
        .core
        .flow_tracker
        .sorted_flows(&app.flows_sort)
        .into_iter()
        .filter(|flow| flow.key == key)
        .map(|flow| {
            Row::new(vec![
                Cell::from(format!(
                    "{}:{} <-> {}:{}",
                    flow.key.ep1.0, flow.key.ep1.1, flow.key.ep2.0, flow.key.ep2.1
                )),
                Cell::from(flow.key.proto.clone()),
                Cell::from(flow.packets.to_string()),
                Cell::from(flow.bytes.to_string()),
                Cell::from(format!("{:.1}", flow.beacon_score)),
            ])
        })
        .collect();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(6), Constraint::Min(0)])
        .split(area);

    if rows.is_empty() {
        f.render_widget(
            Paragraph::new("No flow record exists for this packet yet.")
                .block(panel("Flow Context"))
                .wrap(Wrap { trim: false }),
            chunks[0],
        );
    } else {
        let table = Table::new(
            rows,
            [
                Constraint::Percentage(48),
                Constraint::Length(8),
                Constraint::Length(8),
                Constraint::Length(10),
                Constraint::Length(8),
            ],
        )
        .header(
            Row::new(["Flow", "Proto", "Packets", "Bytes", "Beacon"])
                .style(Style::default().fg(C_FG2())),
        )
        .block(panel("Flow Context"));
        f.render_widget(table, chunks[0]);
    }

    draw_stream_context(f, app, chunks[1]);
}

pub(super) fn draw_stream_context(f: &mut Frame, app: &App, area: Rect) {
    let Some(stream) = app.active_investigation_stream() else {
        f.render_widget(
            Paragraph::new("No reassembled TCP stream is available for this packet.\n\nFor UDP protocols such as DTLS, use Headers for record fields and Security/Encrypted for context.")
                .block(panel("Stream Reassembly"))
                .wrap(Wrap { trim: false }),
            area,
        );
        return;
    };

    let mut lines = vec![
        Line::from(vec![Span::styled(stream.key.id(), heading())]),
        Line::from(format!(
            "A bytes: {}   B bytes: {}   Segments: {}   Closed: {}   s: follow stream",
            stream.client_data.len(),
            stream.server_data.len(),
            stream.segments.len(),
            stream.closed,
        )),
        Line::from(format!(
            "First seen: {:.6}s   Last seen: {:.6}s",
            stream.first_seen, stream.last_seen
        )),
        Line::from(format!(
            "Pending: {}  Dropped: {}  Truncated: {}  Reset: {}  Epoch ambiguous: {}",
            stream.pending_segments(),
            stream.dropped_segments,
            stream.truncated,
            stream.reset,
            stream.epoch_ambiguous
        )),
        Line::raw(""),
    ];
    lines.extend(stream_segment_lines(stream));
    f.render_widget(
        Paragraph::new(scrolled(lines, app.investigation_scroll, area))
            .block(panel("Stream Reassembly"))
            .wrap(Wrap { trim: false }),
        area,
    );
}

pub(super) fn stream_segment_lines(stream: &ReassembledStream) -> Vec<Line<'static>> {
    if stream.segments.is_empty() {
        return vec![Line::from(
            "The stream exists, but no payload bytes have been reassembled yet.",
        )];
    }

    stream
        .segments
        .iter()
        .enumerate()
        .map(|(index, segment)| {
            let data = if segment.from_client {
                &stream.client_data
            } else {
                &stream.server_data
            };
            let end = segment
                .offset
                .saturating_add(segment.length)
                .min(data.len());
            let preview = if segment.offset < end {
                printable_bytes(&data[segment.offset..end], 96)
            } else {
                String::new()
            };
            let direction = if segment.from_client { "A->B" } else { "B->A" };
            let color = if segment.from_client {
                C_CYAN()
            } else {
                C_GREEN()
            };
            Line::from(vec![
                Span::styled(
                    format!("{:>3} {} ", index + 1, direction),
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(
                        "#{} {:.6}s len={}  ",
                        segment.packet_no, segment.timestamp, segment.length
                    ),
                    Style::default().fg(C_FG2()),
                ),
                Span::styled(preview, Style::default().fg(color)),
            ])
        })
        .collect()
}
