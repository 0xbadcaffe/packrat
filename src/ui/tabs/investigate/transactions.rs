use super::*;
use crate::analysis::transactions::{HttpMessage, MessageState, MultiplexedMessage, is_http2};

pub(super) fn draw(f: &mut Frame, app: &App, area: Rect) {
    if app
        .active_investigation_packet()
        .is_some_and(|packet| packet.protocol.eq_ignore_ascii_case("QUIC"))
    {
        super::transactions_http3::draw(f, app, area);
        return;
    }
    let snapshot = app.transaction_inspection();
    let stream = if app.background_analysis_enabled() {
        snapshot.map(|snapshot| snapshot.stream.as_ref())
    } else {
        app.active_investigation_stream()
    };
    let Some(stream) = stream else {
        f.render_widget(
            Paragraph::new(if app.background_analysis_enabled() {
                "Transaction snapshot pending or no retained TCP stream."
            } else {
                "No retained TCP stream for this selection."
            })
            .block(panel("HTTP Transactions")),
            area,
        );
        return;
    };
    if is_http2(stream) {
        let report = if app.background_analysis_enabled() {
            snapshot.and_then(|snapshot| snapshot.http2.clone())
        } else {
            app.core.http2_transactions(&stream.key.id())
        };
        if let Some(report) = report {
            draw_http2(f, app, stream, &report, area);
        }
        return;
    }
    let report = if app.background_analysis_enabled() {
        snapshot.and_then(|snapshot| snapshot.http1.clone())
    } else {
        app.core.http_transactions(&stream.key.id())
    };
    let Some(report) = report else {
        return;
    };
    let packet_no = app.active_investigation_packet().map(|packet| packet.no);
    let mut lines = vec![
        Line::styled(
            format!("{} <-> {}", stream.key.ep_a, stream.key.ep_b),
            heading(),
        ),
        Line::from(format!("{} HTTP/1 exchanges", report.transactions.len())),
    ];
    for limitation in &report.limitations {
        lines.push(Line::styled(
            limitation.clone(),
            Style::default().fg(C_YELLOW()),
        ));
    }
    for transaction in &report.transactions {
        let selected = packet_no.is_some_and(|number| {
            transaction.request.packet_numbers.contains(&number)
                || transaction
                    .response
                    .as_ref()
                    .is_some_and(|response| response.packet_numbers.contains(&number))
                || transaction
                    .interim_responses
                    .iter()
                    .any(|response| response.packet_numbers.contains(&number))
        });
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            format!(
                "{} Exchange #{}",
                if selected { ">" } else { " " },
                transaction.index
            ),
            heading(),
        ));
        message_lines(&mut lines, &transaction.request, stream);
        for interim in &transaction.interim_responses {
            message_lines(&mut lines, interim, stream);
        }
        if let Some(response) = &transaction.response {
            message_lines(&mut lines, response, stream);
        } else {
            lines.push(Line::styled(
                "  Response: not captured",
                Style::default().fg(C_YELLOW()),
            ));
        }
    }
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((app.investigation_scroll.min(u16::MAX as usize) as u16, 0))
            .block(panel("HTTP Transactions")),
        area,
    );
}

fn draw_http2(
    f: &mut Frame,
    app: &App,
    stream: &ReassembledStream,
    report: &crate::analysis::transactions::MultiplexedConversation,
    area: Rect,
) {
    let mut lines = vec![Line::styled(
        format!("{} HTTP/2 exchanges", report.transactions.len()),
        heading(),
    )];
    for limitation in &report.limitations {
        lines.push(Line::styled(
            limitation.clone(),
            Style::default().fg(C_YELLOW()),
        ));
    }
    if let Some(last) = report.goaway_stream {
        lines.push(Line::from(format!("GOAWAY last stream: {last}")));
    }
    for transaction in &report.transactions {
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            format!(
                "Stream #{}  Reset: {:?}  Promised by: {:?}",
                transaction.stream_id, transaction.reset_code, transaction.promised_by
            ),
            heading(),
        ));
        if let Some(request) = &transaction.request {
            multiplexed_lines(&mut lines, request, "Request", stream);
        }
        for interim in &transaction.interim_responses {
            multiplexed_lines(&mut lines, interim, "Interim", stream);
        }
        if let Some(response) = &transaction.response {
            multiplexed_lines(&mut lines, response, "Response", stream);
        }
    }
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((app.investigation_scroll.min(u16::MAX as usize) as u16, 0))
            .block(panel("HTTP/2 Transactions")),
        area,
    );
}

fn multiplexed_lines(
    lines: &mut Vec<Line<'static>>,
    message: &MultiplexedMessage,
    role: &str,
    stream: &ReassembledStream,
) {
    let state = match message.state {
        MessageState::Complete => C_GREEN(),
        MessageState::Ambiguous => C_RED(),
        _ => C_YELLOW(),
    };
    lines.push(Line::styled(
        format!(
            "  {role} [{:?}]  Body: {} bytes  Packets {:?}",
            message.state,
            message.body_bytes(),
            message.packet_numbers
        ),
        Style::default().fg(state),
    ));
    for header in &message.headers {
        lines.push(Line::from(format!(
            "    {}: {}",
            printable_bytes(header.name.as_bytes(), 128),
            printable_bytes(&header.value, 256)
        )));
    }
    for diagnostic in &message.diagnostics {
        lines.push(Line::styled(
            diagnostic.clone(),
            Style::default().fg(C_YELLOW()),
        ));
    }
    if let Some(span) = message.body.first() {
        lines.push(Line::from(format!(
            "    Body: {}",
            printable_bytes(
                span.direction
                    .bytes(stream)
                    .get(span.start..span.end)
                    .unwrap_or_default(),
                128
            )
        )));
    }
    for header in &message.trailers {
        lines.push(Line::from(format!(
            "    Trailer {}: {}",
            printable_bytes(header.name.as_bytes(), 128),
            printable_bytes(&header.value, 256)
        )));
    }
}

fn message_lines(
    lines: &mut Vec<Line<'static>>,
    message: &HttpMessage,
    stream: &ReassembledStream,
) {
    let title = if let Some(method) = &message.method {
        format!(
            "{} {}",
            method,
            printable_bytes(message.target.as_deref().unwrap_or("?").as_bytes(), 512)
        )
    } else {
        format!(
            "HTTP {}",
            message.status.map_or("?".into(), |code| code.to_string())
        )
    };
    let direction = if message.span.direction.from_a() {
        "A->B"
    } else {
        "B->A"
    };
    let color = match message.state {
        MessageState::Complete => C_GREEN(),
        MessageState::Ambiguous => C_RED(),
        _ => C_YELLOW(),
    };
    lines.push(Line::styled(
        format!("  {direction} {title} [{:?}]", message.state),
        Style::default().fg(color),
    ));
    lines.push(Line::from(format!(
        "  Bytes {}..{}  Body {} bytes  Packets {:?}",
        message.span.start,
        message.span.end,
        message.captured_body_bytes(),
        message.packet_numbers
    )));
    if let Some(diagnostic) = &message.diagnostic {
        lines.push(Line::styled(
            format!("  {diagnostic}"),
            Style::default().fg(C_YELLOW()),
        ));
    }
    for header in &message.headers {
        lines.push(Line::from(format!(
            "    {}: {}",
            printable_bytes(header.name.as_bytes(), 128),
            printable_bytes(&header.value, 256)
        )));
    }
    if let Some(span) = message.body.first() {
        let preview = printable_bytes(
            span.direction
                .bytes(stream)
                .get(span.start..span.end)
                .unwrap_or_default(),
            128,
        );
        lines.push(Line::from(format!("    Body: {preview}")));
    }
    for trailer in &message.trailers {
        lines.push(Line::from(format!(
            "    Trailer {}: {}",
            printable_bytes(trailer.name.as_bytes(), 128),
            printable_bytes(&trailer.value, 256)
        )));
    }
}
