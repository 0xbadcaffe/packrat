use super::*;
use crate::analysis::transactions::{HttpMessage, MessageState};

pub(super) fn draw(f: &mut Frame, app: &App, area: Rect) {
    let Some(stream) = app.active_investigation_stream() else {
        f.render_widget(
            Paragraph::new("No retained TCP stream for this selection.")
                .block(panel("HTTP Transactions")),
            area,
        );
        return;
    };
    let Some(report) = app.core.http_transactions(&stream.key.id()) else {
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
            header.name,
            printable_bytes(&header.value, 256)
        )));
    }
    if let Some(span) = message.body.first() {
        let preview = printable_bytes(&span.direction.bytes(stream)[span.start..span.end], 128);
        lines.push(Line::from(format!("    Body: {preview}")));
    }
    for trailer in &message.trailers {
        lines.push(Line::from(format!(
            "    Trailer {}: {}",
            trailer.name,
            printable_bytes(&trailer.value, 256)
        )));
    }
}
