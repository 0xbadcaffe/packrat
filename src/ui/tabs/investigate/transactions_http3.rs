use super::*;
use crate::analysis::transactions::{MessageState, http3::Http3Message};

pub(super) fn draw(f: &mut Frame, app: &App, area: Rect) {
    let report = if app.background_analysis_enabled() {
        app.transaction_http3_inspection()
            .map(|snapshot| snapshot.conversation.clone())
    } else {
        app.active_investigation_packet().and_then(|packet| {
            let tracker = &app.core.quic_scope.http3;
            tracker
                .conversation(tracker.connection_for_packet(packet.no)?)
                .map(std::sync::Arc::new)
        })
    };
    let Some(report) = report else {
        let detail = app
            .core
            .quic_scope
            .last_decode_error
            .as_deref()
            .unwrap_or("No authenticated HTTP/3 snapshot is available for this packet.");
        f.render_widget(
            Paragraph::new(printable_bytes(detail.as_bytes(), 512))
                .wrap(Wrap { trim: false })
                .block(panel("HTTP/3 Transactions")),
            area,
        );
        return;
    };
    let mut lines = vec![Line::styled(
        format!("HTTP/3 connection {}", report.connection_id),
        heading(),
    )];
    for limitation in &report.limitations {
        lines.push(Line::styled(
            limitation.clone(),
            Style::default().fg(C_YELLOW()),
        ));
    }
    for exchange in &report.transactions {
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            format!("Request stream #{}", exchange.stream_id),
            heading(),
        ));
        if let Some(request) = &exchange.request {
            message_lines(&mut lines, "Request", request);
        }
        for interim in &exchange.interim_responses {
            message_lines(&mut lines, "Interim", interim);
        }
        if let Some(response) = &exchange.response {
            message_lines(&mut lines, "Response", response);
        }
    }
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((app.investigation_scroll.min(u16::MAX as usize) as u16, 0))
            .block(panel("HTTP/3 Transactions")),
        area,
    );
}

fn message_lines(lines: &mut Vec<Line<'static>>, role: &str, message: &Http3Message) {
    let color = match message.state {
        MessageState::Complete => C_GREEN(),
        MessageState::Ambiguous => C_RED(),
        _ => C_YELLOW(),
    };
    lines.push(Line::styled(
        format!(
            "  {role} [{:?}] Body: {} bytes  FIN: {}  Reset: {:?}",
            message.state,
            message.body_bytes(),
            message.end_stream,
            message.reset_code
        ),
        Style::default().fg(color),
    ));
    lines.push(Line::from(format!(
        "  Completion packets {:?}",
        message.packet_numbers
    )));
    for header in &message.headers {
        lines.push(Line::from(format!(
            "    {}: {}",
            printable_bytes(header.name.as_bytes(), 128),
            printable_bytes(&header.value, 256)
        )));
    }
    for body in message.body.iter().take(4) {
        lines.push(Line::from(format!(
            "    DATA @{}: {}",
            body.frame_offset,
            printable_bytes(&body.data, 128)
        )));
    }
    for trailer in &message.trailers {
        lines.push(Line::from(format!(
            "    Trailer {}: {}",
            printable_bytes(trailer.name.as_bytes(), 128),
            printable_bytes(&trailer.value, 256)
        )));
    }
    for diagnostic in &message.diagnostics {
        lines.push(Line::styled(
            diagnostic.clone(),
            Style::default().fg(C_YELLOW()),
        ));
    }
}
