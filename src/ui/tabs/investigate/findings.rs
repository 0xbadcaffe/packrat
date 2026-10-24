use super::*;

pub(super) fn draw_strings(f: &mut Frame, app: &App, packet: &Packet, area: Rect) {
    let mut lines = Vec::new();
    let mut run = Vec::new();
    for byte in &packet.bytes {
        if byte.is_ascii_graphic() || *byte == b' ' {
            run.push(*byte);
        } else if run.len() >= 4 {
            lines.push(Line::from(String::from_utf8_lossy(&run).to_string()));
            run.clear();
        } else {
            run.clear();
        }
    }
    if run.len() >= 4 {
        lines.push(Line::from(String::from_utf8_lossy(&run).to_string()));
    }
    if lines.is_empty() {
        lines.push(Line::from("No printable strings of length >= 4."));
    }
    f.render_widget(
        Paragraph::new(scrolled(lines, app.investigation_scroll, area))
            .block(panel("Packet Strings"))
            .wrap(Wrap { trim: false }),
        area,
    );
}

pub(super) fn draw_encrypted(f: &mut Frame, app: &App, packet: &Packet, area: Rect) {
    let mut lines = vec![
        Line::from(format!("Protocol: {}", packet.protocol)),
        Line::from(format!("Known TLS sessions: {}", app.tls_tracker.len())),
        Line::from(format!(
            "Known QUIC connections: {}",
            app.quic_scope.connections.len()
        )),
    ];
    if let Some(session) = app.tls_tracker.get(&packet_flow_id(packet)) {
        lines.push(Line::raw(""));
        lines.push(Line::from(vec![Span::styled("TLS session", heading())]));
        lines.push(Line::from(format!("Flow: {}", session.flow_id)));
        lines.push(Line::from(format!(
            "Version: {}",
            session.tls_version.as_deref().unwrap_or("unknown")
        )));
        lines.push(Line::from(format!(
            "SNI: {}",
            session.sni.as_deref().unwrap_or("none")
        )));
        lines.push(Line::from(format!(
            "ALPN: {}",
            session.alpn.as_deref().unwrap_or("none")
        )));
        lines.push(Line::from(format!(
            "JA4: {}",
            session.ja4.as_deref().unwrap_or("none")
        )));
        lines.push(Line::from(format!(
            "Key material: {}",
            if session.key_material {
                "available"
            } else {
                "not available"
            }
        )));
        for record in session
            .decrypted_records
            .iter()
            .filter(|record| record.packet_no == packet.no)
        {
            lines.push(Line::from(format!(
                "Decoded: {} {} bytes - {}",
                record.content_type,
                record.plaintext.len(),
                record.detail
            )));
        }
    }
    for connection in app.quic_scope.connections.values() {
        let frames: Vec<_> = connection
            .decoded_frames
            .iter()
            .filter(|frame| frame.packet_no == packet.no)
            .collect();
        if !frames.is_empty()
            || connection.addresses.contains(&packet.src)
            || connection.addresses.contains(&packet.dst)
        {
            lines.push(Line::raw(""));
            lines.push(Line::from(vec![Span::styled("QUIC connection", heading())]));
            lines.push(Line::from(format!("ID: {}", connection.id)));
            lines.push(Line::from(format!(
                "Version: {}",
                connection
                    .version
                    .map(|v| format!("{v:08x}"))
                    .unwrap_or_else(|| "short".into())
            )));
            lines.push(Line::from(format!("RATQ: {}", connection.ratq)));
            for frame in frames {
                lines.push(Line::from(format!(
                    "Decoded frame: {} - {}",
                    frame.frame_type, frame.detail
                )));
            }
        }
    }
    if lines.len() == 3 {
        lines.push(Line::raw(""));
        lines.push(Line::from(
            "No TLS/QUIC session context is tied to this packet yet.",
        ));
    }
    f.render_widget(
        Paragraph::new(scrolled(lines, app.investigation_scroll, area))
            .block(panel("Encrypted Context"))
            .wrap(Wrap { trim: false }),
        area,
    );
}

pub(super) fn draw_security(f: &mut Frame, app: &App, packet: &Packet, area: Rect) {
    let mut lines = vec![
        Line::from(vec![Span::styled(
            format!("Packet #{} security context", packet.no),
            heading(),
        )]),
        Line::from(format!("Endpoint pair: {} -> {}", packet.src, packet.dst)),
        Line::raw(""),
    ];

    let mut count = 0usize;
    for alert in app
        .security
        .ids_alerts
        .iter()
        .filter(|alert| alert.pkt_no == packet.no)
    {
        count += 1;
        lines.push(Line::from(format!(
            "IDS {} {} - {}",
            alert.severity, alert.signature, alert.detail
        )));
    }
    for hit in app
        .security
        .vuln_hits
        .iter()
        .filter(|hit| hit.pkt_no == packet.no)
    {
        count += 1;
        lines.push(Line::from(format!("VULN {} - {}", hit.kind, hit.detail)));
    }
    for hit in app
        .security
        .tls_weaknesses
        .iter()
        .filter(|hit| hit.pkt_no == packet.no)
    {
        count += 1;
        lines.push(Line::from(format!("TLS {} - {}", hit.kind, hit.detail)));
    }
    for hit in app
        .ioc_engine
        .hits
        .iter()
        .filter(|hit| hit.pkt_no == packet.no)
    {
        count += 1;
        lines.push(Line::from(format!(
            "IOC {} {} via {}",
            hit.ioc.kind, hit.ioc.value, hit.context
        )));
    }
    for hit in app
        .rule_engine
        .hits
        .iter()
        .filter(|hit| hit.pkt_no == packet.no)
    {
        count += 1;
        lines.push(Line::from(format!(
            "RULE {} - {}",
            hit.rule_name, hit.message
        )));
    }
    for cred in app
        .credentials
        .iter()
        .filter(|cred| cred.pkt_no == packet.no)
    {
        count += 1;
        lines.push(Line::from(format!(
            "CRED {} {} = {}",
            cred.proto, cred.kind, cred.value
        )));
    }
    if count == 0 {
        lines.push(Line::from("No packet-specific security findings recorded."));
    }
    f.render_widget(
        Paragraph::new(scrolled(lines, app.investigation_scroll, area))
            .block(panel("Security Context"))
            .wrap(Wrap { trim: false }),
        area,
    );
}

pub(super) fn draw_notes(f: &mut Frame, app: &App, packet: &Packet, area: Rect) {
    let evidence = EvidenceRef::Packet(PacketRef(packet.no));
    let notes = app.notebook.for_evidence(&evidence);
    let lines = if notes.is_empty() {
        vec![Line::from("No notes linked to this packet yet.")]
    } else {
        notes
            .into_iter()
            .map(|note| Line::from(format!("#{} {}", note.id, note.text)))
            .collect()
    };
    f.render_widget(
        Paragraph::new(scrolled(lines, app.investigation_scroll, area))
            .block(panel("Packet Notes"))
            .wrap(Wrap { trim: false }),
        area,
    );
}
