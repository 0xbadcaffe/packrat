use super::*;

pub(super) fn draw(f: &mut Frame, app: &App, packet: &Packet, area: Rect) {
    let mut exchanges = app.dns_exchanges(&app.core, packet);
    let selected = app.dns_exchange_index(&exchanges);
    let title = if exchanges.len() > 1 {
        format!("DNS Transactions ({}/{})", selected + 1, exchanges.len())
    } else {
        "DNS Transaction".into()
    };
    let lines = match (!exchanges.is_empty()).then(|| exchanges.swap_remove(selected)) {
        Some(exchange) => {
            let mut lines = vec![
                Line::styled(format!("{} transaction 0x{:04x}", exchange.transport, exchange.transaction_id), heading()),
                Line::raw(format!("{}  type {}  class {}", exchange.question, exchange.query_type, exchange.query_class)),
                Line::raw(format!("Client [{}]:{}", exchange.client, exchange.client_port)),
                Line::raw(format!("Expected resolver {}", exchange.expected_resolver)),
                Line::raw(format!("{} Query #{}", marker(packet.no, exchange.query_packet), exchange.query_packet)),
            ];
            for frame in exchange.query_frames.into_iter().filter(|&frame| frame != exchange.query_packet) {
                lines.push(Line::raw(format!("{}   Query bytes #{frame}", marker(packet.no, frame))));
            }
            for frame in exchange.repeated_query_packets {
                if exchange.timing_retry.as_ref().is_none_or(|retry| retry.packet != frame) {
                    lines.push(Line::raw(format!("{} Repeat query #{frame}", marker(packet.no, frame))));
                }
            }
            if let Some(retry) = exchange.timing_retry {
                lines.push(Line::raw(format!("{} Retry kept query eligible #{}", marker(packet.no, retry.packet), retry.packet)));
                for frame in retry.frames.into_iter().filter(|&frame| frame != retry.packet) {
                    lines.push(Line::raw(format!("{}   Retry bytes #{frame}", marker(packet.no, frame))));
                }
            }
            if exchange.additional_queries_omitted {
                lines.push(Line::raw("Additional repeat queries exceeded the investigation limit"));
            }
            if exchange.replies.is_empty() {
                lines.push(Line::raw("No matched reply retained"));
            }
            for reply in exchange.replies {
                let code = reply.response_code.map_or_else(
                    || format!("base RCODE {} (full code unverified)", reply.base_rcode),
                    |code| format!("RCODE {code}"),
                );
                lines.push(Line::raw(format!(
                    "{} Reply #{} from {}  {code}",
                    marker(packet.no, reply.packet), reply.packet, reply.resolver,
                )));
                if reply.question != exchange.question {
                    lines.push(Line::raw(format!("  Reply question: {}", reply.question)));
                }
                if reply.truncated {
                    lines.push(Line::raw("  DNS TC bit set: answer may be incomplete"));
                }
                for frame in reply.frames.into_iter().filter(|&frame| frame != reply.packet) {
                    lines.push(Line::raw(format!("{}   Reply bytes #{frame}", marker(packet.no, frame))));
                }
            }
            if exchange.additional_replies_omitted {
                lines.push(Line::raw("Additional replies exceeded the investigation limit"));
            }
            lines
        }
        None => vec![Line::raw("No retained DNS exchange matches this frame.")],
    };
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false })
            .scroll((app.investigation_scroll.min(u16::MAX as usize) as u16, 0))
            .block(panel_owned(title)),
        area,
    );
}

fn marker(active: u64, frame: u64) -> &'static str {
    if active == frame { ">" } else { " " }
}
