use super::*;

pub(super) fn draw(f: &mut Frame, app: &App, packet: &Packet, area: Rect) {
    let lines = match app.core.security.dns_exchange_for_packet(packet) {
        Some(exchange) => {
            let mut lines = vec![
                Line::styled(format!("Transaction 0x{:04x}", exchange.transaction_id), heading()),
                Line::raw(format!("{}  type {}  class {}", exchange.question, exchange.query_type, exchange.query_class)),
                Line::raw(format!("Client [{}]:{}", exchange.client, exchange.client_port)),
                Line::raw(format!("Expected resolver {}", exchange.expected_resolver)),
                Line::raw(format!("{} Query #{}", marker(packet.no, exchange.query_packet), exchange.query_packet)),
            ];
            if exchange.replies.is_empty() {
                lines.push(Line::raw("No matched reply retained"));
            }
            for reply in exchange.replies {
                lines.push(Line::raw(format!(
                    "{} Reply #{} from {}  base RCODE {}",
                    marker(packet.no, reply.packet), reply.packet, reply.resolver, reply.base_rcode,
                )));
                if reply.question != exchange.question {
                    lines.push(Line::raw(format!("  Reply question: {}", reply.question)));
                }
            }
            if exchange.additional_replies_omitted {
                lines.push(Line::raw("Additional replies exceeded the investigation limit"));
            }
            lines
        }
        None => vec![Line::raw("No retained UDP DNS exchange matches this frame.")],
    };
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false })
            .scroll((app.investigation_scroll.min(u16::MAX as usize) as u16, 0))
            .block(panel("DNS Transaction")),
        area,
    );
}

fn marker(active: u64, frame: u64) -> &'static str {
    if active == frame { ">" } else { " " }
}
