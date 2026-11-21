use super::*;

impl App {
    pub(crate) fn next_dns_evidence_frame(&mut self) {
        let Some(packet) = self.active_investigation_packet() else { return };
        if !packet.protocol.eq_ignore_ascii_case("DNS")
            && packet.src_port != Some(53) && packet.dst_port != Some(53)
        {
            return;
        }
        let current = packet.no;
        let exchange = self.query_core(|core| core.security.dns_exchange_for_packet(packet));
        let Some(Some(exchange)) = exchange else {
            self.set_status("No retained DNS exchange for this frame");
            return;
        };
        let frames: Vec<_> = std::iter::once(exchange.query_packet)
            .chain(exchange.replies.iter().map(|reply| reply.packet)).collect();
        let Some(index) = frames.iter().position(|&frame| frame == current) else { return };
        let mut archive = None;
        let mut attempted_archive = false;
        let mut unavailable = 0;
        for offset in 1..frames.len() {
            let frame = frames[(index + offset) % frames.len()];
            let mut packet = self.packet_by_no(frame).cloned();
            if packet.is_none()
                && let Some(scope) = self.capture_id.as_deref()
            {
                if !attempted_archive {
                    attempted_archive = true;
                    archive = self.packet_archive.as_ref().and_then(|worker| worker.reader().ok());
                }
                packet = archive.as_mut().and_then(|reader| reader.packet_for_capture(scope, frame).ok().flatten());
            }
            let Some(packet) = packet else {
                unavailable += 1;
                continue;
            };
            match self.worklist.pin_packet(&packet) {
                Ok(added) => self.project_dirty |= added,
                Err(error) => {
                    self.set_status(error);
                    return;
                }
            }
            self.investigation_scroll = 0;
            self.reset_header_focus();
            self.set_status(if unavailable == 0 {
                format!("DNS evidence frame #{frame}")
            } else {
                format!("DNS evidence frame #{frame}; skipped {unavailable} unavailable")
            });
            return;
        }
        self.set_status("No other DNS evidence frames are available");
    }
}

#[cfg(test)]
#[path = "../../tests/unit/app_dns_navigation_tests.rs"]
mod tests;
