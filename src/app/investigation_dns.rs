use super::*;
use crate::analysis::dns_transactions::DnsExchangeEvidence;

pub(super) struct DnsSelection {
    id: u16,
    query_packet: u64,
    question: String,
    query_type: u16,
    query_class: u16,
}

impl DnsSelection {
    fn new(exchange: &DnsExchangeEvidence) -> Self {
        Self {
            id: exchange.transaction_id,
            query_packet: exchange.query_packet,
            question: exchange.question.clone(),
            query_type: exchange.query_type,
            query_class: exchange.query_class,
        }
    }

    fn matches(&self, exchange: &DnsExchangeEvidence) -> bool {
        self.id == exchange.transaction_id
            && self.query_packet == exchange.query_packet
            && self.question == exchange.question
            && self.query_type == exchange.query_type
            && self.query_class == exchange.query_class
    }
}

#[derive(PartialEq, Eq)]
enum DnsFrameOrigin<'a> {
    Current,
    Saved(Option<&'a str>),
}

impl App {
    pub(crate) fn dns_exchanges(
        &self,
        core: &AnalysisCore,
        packet: &Packet,
    ) -> Vec<DnsExchangeEvidence> {
        core.security
            .dns_exchanges_for_packet(packet)
            .into_iter()
            .filter_map(|exchange| self.scope_dns_exchange(packet.no, exchange))
            .collect()
    }

    pub(crate) fn dns_exchange_index(&self, exchanges: &[DnsExchangeEvidence]) -> usize {
        self.dns_transaction_selection
            .as_ref()
            .and_then(|selection| {
                exchanges
                    .iter()
                    .position(|exchange| selection.matches(exchange))
            })
            .unwrap_or(0)
    }

    pub(crate) fn cycle_dns_exchange(&mut self, forward: bool) {
        let Some(exchanges) = self
            .active_investigation_packet()
            .and_then(|packet| self.query_core(|core| self.dns_exchanges(core, packet)))
        else {
            return;
        };
        if exchanges.len() < 2 {
            return;
        }
        let current = self.dns_exchange_index(&exchanges);
        let next = (if forward {
            current + 1
        } else {
            current + exchanges.len() - 1
        }) % exchanges.len();
        self.dns_transaction_selection = Some(DnsSelection::new(&exchanges[next]));
        self.investigation_scroll = 0;
    }

    fn dns_frame_origin(&self, frame: u64) -> DnsFrameOrigin<'_> {
        if let Some(scope) = self.worklist.restored_packet_scopes.get(&frame) {
            DnsFrameOrigin::Saved(Some(scope))
        } else if frame <= self.restored_project_max_frame {
            DnsFrameOrigin::Saved(None)
        } else {
            DnsFrameOrigin::Current
        }
    }

    pub(crate) fn scope_dns_exchange(
        &self,
        frame: u64,
        mut exchange: DnsExchangeEvidence,
    ) -> Option<DnsExchangeEvidence> {
        let origin = self.dns_frame_origin(frame);
        if self.dns_frame_origin(exchange.query_packet) != origin {
            return None;
        }
        exchange
            .query_frames
            .retain(|&query| self.dns_frame_origin(query) == origin);
        exchange
            .repeated_query_packets
            .retain(|&query| self.dns_frame_origin(query) == origin);
        exchange.timing_retry = exchange.timing_retry.filter(|retry| {
            self.dns_frame_origin(retry.packet) == origin
                && retry.frames.iter().all(|&frame| self.dns_frame_origin(frame) == origin)
        });
        exchange
            .replies
            .retain(|reply| self.dns_frame_origin(reply.packet) == origin);
        for reply in &mut exchange.replies {
            reply
                .frames
                .retain(|&frame| self.dns_frame_origin(frame) == origin);
        }
        let includes_frame = exchange.frame_numbers().any(|candidate| candidate == frame);
        includes_frame.then_some(exchange)
    }

    pub(crate) fn next_dns_evidence_frame(&mut self) {
        let Some(packet) = self.active_investigation_packet() else {
            return;
        };
        if !packet.protocol.eq_ignore_ascii_case("DNS")
            && packet.src_port != Some(53)
            && packet.dst_port != Some(53)
        {
            return;
        }
        let current = packet.no;
        let exchange = self.query_core(|core| {
            let mut exchanges = self.dns_exchanges(core, packet);
            let index = self.dns_exchange_index(&exchanges);
            (!exchanges.is_empty()).then(|| exchanges.swap_remove(index))
        });
        let Some(Some(exchange)) = exchange else {
            self.set_status("No retained DNS exchange for this frame");
            return;
        };
        self.dns_transaction_selection = Some(DnsSelection::new(&exchange));
        let mut frames: Vec<_> = exchange.frame_numbers().collect();
        frames.sort_unstable();
        frames.dedup();
        let Some(index) = frames.iter().position(|&frame| frame == current) else {
            return;
        };
        let mut archive = None;
        let mut attempted_archive = false;
        let mut unavailable = 0;
        for offset in 1..frames.len() {
            let frame = frames[(index + offset) % frames.len()];
            let mut packet = self.packet_by_no(frame).cloned();
            if packet.is_none()
                && self.dns_frame_origin(frame) == DnsFrameOrigin::Current
                && let Some(scope) = self.capture_id.as_deref()
            {
                if !attempted_archive {
                    attempted_archive = true;
                    archive = self
                        .packet_archive
                        .as_ref()
                        .and_then(|worker| worker.reader().ok());
                }
                packet = archive
                    .as_mut()
                    .and_then(|reader| reader.packet_for_capture(scope, frame).ok().flatten());
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
