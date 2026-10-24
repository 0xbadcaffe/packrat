use super::*;
use crate::engine::snapshot::Http3InspectionSnapshot;

struct Request {
    id: u64,
    generation: u64,
    packet: u64,
    connection: String,
    revision: u64,
}

#[derive(Default)]
pub(super) struct Http3InspectionState {
    next_id: u64,
    pending: Option<Request>,
    completed: Option<(u64, u64, String, u64)>,
    snapshot: Option<Http3InspectionSnapshot>,
}

impl App {
    pub fn transaction_http3_inspection(&self) -> Option<&Http3InspectionSnapshot> {
        let snapshot = self.inspection_http3.snapshot.as_ref()?;
        let generation = self.analysis_worker.as_ref()?.generation();
        (snapshot.generation == generation
            && self
                .active_investigation_packet()
                .is_some_and(|packet| packet.no == snapshot.packet_no))
        .then_some(snapshot)
    }

    pub(super) fn http3_inspection_pending(&self) -> bool {
        self.inspection_http3.pending.is_some()
    }

    pub(super) fn poll_http3_inspection(&mut self) {
        if self.active_tab != Tab::Investigate
            || self.investigation_view != InvestigationView::Transactions
            || self.inspection_http3.pending.is_some()
        {
            return;
        }
        let Some(packet) = self.active_investigation_packet() else {
            return;
        };
        if !packet.protocol.eq_ignore_ascii_case("QUIC") {
            return;
        }
        let number = packet.no;
        let Some(worker) = self.analysis_worker.as_ref() else {
            return;
        };
        let generation = worker.generation();
        let Some(Some((id, revision))) = self.query_core(|core| {
            let tracker = &core.quic_scope.http3;
            let id = tracker.connection_for_packet(number)?;
            Some((id.to_string(), tracker.connection_revision(id)?))
        }) else {
            return;
        };
        if self
            .inspection_http3
            .completed
            .as_ref()
            .is_some_and(|prior| prior == &(generation, number, id.clone(), revision))
        {
            return;
        }
        let request = self.inspection_http3.next_id.wrapping_add(1);
        if worker.try_inspect_http3(request, number).is_ok() {
            self.inspection_http3.next_id = request;
            self.inspection_http3.pending = Some(Request {
                id: request,
                generation,
                packet: number,
                connection: id,
                revision,
            });
        }
    }

    pub(super) fn receive_http3_inspection(
        &mut self,
        generation: u64,
        request_id: u64,
        result: Result<Http3InspectionSnapshot, String>,
    ) {
        let Some(pending) = self.inspection_http3.pending.as_ref() else {
            return;
        };
        if pending.id != request_id
            || pending.generation != generation
            || self
                .analysis_worker
                .as_ref()
                .is_none_or(|worker| worker.generation() != generation)
        {
            return;
        }
        let pending = self.inspection_http3.pending.take().unwrap();
        self.inspection_http3.completed = Some((
            generation,
            pending.packet,
            pending.connection.clone(),
            pending.revision,
        ));
        match result {
            Ok(snapshot)
                if snapshot.generation == generation
                    && snapshot.packet_no == pending.packet
                    && snapshot.conversation.connection_id == pending.connection =>
            {
                self.inspection_http3.completed = Some((
                    generation,
                    pending.packet,
                    pending.connection,
                    snapshot.revision,
                ));
                self.inspection_http3.snapshot = Some(snapshot);
            }
            Err(error) => self.set_status(format!("HTTP/3 inspection: {error}")),
            _ => self.set_status("HTTP/3 inspection context mismatch"),
        }
    }
}
