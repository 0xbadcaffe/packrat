use super::*;
use crate::engine::snapshot::InspectionSnapshot;

#[derive(Default)]
pub(super) struct InspectionState {
    next_id: u64,
    pending: Option<(u64, u64, String, u64)>,
    completed: Option<(u64, String, u64)>,
    snapshot: Option<InspectionSnapshot>,
}

impl App {
    fn investigation_stream_id(&self) -> Option<String> {
        if let Some(InvestigationItem::Stream(id)) = self.active_investigation_item() {
            Some(id.clone())
        } else {
            self.active_investigation_packet()
                .and_then(StreamKey::from_packet)
                .map(|key| key.id())
        }
    }

    pub fn transaction_inspection(&self) -> Option<&InspectionSnapshot> {
        let snapshot = self.inspection.snapshot.as_ref()?;
        let worker = self.analysis_worker.as_ref()?;
        (snapshot.generation == worker.generation()
            && self.investigation_stream_id().as_deref() == Some(snapshot.stream.key.id().as_str()))
        .then_some(snapshot)
    }

    pub(super) fn inspection_pending(&self) -> bool {
        self.inspection.pending.is_some()
    }

    pub(super) fn reset_inspection(&mut self) {
        self.inspection = Default::default();
    }

    pub(super) fn poll_inspection(&mut self) {
        if self.active_tab != Tab::Investigate
            || self.investigation_view != InvestigationView::Transactions
            || self.inspection.pending.is_some()
        {
            return;
        }
        let Some(id) = self.investigation_stream_id() else {
            return;
        };
        let Some(worker) = self.analysis_worker.as_ref() else {
            return;
        };
        let generation = worker.generation();
        let Some(Some(revision)) =
            self.query_core(|core| core.streams.get(&id).map(|stream| stream.revision))
        else {
            return;
        };
        if self
            .inspection
            .completed
            .as_ref()
            .is_some_and(|seen| seen == &(generation, id.clone(), revision))
        {
            return;
        }
        let request = self.inspection.next_id.wrapping_add(1);
        if worker.try_inspect(request, id.clone()).is_ok() {
            self.inspection.next_id = request;
            self.inspection.pending = Some((request, generation, id, revision));
        }
    }

    pub(super) fn receive_inspection(
        &mut self,
        generation: u64,
        request_id: u64,
        result: Result<InspectionSnapshot, String>,
    ) {
        let Some((pending_id, pending_generation, _, _)) = self.inspection.pending.as_ref() else {
            return;
        };
        if request_id != *pending_id
            || generation != *pending_generation
            || self
                .analysis_worker
                .as_ref()
                .is_none_or(|worker| worker.generation() != generation)
        {
            return;
        }
        let (_, _, id, revision) = self.inspection.pending.take().unwrap();
        self.inspection.completed = Some((generation, id.clone(), revision));
        match result {
            Ok(snapshot) if snapshot.stream.key.id() == id && snapshot.generation == generation => {
                self.inspection.completed = Some((generation, id, snapshot.stream.revision));
                self.inspection.snapshot = Some(snapshot);
            }
            Err(error) => self.set_status(format!("Transaction inspection: {error}")),
            _ => self.set_status("Transaction inspection context mismatch"),
        }
    }
}
