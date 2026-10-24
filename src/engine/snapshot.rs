use super::AnalysisCore;
use crate::analysis::stream::ReassembledStream;
use crate::analysis::transactions::{HttpConversation, MultiplexedConversation};
use std::sync::Arc;

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct AnalysisSnapshot {
    pub generation: u64,
    pub sequence: u64,
    pub analyzed: u64,
    pub skipped: u64,
    pub flows: usize,
    pub hosts: usize,
    pub alerts: usize,
    pub incidents: usize,
    pub evicted_streams: u64,
    pub streams: Vec<StreamSummary>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StreamSummary {
    pub id: String,
    pub revision: u64,
    pub endpoint_a: String,
    pub endpoint_b: String,
    pub bytes_a: usize,
    pub bytes_b: usize,
    pub pending_segments: usize,
    pub incomplete: bool,
    pub reset: bool,
}

#[derive(Debug, Clone)]
pub struct InspectionSnapshot {
    pub generation: u64,
    pub sequence: u64,
    pub stream: Arc<ReassembledStream>,
    pub http1: Option<Arc<HttpConversation>>,
    pub http2: Option<Arc<MultiplexedConversation>>,
}

#[derive(Debug, Clone)]
pub struct Http3InspectionSnapshot {
    pub generation: u64,
    pub sequence: u64,
    pub packet_no: u64,
    pub revision: u64,
    pub conversation: Arc<crate::analysis::transactions::http3::Http3Conversation>,
}

impl AnalysisSnapshot {
    pub(super) fn capture(
        core: &AnalysisCore,
        generation: u64,
        sequence: u64,
        analyzed: u64,
        skipped: u64,
    ) -> Self {
        Self {
            generation,
            sequence,
            analyzed,
            skipped,
            flows: core.flow_tracker.flows.len(),
            hosts: core.hosts.len(),
            alerts: core.alert_center.items.len(),
            incidents: core.incidents.incidents.len(),
            evicted_streams: core.streams.evicted_streams(),
            streams: core
                .streams
                .all()
                .into_iter()
                .map(|stream| StreamSummary {
                    id: stream.key.id(),
                    revision: stream.revision,
                    endpoint_a: stream.key.ep_a.clone(),
                    endpoint_b: stream.key.ep_b.clone(),
                    bytes_a: stream.client_data.len(),
                    bytes_b: stream.server_data.len(),
                    pending_segments: stream.pending_segments(),
                    incomplete: stream.midstream || stream.has_gaps(),
                    reset: stream.reset,
                })
                .collect(),
        }
    }
}

impl AnalysisCore {
    pub fn inspection_snapshot(
        &self,
        id: &str,
        generation: u64,
        sequence: u64,
    ) -> Option<InspectionSnapshot> {
        let stream = self.streams.get(id)?;
        let http2 = crate::analysis::transactions::is_http2(stream);
        Some(InspectionSnapshot {
            generation,
            sequence,
            stream: Arc::new(stream.clone()),
            http1: if http2 {
                None
            } else {
                self.http_transactions(id)
            },
            http2: if http2 {
                self.http2_transactions(id)
            } else {
                None
            },
        })
    }
}
