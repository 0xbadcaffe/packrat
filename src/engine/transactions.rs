use std::cell::RefCell;
use std::sync::Arc;

use super::AnalysisCore;
use crate::analysis::stream::StreamKey;
use crate::analysis::transactions::{
    HttpConversation, MessageState, MultiplexedConversation, reconstruct_http, reconstruct_http2,
};
use crate::net::packet::Packet;

#[derive(Default)]
pub(super) struct TransactionCache {
    http1: RefCell<Option<CachedConversation>>,
    http2: RefCell<Option<CachedHttp2>>,
}

struct CachedHttp2 {
    stream_id: String,
    revision: u64,
    conversation: Arc<MultiplexedConversation>,
}

struct CachedConversation {
    stream_id: String,
    revision: u64,
    conversation: Arc<HttpConversation>,
}

impl AnalysisCore {
    pub(super) fn http_401_exchange_frames(&self, trigger: &Packet) -> Option<Vec<u64>> {
        const MAX_EXCHANGE_FRAMES: usize = 32;
        let id = StreamKey::from_packet(trigger)?.id();
        let stream = self.streams.get(&id)?;
        if stream.midstream || stream.has_gaps() || stream.reset || stream.provenance_truncated {
            return None;
        }
        let conversation = self.http_transactions(&id)?;
        let mut matches = conversation.transactions.iter().filter_map(|exchange| {
            let response = exchange.response.as_ref()?;
            (response.status == Some(401) && response.packet_numbers.contains(&trigger.no))
                .then_some((&exchange.request, response))
        });
        let (request, response) = matches.next()?;
        if matches.next().is_some()
            || request.state != MessageState::Complete
            || response.state != MessageState::Complete
            || request.packet_numbers.is_empty()
            || request.packet_numbers.iter().any(|&frame| frame == 0 || frame >= trigger.no)
            || response.packet_numbers.iter().any(|&frame| frame == 0)
            || request.packet_numbers.len() + response.packet_numbers.len() > MAX_EXCHANGE_FRAMES
        {
            return None;
        }
        Some(request.packet_numbers.iter().chain(&response.packet_numbers).copied().collect())
    }

    /// Query derived exchanges without cloning stream payloads. Only the most
    /// recently queried conversation is cached, keeping UI redraws bounded.
    pub fn http_transactions(&self, stream_id: &str) -> Option<Arc<HttpConversation>> {
        let stream = self.streams.get(stream_id)?;
        let mut cache = self.transaction_cache.http1.borrow_mut();
        if let Some(cached) = cache.as_ref() {
            if cached.stream_id == stream_id && cached.revision == stream.revision {
                return Some(Arc::clone(&cached.conversation));
            }
        }
        let conversation = Arc::new(reconstruct_http(stream));
        *cache = Some(CachedConversation {
            stream_id: stream_id.into(),
            revision: stream.revision,
            conversation: Arc::clone(&conversation),
        });
        Some(conversation)
    }

    pub fn http2_transactions(&self, stream_id: &str) -> Option<Arc<MultiplexedConversation>> {
        let stream = self.streams.get(stream_id)?;
        let mut cache = self.transaction_cache.http2.borrow_mut();
        if let Some(cached) = cache.as_ref() {
            if cached.stream_id == stream_id && cached.revision == stream.revision {
                return Some(Arc::clone(&cached.conversation));
            }
        }
        let conversation = Arc::new(reconstruct_http2(stream));
        *cache = Some(CachedHttp2 {
            stream_id: stream_id.into(),
            revision: stream.revision,
            conversation: Arc::clone(&conversation),
        });
        Some(conversation)
    }
}
