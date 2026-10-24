use std::cell::RefCell;
use std::sync::Arc;

use super::AnalysisCore;
use crate::analysis::transactions::{
    HttpConversation, MultiplexedConversation, reconstruct_http, reconstruct_http2,
};

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
