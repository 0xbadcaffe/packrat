use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;

use super::AnalysisCore;
use crate::analysis::alert_center::MAX_ALERT_PACKET_REFS;
use crate::analysis::stream::ReassembledStream;
use crate::analysis::transactions::{
    HttpConversation, MessageState, MultiplexedConversation, reconstruct_http, reconstruct_http2,
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

fn http_401_exchange_frames(
    stream: &ReassembledStream, conversation: &HttpConversation, trigger: u64,
) -> Option<Vec<u64>> {
    const MAX_EXCHANGE_FRAMES: usize = 32;
    let mut matches = conversation.transactions.iter().filter_map(|exchange| {
        let response = exchange.response.as_ref()?;
        if response.status != Some(401) || !response.headers_complete
            || !matches!(response.state, MessageState::Complete | MessageState::Incomplete)
            || !response.packet_numbers.contains(&trigger)
        {
            return None;
        }
        let headers = stream.packet_numbers(
            response.span.direction.from_a(), response.span.start, response.header_end,
        );
        headers.contains(&trigger).then_some((&exchange.request, headers))
    });
    let (request, reply_headers) = matches.next()?;
    let first_reply_frame = *reply_headers.first()?;
    if matches.next().is_some()
        || request.state != MessageState::Complete
        || request.packet_numbers.is_empty()
        || request.packet_numbers.iter().any(|&frame| frame == 0 || frame >= first_reply_frame)
        || request.packet_numbers.len() + reply_headers.len() > MAX_EXCHANGE_FRAMES
    {
        return None;
    }
    Some(request.packet_numbers.iter().copied().chain(reply_headers).collect())
}

impl AnalysisCore {
    pub(super) fn observe_split_http_401(&mut self, pkt: &crate::net::packet::Packet) -> Option<(u32, Vec<u64>)> {
        let (id, from_a, previous, initial) = self.streams.http_auth_candidate(pkt)?;
        let stream = self.streams.get(&id)?;
        let conversation = self.http_transactions(&id)?;
        let mut candidates = conversation.transactions.iter().filter_map(|exchange| {
            let response = exchange.response.as_ref()?;
            if response.status != Some(401) || !response.headers_complete
                || !matches!(response.state, MessageState::Complete | MessageState::Incomplete)
                || response.header_end <= previous || response.span.direction.from_a() != from_a
                || exchange.request.state != MessageState::Complete
            {
                return None;
            }
            let frames = stream.packet_numbers(from_a, response.span.start, response.header_end);
            let first = *frames.first()?;
            if !(2..=16).contains(&frames.len()) || !frames.contains(&pkt.no)
                || exchange.request.packet_numbers.is_empty()
                || exchange.request.packet_numbers.iter().any(|&frame| frame == 0 || frame >= first)
            {
                return None;
            }
            Some((initial.wrapping_add(u32::try_from(response.span.start).ok()?), frames))
        });
        let result = candidates.next()?;
        candidates.next().is_none().then_some(result)
    }

    pub(super) fn attach_http_401_exchanges(
        &self, samples: &[(u64, String)], packet_refs: &mut Vec<u64>,
    ) -> usize {
        let mut conversations = HashMap::new();
        let mut linked = 0;
        // Give recent replies first use of the remaining evidence budget.
        for (frame, id) in samples.iter().rev() {
            let conversation = conversations.entry(id.as_str()).or_insert_with(|| {
                let stream = self.streams.get(id)?;
                if stream.midstream || stream.has_gaps() || stream.reset || stream.provenance_truncated {
                    return None;
                }
                Some((stream, self.http_transactions(id)?))
            });
            let Some(mut frames) = conversation.as_ref()
                .and_then(|(stream, conversation)| http_401_exchange_frames(stream, conversation, *frame)) else { continue };
            frames.retain(|frame| !packet_refs.contains(frame));
            if packet_refs.len() + frames.len() <= MAX_ALERT_PACKET_REFS {
                packet_refs.extend(frames);
                linked += 1;
            }
        }
        linked
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
