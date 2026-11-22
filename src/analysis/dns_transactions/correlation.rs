use super::{PendingQuery, Question, RecentResponse, RESPONSE_TTL_SECS, TRANSACTION_TTL_SECS};

const MAX_CANDIDATES: usize = 4;
const MAX_QUERY_REPEATS: usize = 4;
const MAX_PENDING_AGE_SECS: f64 = 2.0 * TRANSACTION_TTL_SECS;

#[derive(Debug, Default)]
pub(super) struct ExchangeBucket {
    pub(super) entries: Vec<Exchange>,
    saturated_at: Option<f64>,
}

#[derive(Debug)]
pub(super) struct Exchange {
    pub(super) query: PendingQuery,
    pub(super) reply: Option<RecentResponse>,
    pub(super) repeat_frames: Vec<u64>,
    pub(super) repeats_omitted: bool,
    latest_query_at: f64,
}

impl Exchange {
    fn new(query: PendingQuery) -> Self {
        Self {
            latest_query_at: query.timestamp,
            query,
            reply: None,
            repeat_frames: Vec::new(),
            repeats_omitted: false,
        }
    }

    fn record_query(&mut self, query: PendingQuery) {
        let latest = self.reply.as_ref().map_or(self.latest_query_at, |reply| {
            self.latest_query_at.max(reply.timestamp)
        });
        if query.timestamp < latest {
            return;
        }
        if self.reply.is_some() || query.wire_fingerprint != self.query.wire_fingerprint {
            *self = Self::new(query);
            return;
        }
        if query.packet_no == self.query.packet_no || self.repeat_frames.contains(&query.packet_no) {
            return;
        }
        self.latest_query_at = query.timestamp;
        if self.repeat_frames.len() < MAX_QUERY_REPEATS {
            self.repeat_frames.push(query.packet_no);
        } else {
            self.repeats_omitted = true;
        }
    }

    fn is_pending_at(&self, now: f64) -> bool {
        now - self.latest_query_at <= TRANSACTION_TTL_SECS
            && now - self.query.timestamp <= MAX_PENDING_AGE_SECS
    }
}

pub(super) enum ReplyMatch {
    Matched(usize),
    Ambiguous,
    Missing,
}

impl ExchangeBucket {
    pub(super) fn record(&mut self, query: PendingQuery) {
        self.expire(query.timestamp);
        if let Some(entry) = self.entries.iter_mut().find(|entry| {
            entry.query.server == query.server && entry.query.question == query.question
        }) {
            entry.record_query(query);
        } else if self.entries.len() < MAX_CANDIDATES {
            self.entries.push(Exchange::new(query));
        } else {
            // A discarded query may be the true match for a later partial match.
            self.saturated_at = Some(self.saturated_at.map_or(query.timestamp, |old| old.max(query.timestamp)));
        }
    }

    pub(super) fn expire(&mut self, now: f64) {
        self.entries.retain(|entry| {
            entry.reply.as_ref().map_or_else(
                || entry.is_pending_at(now),
                |reply| now - reply.timestamp <= RESPONSE_TTL_SECS,
            )
        });
        if self.saturated_at.is_some_and(|seen| now - seen > TRANSACTION_TTL_SECS) {
            self.saturated_at = None;
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.saturated_at.is_none()
    }

    pub(super) fn find_reply(&self, now: f64, resolver: &str, question: &Question) -> ReplyMatch {
        let mut partial = None;
        let mut ambiguous = self.saturated_at.is_some();
        for (index, entry) in self.entries.iter().enumerate() {
            let newest = entry.reply.as_ref().map_or(entry.query.timestamp, |reply| reply.timestamp);
            if newest > now {
                continue;
            }
            let same_resolver = entry.query.server == resolver;
            let same_question = entry.query.question == *question;
            if same_resolver && same_question {
                return ReplyMatch::Matched(index);
            }
            if (same_resolver || same_question) && partial.replace(index).is_some() {
                ambiguous = true;
            }
        }
        match (ambiguous, partial) {
            (true, _) => ReplyMatch::Ambiguous,
            (false, Some(index)) => ReplyMatch::Matched(index),
            (false, None) => ReplyMatch::Missing,
        }
    }
}
