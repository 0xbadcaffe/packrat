use super::{PendingQuery, Question, RecentResponse, RESPONSE_TTL_SECS, TRANSACTION_TTL_SECS};

const MAX_CANDIDATES: usize = 4;

#[derive(Debug, Default)]
pub(super) struct ExchangeBucket {
    pub(super) entries: Vec<Exchange>,
    saturated_at: Option<f64>,
}

#[derive(Debug)]
pub(super) struct Exchange {
    pub(super) query: PendingQuery,
    pub(super) reply: Option<RecentResponse>,
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
            let newest = entry.reply.as_ref().map_or(entry.query.timestamp, |reply| reply.timestamp);
            if query.timestamp >= newest {
                *entry = Exchange { query, reply: None };
            }
        } else if self.entries.len() < MAX_CANDIDATES {
            self.entries.push(Exchange { query, reply: None });
        } else {
            // A discarded query may be the true match for a later partial match.
            self.saturated_at = Some(self.saturated_at.map_or(query.timestamp, |old| old.max(query.timestamp)));
        }
    }

    pub(super) fn expire(&mut self, now: f64) {
        self.entries.retain(|entry| {
            let (seen, ttl) = entry.reply.as_ref().map_or(
                (entry.query.timestamp, TRANSACTION_TTL_SECS),
                |reply| (reply.timestamp, RESPONSE_TTL_SECS),
            );
            now - seen <= ttl
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
