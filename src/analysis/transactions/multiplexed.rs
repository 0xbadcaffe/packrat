use super::{ByteSpan, HttpHeader, MessageState};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum MultiplexedProtocol {
    Http2,
    Http3,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MultiplexedMessage {
    pub headers: Vec<HttpHeader>,
    pub trailers: Vec<HttpHeader>,
    pub body: Vec<ByteSpan>,
    pub state: MessageState,
    pub end_stream: bool,
    pub packet_numbers: Vec<u64>,
    pub diagnostics: Vec<String>,
}

impl Default for MultiplexedMessage {
    fn default() -> Self {
        Self {
            headers: Vec::new(),
            trailers: Vec::new(),
            body: Vec::new(),
            state: MessageState::Incomplete,
            end_stream: false,
            packet_numbers: Vec::new(),
            diagnostics: Vec::new(),
        }
    }
}

impl MultiplexedMessage {
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers
            .iter()
            .find(|header| header.name == name)
            .map(|header| header.value.as_slice())
    }
    pub fn body_bytes(&self) -> usize {
        self.body.iter().map(|span| span.end - span.start).sum()
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MultiplexedTransaction {
    pub stream_id: u64,
    pub request: Option<MultiplexedMessage>,
    pub response: Option<MultiplexedMessage>,
    pub interim_responses: Vec<MultiplexedMessage>,
    pub reset_code: Option<u64>,
    pub promised_by: Option<u64>,
}

impl MultiplexedTransaction {
    pub(super) fn new(stream_id: u64) -> Self {
        Self {
            stream_id,
            request: None,
            response: None,
            interim_responses: Vec::new(),
            reset_code: None,
            promised_by: None,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MultiplexedConversation {
    pub protocol: MultiplexedProtocol,
    pub transactions: Vec<MultiplexedTransaction>,
    pub limitations: Vec<String>,
    pub goaway_stream: Option<u64>,
}
