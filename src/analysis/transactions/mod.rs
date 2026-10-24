//! Bounded, byte-backed application exchanges reconstructed from TCP streams.

use crate::analysis::stream::ReassembledStream;

mod framing;
mod http;
mod http2;
mod http2_headers;
mod http2_wire;
mod message;
mod multiplexed;

pub use multiplexed::{
    MultiplexedConversation, MultiplexedMessage, MultiplexedProtocol, MultiplexedTransaction,
};

pub use http::reconstruct_http;
pub use http2::reconstruct_http2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Direction {
    AtoB,
    BtoA,
}

impl Direction {
    pub fn from_a(self) -> bool {
        self == Self::AtoB
    }
    pub fn reverse(self) -> Self {
        if self.from_a() {
            Self::BtoA
        } else {
            Self::AtoB
        }
    }
    pub fn bytes(self, stream: &ReassembledStream) -> &[u8] {
        if self.from_a() {
            &stream.client_data
        } else {
            &stream.server_data
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ByteSpan {
    pub direction: Direction,
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum MessageState {
    Complete,
    Incomplete,
    Ambiguous,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct HttpHeader {
    pub name: String,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct HttpMessage {
    pub method: Option<String>,
    pub target: Option<String>,
    pub status: Option<u16>,
    pub span: ByteSpan,
    pub header_end: usize,
    /// Transfer-decoded ranges; Content-Encoding is not decompressed.
    pub body: Vec<ByteSpan>,
    pub headers: Vec<HttpHeader>,
    pub trailers: Vec<HttpHeader>,
    pub state: MessageState,
    pub diagnostic: Option<String>,
    pub packet_numbers: Vec<u64>,
    pub completion_packet: Option<u64>,
}

impl HttpMessage {
    pub fn captured_body_bytes(&self) -> usize {
        self.body
            .iter()
            .map(|span| span.end.saturating_sub(span.start))
            .sum()
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct HttpTransaction {
    pub index: usize,
    pub request: HttpMessage,
    pub interim_responses: Vec<HttpMessage>,
    pub response: Option<HttpMessage>,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct HttpConversation {
    pub transactions: Vec<HttpTransaction>,
    pub limitations: Vec<String>,
}

const MAX_TRANSACTIONS: usize = 128;
const MAX_HEADER_BYTES: usize = 65_536;
const MAX_HEADERS: usize = 128;
const MAX_CHUNKS: usize = 8192;
