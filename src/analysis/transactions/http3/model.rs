use super::super::{HttpHeader, MessageState};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Http3Sender {
    Client,
    Server,
}

/// Trusted helper output after QUIC authentication and stateful QPACK decoding.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuthenticatedHttp3Batch {
    pub connection_id: String,
    pub alpn: String,
    pub events: Vec<Http3Event>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Http3Event {
    pub stream_id: u64,
    pub sender: Http3Sender,
    #[serde(flatten)]
    pub event: Http3EventKind,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Http3EventKind {
    Headers {
        offset: u64,
        wire_length: u64,
        headers: Vec<HttpHeader>,
    },
    Data {
        offset: u64,
        wire_length: u64,
        data: Vec<u8>,
    },
    Extension {
        offset: u64,
        wire_length: u64,
        frame_type: u64,
    },
    Finished {
        final_size: u64,
    },
    Reset {
        final_size: u64,
        error_code: u64,
    },
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Http3BodyChunk {
    /// Offset of the DATA frame in authenticated QUIC stream plaintext, not the capture.
    pub frame_offset: u64,
    pub data: Vec<u8>,
    pub packet_numbers: Vec<u64>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Http3Message {
    pub headers: Vec<HttpHeader>,
    pub trailers: Vec<HttpHeader>,
    pub body: Vec<Http3BodyChunk>,
    pub state: MessageState,
    pub packet_numbers: Vec<u64>,
    pub end_stream: bool,
    pub reset_code: Option<u64>,
    pub diagnostics: Vec<String>,
}

impl Default for Http3Message {
    fn default() -> Self {
        Self {
            headers: Vec::new(),
            trailers: Vec::new(),
            body: Vec::new(),
            state: MessageState::Incomplete,
            packet_numbers: Vec::new(),
            end_stream: false,
            reset_code: None,
            diagnostics: Vec::new(),
        }
    }
}

impl Http3Message {
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers
            .iter()
            .find(|header| header.name == name)
            .map(|header| header.value.as_slice())
    }
    pub fn body_bytes(&self) -> usize {
        self.body.iter().map(|chunk| chunk.data.len()).sum()
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Http3Exchange {
    pub stream_id: u64,
    pub request: Option<Http3Message>,
    pub response: Option<Http3Message>,
    pub interim_responses: Vec<Http3Message>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Http3Conversation {
    pub connection_id: String,
    pub transactions: Vec<Http3Exchange>,
    pub limitations: Vec<String>,
}
