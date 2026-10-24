use super::*;

/// Reconstruct retained HTTP/1 exchanges without guessing across framing errors.
/// HTTP/2, encrypted bytes, and content decompression are outside this decoder.
pub fn reconstruct_http(stream: &ReassembledStream) -> HttpConversation {
    let mut report = HttpConversation::default();
    if stream.midstream {
        report
            .limitations
            .push("Capture starts midstream; earlier exchanges may be missing".into());
    }
    if stream.has_gaps() {
        report.limitations.push(
            "Stream has pending gaps, discarded bytes, or an ambiguous connection epoch".into(),
        );
    }
    if stream.reset {
        report
            .limitations
            .push("Connection reset is not a clean message EOF".into());
    }
    if stream.provenance_truncated {
        report
            .limitations
            .push("Packet provenance retention limit reached".into());
    }
    if stream.client_data.starts_with(b"PRI * HTTP/2.0")
        || stream.server_data.starts_with(b"PRI * HTTP/2.0")
    {
        report
            .limitations
            .push("HTTP/2 requires a separate framed decoder".into());
        return report;
    }
    let from_a = message::request_candidate(&stream.client_data);
    let from_b = message::request_candidate(&stream.server_data);
    let direction = match (from_a, from_b) {
        (true, false) => Direction::AtoB,
        (false, true) => Direction::BtoA,
        (true, true) => {
            report
                .limitations
                .push("Both directions resemble requests; direction is ambiguous".into());
            return report;
        }
        _ => {
            report
                .limitations
                .push("No HTTP/1 request prefix established in retained bytes".into());
            return report;
        }
    };
    let mut request_offset = 0;
    let mut response_offset = 0;
    let mut response_blocked = false;
    let mut upgraded = false;
    for index in 0..MAX_TRANSACTIONS {
        if request_offset == direction.bytes(stream).len() {
            break;
        }
        let request = message::request(stream, direction, request_offset);
        let request_complete = request.state == MessageState::Complete;
        request_offset = request.span.end;
        let method = request.method.as_deref().unwrap_or("");
        let mut interim = Vec::new();
        let mut response = None;
        if !response_blocked {
            for _ in 0..16 {
                if response_offset == direction.reverse().bytes(stream).len() {
                    break;
                }
                let current =
                    message::response(stream, direction.reverse(), response_offset, method);
                response_offset = current.span.end;
                let complete = current.state == MessageState::Complete;
                let informational = current
                    .status
                    .is_some_and(|code| (100..200).contains(&code) && code != 101);
                if complete && informational {
                    interim.push(current);
                    continue;
                }
                upgraded = complete
                    && (current.status == Some(101)
                        || method == "CONNECT"
                            && current
                                .status
                                .is_some_and(|code| (200..300).contains(&code)));
                response_blocked = !complete;
                response = Some(current);
                break;
            }
            if interim.len() == 16 {
                report
                    .limitations
                    .push("Informational-response limit reached".into());
                response_blocked = true;
            }
        }
        report.transactions.push(HttpTransaction {
            index: index + 1,
            request,
            interim_responses: interim,
            response,
        });
        if !request_complete || upgraded {
            break;
        }
    }
    if upgraded {
        report
            .limitations
            .push("Protocol upgrade or CONNECT tunnel begins after this exchange".into());
    } else if report.transactions.len() == MAX_TRANSACTIONS
        && request_offset < direction.bytes(stream).len()
    {
        report
            .limitations
            .push("Transaction count exceeds reconstruction limit".into());
    }
    report
}
