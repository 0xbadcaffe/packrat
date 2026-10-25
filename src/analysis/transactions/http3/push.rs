use super::super::MessageState;
use super::*;

pub(super) fn inspect(
    connection: &Connection,
    controls: &mut [Http3ControlStream],
) -> Vec<Http3Push> {
    let mut pushes = BTreeMap::new();
    promises(connection, &mut pushes);
    for (stream_id, halves) in connection.streams.iter().filter(|(id, _)| **id % 4 == 3) {
        let Some(half) = halves.get(&Http3Sender::Server) else {
            continue;
        };
        let Some(Http3EventKind::PushStart { push_id, .. }) =
            half.frames.get(&0).map(|frame| &frame.event)
        else {
            continue;
        };
        let push = pushes.entry(*push_id).or_insert_with(|| new_push(*push_id));
        if !push.streams.is_empty() {
            issue(
                push,
                "Push ID is reused by multiple push streams; all retained responses are shown",
            );
        }
        let method = push
            .request_headers
            .iter()
            .find(|header| header.name == ":method")
            .map(|header| header.value.as_slice());
        let (response, interim_responses) =
            reconstruct::message(half, false, method, connection.limited);
        push.streams.push(Http3PushStream {
            stream_id: *stream_id,
            response,
            interim_responses,
        });
    }
    let grant = controls
        .iter()
        .filter(|stream| {
            stream.sender == Http3Sender::Client && stream.state != MessageState::Ambiguous
        })
        .filter_map(|stream| stream.max_push_id)
        .max();
    let grant_prefix_complete = controls.iter().any(|stream| {
        stream.sender == Http3Sender::Client && stream.state == MessageState::Complete
    });
    let goaway = controls
        .iter()
        .filter(|stream| {
            stream.sender == Http3Sender::Client && stream.state != MessageState::Ambiguous
        })
        .filter_map(|stream| stream.goaway)
        .min();
    for stream in controls {
        for id in &stream.cancelled_pushes {
            let push = pushes.entry(*id).or_insert_with(|| new_push(*id));
            if !push.cancelled_by.contains(&stream.sender) {
                push.cancelled_by.push(stream.sender);
            }
            if grant_prefix_complete && grant.is_some_and(|maximum| *id > maximum) {
                issue(push, "CANCEL_PUSH exceeds the captured MAX_PUSH_ID");
                stream.state = MessageState::Ambiguous;
                let detail = "CANCEL_PUSH exceeds the captured MAX_PUSH_ID";
                if stream.diagnostics.len() < 16
                    && !stream.diagnostics.iter().any(|prior| prior == detail)
                {
                    stream.diagnostics.push(detail.into());
                }
            }
        }
    }
    for push in pushes.values_mut() {
        push.goaway_excluded = goaway.is_some_and(|limit| push.push_id >= limit);
        if !grant.is_some_and(|maximum| push.push_id <= maximum) {
            if grant_prefix_complete && grant.is_some() {
                issue(push, "Push ID exceeds the captured MAX_PUSH_ID");
            } else {
                incomplete(push, "No captured MAX_PUSH_ID grant covers this push");
            }
        }
        if push.promised_on.is_empty() {
            incomplete(push, "Matching PUSH_PROMISE has not been captured");
        }
        if push.streams.is_empty() {
            incomplete(
                push,
                "Push response stream has not been captured; cancellation may make this intentional",
            );
        }
        let bad_response = push.streams.iter().any(|stream| {
            stream
                .response
                .as_ref()
                .is_some_and(|message| message.state == MessageState::Ambiguous)
        });
        let partial_response = push.streams.iter().any(|stream| {
            stream
                .response
                .as_ref()
                .is_none_or(|message| message.state != MessageState::Complete)
        });
        if bad_response {
            issue(push, "A pushed response has ambiguous framing");
        } else if partial_response {
            incomplete(push, "Pushed response is not complete");
        }
        if connection.limited {
            incomplete(
                push,
                "Connection retention or rejected-input limits were reached",
            );
        }
        push.promise_packets.sort_unstable();
    }
    pushes.into_values().collect()
}

fn promises(connection: &Connection, pushes: &mut BTreeMap<u64, Http3Push>) {
    for (id, halves) in connection.streams.iter().filter(|(id, _)| **id % 4 == 0) {
        let Some(half) = halves.get(&Http3Sender::Server) else {
            continue;
        };
        let mut expected = 0;
        let mut contiguous = true;
        for (offset, frame) in &half.frames {
            contiguous &= *offset == expected;
            expected = *offset + frame.length;
            let Http3EventKind::PushPromise {
                push_id, headers, ..
            } = &frame.event
            else {
                continue;
            };
            let push = pushes.entry(*push_id).or_insert_with(|| new_push(*push_id));
            if push.promised_on.is_empty() {
                push.request_headers = headers.clone();
            } else if push.request_headers != *headers {
                issue(
                    push,
                    "Conflicting PUSH_PROMISE headers for the same push ID",
                );
            }
            if !push.promised_on.contains(id) {
                push.promised_on.push(*id);
            }
            for packet in &frame.packets {
                if !push.promise_packets.contains(packet) {
                    if push.promise_packets.len() < 256 {
                        push.promise_packets.push(*packet);
                    } else {
                        incomplete(push, "Promise packet provenance limit was reached");
                    }
                }
            }
            if !contiguous || half.limited {
                incomplete(
                    push,
                    "Promising request-stream context has a capture gap or retention limit",
                );
            }
            if half.ambiguous {
                issue(
                    push,
                    "Promising request stream has conflicting retained ranges",
                );
            }
            if let Err(error) = reconstruct::validate_headers(headers, true, false) {
                issue(push, &error);
            }
            if !headers
                .iter()
                .any(|header| header.name == ":authority" && !header.value.is_empty())
            {
                issue(push, "Promised request has no :authority");
            }
            match reconstruct::content_length(headers) {
                Ok(Some(length)) if length != 0 => issue(
                    push,
                    "Promised request indicates content, which server push forbids",
                ),
                Err(error) => issue(push, error),
                _ => (),
            }
            if headers
                .iter()
                .find(|header| header.name == ":method")
                .is_some_and(|header| header.value != b"GET" && header.value != b"HEAD")
            {
                if push.state != MessageState::Ambiguous {
                    push.state = MessageState::Unsupported;
                }
                note(
                    push,
                    "Promised method is not known to be safe and cacheable; only GET and HEAD are reconstructed",
                );
            }
        }
    }
}

fn new_push(push_id: u64) -> Http3Push {
    Http3Push {
        push_id,
        promised_on: Vec::new(),
        request_headers: Vec::new(),
        promise_packets: Vec::new(),
        streams: Vec::new(),
        cancelled_by: Vec::new(),
        goaway_excluded: false,
        state: MessageState::Complete,
        diagnostics: Vec::new(),
    }
}

fn incomplete(push: &mut Http3Push, detail: &str) {
    if push.state == MessageState::Complete {
        push.state = MessageState::Incomplete;
    }
    note(push, detail);
}

fn issue(push: &mut Http3Push, detail: &str) {
    push.state = MessageState::Ambiguous;
    note(push, detail);
}

fn note(push: &mut Http3Push, detail: &str) {
    if push.diagnostics.len() < 16 && !push.diagnostics.iter().any(|prior| prior == detail) {
        push.diagnostics.push(detail.into());
    }
}
