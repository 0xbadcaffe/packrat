use super::super::MessageState;
use super::*;

pub(super) fn inspect(connection: &Connection) -> Vec<Http3ControlStream> {
    let mut reports = Vec::new();
    let mut declared = Vec::new();
    for (id, halves) in connection.streams.iter().filter(|(id, _)| **id % 4 >= 2) {
        for (sender, half) in halves {
            if half
                .frames
                .get(&0)
                .is_some_and(|frame| matches!(frame.event, Http3EventKind::ControlStart { .. }))
            {
                declared.push((*sender, *id));
            }
            if half.frames.values().any(|frame| {
                matches!(
                    frame.event,
                    Http3EventKind::ControlStart { .. }
                        | Http3EventKind::Settings { .. }
                        | Http3EventKind::Goaway { .. }
                        | Http3EventKind::MaxPushId { .. }
                        | Http3EventKind::CancelPush { .. }
                )
            }) {
                reports.push(stream(*id, *sender, half, connection.limited));
            }
        }
    }
    for sender in [Http3Sender::Client, Http3Sender::Server] {
        if declared
            .iter()
            .filter(|(owner, _)| *owner == sender)
            .count()
            > 1
        {
            for report in reports.iter_mut().filter(|report| report.sender == sender) {
                issue(report, "Multiple control streams from the same endpoint");
            }
        }
    }
    reports
}

fn stream(id: u64, sender: Http3Sender, half: &HalfStream, limited: bool) -> Http3ControlStream {
    let mut report = Http3ControlStream {
        stream_id: id,
        sender,
        settings: Vec::new(),
        goaway: None,
        max_push_id: None,
        cancelled_pushes: Vec::new(),
        state: MessageState::Incomplete,
        packet_numbers: Vec::new(),
        diagnostics: Vec::new(),
    };
    let mut expected = 0;
    let mut started = false;
    let mut settings = false;
    let mut missing = limited || half.limited;
    for (offset, frame) in &half.frames {
        for packet in &frame.packets {
            if !report.packet_numbers.contains(packet) {
                if report.packet_numbers.len() < 256 {
                    report.packet_numbers.push(*packet);
                } else {
                    missing = true;
                }
            }
        }
        if *offset != expected {
            note(
                &mut report,
                "Control stream has a missing plaintext range; later frames are not interpreted",
            );
            missing = true;
            break;
        }
        expected += frame.length;
        if !started {
            started = matches!(frame.event, Http3EventKind::ControlStart { .. });
            if !started {
                issue(
                    &mut report,
                    "Control stream prefix is missing or has the wrong type",
                );
                break;
            }
            continue;
        }
        if !settings && !matches!(frame.event, Http3EventKind::Settings { .. }) {
            issue(&mut report, "SETTINGS must be the first control frame");
        }
        match &frame.event {
            Http3EventKind::Settings { entries, .. } => {
                if settings {
                    issue(&mut report, "Duplicate SETTINGS frame");
                } else {
                    settings = true;
                    report.settings = entries.clone();
                    let mut seen = std::collections::BTreeSet::new();
                    for entry in entries {
                        if !seen.insert(entry.identifier) {
                            issue(&mut report, "Duplicate SETTINGS identifier");
                        }
                        if matches!(entry.identifier, 2..=5) {
                            issue(
                                &mut report,
                                "HTTP/2-only SETTINGS identifier is forbidden in HTTP/3",
                            );
                        }
                        if matches!(entry.identifier, 8 | 0x33) && entry.value > 1 {
                            issue(&mut report, "Boolean SETTINGS value is not zero or one");
                        }
                    }
                }
            }
            Http3EventKind::Goaway { identifier, .. } => {
                if sender == Http3Sender::Server && identifier % 4 != 0 {
                    issue(
                        &mut report,
                        "Server GOAWAY does not identify a client request stream",
                    );
                }
                if report.goaway.is_some_and(|prior| *identifier > prior) {
                    issue(&mut report, "GOAWAY identifier increased");
                }
                report.goaway = Some(
                    report
                        .goaway
                        .map_or(*identifier, |prior| prior.min(*identifier)),
                );
            }
            Http3EventKind::MaxPushId { push_id, .. } => {
                if sender != Http3Sender::Client {
                    issue(&mut report, "Only a client can send MAX_PUSH_ID");
                }
                if report.max_push_id.is_some_and(|prior| *push_id < prior) {
                    issue(&mut report, "MAX_PUSH_ID decreased");
                }
                report.max_push_id = Some(
                    report
                        .max_push_id
                        .map_or(*push_id, |prior| prior.max(*push_id)),
                );
            }
            Http3EventKind::CancelPush { push_id, .. } => {
                if !report.cancelled_pushes.contains(push_id) {
                    report.cancelled_pushes.push(*push_id);
                }
            }
            Http3EventKind::Extension { frame_type, .. } if *frame_type != 5 => (),
            _ => issue(&mut report, "Unexpected HTTP/3 frame on a control stream"),
        }
    }
    if !settings {
        note(&mut report, "SETTINGS has not been captured");
        missing = true;
    }
    for packet in &half.final_packets {
        if !report.packet_numbers.contains(packet) {
            if report.packet_numbers.len() < 256 {
                report.packet_numbers.push(*packet);
            } else {
                missing = true;
            }
        }
    }
    if half.ambiguous {
        issue(
            &mut report,
            "Conflicting control-stream ranges or final sizes",
        );
    }
    if half.final_size.is_some() || half.reset_code.is_some() {
        issue(&mut report, "Critical control stream was closed or reset");
    }
    if missing {
        note(&mut report, "Control-stream evidence is incomplete");
    }
    if report.state != MessageState::Ambiguous && settings && !missing {
        report.state = MessageState::Complete;
    }
    report.packet_numbers.sort_unstable();
    report
}

fn issue(report: &mut Http3ControlStream, detail: &str) {
    report.state = MessageState::Ambiguous;
    note(report, detail);
}

fn note(report: &mut Http3ControlStream, detail: &str) {
    if report.diagnostics.len() < 16 && !report.diagnostics.iter().any(|prior| prior == detail) {
        report.diagnostics.push(detail.into());
    }
}
