use super::*;

pub(super) fn rtsp(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(
        (1024u16 + (pkt.no.wrapping_mul(2870177450u64).wrapping_add(145u64) % 64512u64) as u16),
    );
    sections.push(TreeSection {
        title: format!(
            "Transmission Control Protocol, Src Port: {}, Dst Port: 554",
            sp
        ),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", "554 (RTSP)", FieldColor::Yellow),
        ],
    });
    let methods = [
        "DESCRIBE", "ANNOUNCE", "SETUP", "PLAY", "PAUSE", "TEARDOWN", "OPTIONS",
    ];
    let m = methods[stable(pkt.no, methods.len())];
    let streams = [
        "rtsp://stream.example.com/live.sdp",
        "rtsp://camera.local/h264",
        "rtsp://server/track1",
    ];
    let url = streams[stable(pkt.no, streams.len())];
    let cseq: u32 =
        ((1u64 + (pkt.no.wrapping_mul(1145919239u64).wrapping_add(146u64) % 100u64)) as u32);
    sections.push(TreeSection {
        title: format!("Real-Time Streaming Protocol — {}", m),
        expanded: true,
        fields: vec![
            tf("Method:", m, FieldColor::Green),
            tf("URL:", url, FieldColor::Cyan),
            tf("Version:", "RTSP/1.0", FieldColor::Default),
            tf("CSeq:", &cseq.to_string(), FieldColor::Yellow),
            tf(
                "Session:",
                &format!(
                    "{:016x}",
                    pkt.no.wrapping_mul(134217757u64).wrapping_add(35u64)
                ),
                FieldColor::Default,
            ),
        ],
    });
}

pub(super) fn kafka(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(
        (1024u16 + (pkt.no.wrapping_mul(3264354801u64).wrapping_add(147u64) % 64512u64) as u16),
    );
    sections.push(TreeSection {
        title: format!(
            "Transmission Control Protocol, Src Port: {}, Dst Port: 9092",
            sp
        ),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", "9092 (Kafka)", FieldColor::Yellow),
        ],
    });
    let apis = [
        (0u16, "Produce"),
        (1, "Fetch"),
        (2, "ListOffsets"),
        (3, "Metadata"),
        (8, "OffsetCommit"),
        (9, "OffsetFetch"),
        (10, "FindCoordinator"),
        (11, "JoinGroup"),
        (12, "Heartbeat"),
        (13, "LeaveGroup"),
        (14, "SyncGroup"),
    ];
    let (api_key, api_name) = apis[stable(pkt.no, apis.len())];
    let corr: i32 = (pkt.no.wrapping_mul(1073741827u64).wrapping_add(72u64) as i32);
    let topics = [
        "orders",
        "events",
        "metrics",
        "logs",
        "payments",
        "user-activity",
    ];
    let topic = topics[stable(pkt.no, topics.len())];
    sections.push(TreeSection {
        title: format!("Apache Kafka — {} (apiKey={})", api_name, api_key),
        expanded: true,
        fields: vec![
            tf(
                "API Key:",
                &format!("{} ({})", api_key, api_name),
                FieldColor::Yellow,
            ),
            tf(
                "API Version:",
                &(0u16 + (pkt.no.wrapping_mul(1452813781u64).wrapping_add(148u64) % 11u64) as u16)
                    .to_string(),
                FieldColor::Default,
            ),
            tf("Correlation ID:", &corr.to_string(), FieldColor::Cyan),
            tf("Client ID:", "kafka-consumer-1", FieldColor::Default),
            tf("Topic:", topic, FieldColor::Green),
            tf(
                "Partition:",
                &(0u32 + (pkt.no.wrapping_mul(987654323u64).wrapping_add(149u64) % 8u64) as u32)
                    .to_string(),
                FieldColor::Default,
            ),
        ],
    });
}

pub(super) fn amqp(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(
        (1024u16 + (pkt.no.wrapping_mul(4294967291u64).wrapping_add(150u64) % 64512u64) as u16),
    );
    sections.push(TreeSection {
        title: format!(
            "Transmission Control Protocol, Src Port: {}, Dst Port: 5672",
            sp
        ),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", "5672 (AMQP)", FieldColor::Yellow),
        ],
    });
    let methods = [
        (10u16, 10u16, "connection.start"),
        (10, 30, "connection.tune"),
        (10, 40, "connection.open"),
        (20, 10, "channel.open"),
        (40, 10, "exchange.declare"),
        (50, 10, "queue.declare"),
        (50, 20, "queue.bind"),
        (60, 40, "basic.publish"),
        (60, 60, "basic.deliver"),
        (60, 80, "basic.ack"),
    ];
    let (class_id, method_id, method_name) = methods[stable(pkt.no, methods.len())];
    let exchange = ["amq.direct", "amq.topic", "amq.fanout", "events", "orders"];
    let routing_key = [
        "order.created",
        "user.signup",
        "payment.processed",
        "error.fatal",
    ];
    sections.push(TreeSection {
        title: format!("AMQP 0-9-1 — {}", method_name),
        expanded: true,
        fields: vec![
            tf("Frame Type:", "1 (method)", FieldColor::Default),
            tf("Channel:", "1", FieldColor::Cyan),
            tf("Class ID:", &class_id.to_string(), FieldColor::Default),
            tf("Method ID:", &method_id.to_string(), FieldColor::Default),
            tf("Method:", method_name, FieldColor::Yellow),
            tf(
                "Exchange:",
                exchange[stable(pkt.no, exchange.len())],
                FieldColor::Green,
            ),
            tf(
                "Routing Key:",
                routing_key[stable(pkt.no, routing_key.len())],
                FieldColor::Cyan,
            ),
        ],
    });
}
