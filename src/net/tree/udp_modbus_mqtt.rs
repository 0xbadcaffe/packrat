use super::*;

pub(super) fn udp(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(12345);
    let dp = pkt.dst_port.unwrap_or(53);
    sections.push(TreeSection {
        title: format!("User Datagram Protocol, Src Port: {}, Dst Port: {}", sp, dp),
        expanded: true,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", &dp.to_string(), FieldColor::Yellow),
            tf(
                "Length:",
                &(pkt.length as usize).saturating_sub(20).to_string(),
                FieldColor::Default,
            ),
        ],
    });
}

pub(super) fn modbus(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(1024);
    sections.push(TreeSection {
        title: format!(
            "Transmission Control Protocol, Src Port: {}, Dst Port: 502",
            sp
        ),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", "502", FieldColor::Yellow),
        ],
    });
    let tid: u16 = (pkt.no.wrapping_mul(536870923u64).wrapping_add(53u64) as u16);
    let unit_id: u8 =
        ((1u64 + (pkt.no.wrapping_mul(268435459u64).wrapping_add(94u64) % 247u64)) as u8);
    let fn_codes = [
        (1u8, "Read Coils"),
        (2, "Read Discrete Inputs"),
        (3, "Read Holding Registers"),
        (4, "Read Input Registers"),
        (5, "Write Single Coil"),
        (6, "Write Single Register"),
        (15, "Write Multiple Coils"),
        (16, "Write Multiple Registers"),
    ];
    let (fc, fc_name) = fn_codes[stable(pkt.no, fn_codes.len())];
    let addr: u16 =
        ((0u64 + (pkt.no.wrapping_mul(134217757u64).wrapping_add(95u64) % 1001u64)) as u16);
    let qty: u16 =
        ((1u64 + (pkt.no.wrapping_mul(67108859u64).wrapping_add(96u64) % 125u64)) as u16);
    sections.push(TreeSection {
        title: "Modbus/TCP".into(),
        expanded: true,
        fields: vec![
            tf(
                "Transaction ID:",
                &format!("0x{:04x}", tid),
                FieldColor::Cyan,
            ),
            tf("Protocol ID:", "0x0000 (Modbus)", FieldColor::Default),
            tf("Length:", &(6u16).to_string(), FieldColor::Default),
            tf("Unit ID:", &unit_id.to_string(), FieldColor::Yellow),
            tf(
                "Function Code:",
                &format!("{} ({})", fc, fc_name),
                FieldColor::Green,
            ),
            tf(
                "Starting Address:",
                &format!("0x{:04x} ({})", addr, addr),
                FieldColor::Default,
            ),
            tf("Quantity:", &qty.to_string(), FieldColor::Default),
        ],
    });
}

pub(super) fn mqtt(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(1024);
    let dp = if pkt.protocol == "MQTT-TLS" {
        8883u16
    } else {
        1883
    };
    sections.push(TreeSection {
        title: format!(
            "Transmission Control Protocol, Src Port: {}, Dst Port: {}",
            sp, dp
        ),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", &dp.to_string(), FieldColor::Yellow),
        ],
    });
    let topics = [
        "sensors/temperature",
        "sensors/pressure",
        "actuators/valve",
        "plant/line1/status",
    ];
    let topic = topics[stable(pkt.no, topics.len())];
    let msg_types = [
        (1u8, "CONNECT"),
        (2, "CONNACK"),
        (3, "PUBLISH"),
        (4, "PUBACK"),
        (8, "SUBSCRIBE"),
        (9, "SUBACK"),
        (14, "DISCONNECT"),
    ];
    let (mt, mt_name) = msg_types[stable(pkt.no, msg_types.len())];
    let mut fields = vec![
        tf(
            "Message Type:",
            &format!("{} ({})", mt, mt_name),
            FieldColor::Yellow,
        ),
        tf("QoS:", "0 (At most once)", FieldColor::Default),
        tf("Retain:", "0", FieldColor::Default),
    ];
    if mt == 3 {
        fields.push(tf("Topic:", topic, FieldColor::Cyan));
        fields.push(tf(
            "Payload Length:",
            &(4u16 + (pkt.no.wrapping_mul(33554467u64).wrapping_add(97u64) % 61u64) as u16)
                .to_string(),
            FieldColor::Default,
        ));
    } else if mt == 1 {
        let client = ["sensor_01", "plc_gateway", "hmi_client", "mqtt_logger"];
        fields.push(tf(
            "Client ID:",
            client[stable(pkt.no, client.len())],
            FieldColor::Cyan,
        ));
        fields.push(tf("Keep Alive:", "60", FieldColor::Default));
        fields.push(tf("Clean Session:", "1", FieldColor::Default));
    }
    sections.push(TreeSection {
        title: format!("MQ Telemetry Transport Protocol ({} v3.1.1)", mt_name),
        expanded: true,
        fields,
    });
}
