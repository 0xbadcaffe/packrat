use super::*;

fn txt_exchange(no: u64, id: u16) -> [Packet; 2] {
    let mut query = dns_packet(no, false, "10.0.0.5", "10.0.0.53", id, "example.test");
    let mut reply = dns_packet(no + 1, true, "10.0.0.53", "10.0.0.5", id, "example.test");
    for packet in [&mut query, &mut reply] {
        let qtype = packet.bytes.len() - 4;
        packet.bytes[qtype..qtype + 2].copy_from_slice(&16_u16.to_be_bytes());
    }
    [query, reply]
}

fn txt_data(sizes: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    for &length in sizes {
        data.push(length);
        data.resize(data.len() + usize::from(length), b'x');
    }
    data
}

fn add_padding(reply: &mut Packet) {
    const LENGTH: u16 = 600;
    reply.bytes[53] = 1;
    reply.bytes.extend([0, 0, 41, 4, 208, 0, 0, 0, 0]);
    reply.bytes.extend((LENGTH + 4).to_be_bytes());
    reply.bytes.extend(12_u16.to_be_bytes());
    reply.bytes.extend(LENGTH.to_be_bytes());
    reply.bytes.resize(reply.bytes.len() + usize::from(LENGTH), 0);
    reply.length = reply.bytes.len() as u16;
    reply.bytes[16..18].copy_from_slice(&(reply.length - 14).to_be_bytes());
    reply.bytes[38..40].copy_from_slice(&(reply.length - 34).to_be_bytes());
}

#[test]
fn large_txt_counts_only_complete_answer_character_strings() {
    let mut core = AnalysisCore::default();
    let large = txt_data(&[255, 255, 90]);
    let at_threshold = txt_data(&[255, 255, 2]);
    for (index, (txt, padding, additional_only, truncated)) in [
        (txt_data(&[3]), true, false, false),
        (at_threshold, false, false, false),
        (large.clone(), false, true, false),
        (large.clone(), false, false, true),
        (vec![255; 520], false, false, false),
    ].into_iter().enumerate() {
        let [query, mut reply] = txt_exchange(2 * index as u64 + 1, index as u16 + 1);
        append_answer(&mut reply, &[0xc0, 0x0c], 16, 300, &txt);
        if padding {
            add_padding(&mut reply);
        } else if additional_only {
            reply.bytes[49] = 0; // ANCOUNT.
            reply.bytes[53] = 1; // ARCOUNT.
        } else if truncated {
            reply.bytes[44] |= 0x02;
        }
        reply.info = "summary: oversized TXT".into();
        core.analyze(&query);
        core.analyze(&reply);
    }
    assert!(core.alert_center.items.is_empty());

    let [query, mut reply] = txt_exchange(11, 6);
    append_answer(&mut reply, &[0xc0, 0x0c], 16, 300, &large);
    core.analyze(&query);
    core.analyze(&reply);
    core.analyze(&reply);
    let alert = &core.alert_center.items[0];
    assert_eq!(core.alert_center.items.len(), 1);
    assert_eq!(alert.hit_count, 1);
    assert_eq!(alert.severity, "LOW");
    assert_eq!(alert.packet_refs, [11, 12]);
    assert_eq!(alert.provenance.as_ref().unwrap().rule_id, "dns.large_txt_answer");
    assert!(alert.detail.contains("600 bytes of TXT answer data"));
    assert!(core.incidents.incidents.is_empty());
}
