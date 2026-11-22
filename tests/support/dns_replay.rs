use packrat_tui::export::pcapng::PcapNgWriter;
use packrat_tui::net::parser::parse_ethernet;
use std::path::Path;

pub enum Scenario {
    Equivalent,
    ChangedAnswer,
    ChangedWire,
}

pub fn write_fixture(path: &Path, scenario: Scenario) {
    let rr_type = match scenario {
        Scenario::ChangedWire => 65_280_u16,
        _ => 1,
    };
    let mut capture = PcapNgWriter::create(path).unwrap();
    for frame in 1..=4 {
        let response = frame != 1;
        let equivalent_variation = frame == 3 && rr_type == 1;
        let mut dns = vec![
            0,
            49,
            if response { 0x81 } else { 1 },
            if response { 0x80 } else { 0 },
            0,
            1,
            0,
            u8::from(response),
            0,
            0,
            0,
            0,
        ];
        dns.extend_from_slice(if equivalent_variation {
            b"\x04SAFE\x07EXAMPLE\0"
        } else {
            b"\x04safe\x07example\0"
        });
        dns.extend_from_slice(&[0, 1, 0, 1]);
        if response {
            let changed = frame == 4 && !matches!(scenario, Scenario::Equivalent);
            let value = if changed { 2 } else { 1 };
            let address = [192, 0, 2, value];
            let opaque = [value];
            let rdata: &[u8] = if rr_type == 1 { &address } else { &opaque };
            dns.extend_from_slice(&[0xc0, 0x0c]);
            dns.extend_from_slice(&rr_type.to_be_bytes());
            dns.extend_from_slice(&[0, 1]);
            dns.extend_from_slice(
                &(if equivalent_variation { 299_u32 } else { 300 }).to_be_bytes(),
            );
            dns.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            dns.extend_from_slice(rdata);
        }

        let mut bytes = vec![0_u8; 42];
        bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        bytes[14] = 0x45;
        bytes[16..18].copy_from_slice(&((28 + dns.len()) as u16).to_be_bytes());
        bytes[22] = 64;
        bytes[23] = 17;
        let (src, dst, sport, dport): (_, _, u16, u16) = if response {
            ([10, 0, 0, 53], [10, 0, 0, 5], 53, 40_000)
        } else {
            ([10, 0, 0, 5], [10, 0, 0, 53], 40_000, 53)
        };
        bytes[26..30].copy_from_slice(&src);
        bytes[30..34].copy_from_slice(&dst);
        bytes[34..36].copy_from_slice(&sport.to_be_bytes());
        bytes[36..38].copy_from_slice(&dport.to_be_bytes());
        bytes[38..40].copy_from_slice(&((8 + dns.len()) as u16).to_be_bytes());
        bytes.extend_from_slice(&dns);
        capture
            .write_packet(&parse_ethernet(&bytes, frame, frame as f64))
            .unwrap();
    }
    capture.flush().unwrap();
}
