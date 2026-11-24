use packrat_tui::{
    export::pcapng::PcapNgWriter,
    net::{
        packet::{CaptureMetadata, CaptureTimestamp, TimestampResolution},
        parser::parse_ethernet,
    },
};
use std::path::Path;

pub fn write_fixture(path: &Path, frames: u64, varied_bytes: bool, split_interface: bool) {
    write_timed_fixture(path, 1..=frames, varied_bytes, split_interface);
}

pub fn write_timed_fixture(
    path: &Path,
    ticks: impl IntoIterator<Item = u64>,
    varied_bytes: bool,
    split_interface: bool,
) {
    write_scoped_fixture(path, ticks, varied_bytes, split_interface, false);
}

pub fn write_vlans_fixture(path: &Path, frames: u64, varied_bytes: bool) {
    write_scoped_fixture(path, 1..=frames, varied_bytes, false, true);
}

fn write_scoped_fixture(
    path: &Path,
    ticks: impl IntoIterator<Item = u64>,
    varied_bytes: bool,
    split_interface: bool,
    split_tag_paths: bool,
) {
    let mut capture = PcapNgWriter::create(path).unwrap();
    let payload: Vec<u8> = (0..60_000)
        .map(|index| {
            if varied_bytes {
                (index * 73 % 256) as u8
            } else {
                0
            }
        })
        .collect();
    let mut bytes = vec![0_u8; 42];
    bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    bytes[14] = 0x45;
    bytes[16..18].copy_from_slice(&((28 + payload.len()) as u16).to_be_bytes());
    bytes[22] = 64;
    bytes[23] = 17;
    bytes[26..30].copy_from_slice(&[10, 0, 0, 5]);
    bytes[30..34].copy_from_slice(&[198, 51, 100, 10]);
    bytes[34..36].copy_from_slice(&40_000_u16.to_be_bytes());
    bytes[36..38].copy_from_slice(&45_001_u16.to_be_bytes());
    bytes[38..40].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    bytes.extend_from_slice(&payload);
    let tagged = |tpid: u16| {
        let mut raw = bytes.clone();
        raw.splice(12..12, [tpid, 20].into_iter().flat_map(u16::to_be_bytes));
        raw
    };
    let tagged_paths = split_tag_paths.then(|| [tagged(0x8100), tagged(0x88a8)]);

    for (index, ticks) in ticks.into_iter().enumerate() {
        let frame = index as u64 + 1;
        let raw = tagged_paths.as_ref().map_or(&bytes, |paths| &paths[index % 2]);
        let len = raw.len() as u32;
        let mut packet = parse_ethernet(raw, frame, ticks as f64 / 10.0);
        packet.capture = Some(CaptureMetadata {
            timestamp: Some(CaptureTimestamp {
                ticks,
                resolution: TimestampResolution::Decimal(1),
                offset_seconds: 0,
            }),
            captured_length: len,
            wire_length: len,
            link_type: 1,
            section_id: 0,
            interface_id: if split_interface {
                (frame % 2) as u32
            } else {
                0
            },
            interface_name: None,
            comments: vec![],
        });
        capture.write_packet(&packet).unwrap();
    }
    capture.flush().unwrap();
}

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn tcp_control_and_data_replay_distinguishes_an_upload_from_ack_only_traffic() {
    use serde_json::{Value, json};

    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let rule = "traffic.asymmetric_outbound";
    for (name, frames, flags, payload) in [
        ("acks", 19_000, 0x10, Vec::new()),
        ("upload", 17, 0x18, vec![0; 60_000]),
    ] {
        let mut writer = PcapNgWriter::create(&root.join(format!("{name}.pcapng"))).unwrap();
        for frame in 1..=frames {
            let mut packet = super::support::tcp(frame, frame as u32 * 60_000, flags, &payload, false);
            packet.bytes[26..34].copy_from_slice(&[10, 0, 0, 5, 198, 51, 100, 10]);
            packet.timestamp = frame as f64 / 10.0;
            writer.write_packet(&packet).unwrap();
        }
        writer.flush().unwrap();
    }
    let manifest = root.join("tcp-volume.json");
    let labels = json!({"version":1,"strict":true,"cases":[
        {"name":"ACK-only traffic","capture":"acks.pcapng","expect_counts":{(rule):0},"expect_snapshots":0},
        {"name":"outbound payload","capture":"upload.pcapng","expect_counts":{(rule):1},"expect_snapshots":1,
         "opening_frames":{(rule):[17]},
         "opening_evidence":[{"rule_id":rule,"opening_frame":17,"frames":(10..=17).collect::<Vec<_>>()}]}
    ]});
    std::fs::write(&manifest, labels.to_string()).unwrap();
    let baseline = std::env::var("PACKRAT_REPLAY_BASELINE_ANALYZER").ok();
    let output = super::run_suite_with_baseline(&manifest, baseline.as_deref());
    assert!(output.status.success(), "{}\n{}",
        String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["passed"], 2);
    assert_eq!(report["cases"][0]["summary"]["analyzed"], 19_000);
    if baseline.is_some() {
        println!("{}", String::from_utf8_lossy(&output.stdout));
    }
}

#[test]
#[ignore = "requires Bash and jq; run explicitly by Linux CI"]
fn outbound_entropy_replay_reports_separate_episodes() {
    use serde_json::{Value, json};

    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let entropy = "traffic.high_entropy_outbound";
    write_timed_fixture(
        &root.join("episodes.pcapng"),
        (1..=5).chain(36_210..=36_214),
        true,
        false,
    );
    let manifest = root.join("episodes.json");
    let labels = json!({"version":1, "strict":true, "cases":[{
        "name":"renewed outbound entropy", "capture":"episodes.pcapng",
        "expect_counts":{(entropy):2}, "opening_frames":{(entropy):[5,10]},
        "expect_snapshots":2
    }]});
    std::fs::write(&manifest, labels.to_string()).unwrap();
    let output = super::run_suite(&manifest);
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["passed"], 1);
}
