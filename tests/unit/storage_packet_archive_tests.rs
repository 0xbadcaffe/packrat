use super::*;
use crate::net::parser::parse_ethernet;

#[test]
fn active_archive_allows_readers_and_rejects_another_writer() {
    let path = std::env::temp_dir().join(format!("packrat-concurrent-{}", rand::random::<u64>()));
    let mut writer = PacketArchive::open(&path).unwrap();
    let reader = PacketArchive::open_readonly(&path).unwrap();
    assert_eq!(reader.count().unwrap(), 0);
    writer.append(&[parse_ethernet(&[1, 2, 3], 1, 1.0)]).unwrap();
    assert_eq!(reader.count().unwrap(), 1);
    assert!(PacketArchive::open(&path).is_err());
    drop(reader);
    drop(writer);
    assert!(PacketArchive::open(&path).is_ok());
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn background_worker_flushes_all_accepted_records_before_shutdown() {
    let path = std::env::temp_dir().join(format!("packrat-worker-{}", rand::random::<u64>()));
    let mut worker = ArchiveWorker::open(&path).unwrap();
    for number in 1..=100 {
        worker.record(&parse_ethernet(&[1, 2, 3], number, number as f64)).unwrap();
    }
    worker.finish().unwrap();
    let mut archive = PacketArchive::open_readonly(&path).unwrap();
    assert_eq!(archive.count().unwrap(), 100);
    assert_eq!(archive.packet(100).unwrap().no, 100);
    assert_eq!(archive.find_host("?.?.?.?", 98, 10).unwrap(), vec![99, 100]);
    assert!(archive.find_host("' OR 1=1 --", 0, 10).unwrap().is_empty());
    drop(archive);
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn readonly_inspection_preserves_uncommitted_bytes() {
    let path = std::env::temp_dir().join(format!("packrat-readonly-{}", rand::random::<u64>()));
    drop(PacketArchive::open(&path).unwrap());
    std::fs::write(path.join("packets.bin"), b"recovery-evidence").unwrap();
    let archive = PacketArchive::open_readonly(&path).unwrap();
    assert_eq!(archive.count().unwrap(), 0);
    assert_eq!(std::fs::read(path.join("packets.bin")).unwrap(), b"recovery-evidence");
    drop(archive);
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn archive_round_trip_recovers_uncommitted_tail_and_detects_tampering() {
    let path = std::env::temp_dir().join(format!(
        "packrat-archive-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    let packet = parse_ethernet(&[1, 2, 3, 4], 9, 1.0);
    {
        let mut archive = PacketArchive::open(&path).unwrap();
        archive.append(&[packet.clone()]).unwrap();
        assert_eq!(archive.count().unwrap(), 1);
        assert_eq!(archive.packet(1).unwrap().bytes, packet.bytes);
    }
    OpenOptions::new()
        .append(true)
        .open(path.join("packets.bin"))
        .unwrap()
        .write_all(b"uncommitted")
        .unwrap();
    let mut archive = PacketArchive::open(&path).unwrap();
    assert_eq!(
        std::fs::metadata(path.join("packets.bin")).unwrap().len(),
        4
    );
    assert_eq!(archive.packet(1).unwrap().no, 9);
    OpenOptions::new()
        .write(true)
        .open(path.join("packets.bin"))
        .unwrap()
        .write_all(b"X")
        .unwrap();
    assert!(archive.packet(1).unwrap_err().contains("integrity"));
    drop(archive);
    std::fs::remove_dir_all(path).unwrap();
}
