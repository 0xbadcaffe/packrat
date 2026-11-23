use super::*;

#[test]
fn archive_index_bounds_metadata_and_preserves_other_frames() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive");
    let mut writer = PacketArchive::open(&path).unwrap();
    let frame = |number| parse_ethernet(&[1, 2, 3], number, number as f64);
    writer.append(&[frame(1)]).unwrap();
    let mut oversized = frame(3);
    oversized.info = "x".repeat(reader::MAX_ARCHIVE_ROW_BYTES as usize * 2);
    assert!(writer.append(&[frame(2), oversized]).is_err());
    assert_eq!(writer.count().unwrap(), 1);
    assert_eq!(std::fs::metadata(path.join("packets.bin")).unwrap().len(), 3);

    writer.append(&[frame(2)]).unwrap();
    drop(writer);
    let index = Connection::open(path.join("index.sqlite")).unwrap();
    let mut oversized_metadata = frame(1);
    oversized_metadata.bytes.clear();
    oversized_metadata.info = "x".repeat(reader::MAX_ARCHIVE_ROW_BYTES as usize * 2);
    index.execute(
        "UPDATE packets SET metadata=?1 WHERE id=1",
        [serde_json::to_string(&oversized_metadata).unwrap()],
    ).unwrap();
    drop(index);

    let mut reader = PacketArchive::open_readonly(&path).unwrap();
    assert!(reader.packet(1).is_err());
    assert_eq!(reader.packet(2).unwrap().no, 2);
}
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

#[test]
fn scoped_archive_recovers_only_the_requested_capture_and_frame() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("archive");
    let path = archive.as_path();
    let legacy = parse_ethernet(&[1, 1], 7, 1.0);
    let first = parse_ethernet(&[2, 2], 7, 2.0);
    let second = parse_ethernet(&[3, 3], 7, 3.0);
    let mut worker = ArchiveWorker::open(path).unwrap();
    worker.record(&legacy).unwrap();
    worker.record_scoped(&Arc::from("capture-a"), &first).unwrap();
    worker.record_scoped(&Arc::from("capture-b"), &second).unwrap();
    worker.finish().unwrap();

    let mut reader = PacketArchive::open_readonly(path).unwrap();
    assert_eq!(reader.packet(1).unwrap().bytes, legacy.bytes);
    assert_eq!(reader.packet_for_capture("capture-a", 7).unwrap().unwrap().bytes, first.bytes);
    assert_eq!(reader.packet_for_capture("capture-b", 7).unwrap().unwrap().bytes, second.bytes);
    assert!(reader.packet_for_capture("capture-c", 7).unwrap().is_none());
    assert!(reader.packet_for_capture("capture-a", 8).unwrap().is_none());
    assert!(reader.packet_for_capture("", 7).is_err());

    let mut writer = PacketArchive::open(path).unwrap();
    let new_frame = parse_ethernet(&[4, 4], 8, 4.0);
    assert!(writer.append_scoped("capture-a", &[new_frame, second]).is_err());
    assert_eq!(writer.count().unwrap(), 3);
    assert_eq!(std::fs::metadata(path.join("packets.bin")).unwrap().len(), 6);
    assert!(reader.packet_for_capture("capture-a", 8).unwrap().is_none());
    assert_eq!(reader.packet_for_capture("capture-a", 7).unwrap().unwrap().bytes, first.bytes);
}

#[test]
fn scoped_lookup_rejects_wrong_capture_rows_with_the_same_frame_number() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive");
    let mut writer = PacketArchive::open(&path).unwrap();
    let frame = |value| parse_ethernet(&[value], 7, 1.0);
    writer.append_scoped("capture-a", &[frame(1)]).unwrap();
    writer.append_scoped("capture-b", &[frame(2)]).unwrap();
    writer.append(&[frame(3)]).unwrap();
    writer.append_scoped("legacy", &[frame(4)]).unwrap();
    let mut legacy = frame(4);
    legacy.bytes.clear();
    writer.db.execute("UPDATE packets SET metadata=?1 WHERE id=4", [serde_json::to_string(&legacy).unwrap()]).unwrap();
    let metadata: String = writer.db.query_row("SELECT metadata FROM packets WHERE id=2", [], |row| row.get(0)).unwrap();
    let old_reader_packet: Packet = serde_json::from_str(&metadata).unwrap();
    assert_eq!(old_reader_packet.no, 7);
    let mut reader = PacketArchive::open_readonly(&path).unwrap();
    assert_eq!(reader.packet_for_capture("legacy", 7).unwrap().unwrap().bytes, [4]);
    assert_eq!(reader.packet_for_capture("capture-a", 7).unwrap().unwrap().bytes, [1]);
    for wrong_row in [2, 3] {
        writer.db.execute("UPDATE capture_frames SET packet_id=?1 WHERE capture_id='capture-a'", [wrong_row]).unwrap();
        assert!(reader.packet_for_capture("capture-a", 7).unwrap_err().contains("scope"));
        assert_eq!(reader.packet_for_capture("capture-b", 7).unwrap().unwrap().bytes, [2]);
    }
}

#[test]
fn scoped_lookup_does_not_guess_for_legacy_archives() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("archive");
    let path = archive.as_path();
    let packet = parse_ethernet(&[1, 2, 3], 7, 1.0);
    let mut writer = PacketArchive::open(path).unwrap();
    writer.append(&[packet.clone()]).unwrap();
    writer.db.execute("DROP TABLE capture_frames", []).unwrap();
    drop(writer);

    let mut reader = PacketArchive::open_readonly(path).unwrap();
    assert_eq!(reader.packet(1).unwrap().bytes, packet.bytes);
    assert!(reader.packet_for_capture("capture-a", 7).unwrap().is_none());
    drop(reader);

    let mut writer = PacketArchive::open(path).unwrap();
    writer.append_scoped("capture-a", &[packet]).unwrap();
    assert_eq!(writer.count().unwrap(), 2);
    assert_eq!(writer.packet_for_capture("capture-a", 7).unwrap().unwrap().no, 7);
}

#[test]
fn archive_payload_cap_keeps_committed_evidence_and_never_overwrites() {
    let directory = tempfile::tempdir().unwrap();
    let archive = directory.path().join("archive");
    let limits = ArchiveLimits {
        max_payload_bytes: 7,
        reserve_free_bytes: 0,
        ..ArchiveLimits::default()
    };
    let frame = |number| parse_ethernet(&[1, 2, 3], number, number as f64);
    let mut worker = ArchiveWorker::open_with_limits(&archive, limits).unwrap();
    for number in 1..=9 {
        worker.record(&frame(number)).unwrap();
    }
    worker.finish().unwrap();
    assert_eq!(worker.pause_reason(), Some("packet-byte limit reached"));
    assert_eq!(worker.pause_code(), Some("byte_limit"));
    assert_eq!(worker.usage().unwrap().payload_bytes, 6);
    assert_eq!(worker.usage().unwrap().frames, 2);
    assert_eq!(worker.usage().unwrap().max_payload_bytes, 7);
    assert_eq!(worker.take_pause_notice(), worker.pause_reason());
    assert_eq!(worker.take_pause_notice(), None);
    worker.record(&frame(10)).unwrap();

    let mut worker = ArchiveWorker::open_with_limits(&archive, limits).unwrap();
    assert_eq!(worker.usage().unwrap().frames, 2);
    worker.record(&frame(11)).unwrap();
    worker.finish().unwrap();
    assert_eq!(worker.pause_reason(), Some("packet-byte limit reached"));
    let mut reader = PacketArchive::open_readonly(&archive).unwrap();
    assert_eq!(reader.count().unwrap(), 2);
    assert_eq!(reader.packet(2).unwrap().no, 2);
    assert_eq!(std::fs::metadata(archive.join("packets.bin")).unwrap().len(), 6);
}

#[test]
fn archive_pauses_before_using_the_free_space_reserve() {
    let directory = tempfile::tempdir().unwrap();
    let archive = directory.path().join("archive");
    let limits = ArchiveLimits {
        reserve_free_bytes: u64::MAX,
        ..ArchiveLimits::default()
    };
    let mut worker = ArchiveWorker::open_with_limits(&archive, limits).unwrap();
    worker.record(&parse_ethernet(&[1, 2, 3], 1, 1.0)).unwrap();
    worker.finish().unwrap();
    assert_eq!(worker.pause_reason(), Some("filesystem free-space reserve reached"));
    assert_eq!(worker.pause_code(), Some("disk_reserve"));
    assert_eq!(PacketArchive::open_readonly(&archive).unwrap().count().unwrap(), 0);
}

#[test]
fn alert_archive_deduplicates_queued_and_committed_frames_without_crossing_capture_ids() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("evidence");
    let scope_a: Arc<str> = "capture-a".into();
    let scope_b: Arc<str> = "capture-b".into();
    let frame_a = parse_ethernet(&[1, 2, 3], 1, 1.0);
    let frame_b = parse_ethernet(&[4, 5, 6], 1, 1.0);
    let limits = ArchiveLimits { max_frames: 2, reserve_free_bytes: 0, ..ArchiveLimits::default() };
    let mut writer = ArchiveWorker::open_alert_evidence(&path, limits).unwrap();
    for _ in 0..4 {
        writer.record_scoped(&scope_a, &frame_a).unwrap();
    }
    writer.finish().unwrap();
    assert_eq!(writer.pause_reason(), None);
    assert_eq!(writer.usage().unwrap().frames, 1);

    let mut writer = ArchiveWorker::open_alert_evidence(&path, limits).unwrap();
    writer.record_scoped(&scope_a, &frame_a).unwrap();
    writer.record_scoped(&scope_b, &frame_b).unwrap();
    writer.finish().unwrap();
    assert_eq!(writer.pause_reason(), Some("frame limit reached"));
    assert_eq!(writer.pause_code(), Some("frame_limit"));
    let mut reader = PacketArchive::open_readonly(&path).unwrap();
    assert_eq!(reader.count().unwrap(), 2);
    assert_eq!(reader.packet_for_capture(&scope_a, 1).unwrap().unwrap().bytes, frame_a.bytes);
    assert_eq!(reader.packet_for_capture(&scope_b, 1).unwrap().unwrap().bytes, frame_b.bytes);
}

#[test]
fn archive_worker_failure_sets_a_stable_pause_code() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("evidence");
    let mut worker = ArchiveWorker::open_alert_evidence(&path, ArchiveLimits::default()).unwrap();
    worker.record(&parse_ethernet(&[1, 2, 3], 1, 1.0)).unwrap();
    assert!(worker.finish().unwrap_err().contains("requires capture scope"));
    assert_eq!(worker.pause_reason(), Some("archive write failed"));
    assert_eq!(worker.pause_code(), Some("write_failed"));
}

#[test]
fn archive_policy_cannot_change_on_reopen_but_either_mode_can_be_read() {
    let dir = tempfile::tempdir().unwrap();
    let full = dir.path().join("full");
    let selective = dir.path().join("selective");
    drop(PacketArchive::open(&full).unwrap());
    let mut worker = ArchiveWorker::open_alert_evidence(&selective, ArchiveLimits::default()).unwrap();
    let frame = parse_ethernet(&[1, 2, 3], 1, 1.0);
    worker.record_scoped(&Arc::from("scope"), &frame).unwrap();
    worker.finish().unwrap();

    let error = ArchiveWorker::open_alert_evidence(&full, ArchiveLimits::default()).err().unwrap();
    assert!(error.contains("all_packets, cannot open for alert_evidence"), "{error}");
    let error = PacketArchive::open(&selective).err().unwrap();
    assert!(error.contains("alert_evidence, cannot open for all_packets"), "{error}");
    assert_eq!(PacketArchive::open_readonly(&full).unwrap().count().unwrap(), 0);
    let mut reader = PacketArchive::open_readonly(&selective).unwrap();
    assert_eq!(reader.packet_for_capture("scope", 1).unwrap().unwrap().bytes, frame.bytes);
}

#[test]
fn legacy_archives_with_frames_or_unindexed_bytes_cannot_be_claimed_as_alert_only() {
    let dir = tempfile::tempdir().unwrap();
    for indexed in [false, true] {
        let path = dir.path().join(if indexed { "indexed" } else { "interrupted" });
        let mut writer = PacketArchive::open(&path).unwrap();
        if indexed {
            writer.append(&[parse_ethernet(&[1, 2, 3], 1, 1.0)]).unwrap();
        }
        writer.db.execute("DROP TABLE archive_retention", []).unwrap();
        drop(writer);
        if !indexed {
            std::fs::write(path.join("packets.bin"), [1, 2, 3]).unwrap();
        }
        let error = ArchiveWorker::open_alert_evidence(&path, ArchiveLimits::default()).err().unwrap();
        assert!(error.contains("legacy archive with existing packet data"), "{error}");
        assert_eq!(std::fs::read(path.join("packets.bin")).unwrap(), [1, 2, 3]);
        assert_eq!(PacketArchive::open(&path).unwrap().count().unwrap(), u64::from(indexed));
    }
}

#[cfg(unix)]
#[test]
fn writable_archives_require_a_private_real_directory() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let directory = tempfile::tempdir().unwrap();
    let archive = directory.path().join("archive");
    std::fs::create_dir(&archive).unwrap();
    std::fs::set_permissions(&archive, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(PacketArchive::open(&archive).err().unwrap().contains("private"));
    assert!(std::fs::read_dir(&archive).unwrap().next().is_none());
    std::fs::set_permissions(&archive, std::fs::Permissions::from_mode(0o700)).unwrap();
    let redirected = directory.path().join("redirected");
    symlink(&archive, &redirected).unwrap();
    assert!(PacketArchive::open(&redirected.join("")).is_err());
    assert!(std::fs::read_dir(&archive).unwrap().next().is_none());
    assert!(PacketArchive::open(&archive).is_ok());
}

#[cfg(unix)]
#[test]
fn writable_archives_reject_redirected_or_public_evidence_files() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let directory = tempfile::tempdir().unwrap();
    let archive = directory.path().join("archive");
    drop(PacketArchive::open(&archive).unwrap());
    let packets = archive.join("packets.bin");
    std::fs::write(&packets, b"original bytes").unwrap();
    std::fs::set_permissions(&packets, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(PacketArchive::open(&archive).is_err());
    assert_eq!(std::fs::read(&packets).unwrap(), b"original bytes");
    let sidecar = archive.join("index.sqlite-wal");
    std::fs::set_permissions(&packets, std::fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&packets, &sidecar).unwrap();
    assert!(PacketArchive::open(&archive).is_err());
    std::fs::remove_file(&sidecar).unwrap();
    let other = directory.path().join("linked-bytes");
    std::fs::hard_link(&packets, &other).unwrap();
    assert!(PacketArchive::open(&archive).is_err());
    assert_eq!(std::fs::read(&other).unwrap(), b"original bytes");
}
