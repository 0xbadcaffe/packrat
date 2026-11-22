//! Durable packet bytes and a transactional, rebuildable metadata index.

use crate::net::packet::Packet;
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

#[path = "packet_archive_policy.rs"]
mod policy;
#[path = "packet_archive_reader.rs"]
mod reader;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchiveLimits {
    pub max_payload_bytes: u64,
    pub max_frames: u64,
    pub reserve_free_bytes: u64,
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            max_payload_bytes: 256 * 1024 * 1024,
            max_frames: 100_000,
            reserve_free_bytes: 512 * 1024 * 1024,
        }
    }
}

pub struct PacketArchive {
    db: Connection,
    bytes: File,
    _writer_guard: Option<File>,
}

fn validate_archive_entry(path: &Path, metadata: &std::fs::Metadata, directory: bool) -> Result<(), String> {
    let valid_type = if directory { metadata.is_dir() } else { metadata.is_file() };
    if !valid_type {
        return Err(format!("Archive entry must be a real directory or regular file: {}", path.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no arguments or caller invariants.
        let owner = unsafe { libc::geteuid() };
        if metadata.uid() != owner || metadata.mode() & 0o077 != 0 || (!directory && metadata.nlink() != 1) {
            return Err(format!(
                "Archive entry must be private, owned by the archive writer, and not shared by hard links: {}",
                path.display(),
            ));
        }
    }
    Ok(())
}

fn check_existing_archive_file(path: &Path) -> Result<(), String> {
    match path.symlink_metadata() {
        Ok(metadata) => validate_archive_entry(path, &metadata, false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("Stat archive entry {}: {error}", path.display())),
    }
}

fn private_file(path: &Path) -> Result<File, String> {
    check_existing_archive_file(path)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)] {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|error| format!("Open archive entry {}: {error}", path.display()))?;
    validate_archive_entry(path, &file.metadata().map_err(|error| error.to_string())?, false)?;
    Ok(file)
}

impl PacketArchive {
    pub fn open_readonly(directory: &Path) -> Result<Self, String> {
        let (db, bytes) = reader::open_entries(directory)?;
        Ok(Self { db, bytes, _writer_guard: None })
    }

    pub fn open(directory: &Path) -> Result<Self, String> {
        Self::open_for_policy(directory, false)
    }

    fn open_for_policy(directory: &Path, alert_only: bool) -> Result<Self, String> {
        // Strip trailing separators before testing the directory itself, not its target.
        let directory = directory.components().collect::<PathBuf>();
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)] {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&directory).map_err(|error| error.to_string())?;
        let metadata = directory.symlink_metadata().map_err(|error| error.to_string())?;
        validate_archive_entry(&directory, &metadata, true)?;
        // SQLite's no-follow flag also covers parent components such as macOS /var.
        #[cfg(unix)]
        let directory = directory.canonicalize().map_err(|error| error.to_string())?;
        let guard = private_file(&directory.join("writer.lock"))?;
        fs2::FileExt::try_lock_exclusive(&guard).map_err(|error| format!("Archive already has a writer: {error}"))?;
        for sidecar in ["index.sqlite-wal", "index.sqlite-shm", "index.sqlite-journal"] {
            check_existing_archive_file(&directory.join(sidecar))?;
        }
        let index = directory.join("index.sqlite");
        drop(private_file(&index)?);
        let bytes = private_file(&directory.join("packets.bin"))?;
        let mut db = Connection::open_with_flags(
            index,
            rusqlite::OpenFlags::default() | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        ).map_err(|error| error.to_string())?;
        db.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|error| error.to_string())?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY, frame_number TEXT NOT NULL,
                timestamp REAL NOT NULL, source TEXT NOT NULL, destination TEXT NOT NULL,
                protocol TEXT NOT NULL, byte_offset INTEGER NOT NULL,
                byte_length INTEGER NOT NULL, sha256 TEXT NOT NULL, metadata TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS packet_time ON packets(timestamp);
            CREATE INDEX IF NOT EXISTS packet_source ON packets(source, timestamp);
            CREATE INDEX IF NOT EXISTS packet_destination ON packets(destination, timestamp);
            CREATE TABLE IF NOT EXISTS capture_frames (
                capture_id TEXT NOT NULL, frame_number TEXT NOT NULL,
                packet_id INTEGER NOT NULL REFERENCES packets(id),
                PRIMARY KEY (capture_id, frame_number));",
        )
        .map_err(|error| error.to_string())?;
        let end: i64 = db
            .query_row(
                "SELECT COALESCE(MAX(byte_offset + byte_length), 0) FROM packets",
                [],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        let end = u64::try_from(end).map_err(|_| "Invalid archive offset")?;
        let length = bytes.metadata().map_err(|error| error.to_string())?.len();
        if length < end {
            return Err("Packet archive is truncated: committed bytes are missing".into());
        }
        policy::bind(&mut db, alert_only, length != 0)?;
        // A crash before the SQLite commit can leave an unindexed tail.
        bytes.set_len(end).map_err(|error| error.to_string())?;
        Ok(Self { db, bytes, _writer_guard: Some(guard) })
    }

    pub fn append(&mut self, packets: &[Packet]) -> Result<(), String> {
        self.append_entries(packets.iter().map(|packet| (None, packet)))
    }

    pub fn append_scoped(&mut self, capture_id: &str, packets: &[Packet]) -> Result<(), String> {
        if !valid_capture_id(capture_id) {
            return Err("Invalid archive capture ID".into());
        }
        self.append_entries(packets.iter().map(|packet| (Some(capture_id), packet)))
    }

    fn append_entries<'a>(
        &mut self,
        entries: impl Iterator<Item = (Option<&'a str>, &'a Packet)> + Clone,
    ) -> Result<(), String> {
        if entries
            .clone()
            .any(|(scope, _)| scope.is_some_and(|id| !valid_capture_id(id)))
        {
            return Err("Invalid archive capture ID".into());
        }
        if entries
            .clone()
            .any(|(_, packet)| !packet.timestamp.is_finite() || packet.bytes.len() > 1_048_576)
        {
            return Err("Invalid packet timestamp or archive record length".into());
        }
        let transaction = self.db.transaction().map_err(|error| error.to_string())?;
        let mut offset = self
            .bytes
            .seek(SeekFrom::End(0))
            .map_err(|error| error.to_string())?;
        for (capture_id, packet) in entries.clone() {
            let mut metadata = packet.clone();
            metadata.bytes.clear();
            let metadata = serde_json::to_string(&metadata).map_err(|error| error.to_string())?;
            let digest = format!("{:x}", Sha256::digest(&packet.bytes));
            let frame_number = packet.no.to_string();
            transaction.execute("INSERT INTO packets(frame_number,timestamp,source,destination,protocol,byte_offset,byte_length,sha256,metadata)
                VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)", params![frame_number, packet.timestamp,
                packet.src, packet.dst, packet.protocol, i64::try_from(offset).map_err(|_| "Archive offset exceeds SQLite range")?, packet.bytes.len() as i64, digest, metadata])
                .map_err(|error| error.to_string())?;
            if let Some(capture_id) = capture_id {
                transaction.execute(
                    "INSERT INTO capture_frames(capture_id,frame_number,packet_id) VALUES (?1,?2,?3)",
                    params![capture_id, frame_number, transaction.last_insert_rowid()],
                ).map_err(|error| format!("Index archived capture frame: {error}"))?;
            }
            offset += packet.bytes.len() as u64;
        }
        for (_, packet) in entries {
            self.bytes
                .write_all(&packet.bytes)
                .map_err(|error| error.to_string())?;
        }
        self.bytes.sync_data().map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())
    }

    pub fn count(&self) -> Result<u64, String> {
        let count: i64 = self.db
            .query_row("SELECT COUNT(*) FROM packets", [], |row| row.get(0))
            .map_err(|error| error.to_string())?;
        u64::try_from(count).map_err(|_| "Invalid archive count".into())
    }

    pub fn find_host(&self, address: &str, after_id: i64, limit: usize) -> Result<Vec<i64>, String> {
        let mut statement = self.db.prepare(
            "SELECT id FROM packets WHERE (source=?1 OR destination=?1) AND id>?2 ORDER BY id LIMIT ?3"
        ).map_err(|error| error.to_string())?;
        let rows = statement.query_map(params![address, after_id, limit.clamp(1, 1000) as i64], |row| row.get(0))
            .map_err(|error| error.to_string())?;
        rows.collect::<rusqlite::Result<Vec<i64>>>().map_err(|error| error.to_string())
    }

    pub fn packet_ids(&self, after_id: i64, limit: usize) -> Result<Vec<i64>, String> {
        let mut statement = self.db.prepare("SELECT id FROM packets WHERE id>?1 ORDER BY id LIMIT ?2")
            .map_err(|error| error.to_string())?;
        let rows = statement.query_map(params![after_id, limit.clamp(1, 1000) as i64], |row| row.get(0))
            .map_err(|error| error.to_string())?;
        rows.collect::<rusqlite::Result<Vec<i64>>>().map_err(|error| error.to_string())
    }

    pub fn packet(&mut self, id: i64) -> Result<Packet, String> {
        let (offset, length, digest, metadata): (i64, i64, String, String) = self
            .db
            .query_row(
                "SELECT byte_offset,byte_length,sha256,metadata FROM packets WHERE id=?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(|error| error.to_string())?;
        if !(0..=1_048_576).contains(&length) || offset < 0 {
            return Err("Invalid archived packet length".into());
        }
        let mut bytes = vec![0; length as usize];
        self.bytes
            .seek(SeekFrom::Start(offset as u64))
            .map_err(|error| error.to_string())?;
        self.bytes
            .read_exact(&mut bytes)
            .map_err(|error| error.to_string())?;
        if format!("{:x}", Sha256::digest(&bytes)) != digest {
            return Err("Packet archive integrity check failed".into());
        }
        let mut packet: Packet =
            serde_json::from_str(&metadata).map_err(|error| error.to_string())?;
        packet.bytes = bytes;
        Ok(packet)
    }

    pub fn packet_for_capture(
        &mut self,
        capture_id: &str,
        frame_number: u64,
    ) -> Result<Option<Packet>, String> {
        if !valid_capture_id(capture_id) {
            return Err("Invalid archive capture ID".into());
        }
        let has_scoped_index: bool = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='capture_frames')",
            [],
            |row| row.get(0),
        ).map_err(|error| error.to_string())?;
        if !has_scoped_index {
            return Ok(None);
        }
        let id = self.db.query_row(
            "SELECT packet_id FROM capture_frames WHERE capture_id=?1 AND frame_number=?2",
            params![capture_id, frame_number.to_string()],
            |row| row.get(0),
        ).optional().map_err(|error| error.to_string())?;
        let Some(id) = id else { return Ok(None) };
        let packet = self.packet(id)?;
        if packet.no != frame_number {
            return Err("Archive capture index points to a different frame".into());
        }
        Ok(Some(packet))
    }
}

pub(crate) fn valid_capture_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

pub struct ArchiveWorker {
    directory: PathBuf,
    sender: Option<std::sync::mpsc::SyncSender<ArchiveRecord>>,
    worker: Option<std::thread::JoinHandle<Result<(), String>>>,
    pause_reason: Arc<OnceLock<&'static str>>,
    pause_reported: bool,
    alert_evidence_only: bool,
}

struct ArchiveRecord {
    capture_id: Option<Arc<str>>,
    packet: Packet,
}

impl ArchiveWorker {
    pub fn open(directory: &Path) -> Result<Self, String> {
        Self::open_with_limits(directory, ArchiveLimits::default())
    }

    pub fn open_with_limits(directory: &Path, limits: ArchiveLimits) -> Result<Self, String> {
        Self::open_with_policy(directory, limits, false)
    }

    pub fn open_alert_evidence(directory: &Path, limits: ArchiveLimits) -> Result<Self, String> {
        Self::open_with_policy(directory, limits, true)
    }

    fn open_with_policy(directory: &Path, limits: ArchiveLimits, alert_evidence_only: bool) -> Result<Self, String> {
        let mut archive = PacketArchive::open_for_policy(directory, alert_evidence_only)?;
        let mut frames = archive.count()?;
        let mut bytes = archive.bytes.metadata().map_err(|error| error.to_string())?.len();
        let pause_reason = Arc::new(OnceLock::new());
        let worker_pause = Arc::clone(&pause_reason);
        let worker_directory = directory.to_owned();
        let (sender, receiver) = std::sync::mpsc::sync_channel::<ArchiveRecord>(4096);
        let worker = std::thread::spawn(move || {
            while let Ok(first) = receiver.recv() {
                let mut batch = vec![first];
                batch.extend(receiver.try_iter().take(255));
                if alert_evidence_only {
                    let mut seen = std::collections::HashSet::new();
                    let mut unique = Vec::with_capacity(batch.len());
                    for record in batch {
                        let scope = record.capture_id.as_ref().ok_or("Alert archive requires capture scope")?;
                        if seen.insert((Arc::clone(scope), record.packet.no)) && !archive.contains_frame(scope, record.packet.no)? {
                            unique.push(record);
                        }
                    }
                    if unique.is_empty() {
                        continue;
                    }
                    batch = unique;
                }
                let available =
                    fs2::available_space(&worker_directory).map_err(|error| error.to_string())?;
                let writable = available.saturating_sub(limits.reserve_free_bytes);
                let mut pending_bytes = 0_u64;
                let mut allowed = 0;
                let mut reason = None;
                for record in &batch {
                    let next = pending_bytes.saturating_add(record.packet.bytes.len() as u64);
                    if frames.saturating_add(allowed as u64) >= limits.max_frames {
                        reason = Some("frame limit reached");
                    } else if bytes.saturating_add(next) > limits.max_payload_bytes {
                        reason = Some("packet-byte limit reached");
                    // Leave headroom for SQLite index pages and the WAL.
                    } else if next.saturating_add((allowed as u64 + 1) * 64 * 1024) > writable {
                        reason = Some("filesystem free-space reserve reached");
                    }
                    if reason.is_some() {
                        break;
                    }
                    pending_bytes = next;
                    allowed += 1;
                }
                if allowed > 0 {
                    archive.append_entries(
                        batch[..allowed]
                            .iter()
                            .map(|record| (record.capture_id.as_deref(), &record.packet)),
                    )?;
                    frames += allowed as u64;
                    bytes += pending_bytes;
                }
                let reason = reason.or_else(|| {
                    if frames >= limits.max_frames {
                        Some("frame limit reached")
                    } else if bytes >= limits.max_payload_bytes {
                        Some("packet-byte limit reached")
                    } else {
                        None
                    }
                });
                if let Some(reason) = reason {
                    let _ = worker_pause.set(reason);
                    break;
                }
            }
            Ok(())
        });
        Ok(Self {
            directory: directory.to_owned(),
            sender: Some(sender),
            worker: Some(worker),
            pause_reason,
            pause_reported: false,
            alert_evidence_only,
        })
    }

    pub(crate) fn alert_evidence_only(&self) -> bool {
        self.alert_evidence_only
    }

    pub(crate) fn pause(&self, reason: &'static str) {
        let _ = self.pause_reason.set(reason);
    }

    pub fn pause_reason(&self) -> Option<&'static str> {
        self.pause_reason.get().copied()
    }

    pub(crate) fn take_pause_notice(&mut self) -> Option<&'static str> {
        let reason = self.pause_reason()?;
        if self.pause_reported {
            return None;
        }
        self.pause_reported = true;
        Some(reason)
    }

    pub(crate) fn reader(&self) -> Result<PacketArchive, String> {
        let archive = PacketArchive::open_readonly(&self.directory)?;
        archive.db.busy_timeout(std::time::Duration::ZERO).map_err(|error| error.to_string())?;
        Ok(archive)
    }

    pub fn record(&self, packet: &Packet) -> Result<(), String> {
        self.queue_packet(None, packet)
    }

    pub fn record_scoped(&self, capture_id: &Arc<str>, packet: &Packet) -> Result<(), String> {
        if !valid_capture_id(capture_id) {
            return Err("Invalid archive capture ID".into());
        }
        self.queue_packet(Some(Arc::clone(capture_id)), packet)
    }

    fn queue_packet(&self, capture_id: Option<Arc<str>>, packet: &Packet) -> Result<(), String> {
        if self.pause_reason().is_some() {
            return Ok(());
        }
        let result = self.sender
            .as_ref()
            .ok_or("Archive closed")?
            .try_send(ArchiveRecord {
                capture_id,
                packet: packet.clone(),
            });
        if self.pause_reason().is_some() {
            return Ok(());
        }
        result.map_err(|error| format!("Packet archive unavailable or queue full: {error}"))
    }

    pub fn poll_error(&mut self) -> Option<String> {
        if self
            .worker
            .as_ref()
            .is_some_and(|worker| worker.is_finished())
        {
            self.finish().err()
        } else {
            None
        }
    }

    pub fn finish(&mut self) -> Result<(), String> {
        self.sender.take();
        match self.worker.take() {
            Some(worker) => worker
                .join()
                .map_err(|_| "Packet archive worker panicked".to_string())?,
            None => Ok(()),
        }
    }
}

impl Drop for ArchiveWorker {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

#[cfg(test)]
#[path = "../../tests/unit/storage_packet_archive_tests.rs"]
mod tests;
