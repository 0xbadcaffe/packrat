//! Durable packet bytes and a transactional, rebuildable metadata index.

use crate::net::packet::Packet;
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

pub struct PacketArchive {
    db: Connection,
    bytes: File,
    _writer_guard: Option<File>,
}

fn private_file(path: &Path) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)] {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(|error| error.to_string())
}

impl PacketArchive {
    pub fn open_readonly(directory: &Path) -> Result<Self, String> {
        let db = Connection::open_with_flags(
            directory.join("index.sqlite"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .map_err(|error| error.to_string())?;
        let bytes = File::open(directory.join("packets.bin")).map_err(|error| error.to_string())?;
        Ok(Self { db, bytes, _writer_guard: None })
    }

    pub fn open(directory: &Path) -> Result<Self, String> {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)] {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(directory).map_err(|error| error.to_string())?;
        let guard = private_file(&directory.join("writer.lock"))?;
        fs2::FileExt::try_lock_exclusive(&guard).map_err(|error| format!("Archive already has a writer: {error}"))?;
        drop(private_file(&directory.join("index.sqlite"))?);
        let db =
            Connection::open(directory.join("index.sqlite")).map_err(|error| error.to_string())?;
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
            CREATE INDEX IF NOT EXISTS packet_destination ON packets(destination, timestamp);",
        )
        .map_err(|error| error.to_string())?;
        let bytes = private_file(&directory.join("packets.bin"))?;
        let end: i64 = db
            .query_row(
                "SELECT COALESCE(MAX(byte_offset + byte_length), 0) FROM packets",
                [],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        let end = u64::try_from(end).map_err(|_| "Invalid archive offset")?;
        if bytes.metadata().map_err(|error| error.to_string())?.len() < end {
            return Err("Packet archive is truncated: committed bytes are missing".into());
        }
        // A crash before the SQLite commit can leave an unindexed tail.
        bytes.set_len(end).map_err(|error| error.to_string())?;
        Ok(Self { db, bytes, _writer_guard: Some(guard) })
    }

    pub fn append(&mut self, packets: &[Packet]) -> Result<(), String> {
        if packets
            .iter()
            .any(|packet| !packet.timestamp.is_finite() || packet.bytes.len() > 1_048_576)
        {
            return Err("Invalid packet timestamp or archive record length".into());
        }
        let transaction = self.db.transaction().map_err(|error| error.to_string())?;
        let mut offset = self
            .bytes
            .seek(SeekFrom::End(0))
            .map_err(|error| error.to_string())?;
        for packet in packets {
            let mut metadata = packet.clone();
            metadata.bytes.clear();
            let metadata = serde_json::to_string(&metadata).map_err(|error| error.to_string())?;
            let digest = format!("{:x}", Sha256::digest(&packet.bytes));
            self.bytes
                .write_all(&packet.bytes)
                .map_err(|error| error.to_string())?;
            transaction.execute("INSERT INTO packets(frame_number,timestamp,source,destination,protocol,byte_offset,byte_length,sha256,metadata)
                VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)", params![packet.no.to_string(), packet.timestamp,
                packet.src, packet.dst, packet.protocol, i64::try_from(offset).map_err(|_| "Archive offset exceeds SQLite range")?, packet.bytes.len() as i64, digest, metadata])
                .map_err(|error| error.to_string())?;
            offset += packet.bytes.len() as u64;
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
}

pub struct ArchiveWorker {
    sender: Option<std::sync::mpsc::SyncSender<Packet>>,
    worker: Option<std::thread::JoinHandle<Result<(), String>>>,
}

impl ArchiveWorker {
    pub fn open(directory: &Path) -> Result<Self, String> {
        let mut archive = PacketArchive::open(directory)?;
        let (sender, receiver) = std::sync::mpsc::sync_channel::<Packet>(4096);
        let worker = std::thread::spawn(move || {
            while let Ok(first) = receiver.recv() {
                let mut batch = vec![first];
                batch.extend(receiver.try_iter().take(255));
                archive.append(&batch)?;
            }
            Ok(())
        });
        Ok(Self {
            sender: Some(sender),
            worker: Some(worker),
        })
    }

    pub fn record(&self, packet: &Packet) -> Result<(), String> {
        self.sender
            .as_ref()
            .ok_or("Archive closed")?
            .try_send(packet.clone())
            .map_err(|error| format!("Packet archive unavailable or queue full: {error}"))
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
