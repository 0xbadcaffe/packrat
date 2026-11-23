use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use rusqlite::limits::Limit;
use sha2::{Digest, Sha256};
use std::fs::{File, Metadata, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use super::{PacketArchive, valid_capture_id};
use crate::net::packet::Packet;

pub(super) const MAX_ARCHIVE_ROW_BYTES: i32 = 256 * 1024;

#[derive(serde::Serialize, serde::Deserialize)]
struct PacketMetadata {
    #[serde(flatten)]
    packet: Packet,
    // An absent wrapper is a legacy row; a wrapper with no ID is explicitly unscoped.
    #[serde(default)]
    archive_origin: Option<ArchiveOrigin>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ArchiveOrigin {
    capture_id: Option<String>,
}

pub(super) fn encode_metadata(packet: &Packet, capture_id: Option<&str>) -> Result<String, String> {
    let mut packet = packet.clone();
    packet.bytes.clear();
    let archive_origin = Some(ArchiveOrigin { capture_id: capture_id.map(str::to_owned) });
    serde_json::to_string(&PacketMetadata { packet, archive_origin }).map_err(|error| error.to_string())
}

impl PacketArchive {
    pub fn packet(&mut self, id: i64) -> Result<Packet, String> {
        self.read_packet(id, None)
    }

    fn read_packet(&mut self, id: i64, scope: Option<&str>) -> Result<Packet, String> {
        let (offset, length, digest, metadata): (i64, i64, String, String) = self.db.query_row(
            "SELECT byte_offset,byte_length,sha256,metadata FROM packets WHERE id=?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).map_err(|error| error.to_string())?;
        if !(0..=1_048_576).contains(&length) || offset < 0 {
            return Err("Invalid archived packet length".into());
        }
        let PacketMetadata { mut packet, archive_origin } =
            serde_json::from_str(&metadata).map_err(|error| error.to_string())?;
        if let Some((expected, origin)) = scope.zip(archive_origin)
            && origin.capture_id.as_deref() != Some(expected)
        {
            return Err("Archive capture index points to a different capture scope".into());
        }
        let mut bytes = vec![0; length as usize];
        self.bytes.seek(SeekFrom::Start(offset as u64)).map_err(|error| error.to_string())?;
        self.bytes.read_exact(&mut bytes).map_err(|error| error.to_string())?;
        if format!("{:x}", Sha256::digest(&bytes)) != digest {
            return Err("Packet archive integrity check failed".into());
        }
        packet.bytes = bytes;
        Ok(packet)
    }

    pub fn packet_for_capture(&mut self, capture_id: &str, frame_number: u64) -> Result<Option<Packet>, String> {
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
        let packet = self.read_packet(id, Some(capture_id))?;
        if packet.no != frame_number {
            return Err("Archive capture index points to a different frame".into());
        }
        Ok(Some(packet))
    }
}

pub(super) fn open_index(path: &Path, flags: OpenFlags) -> Result<Connection, String> {
    let db = Connection::open_with_flags(path, flags | OpenFlags::SQLITE_OPEN_NOFOLLOW)
        .map_err(|error| error.to_string())?;
    // Packet bytes live outside SQLite. Only bounded metadata should enter or leave the index.
    db.set_limit(Limit::SQLITE_LIMIT_LENGTH, MAX_ARCHIVE_ROW_BYTES)
        .map_err(|error| error.to_string())?;
    Ok(db)
}

fn validate_type(path: &Path, metadata: &Metadata, directory: bool) -> Result<(), String> {
    let valid = if directory { metadata.is_dir() } else { metadata.is_file() };
    if !valid {
        return Err(format!("Archive entry is not a real directory or regular file: {}", path.display()));
    }
    Ok(())
}

fn check_entry(path: &Path, directory: bool, optional: bool) -> Result<(), String> {
    match path.symlink_metadata() {
        Ok(metadata) => validate_type(path, &metadata, directory),
        Err(error) if optional && error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("Stat archive entry {}: {error}", path.display())),
    }
}

pub(super) fn open_entries(directory: &Path) -> Result<(Connection, File), String> {
    let directory = directory.components().collect::<PathBuf>();
    check_entry(&directory, true, false)?;
    // SQLite's no-follow option also checks parent components, such as macOS /var.
    #[cfg(unix)]
    let directory = directory.canonicalize().map_err(|error| error.to_string())?;
    let path = directory.join("packets.bin");
    check_entry(&path, false, false)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // A path that was regular at stat time could be replaced with a named pipe.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let bytes = options.open(&path)
        .map_err(|error| format!("Open archive entry {}: {error}", path.display()))?;
    validate_type(&path, &bytes.metadata().map_err(|error| error.to_string())?, false)?;

    let index = directory.join("index.sqlite");
    check_entry(&index, false, false)?;
    for sidecar in ["index.sqlite-wal", "index.sqlite-shm", "index.sqlite-journal"] {
        check_entry(&directory.join(sidecar), false, true)?;
    }
    let db = open_index(&index, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    Ok((db, bytes))
}
