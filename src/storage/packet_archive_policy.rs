use super::PacketArchive;
use rusqlite::{Connection, OptionalExtension, params};

const FULL: &str = "all_packets";
const ALERT_ONLY: &str = "alert_evidence";

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct ArchiveUsage {
    pub frames: u64,
    pub max_frames: u64,
    pub payload_bytes: u64,
    pub max_payload_bytes: u64,
}

#[derive(Clone, Copy)]
pub(crate) enum ArchivePause {
    FrameLimit,
    ByteLimit,
    DiskReserve,
    QueueUnavailable,
    WriteFailed,
}

impl ArchivePause {
    pub(super) fn details(self) -> (&'static str, &'static str) {
        match self {
            Self::FrameLimit => ("frame_limit", "frame limit reached"),
            Self::ByteLimit => ("byte_limit", "packet-byte limit reached"),
            Self::DiskReserve => ("disk_reserve", "filesystem free-space reserve reached"),
            Self::QueueUnavailable => ("queue_unavailable", "alert evidence queue unavailable"),
            Self::WriteFailed => ("write_failed", "archive write failed"),
        }
    }
}

pub(super) fn bind(connection: &mut Connection, alert_only: bool, has_bytes: bool) -> Result<(), String> {
    let transaction = connection.transaction().map_err(|error| error.to_string())?;
    transaction.execute_batch(
        "CREATE TABLE IF NOT EXISTS archive_retention (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            policy TEXT NOT NULL
        );",
    ).map_err(|error| error.to_string())?;
    let stored: Option<String> = transaction.query_row(
        "SELECT policy FROM archive_retention WHERE singleton = 1",
        [],
        |row| row.get(0),
    ).optional().map_err(|error| error.to_string())?;
    let requested = if alert_only { ALERT_ONLY } else { FULL };
    let legacy_content = if alert_only && stored.is_none() {
        has_bytes || transaction.query_row("SELECT EXISTS(SELECT 1 FROM packets)", [], |row| row.get::<_, bool>(0))
            .map_err(|error| error.to_string())?
    } else {
        false
    };
    if stored.as_deref().is_some_and(|policy| policy != requested) || legacy_content {
        let current = stored.as_deref().unwrap_or("legacy archive with existing packet data");
        return Err(format!(
            "Archive retention policy is {current}, cannot open for {requested}; choose a different directory"
        ));
    }
    if stored.is_none() {
        transaction.execute(
            "INSERT INTO archive_retention(singleton, policy) VALUES (1, ?1)",
            [requested],
        ).map_err(|error| error.to_string())?;
    }
    transaction.commit().map_err(|error| error.to_string())
}

impl PacketArchive {
    pub(super) fn contains_frame(&self, capture_id: &str, frame: u64) -> Result<bool, String> {
        self.db.prepare_cached("SELECT 1 FROM capture_frames WHERE capture_id=?1 AND frame_number=?2")
            .and_then(|mut query| query.exists(params![capture_id, frame.to_string()]))
            .map_err(|error| error.to_string())
    }
}
