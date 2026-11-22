use super::PacketArchive;
use rusqlite::{Connection, OptionalExtension, params};

const FULL: &str = "all_packets";
const ALERT_ONLY: &str = "alert_evidence";

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
