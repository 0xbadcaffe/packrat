use rusqlite::{Connection, OpenFlags};
use std::fs::{File, Metadata, OpenOptions};
use std::path::{Path, PathBuf};

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
    let db = Connection::open_with_flags(index, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW)
        .map_err(|error| error.to_string())?;
    Ok((db, bytes))
}
