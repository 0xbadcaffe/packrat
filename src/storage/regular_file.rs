use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::path::Path;

pub(crate) fn open(path: &Path, wrong_type: &'static str) -> io::Result<(File, Metadata)> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidInput, wrong_type);
    if !path.metadata()?.is_file() {
        return Err(invalid());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // The path could be replaced with a named pipe between the type check and open.
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(invalid());
    }
    Ok((file, metadata))
}
