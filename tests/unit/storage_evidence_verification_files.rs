use super::*;

#[test]
fn evidence_input_checks_regular_file_and_size() {
    let scratch = tempfile::tempdir().unwrap();
    let path = scratch.path().join("manifest.json");
    std::fs::write(&path, b"fixture").unwrap();
    let (_, length) = open_regular(&path, 7).unwrap();
    assert_eq!(length, 7);
    assert!(open_regular(&path, 6).is_err());
    assert!(open_regular(scratch.path(), 7).is_err());
}

#[cfg(unix)]
#[test]
fn evidence_inputs_do_not_follow_links_or_use_blocking_descriptors() {
    use std::os::{fd::AsRawFd, unix::fs::symlink};

    let scratch = tempfile::tempdir().unwrap();
    let path = scratch.path().join("manifest.json");
    let link = scratch.path().join("linked.json");
    std::fs::write(&path, b"fixture").unwrap();
    symlink(&path, &link).unwrap();
    assert!(open_regular(&link, 7).is_err());
    let (file, _) = open_regular(&path, 7).unwrap();
    // SAFETY: F_GETFL reads the status flags of this open descriptor.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    assert!(flags >= 0);
    assert_ne!(flags & libc::O_NONBLOCK, 0);
}
