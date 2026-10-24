#![cfg(unix)]
use std::{os::unix::fs::PermissionsExt, path::Path, process::Command};

fn select(root: &Path) -> std::process::Output {
    Command::new("bash")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/select-perf.sh"))
        .arg("7.0.0-1017-azure")
        .arg(root)
        .output()
        .unwrap()
}

fn install(root: &Path, relative: &str, success: bool) {
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        &path,
        if success {
            "#!/bin/sh\nprintf 'perf version test\\n'\n"
        } else {
            "#!/bin/sh\nexit 1\n"
        },
    )
    .unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn supported_kernel_tool_package_layouts_are_selected_and_verified() {
    for layout in [
        "linux-tools/7.0.0-1017-azure/perf",
        "linux-tools/7.0.0-1017/perf",
        "linux-tools-7.0.0-1017-azure/perf",
        "linux-tools-7.0.0-1017/perf",
    ] {
        let directory = tempfile::tempdir().unwrap();
        install(directory.path(), layout, true);
        let output = select(directory.path());
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8(output.stdout).unwrap().trim(),
            directory.path().join(layout).to_str().unwrap()
        );
    }
}

#[test]
fn broken_kernel_wrapper_falls_back_to_the_shared_versioned_binary() {
    let directory = tempfile::tempdir().unwrap();
    install(directory.path(), "linux-tools/7.0.0-1017-azure/perf", false);
    install(directory.path(), "linux-tools-7.0.0-1017/perf", true);
    let output = select(directory.path());
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .ends_with("linux-tools-7.0.0-1017/perf\n")
    );
}

#[test]
fn missing_profiler_is_an_explicit_failure_not_a_silently_skipped_check() {
    let directory = tempfile::tempdir().unwrap();
    let output = select(directory.path());
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("No executable perf"));
}

#[test]
fn standalone_linux_perf_package_is_preferred_without_a_symlink_rewrite() {
    let directory = tempfile::tempdir().unwrap();
    install(directory.path(), "bin/perf", true);
    install(directory.path(), "linux-tools-7.0.0-1017/perf", true);
    let binary = directory.path().join("bin/perf");
    let output = Command::new("bash")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/select-perf.sh"))
        .arg("7.0.0-1017-azure")
        .arg(directory.path())
        .arg(&binary)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        binary.to_str().unwrap()
    );
    assert!(
        !std::fs::symlink_metadata(binary)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}
