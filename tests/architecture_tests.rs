use std::path::{Path, PathBuf};

fn rust_files(directory: &Path, files: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
}

#[test]
fn rust_source_and_tests_stay_under_500_lines() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for directory in ["src", "tests"] {
        rust_files(&root.join(directory), &mut files);
    }
    let oversized: Vec<_> = files
        .iter()
        .filter_map(|path| {
            let lines = std::fs::read_to_string(path).unwrap().lines().count();
            (lines >= 500).then(|| {
                format!(
                    "{}: {lines} lines",
                    path.strip_prefix(root).unwrap().display()
                )
            })
        })
        .collect();
    assert!(
        oversized.is_empty(),
        "Split these modules:\n{}",
        oversized.join("\n")
    );
}

#[test]
fn production_modules_do_not_embed_test_bodies() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    for path in files {
        let source = std::fs::read_to_string(&path).unwrap();
        assert!(
            !source.lines().any(|line| {
                let line = line.trim();
                line.starts_with("#[test]")
                    || line.starts_with("#[tokio::test")
                    || line.starts_with("#[rstest]")
            }),
            "Move test bodies into tests/: {}",
            path.display()
        );
    }
}
