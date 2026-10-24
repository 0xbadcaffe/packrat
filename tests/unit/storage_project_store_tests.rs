use super::*;

#[test]
fn atomic_case_replacement_is_private_and_round_trips() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("case.json");
    save(&ProjectState::new("first", ProjectSaveMode::Lightweight), &path).unwrap();
    save(&ProjectState::new("second", ProjectSaveMode::Portable), &path).unwrap();
    assert_eq!(load(&path).unwrap().metadata.name, "second");
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600);
    }
}

#[test]
fn failed_serialization_and_size_limits_leave_previous_case_intact() {
    struct Fails;
    impl serde::Serialize for Fails {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            use serde::ser::SerializeSeq;
            let mut sequence = serializer.serialize_seq(None)?;
            sequence.serialize_element("partial write")?;
            Err(serde::ser::Error::custom("injected serialization failure"))
        }
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("case.json");
    save(&ProjectState::new("keep", ProjectSaveMode::Lightweight), &path).unwrap();
    let original = std::fs::read(&path).unwrap();
    assert!(atomic_json_write(&Fails, &path, MAX_PROJECT_BYTES).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), original);
    assert!(atomic_json_write(&vec![0; 100], &path, 10).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), original);
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[test]
fn future_schemas_and_oversized_case_files_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("case.json");
    let mut state = ProjectState::new("future", ProjectSaveMode::Portable);
    state.metadata.schema_version = SCHEMA_VERSION + 1;
    save(&state, &path).unwrap();
    assert!(load(&path).unwrap_err().to_string().contains("newer"));
    std::fs::File::options().write(true).open(&path).unwrap().set_len(MAX_PROJECT_BYTES + 1).unwrap();
    assert!(load(&path).unwrap_err().to_string().contains("size limit"));
}
