use super::*;

#[test]
fn default_paths_include_working_and_temporary_directories() {
    let paths = default_write_paths().unwrap();
    assert!(paths.contains(&std::env::current_dir().unwrap()));
    assert!(paths.contains(&std::env::temp_dir()));
}
