use packrat_tui::analysis::stream::{export_segments, search_segments};

#[test]
fn searches_case_insensitively_and_reports_segment_offsets() {
    let segments = vec![
        (true, b"GET /Admin HTTP/1.1".to_vec()),
        (false, b"admin denied; admin logged".to_vec()),
    ];
    let matches = search_segments(&segments, b"ADMIN");
    assert_eq!(matches.len(), 3);
    assert_eq!((matches[0].segment_index, matches[0].byte_offset), (0, 5));
    assert_eq!((matches[2].segment_index, matches[2].byte_offset), (1, 14));
}

#[test]
fn exports_exact_directional_stream_bytes() {
    let root = std::env::temp_dir().join(format!("packrat_stream_test_{}", std::process::id()));
    let _ = std::fs::remove_file(root.with_file_name(format!(
        "{}.a-to-b.bin",
        root.file_name().unwrap().to_string_lossy()
    )));
    let _ = std::fs::remove_file(root.with_file_name(format!(
        "{}.b-to-a.bin",
        root.file_name().unwrap().to_string_lossy()
    )));
    let segments = vec![
        (true, b"abc".to_vec()),
        (false, b"reply".to_vec()),
        (true, b"def".to_vec()),
    ];
    let (left, right) = export_segments(&segments, &root).unwrap();
    assert_eq!(std::fs::read(&left).unwrap(), b"abcdef");
    assert_eq!(std::fs::read(&right).unwrap(), b"reply");
    std::fs::remove_file(left).unwrap();
    std::fs::remove_file(right).unwrap();
}
