use super::SecurityEngine;

#[test]
fn filters_positions_without_changing_ascii_or_overlap_semantics() {
    let captures: &[&[u8]] = &[
        b"",
        b"a",
        b"aAaAa",
        b".name: mixED CASE\0\xff\xff\xff\x80",
        b"same same SAME Sam\0E",
    ];
    let patterns: &[&[u8]] = &[
        b"",
        b"a",
        b"AA",
        b"AAA",
        b".NAME",
        b"mixed",
        b"SAME",
        b"\xff\xff",
        b"\xff\x80",
        b"\0",
        b"payload longer than all the fixtures",
    ];
    for data in captures {
        for pattern in patterns {
            let expected_contains = !pattern.is_empty()
                && data
                    .windows(pattern.len())
                    .any(|window| window.eq_ignore_ascii_case(pattern));
            let expected_count = if pattern.is_empty() {
                0
            } else {
                data.windows(pattern.len())
                    .filter(|window| *window == *pattern)
                    .count()
            };
            assert_eq!(
                SecurityEngine::contains_str_ci(data, pattern),
                expected_contains
            );
            assert_eq!(
                SecurityEngine::count_pattern_ascii(data, pattern),
                expected_count
            );
        }
    }
}
