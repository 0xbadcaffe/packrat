use super::find_http_header_end;

#[test]
fn finds_a_new_terminator_at_every_segment_boundary() {
    for header in [
        b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n".as_slice(),
        b"GET / HTTP/1.1\nHost: example.test\n\n".as_slice(),
    ] {
        for split in 0..header.len() {
            assert_eq!(find_http_header_end(&header[..split], 0), None);
            assert_eq!(find_http_header_end(header, split), Some(header.len()), "split at {split}");
        }
        assert_eq!(find_http_header_end(header, header.len()), None);
    }
}

#[test]
fn uses_the_first_completed_boundary_regardless_of_line_ending() {
    let standard = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
    let bare_lf = b"GET / HTTP/1.1\nHost: example.test\n\n";
    for (first, second) in [(standard.as_slice(), bare_lf.as_slice()), (bare_lf.as_slice(), standard.as_slice())] {
        let joined = [first, second].concat();
        assert_eq!(find_http_header_end(&joined, first.len() - 1), Some(first.len()));
        assert_eq!(find_http_header_end(&joined, first.len()), Some(joined.len()));
    }
}

#[test]
fn one_byte_appends_complete_only_at_the_final_boundary() {
    let mut header = b"GET / HTTP/1.1\r\nX-Note: ".to_vec();
    header.resize(32_764, b'a');
    header.extend(b"\r\n\r\n");
    for end in 1..=header.len() {
        let expected = (end == header.len()).then_some(end);
        assert_eq!(find_http_header_end(&header[..end], end - 1), expected);
    }
}
