use super::{parse_args, required_hooks_present};
use std::path::PathBuf;

#[test]
fn parses_collector_options() {
    let options = parse_args([
        "--object",
        "/tmp/socket.bpf.o",
        "--output",
        "/tmp/events.csv",
        "--stats-seconds",
        "9",
        "--check",
    ])
    .unwrap();

    assert_eq!(options.object, PathBuf::from("/tmp/socket.bpf.o"));
    assert_eq!(options.output, Some(PathBuf::from("/tmp/events.csv")));
    assert_eq!(options.stats_seconds, 9);
    assert!(options.check_only);
}

#[test]
fn rejects_incomplete_and_unknown_options() {
    assert!(parse_args(["--object"]).is_err());
    assert!(parse_args(["--stats-seconds", "zero"]).is_err());
    assert!(parse_args(["--unexpected"]).is_err());
}

#[test]
fn requires_all_kernel_lifecycle_symbols() {
    let complete = "0 T inet_csk_accept\n0 T udp_sendmsg\n0 T udp_recvmsg\n";
    assert!(required_hooks_present(complete));
    assert!(!required_hooks_present(
        "0 T inet_csk_accept\n0 T udp_sendmsg\n"
    ));
}
