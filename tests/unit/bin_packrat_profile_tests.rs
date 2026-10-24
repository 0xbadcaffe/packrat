use super::*;

#[test]
fn packet_count_is_validated() {
    assert_eq!(packet_count(["--packets", "42"].map(str::to_string).into_iter()), Ok(42));
    assert!(packet_count(["--packets", "0"].map(str::to_string).into_iter()).is_err());
    assert!(packet_count(["--unknown"].map(str::to_string).into_iter()).is_err());
}
