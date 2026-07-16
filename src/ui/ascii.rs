//! Compact ASCII presentation used only for startup and meaningful empty states.

pub const STARTUP_MARK: &[&str] = &[
    " ____   _   ____ _  ______    _  _____",
    "|  _ \\ / \\ / ___| |/ /  _ \\  / \\|_   _|",
    "| |_) / _ \\ |   | ' /| |_) |/ _ \\ | |",
    "|  __/ ___ \\ |___| . \\|  _ </ ___ \\| |",
    "|_| /_/   \\_\\____|_|\\_\\_| \\_/_/   \\_\\_|",
];

pub const EMPTY_CAPTURE: &[&str] = &[
    "        .----------------.",
    "  ------| listening wire |------",
    "        '----------------'",
];

pub const INCIDENT_MARK: &str = "!!  INTRUSION SIGNAL  !!";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presentation_art_is_terminal_safe_and_compact() {
        for line in STARTUP_MARK.iter().chain(EMPTY_CAPTURE) {
            assert!(line.is_ascii());
            assert!(line.len() <= 64);
            assert!(!line.chars().any(char::is_control));
        }
        assert!(INCIDENT_MARK.is_ascii());
    }
}
