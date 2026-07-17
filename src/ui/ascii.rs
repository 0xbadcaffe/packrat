//! ASCII presentation used only for startup and meaningful empty states.

pub const STARTUP_MARK: &[&str] = &[
    "                                __                  __",
    "______  _____     ____  |  | _________ _____   _/  |_",
    "\\____ \\ \\__  \\  _/ ___\\ |  |/ /\\_  __ \\\\__  \\  \\   __\\",
    "|  |_> > / __ \\_\\  \\___ |    <  |  | \\/ / __ \\_ |  |",
    "|   __/ (____  / \\___  >|__|_ \\ |__|   (____  / |__|",
    "|__|         \\/      \\/      \\/             \\/",
    "       [ CAPTURE ]--[ INSPECT ]--[ DETECT ]--[ RESPOND ]",
];

pub const COMPACT_STARTUP_MARK: &str = "PACKRAT // DEEP WIRE OPS";

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
            assert!(line.len() <= 72);
            assert!(!line.chars().any(char::is_control));
        }
        assert!(COMPACT_STARTUP_MARK.is_ascii());
        assert!(INCIDENT_MARK.is_ascii());
    }
}
