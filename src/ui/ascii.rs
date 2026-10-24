//! ASCII presentation used only for startup and meaningful empty states.

pub const STARTUP_MARK: &[&str] = &[
    " ____   _    ____ _  ______      _  _____",
    "|  _ \\ / \\  / ___| |/ /  _ \\    / \\|_   _|",
    "| |_) / _ \\| |   | ' /| |_) |  / _ \\ | |",
    "|  __/ ___ \\ |___| . \\|  _ <  / ___ \\| |",
    "|_| /_/   \\_\\____|_|\\_\\_| \\_\\/_/   \\_\\_|",
    "  [ CAPTURE ]---[ INSPECT ]---[ CORRELATE ]---[ DETECT ]",
];

pub const PACKRAT_EMOJI: &str = "🐀";
pub const COMPACT_STARTUP_MARK: &str = "PACKRAT // NETWORK EVIDENCE CONSOLE";
pub const NARROW_STARTUP_MARK: &str = "PACKRAT";
pub const FULL_STARTUP_MIN_WIDTH: u16 = 61;

pub const EMPTY_CAPTURE: &[&str] = &[
    "        .----------------.",
    "  ------| listening wire |------",
    "        '----------------'",
];

pub const INCIDENT_MARK: &str = "!!  INTRUSION SIGNAL  !!";

#[cfg(test)]
#[path = "../../tests/unit/ui_ascii_tests.rs"]
mod tests;
