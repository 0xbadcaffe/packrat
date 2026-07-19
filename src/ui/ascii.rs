//! ASCII presentation used only for startup and meaningful empty states.

pub const STARTUP_MARK: &[&str] = &[
    "    ____  ___   ________ ______  ___  ______",
    "   / __ \\/   | / ____/ //_/ __ \\/   |/_  __/",
    "  / /_/ / /| |/ /   / ,< / /_/ / /| | / /",
    " / ____/ ___ / /___/ /| / _, _/ ___ |/ /",
    "/_/   /_/  |_\\____/_/ |_/_/ |_/_/  |_/_/",
    "  [ CAPTURE ]---[ INSPECT ]---[ CORRELATE ]---[ DETECT ]",
];

pub const PACKRAT_ICON: &[&str] = &[
    "        .--~~,__",
    "   :-....,-------,",
    "        `-,,,  ,_      ;",
    "          _,-' ,'\\     ;",
    "         (  ) .|  `-.-'",
    "          `'   \\    /(",
    "                `~~~~~'",
];

pub const COMPACT_STARTUP_MARK: &str = "PACKRAT // NETWORK EVIDENCE CONSOLE";
pub const NARROW_STARTUP_MARK: &str = "PACKRAT";
pub const FULL_STARTUP_MIN_WIDTH: u16 = 61;
pub const ICON_STARTUP_MIN_WIDTH: u16 = 86;

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
        for line in STARTUP_MARK.iter().chain(PACKRAT_ICON).chain(EMPTY_CAPTURE) {
            assert!(line.is_ascii());
            assert!(line.len() <= 72);
            assert!(!line.chars().any(char::is_control));
        }
        assert!(COMPACT_STARTUP_MARK.is_ascii());
        assert!(NARROW_STARTUP_MARK.is_ascii());
        assert!(INCIDENT_MARK.is_ascii());
    }

    #[test]
    fn startup_logo_spells_packrat_on_a_fixed_terminal_grid() {
        assert_eq!(STARTUP_MARK.len(), 6);
        assert_eq!(PACKRAT_ICON.len(), 7);
        assert!(STARTUP_MARK[..5].iter().all(|line| line.len() <= 52));
        assert!(STARTUP_MARK[0].len() > STARTUP_MARK[4].len());
        assert!(STARTUP_MARK[0].starts_with("    "));
        assert!(STARTUP_MARK[4].starts_with("/_/"));
        assert!(STARTUP_MARK[5].contains("CAPTURE"));
        assert!(STARTUP_MARK[5].contains("DETECT"));
    }
}
