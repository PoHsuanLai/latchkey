//! Whose session has the seat: the `ACTIVE_UID=` line of logind's state file. Reading the file is
//! the one effect; the parse is pure.

use std::path::PathBuf;

/// Where logind records the seat's state.
pub const SEAT_FILE: &str = "/run/systemd/seats/seat0";

/// The `ACTIVE_UID=` line of a `seat0` state file; `None` when there is no active session.
pub fn active_uid(text: &str) -> Option<u32> {
    text.lines()
        .find_map(|line| line.strip_prefix("ACTIVE_UID="))
        .and_then(|value| value.trim().parse().ok())
}

/// The file the active uid is read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeatFile(pub PathBuf);

impl SeatFile {
    /// The active uid now; a missing or unreadable file means nobody has the seat.
    pub fn active_uid(&self) -> Option<u32> {
        std::fs::read_to_string(&self.0)
            .ok()
            .and_then(|text| active_uid(&text))
    }
}
