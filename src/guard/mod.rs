//! The guards of a socket served to every local account: who may connect, who is the shell, whose
//! turn it is to complain and how long a listener pauses. Policy-free mechanics: the table of
//! callers, the caps and the messages stay with the daemon that serves the socket.
//!
//! Unix only, behind the `guard` feature, because the caller check is peephole's.

mod accept;
mod seat;
mod shell;

pub use accept::{ACCEPT_PAUSE, AcceptFailure, COMPLAINT_INTERVAL, Voice, accept_failure};
pub use seat::{SEAT_FILE, SeatFile, active_uid};
pub use shell::{Claim, Held, Origin, SeatUser, ShellCheck, Vouch};
