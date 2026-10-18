//! What a failed `accept` means, and how loudly a refusal is logged.

use rustix::io::Errno;
use std::time::Duration;

/// How long the listener is left alone after `accept` failed for a reason that retrying at once
/// will not clear (out of file descriptors).
pub const ACCEPT_PAUSE: Duration = Duration::from_secs(1);
/// How often one subscriber's refusal is written to the log.
pub const COMPLAINT_INTERVAL: Duration = Duration::from_secs(60);

/// What a failed `accept` means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptFailure {
    /// No connection is waiting: the loop is done for this pass.
    NothingPending,
    /// Interrupted: ask again.
    Retry,
    /// The connection stays pending, so polling would return at once and spin: leave the
    /// listener alone for a while.
    Pause,
}

/// What the failed `accept` that reported `e` means.
pub fn accept_failure(e: Errno) -> AcceptFailure {
    match e {
        Errno::AGAIN => AcceptFailure::NothingPending,
        Errno::INTR => AcceptFailure::Retry,
        _ => AcceptFailure::Pause,
    }
}

/// Whether a refusal is written to the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Voice {
    Speak,
    Silent,
}
