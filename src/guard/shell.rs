//! Which connection is the desktop's shell. Every local account can reach the socket, and every
//! program of the person at the seat can use it, so a connection is believed only when the kernel
//! says it runs in a trusted unit under the person's own manager. That is a speed bump and not a
//! wall: a program of the same user can put itself in a control group of that name. What it buys
//! is that no ordinary program of theirs is taken for the shell.
//!
//! A dynamic user without privileges cannot read another user's image path; the unit name in the
//! control group is all there is to go on, and the process is held by its pidfd so the name cannot
//! belong to a process that has since been replaced.

use peephole::{Alive, Pinned, Prober, ProcFs, RealProc};
use peephole_core::{CgroupPath, PinNeed, RoleName, Standing, Table, judge};
use rustix::fd::OwnedFd;

/// How firmly a connection's process must have been held. Peephole's socket pin is made after
/// the connect (`Reopened`), so nothing firmer can be asked yet.
const PIN_NEED: PinNeed = PinNeed::Any;

/// A process we hold, running as the shell, under the manager of `user`.
#[derive(Debug)]
pub struct Held {
    pub process: Pinned,
    pub user: u32,
}

/// What a connection showed itself to be when it connected.
#[derive(Debug)]
pub enum Origin {
    /// In a trusted unit, under this user's manager.
    Shell(Held),
    /// Anything else.
    Other,
}

/// What a connection claims right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Claim {
    /// The shell of this user, and its process is still the one we held.
    Shell {
        user: u32,
    },
    Other,
}

impl Origin {
    /// The claim as of now: a shell whose process has since exited (and whose socket a child
    /// kept open) claims nothing.
    pub fn claim(&self) -> Claim {
        match self {
            Origin::Shell(held) if held.process.alive() == Alive::Yes => {
                Claim::Shell { user: held.user }
            }
            Origin::Shell(_) | Origin::Other => Claim::Other,
        }
    }
}

/// Decides what a freshly connected stream is.
pub trait Vouch: Send + 'static {
    /// The origin of the process on the other end of `stream`.
    fn origin(&self, stream: &OwnedFd) -> Origin;
}

/// The real check: hold the process, read its control group, judge it against a caller table and
/// believe it when its role is one of `accepted`.
#[derive(Debug)]
pub struct ShellCheck<P: ProcFs = RealProc> {
    prober: Prober<P>,
    table: Table,
    accepted: Vec<RoleName>,
}

impl ShellCheck {
    /// The check of this machine against `table`. A table that nobody could parse is an empty
    /// one, which believes nobody: the safe way to fail.
    pub fn system(table: Table, accepted: Vec<RoleName>) -> Self {
        Self::new(Prober::new(RealProc::system()), table, accepted)
    }
}

impl<P: ProcFs> ShellCheck<P> {
    pub fn new(prober: Prober<P>, table: Table, accepted: Vec<RoleName>) -> Self {
        Self {
            prober,
            table,
            accepted,
        }
    }

    /// What the held process `process` is.
    pub fn origin_of(&self, process: Pinned) -> Origin {
        let Ok(facts) = self.prober.probe(&process, None) else {
            return Origin::Other;
        };
        let user = match judge(&facts, &self.table) {
            Standing::Service { role, pin, .. }
                if self.accepted.contains(&role) && PIN_NEED.satisfied_by(pin) =>
            {
                manager_user(&facts.cgroup)
            }
            _ => None,
        };
        user.map_or(Origin::Other, |user| Origin::Shell(Held { process, user }))
    }
}

impl<P: ProcFs + 'static> Vouch for ShellCheck<P> {
    fn origin(&self, stream: &OwnedFd) -> Origin {
        Pinned::of_stream(stream).map_or(Origin::Other, |process| self.origin_of(process))
    }
}

/// Every connection is the shell of the user it runs as.
#[derive(Debug)]
pub struct SeatUser;

impl Vouch for SeatUser {
    fn origin(&self, stream: &OwnedFd) -> Origin {
        Pinned::of_stream(stream).map_or(Origin::Other, |process| {
            let user = process.uid().get();
            Origin::Shell(Held { process, user })
        })
    }
}

/// The user whose manager runs the unit at `cgroup`: the path starts
/// `/user.slice/user-<N>.slice/user@<N>.service/`, and `N` is the same twice.
fn manager_user(cgroup: &CgroupPath) -> Option<u32> {
    let mut segments = cgroup.segments();
    let (slice, user_slice, manager) = (segments.next()?, segments.next()?, segments.next()?);
    let from_slice = user_slice.strip_prefix("user-")?.strip_suffix(".slice")?;
    let from_manager = manager.strip_prefix("user@")?.strip_suffix(".service")?;
    match slice == "user.slice" && from_slice == from_manager {
        true => from_manager.parse().ok(),
        false => None,
    }
}
