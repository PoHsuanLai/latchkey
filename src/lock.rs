//! The one mechanism that makes "one agent per user" true.
//!
//! # Why a lock and not a look
//!
//! The obvious way to find out whether an agent is running is to look at its socket: is the file
//! there, and does anything answer on it? That reads correctly and is wrong under concurrency,
//! in two ways that are easy to write and hard to see.
//!
//! *A client that tidies races every other client.* Between a failed connect and the
//! `remove_file` it does on the strength of it, another client's agent can bind — and the
//! tidying client then deletes a working agent's door. Two people running the same command at
//! the same moment on a cold machine is all it takes.
//!
//! *An agent that clears races every other agent.* Connect, fail, remove, bind: four steps, and
//! two agents can interleave at every one of them. Both clear, both bind, and the second unlinks
//! the first's socket out from under it. The first is then listening on an inode nothing can
//! reach — invisible, holding no clients, and never exiting.
//!
//! Both come from the same mistake: inferring liveness from a file. A socket that refuses
//! connections only *suggests* nobody is home. An advisory lock *is* the answer, because the
//! kernel releases it when the holding process dies — including under `SIGKILL` and a power cut,
//! where no destructor runs. So the stale case needs no heuristic, and the race needs no
//! ordering argument, because there is nothing to order: one `try_lock` decides it.
//!
//! # Why the file is never deleted
//!
//! Unlinking a lock file reintroduces the race in a worse form. A second process can be holding
//! the lock on the very inode being deleted, while a third creates a fresh file at the same path
//! and locks that — two holders, no conflict, and the kernel is right both times. So the file
//! stays. It is empty, it lives beside the socket, and leaving it there costs an inode.

use crate::Error;
use std::path::{Path, PathBuf};

/// Proof that this process is the agent.
///
/// Held for as long as the agent runs. Dropping it — or the process ending by any route at all —
/// releases the lock and lets the next one in.
#[derive(Debug)]
pub struct Held {
    /// Open because dropping it releases the lock, which is the entire point. Also read by
    /// [`Held::standing`], to ask whether the path still names this very file.
    file: std::fs::File,
    path: PathBuf,
}

/// Whether the lock file at the path is still the one this agent holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Standing {
    /// The path names the file this agent holds the lock on.
    Ours,
    /// The path is gone, or names another file (a cache cleaner ran, or someone replaced it). A
    /// new agent would lock the new file and run beside this one, so this agent should stop.
    Displaced,
}

impl Held {
    /// Is the lock file still where this agent locked it?
    ///
    /// The lock belongs to a file, not to a path, and this crate never deletes the file — but
    /// something else can: a cache cleaner, `rm -rf ~/.cache`, a tidy-minded person. The next
    /// client would then create a fresh file, lock it without conflict and start a second agent.
    /// An agent that calls this now and then (once a minute is plenty) and exits on
    /// [`Standing::Displaced`] turns that from two agents for ever into a short overlap.
    pub fn standing(&self) -> Standing {
        same_file(&self.file, &self.path)
    }
}

#[cfg(unix)]
fn same_file(file: &std::fs::File, path: &Path) -> Standing {
    use std::os::unix::fs::MetadataExt as _;
    match (file.metadata(), std::fs::symlink_metadata(path)) {
        (Ok(held), Ok(there)) if held.dev() == there.dev() && held.ino() == there.ino() => {
            Standing::Ours
        }
        _ => Standing::Displaced,
    }
}

#[cfg(not(unix))]
fn same_file(_file: &std::fs::File, _path: &Path) -> Standing {
    // Windows locks by handle in a per-user directory a cleaner does not visit.
    Standing::Ours
}

/// Take the lock, or report who has it.
///
/// Creates the parent directory, `0700` on Unix, because on the socket platforms the directory's
/// permissions are the whole of the authentication: an agent any local process could talk to
/// would be an agent any local process could use. A directory that already exists is trusted only
/// if this user owns it (see [`private_dir`]).
pub fn take(path: &Path) -> Result<Held, Error> {
    if let Some(parent) = path.parent() {
        private_dir(parent)?;
    }
    let file = open_lock(path)?;
    owner_only(path);
    match file.try_lock() {
        Ok(()) => Ok(Held {
            file,
            path: path.to_path_buf(),
        }),
        Err(std::fs::TryLockError::WouldBlock) => Err(Error::AlreadyRunning),
        Err(std::fs::TryLockError::Error(e)) => Err(Error::at(path, e)),
    }
}

/// Open the lock file, creating it owner-only. On Unix a symlink at the path is refused rather than
/// followed, and a file this user does not own is not used.
#[cfg(unix)]
fn open_lock(path: &Path) -> Result<std::fs::File, Error> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|e| Error::at(path, e))?;
    let meta = file.metadata().map_err(|e| Error::at(path, e))?;
    if meta.uid() != rustix::process::geteuid().as_raw() {
        return Err(Error::Unsafe(path.to_path_buf()));
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_lock(path: &Path) -> Result<std::fs::File, Error> {
    std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| Error::at(path, e))
}

/// Make `dir` exist as a directory only this user can enter, or say why it cannot be trusted.
///
/// Created `0700` from the start (so there is no moment it is wider). One that already exists must
/// be a real directory, not a symlink, owned by this user: a directory somebody else made is
/// somebody else's, whatever its mode says now, and an agent run inside it would hand its door
/// to them. A directory this user owns that is looser than `0700` is tightened.
#[cfg(unix)]
pub(crate) fn private_dir(dir: &Path) -> Result<(), Error> {
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| Error::at(dir, e))?;
    let meta = std::fs::symlink_metadata(dir).map_err(|e| Error::at(dir, e))?;
    if !meta.is_dir() || meta.uid() != rustix::process::geteuid().as_raw() {
        return Err(Error::Unsafe(dir.to_path_buf()));
    }
    if meta.mode() & 0o077 != 0 {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| Error::at(dir, e))?;
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn private_dir(dir: &Path) -> Result<(), Error> {
    // Windows inherits the ACL of `%LOCALAPPDATA%`, which is already per-user.
    std::fs::create_dir_all(dir).map_err(|e| Error::at(dir, e))
}

/// Owner-only, where the platform has such a notion.
///
/// Best effort on purpose, and only for files: a filesystem that cannot express it — a FAT-formatted
/// volume, a container bind mount — should not stop the agent starting. The directory is the
/// authentication and is checked hard by [`private_dir`]; this is the belt on top of those braces.
#[cfg(unix)]
pub(crate) fn owner_only(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = if path.is_dir() { 0o700 } else { 0o600 };
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
pub(crate) fn owner_only(_path: &Path) {
    // Windows inherits the ACL of `%LOCALAPPDATA%`, which is already per-user.
}
