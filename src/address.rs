//! Where this user's agent listens, and where the lock that proves it is running lives.
//!
//! Every platform difference in this crate is in this file, and all of it is decided by
//! [`address_on`], which takes the environment as arguments rather than reading it. That is not
//! a style preference: a rule that reads its own environment can only be checked on the machine
//! it was written on, and for a cross-platform agent that is the one thing that must not be
//! true. The macOS and Windows answers below are tested from whatever machine runs `cargo test`.

use crate::Error;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Which platform's rules to apply.
///
/// A value rather than a `cfg!`, so every branch is reachable from a test anywhere. The real one
/// is chosen once, in [`here`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Host {
    Linux,
    Mac,
    Windows,
}

/// What clients connect to.
///
/// Callers do not normally match on this — [`crate::Agent`] hands both arms to the same
/// `interprocess` types, which is the whole point. It is public because a program that wants to
/// *print* its agent's address, or put it in an environment variable for a child, needs to see
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// A Unix domain socket at this path. Linux and macOS.
    Socket(PathBuf),
    /// A named pipe. Windows, whose `AF_UNIX` support exists in the OS since 1803 but not in the
    /// standard library.
    Pipe(String),
}

/// An agent's two addresses: the one clients knock on, and the one the kernel arbitrates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    /// Where to connect.
    pub endpoint: Endpoint,
    /// The file whose lock means "this user's agent is running".
    ///
    /// Separate from the endpoint because a socket cannot be locked and a pipe is not a file at
    /// all, and because the lock has to outlive the endpoint being replaced. See [`crate::lock`]
    /// for why the question is asked this way round.
    pub lock: PathBuf,
}

/// What [`address_on`] reads, gathered rather than looked up.
///
/// All of it optional: every field is missing on some real system, and the rules below say what
/// happens then instead of panicking or guessing.
#[derive(Debug, Default, Clone)]
pub struct Environment {
    /// `XDG_RUNTIME_DIR`. Linux: tmpfs, `0700`, emptied when the session ends — which is exactly
    /// the lifetime a socket wants, and the reason a stale one there cannot survive a reboot.
    pub runtime_dir: Option<OsString>,
    /// `TMPDIR` on Unix, `TEMP` on Windows. On macOS this is per-user and private
    /// (`/var/folders/…`), which makes it the closest thing that platform has to a runtime
    /// directory.
    pub tmpdir: Option<OsString>,
    /// `HOME`, or `USERPROFILE` on Windows.
    pub home: Option<OsString>,
    /// `LOCALAPPDATA`. Windows only, and where its lock file goes.
    pub local_app_data: Option<OsString>,
    /// `USER`, or `USERNAME` on Windows. Used only to name a pipe, whose namespace is shared by
    /// every session on the machine.
    pub user: Option<String>,
}

impl Environment {
    /// Read the real environment. [`crate::Agent::new`] does this for you.
    pub fn read() -> Self {
        Self {
            runtime_dir: std::env::var_os("XDG_RUNTIME_DIR").or_else(runtime_dir_by_uid),
            tmpdir: std::env::var_os("TMPDIR").or_else(|| std::env::var_os("TEMP")),
            home: std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")),
            local_app_data: std::env::var_os("LOCALAPPDATA"),
            user: std::env::var("USER")
                .or_else(|_| std::env::var("USERNAME"))
                .ok(),
        }
    }
}

/// This user's runtime directory found by who they are, for a session that never set
/// `XDG_RUNTIME_DIR` (an ssh login without a session manager is the usual one).
///
/// `/run/user/<uid>` is where the login manager makes it, so it is used when it is a directory
/// this user owns. Without it the address falls back to `$HOME/.cache`, which a cache cleaner is
/// allowed to empty; this keeps that fallback for the machines that really have nothing better.
#[cfg(target_os = "linux")]
fn runtime_dir_by_uid() -> Option<OsString> {
    use std::os::unix::fs::MetadataExt as _;
    let uid = rustix::process::getuid().as_raw();
    let path = PathBuf::from(format!("/run/user/{uid}"));
    let meta = std::fs::metadata(&path).ok()?;
    (meta.is_dir() && meta.uid() == uid).then(|| path.into_os_string())
}

#[cfg(not(target_os = "linux"))]
fn runtime_dir_by_uid() -> Option<OsString> {
    None
}

/// The longest a Unix socket path may be, including its terminating NUL.
///
/// `sun_path` is 108 bytes on Linux and 104 on macOS, and the limit is not advisory: a longer
/// path is silently truncated by some libcs and refused by others, and a truncated one binds
/// somewhere nobody asked for. It bites on macOS, where `TMPDIR` is already something like
/// `/var/folders/qw/8p3n1x_d4tz9g7v0_0000gn/T/` before a name is appended.
pub const fn sun_path_limit(host: Host) -> usize {
    match host {
        Host::Mac => 104,
        Host::Linux | Host::Windows => 108,
    }
}

/// Which platform this build is for.
pub const fn here() -> Host {
    #[cfg(target_os = "macos")]
    {
        Host::Mac
    }
    #[cfg(target_os = "windows")]
    {
        Host::Windows
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        Host::Linux
    }
}

/// Where an agent called `name` listens for this user, given an environment.
///
/// The order within each platform is "the right directory, then one that always exists". The
/// fallbacks matter more than they look: a login shell over ssh often has no `XDG_RUNTIME_DIR`,
/// and refusing to run there would make the agent unavailable in exactly the session most likely
/// to want a command-line client.
pub fn address_on(name: &str, host: Host, env: &Environment) -> Result<Address, Error> {
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        // Refused rather than escaped. The name reaches a filesystem path on two platforms and a
        // machine-wide namespace on the third, and the failure mode of getting that wrong is an
        // agent listening somewhere it should not be.
        return Err(Error::BadName(name.to_owned()));
    }

    match host {
        Host::Windows => {
            // One pipe namespace for the whole machine, so the name has to carry the user: two
            // people signed in to one Windows box are two agents, and without this they would be
            // one — sharing whatever the agent holds.
            let user = env.user.as_deref().unwrap_or("default");
            let dir = env
                .local_app_data
                .as_ref()
                .map(PathBuf::from)
                .or_else(|| env.tmpdir.as_ref().map(PathBuf::from))
                .ok_or(Error::Homeless("neither LOCALAPPDATA nor TEMP is set"))?;
            Ok(Address {
                endpoint: Endpoint::Pipe(format!("{name}-{user}")),
                lock: dir.join(name).join("agent.lock"),
            })
        }
        Host::Linux => {
            let dir = env
                .runtime_dir
                .as_ref()
                .map(PathBuf::from)
                .or_else(|| env.home.as_ref().map(|h| PathBuf::from(h).join(".cache")))
                .ok_or(Error::Homeless("neither XDG_RUNTIME_DIR nor HOME is set"))?;
            socket_address(&dir, name, host)
        }
        Host::Mac => {
            // macOS has no XDG_RUNTIME_DIR at all. Its `TMPDIR` is per-user and private, which is
            // the property that matters; `/tmp` would put the socket somewhere every other
            // account on the machine can see.
            let dir = env
                .tmpdir
                .as_ref()
                .map(PathBuf::from)
                .or_else(|| {
                    env.home
                        .as_ref()
                        .map(|h| PathBuf::from(h).join("Library/Caches"))
                })
                .ok_or(Error::Homeless("neither TMPDIR nor HOME is set"))?;
            socket_address(&dir, name, host)
        }
    }
}

/// The Unix socket and lock for `name` under `dir`, refused if the socket path will not fit.
fn socket_address(dir: &Path, name: &str, host: Host) -> Result<Address, Error> {
    let home = dir.join(name);
    let socket = home.join("agent.sock");
    let length = socket.as_os_str().len() + 1; // the NUL
    if length > sun_path_limit(host) {
        // Said here, in full, rather than discovered later as a path that bound somewhere
        // unexpected. Nothing the caller can do about it except choose a shorter name or set
        // `TMPDIR`, and both of those need the numbers.
        return Err(Error::TooLong {
            path: socket,
            length,
            limit: sun_path_limit(host),
        });
    }
    Ok(Address {
        endpoint: Endpoint::Socket(socket),
        lock: home.join("agent.lock"),
    })
}
