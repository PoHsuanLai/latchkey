//! Helpers the test modules of this binary share.

use latchkey::{Agent, Environment};
use std::path::Path;

/// A name no other test, and no other run, will use.
///
/// A temporary directory is *not* enough isolation, and finding that out is what these tests cost.
/// On Unix the endpoint lives inside the directory, so a per-test directory separates everything.
/// On Windows the endpoint is a named pipe, whose namespace is machine-wide and derives only from
/// the agent's name and the user — so tests that shared a name addressed the same pipe while
/// holding different locks, and their agents fought over one door. The Unix suite passed
/// throughout; the Windows one hung.
///
/// The pid keeps concurrent `cargo test` runs apart, and the counter keeps this run's tests apart
/// from each other. One counter serves the whole binary, so every module draws from the same pool.
pub fn unique_name() -> String {
    use std::sync::atomic::{AtomicU32, Ordering};
    static NEXT: AtomicU32 = AtomicU32::new(0);
    format!(
        "t{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

/// An agent addressed inside `dir`, under the name `name` for the user `user`.
///
/// `latchkey::here()` rather than a fixed `Host`: the tests that use this are about what the
/// kernel does, so they have to run under the rules of the machine they are on. The *rules
/// themselves* are tested for all three platforms in `address.rs`, where they are a pure function
/// and need no kernel at all.
///
/// The user is a parameter because on Windows it is part of the pipe name: a test that starts a
/// child agent must address it with the same user the child was started with.
pub fn agent_in(dir: &Path, name: &str, user: &str) -> Agent {
    let dir = dir.as_os_str();
    Agent::in_environment(
        name,
        latchkey::here(),
        &Environment {
            runtime_dir: Some(dir),
            tmpdir: Some(dir),
            local_app_data: Some(dir),
            user: Some(user),
            ..Environment::default()
        },
    )
    .unwrap()
}
