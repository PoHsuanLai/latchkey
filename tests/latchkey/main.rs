//! latchkey's integration tests, as one binary.
//!
//! Each former `tests/*.rs` file is a module here, so the crate links once instead of once per
//! file. `helpers` holds what the modules share. Nothing here needs its own process: no test sets
//! process-global state, forks, or depends on a clean environment, and the cross-process tests
//! only set env on the children they spawn.

mod across_processes;
mod address;
mod helpers;
mod lifecycle;

/// Fails if a test file is not part of this binary.
///
/// Cargo finds `tests/latchkey/main.rs` and nothing else in that directory, so a new file that
/// nobody declares would have its tests silently never run. A stray `tests/*.rs` would be picked
/// up as a binary of its own, which is the cost this binary exists to remove, so it fails too.
#[test]
fn every_test_file_is_declared_here() {
    use std::ffi::OsStr;

    let tests = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let folder = tests.join("latchkey");
    let main = std::fs::read_to_string(folder.join("main.rs")).unwrap();
    let declared: Vec<String> = main
        .lines()
        .filter_map(|line| {
            line.trim()
                .strip_prefix("mod ")
                .and_then(|rest| rest.strip_suffix(';'))
                .map(str::to_owned)
        })
        .collect();

    let mut undeclared = Vec::new();
    for entry in std::fs::read_dir(&folder).unwrap() {
        let path = entry.unwrap().path();
        if path.extension() != Some(OsStr::new("rs"))
            || path.file_name() == Some(OsStr::new("main.rs"))
        {
            continue;
        }
        let stem = path.file_stem().unwrap().to_string_lossy().into_owned();
        if !declared.contains(&stem) {
            undeclared.push(stem);
        }
    }
    assert!(
        undeclared.is_empty(),
        "not declared as `mod` in tests/latchkey/main.rs: {undeclared:?}"
    );

    let mut stray = Vec::new();
    for entry in std::fs::read_dir(&tests).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() && path.extension() == Some(OsStr::new("rs")) {
            stray.push(path);
        }
    }
    assert!(
        stray.is_empty(),
        "a test file sits outside tests/latchkey/, where it is its own binary: {stray:?}"
    );
}
