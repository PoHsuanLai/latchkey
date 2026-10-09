//! Where each platform puts its agent.
//!
//! All of it runs on every machine, because [`address_on`] takes the environment as arguments
//! instead of reading it. That is the property the crate is built around: the macOS rule is
//! checked by whoever runs `cargo test`, not by whoever happens to own a Mac.

use latchkey::{Endpoint, Environment, Error, Host, address_on};
use std::ffi::OsStr;
use std::path::PathBuf;

fn os(text: &str) -> &OsStr {
    OsStr::new(text)
}

/// One row per environment. Each row is checked, and a failure names the row.
#[test]
fn where_each_platform_puts_its_agent() {
    let rows: [(&str, Host, Environment, Endpoint, Option<PathBuf>); 4] = [
        // tmpfs, 0700, and emptied when the session ends — the lifetime a socket wants, and the
        // reason a stale one there cannot survive a reboot.
        (
            "linux: the runtime directory",
            Host::Linux,
            Environment {
                runtime_dir: Some(os("/run/user/1000")),
                home: Some(os("/home/ada")),
                ..Environment::default()
            },
            Endpoint::Socket(PathBuf::from("/run/user/1000/mailo/agent.sock")),
            Some(PathBuf::from("/run/user/1000/mailo/agent.lock")),
        ),
        // A login shell over ssh often has no XDG_RUNTIME_DIR. Refusing to run there would make the
        // agent unavailable in exactly the session most likely to want a command-line client.
        (
            "linux: no runtime directory falls back under home",
            Host::Linux,
            Environment {
                home: Some(os("/home/ada")),
                ..Environment::default()
            },
            Endpoint::Socket(PathBuf::from("/home/ada/.cache/mailo/agent.sock")),
            None,
        ),
        // macOS has no XDG_RUNTIME_DIR at all. Its TMPDIR is per-user and private, which is the
        // property that matters; /tmp would put the socket somewhere every other account can see.
        (
            "mac: its own per-user temporary directory",
            Host::Mac,
            Environment {
                tmpdir: Some(os("/var/folders/qw/8p3n1x/T")),
                home: Some(os("/Users/ada")),
                ..Environment::default()
            },
            Endpoint::Socket(PathBuf::from("/var/folders/qw/8p3n1x/T/mailo/agent.sock")),
            None,
        ),
        (
            "mac: no temporary directory falls back to its caches",
            Host::Mac,
            Environment {
                home: Some(os("/Users/ada")),
                ..Environment::default()
            },
            Endpoint::Socket(PathBuf::from("/Users/ada/Library/Caches/mailo/agent.sock")),
            None,
        ),
    ];
    for (label, host, env, endpoint, lock) in rows {
        let found =
            address_on("mailo", host, &env).unwrap_or_else(|e| panic!("row \"{label}\": {e}"));
        assert_eq!(found.endpoint, endpoint, "row \"{label}\": endpoint");
        if let Some(lock) = lock {
            assert_eq!(found.lock, lock, "row \"{label}\": lock");
        }
    }
}

#[test]
fn windows_names_the_pipe_after_the_user() {
    // One pipe namespace for the whole machine, so the name has to carry the user: two people
    // signed in to one Windows box are two agents, and without this they would be one — sharing
    // whatever the agent holds.
    let found = address_on(
        "mailo",
        Host::Windows,
        &Environment {
            local_app_data: Some(os(r"C:\Users\ada\AppData\Local")),
            user: Some("ada"),
            ..Environment::default()
        },
    )
    .unwrap();
    assert_eq!(found.endpoint, Endpoint::Pipe("mailo-ada".to_owned()));
    assert_eq!(
        found.lock,
        PathBuf::from(r"C:\Users\ada\AppData\Local")
            .join("mailo")
            .join("agent.lock")
    );

    // Step 2: two users on one Windows machine are two agents. This was its own test; it is a step
    // here because it asserts one more fact about the same name rule.
    let for_user = |who: &str| {
        address_on(
            "mailo",
            Host::Windows,
            &Environment {
                local_app_data: Some(os(r"C:\x")),
                user: Some(who),
                ..Environment::default()
            },
        )
        .unwrap()
        .endpoint
    };
    assert_ne!(
        for_user("ada"),
        for_user("grace"),
        "step 2 (two users on one Windows machine are two agents)"
    );
}

/// Every input the crate must refuse, and the few it must take. One row per case, each with its
/// why-comment; a failure names the row.
#[test]
fn what_is_refused() {
    /// What a row expects: taken, refused with a message naming each word, or refused as too long.
    enum Want {
        Accepted,
        Refused(&'static [&'static str]),
        TooLong,
    }

    // `sun_path` is 108 bytes on Linux and 104 on macOS, and the limit is not advisory: a longer
    // path is silently truncated by some libcs and refused by others, and a truncated one binds
    // somewhere nobody asked for. Refusing loudly is the only safe answer.
    //
    // This directory is 88 characters, and "/mailo/agent.sock" adds 17, so the whole is 106
    // bytes including the NUL — which fits Linux and does not fit macOS. One environment, two
    // answers, which is exactly the case a single `cfg!` would have hidden. Asserted rather than
    // eyeballed, because the first version of this test used a length that fit both and passed
    // for the wrong reason.
    let long = "/".to_owned() + &"d".repeat(87);
    assert_eq!(
        long.len() + "/mailo/agent.sock".len() + 1,
        106,
        "the fixture is 106 bytes"
    );

    let rows: [(&str, &str, Host, Environment, Want); 15] = [
        // The refusal must say the numbers (104 and the name), so an operator can act on it.
        (
            "too long for sun_path: 106 bytes on macOS (limit 104)",
            "mailo",
            Host::Mac,
            Environment {
                runtime_dir: Some(os(&long)),
                tmpdir: Some(os(&long)),
                ..Environment::default()
            },
            Want::TooLong,
        ),
        (
            "the same 106 bytes fits Linux (limit 108)",
            "mailo",
            Host::Linux,
            Environment {
                runtime_dir: Some(os(&long)),
                tmpdir: Some(os(&long)),
                ..Environment::default()
            },
            Want::Accepted,
        ),
        // The name becomes a path component on two platforms and part of a machine-wide namespace
        // on the third. Escaping it would be a guess about three sets of rules; refusing is not.
        (
            "name: empty",
            "",
            Host::Linux,
            Environment {
                runtime_dir: Some(os("/run/user/1000")),
                ..Environment::default()
            },
            Want::Refused(&[]),
        ),
        (
            "name: ../etc escapes its directory",
            "../etc",
            Host::Linux,
            Environment {
                runtime_dir: Some(os("/run/user/1000")),
                ..Environment::default()
            },
            Want::Refused(&[]),
        ),
        (
            "name: a/b has a separator",
            "a/b",
            Host::Linux,
            Environment {
                runtime_dir: Some(os("/run/user/1000")),
                ..Environment::default()
            },
            Want::Refused(&[]),
        ),
        (
            "name: 'a b' has a space",
            "a b",
            Host::Linux,
            Environment {
                runtime_dir: Some(os("/run/user/1000")),
                ..Environment::default()
            },
            Want::Refused(&[]),
        ),
        (
            "name: a\\b has a backslash",
            r"a\b",
            Host::Linux,
            Environment {
                runtime_dir: Some(os("/run/user/1000")),
                ..Environment::default()
            },
            Want::Refused(&[]),
        ),
        (
            "name: a.b has a dot",
            "a.b",
            Host::Linux,
            Environment {
                runtime_dir: Some(os("/run/user/1000")),
                ..Environment::default()
            },
            Want::Refused(&[]),
        ),
        (
            "name: naïve is not ASCII",
            "naïve",
            Host::Linux,
            Environment {
                runtime_dir: Some(os("/run/user/1000")),
                ..Environment::default()
            },
            Want::Refused(&[]),
        ),
        (
            "name: mailo is accepted",
            "mailo",
            Host::Linux,
            Environment {
                runtime_dir: Some(os("/run/user/1000")),
                ..Environment::default()
            },
            Want::Accepted,
        ),
        (
            "name: my-agent is accepted",
            "my-agent",
            Host::Linux,
            Environment {
                runtime_dir: Some(os("/run/user/1000")),
                ..Environment::default()
            },
            Want::Accepted,
        ),
        (
            "name: agent2 is accepted",
            "agent2",
            Host::Linux,
            Environment {
                runtime_dir: Some(os("/run/user/1000")),
                ..Environment::default()
            },
            Want::Accepted,
        ),
        // There is nowhere to put a socket, and the crate says so rather than guessing a place.
        (
            "nothing set on linux says so",
            "mailo",
            Host::Linux,
            Environment::default(),
            Want::Refused(&["nowhere"]),
        ),
        (
            "nothing set on mac says so",
            "mailo",
            Host::Mac,
            Environment::default(),
            Want::Refused(&["nowhere"]),
        ),
        (
            "nothing set on windows says so",
            "mailo",
            Host::Windows,
            Environment::default(),
            Want::Refused(&["nowhere"]),
        ),
    ];

    for (label, name, host, env, want) in rows {
        let got = address_on(name, host, &env);
        match want {
            Want::Accepted => {
                if let Err(e) = got {
                    panic!("row \"{label}\": refused, but it must be taken: {e}");
                }
            }
            Want::Refused(words) => {
                let said = match got {
                    Ok(found) => {
                        panic!("row \"{label}\": taken as {found:?}, but it must be refused")
                    }
                    Err(e) => e.to_string(),
                };
                for &word in words {
                    assert!(
                        said.contains(word),
                        "row \"{label}\": {said:?} does not name {word:?}"
                    );
                }
            }
            Want::TooLong => {
                let e = match got {
                    Err(e) => e,
                    Ok(found) => {
                        panic!("row \"{label}\": taken as {found:?}, but it must be refused")
                    }
                };
                match &e {
                    Error::TooLong { length, limit, .. } => {
                        assert_eq!(*limit, 104, "row \"{label}\": limit");
                        assert!(*length > 104, "row \"{label}\": length {length}");
                    }
                    other => panic!("row \"{label}\": {other:?}"),
                }
                let said = e.to_string();
                assert!(said.contains("104"), "row \"{label}\": {said}");
                assert!(said.contains("mailo"), "row \"{label}\": {said}");
            }
        }
    }
}
