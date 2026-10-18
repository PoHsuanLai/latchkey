//! The socket guards: who has the seat, and which process is the shell.

use latchkey::guard::{AcceptFailure, Claim, Held, Origin, ShellCheck, accept_failure, active_uid};
use peephole::{FixtureImage, FixtureProc, FixtureProcess, Pinned, Prober};
use peephole_core::{FileTrust, Pid, Pin, RoleName, Table, Uid, Writer};
use rustix::io::Errno;

const PID: u32 = 4242;
const MANAGER_1000: &str = "/user.slice/user-1000.slice/user@1000.service";
const SHELL: RoleName = RoleName::from_static("shell");
const TABLE: &str = r#"
[[peer]]
app  = "org.quire.Shell"
unit = "sill.service"
exe  = [
  "/opt/quire/releases/*/bin/sill",
  "/opt/quire/current/bin/sill",
  "/usr/local/bin/sill",
  "/usr/bin/sill",
]
role = "shell"
"#;

fn check(cgroup: &str, image: FixtureImage<'_>) -> ShellCheck<FixtureProc> {
    let proc = FixtureProc::new().process(FixtureProcess {
        pid: Pid::new(PID).unwrap(),
        cgroup: &format!("0::{cgroup}\n"),
        image,
        flatpak_info: None,
    });
    ShellCheck::new(
        Prober::new(proc),
        Table::from_toml(TABLE).unwrap(),
        vec![SHELL],
    )
}

fn held(uid: u32) -> Pinned {
    Pinned::introduced(Pid::new(PID).unwrap(), Uid::new(uid), Pin::Reopened)
}

fn claim_of(cgroup: &str, image: FixtureImage<'_>) -> Claim {
    check(cgroup, image).origin_of(held(1000)).claim()
}

#[test]
fn active_uid_table() {
    const CASES: &[(&str, &str, Option<u32>)] = &[
        (
            "typical file",
            "# This is private data.\nIS_SEAT0=1\nACTIVE=c2\nACTIVE_UID=1000\nSESSIONS=c2\nUIDS=1000\n",
            Some(1000),
        ),
        ("no active session", "IS_SEAT0=1\nSESSIONS=\nUIDS=\n", None),
        ("empty file", "", None),
        ("root", "ACTIVE_UID=0\n", Some(0)),
        ("not a number", "ACTIVE_UID=bob\n", None),
        ("negative", "ACTIVE_UID=-1\n", None),
        ("empty value", "ACTIVE_UID=\n", None),
        ("a key that ends the same", "OLD_ACTIVE_UID=5\n", None),
        ("indented is not the key", " ACTIVE_UID=7\n", None),
        ("first wins", "ACTIVE_UID=1\nACTIVE_UID=2\n", Some(1)),
        ("trailing space", "ACTIVE_UID=42 \n", Some(42)),
        ("no final newline", "ACTIVE_UID=9", Some(9)),
    ];
    for &(name, text, want) in CASES {
        assert_eq!(active_uid(text), want, "{name}");
    }
}

#[test]
fn only_a_missing_connection_ends_the_pass_quietly() {
    let cases: &[(&str, Errno, AcceptFailure)] = &[
        (
            "nothing waiting",
            Errno::AGAIN,
            AcceptFailure::NothingPending,
        ),
        ("a signal", Errno::INTR, AcceptFailure::Retry),
        ("out of descriptors", Errno::MFILE, AcceptFailure::Pause),
        (
            "out of descriptors system-wide",
            Errno::NFILE,
            AcceptFailure::Pause,
        ),
        ("out of buffers", Errno::NOBUFS, AcceptFailure::Pause),
        ("out of memory", Errno::NOMEM, AcceptFailure::Pause),
        ("anything else", Errno::IO, AcceptFailure::Pause),
    ];
    for &(name, errno, want) in cases {
        assert_eq!(accept_failure(errno), want, "{name}");
    }
}

#[test]
fn only_the_trusted_unit_under_the_users_manager_claims_the_shell() {
    let shell = Claim::Shell { user: 1000 };
    let cases: &[(&str, String, Claim)] = &[
        (
            "the shell",
            format!("{MANAGER_1000}/session.slice/sill.service"),
            shell,
        ),
        (
            "another unit",
            format!("{MANAGER_1000}/app.slice/mailo.service"),
            Claim::Other,
        ),
        (
            "a scope",
            format!("{MANAGER_1000}/app.slice/app-sill-1.scope"),
            Claim::Other,
        ),
        (
            "a system service of that name",
            "/system.slice/sill.service".to_owned(),
            Claim::Other,
        ),
        (
            "a manager of another user than the slice",
            "/user.slice/user-999.slice/user@1000.service/session.slice/sill.service".to_owned(),
            Claim::Other,
        ),
        (
            "not under user.slice",
            "/machine.slice/user-1000.slice/user@1000.service/sill.service".to_owned(),
            Claim::Other,
        ),
    ];
    for (name, cgroup, want) in cases {
        assert_eq!(claim_of(cgroup, FixtureImage::Hidden), *want, "{name}");
    }
}

#[test]
fn a_role_the_check_does_not_accept_claims_nothing() {
    let cgroup = format!("{MANAGER_1000}/session.slice/sill.service");
    let proc = FixtureProc::new().process(FixtureProcess {
        pid: Pid::new(PID).unwrap(),
        cgroup: &format!("0::{cgroup}\n"),
        image: FixtureImage::Hidden,
        flatpak_info: None,
    });
    let nobody = ShellCheck::new(Prober::new(proc), Table::from_toml(TABLE).unwrap(), vec![]);
    assert_eq!(nobody.origin_of(held(1000)).claim(), Claim::Other);
}

#[test]
fn a_readable_image_must_be_the_shells_and_root_owned() {
    let cgroup = format!("{MANAGER_1000}/session.slice/sill.service");
    let shell = Claim::Shell { user: 1000 };
    let cases: &[(&str, FixtureImage<'_>, Claim)] = &[
        (
            "the installed shell",
            FixtureImage::Present("/usr/bin/sill", FileTrust::RootOnly),
            shell,
        ),
        (
            "another program in its unit",
            FixtureImage::Present("/usr/bin/sh", FileTrust::RootOnly),
            Claim::Other,
        ),
        (
            "the shell's path, but writable",
            FixtureImage::Present("/usr/bin/sill", FileTrust::Writable(Writer::Group)),
            Claim::Other,
        ),
    ];
    for (name, image, want) in cases {
        assert_eq!(claim_of(&cgroup, *image), *want, "{name}");
    }
}

#[test]
fn a_shell_whose_process_has_exited_claims_nothing() {
    let cgroup = format!("{MANAGER_1000}/session.slice/sill.service");
    let gone = Pinned::introduced_gone(Pid::new(PID).unwrap(), Uid::new(1000), Pin::Reopened);
    let origin = check(&cgroup, FixtureImage::Hidden).origin_of(gone);
    assert_eq!(origin.claim(), Claim::Other, "never gets the claim");

    let left = Origin::Shell(Held {
        process: Pinned::introduced_gone(Pid::new(PID).unwrap(), Uid::new(1000), Pin::Reopened),
        user: 1000,
    });
    assert_eq!(left.claim(), Claim::Other, "loses it on leaving");
    let alive = Origin::Shell(Held {
        process: held(1000),
        user: 1000,
    });
    assert_eq!(alive.claim(), Claim::Shell { user: 1000 });
}
