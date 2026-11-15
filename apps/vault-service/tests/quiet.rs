//! The command line and the credential helpers write no core file, and output nobody can take any more ends them with 74,
//! not with an abort (lib.rs `quiet_client`): a terminal closed under `ame vault`, while it asked a question, aborted it
//! with a core file of its memory before.

use std::fs::File;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const CLI: &str = env!("CARGO_BIN_EXE_amethystora-vault-cli");
const HELPERS: [&str; 2] = [env!("CARGO_BIN_EXE_git-credential-amethystora"), env!("CARGO_BIN_EXE_docker-credential-amethystora")];

#[test]
fn output_nobody_can_take_ends_the_program_with_74() {
    // The command line's usage, on a standard error that is full
    let status = Command::new(CLI)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(File::create("/dev/full").expect("/dev/full"))
        .status()
        .expect("the command line starts");
    assert_eq!(status.signal(), None, "ended by a signal: {status:?}");
    assert_eq!(status.code(), Some(74));
}

#[test]
fn the_helpers_never_write_a_core_file() {
    for helper in HELPERS {
        // `store` reads what it is given to the end first: with the pipe held open it waits, and its limits can be read
        let mut child = Command::new(helper)
            .arg("store")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("the helper starts");
        let limits = format!("/proc/{}/limits", child.id());
        let started = Instant::now();
        let line = loop {
            let read = std::fs::read_to_string(&limits).unwrap_or_default();
            // Until the helper itself has set it, the limit is the test's own (a soft 0 is common): read until both are 0
            // or a second has passed
            let line = read.lines().find(|line| line.starts_with("Max core file size")).unwrap_or_default().to_string();
            let both = line.split_whitespace().skip(4).take(2).all(|limit| limit == "0") && line.split_whitespace().count() > 5;
            if both || started.elapsed() > Duration::from_secs(1) {
                break line;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        drop(child.stdin.take());
        let _ = child.wait();
        let fields: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(fields.get(4..6), Some(&["0", "0"][..]), "{helper}: {line}");
    }
}
