//! What the job process shuts itself off from (`confine.rs`): each test starts itself again as the probe, which confines itself and
//! then tries one thing a compromised parser would, so that the filter and the file rules are proved by what they stop.

use std::ffi::CString;
use std::process::Command;

use amethystora_vault_service::confine::{confine, landlock_abi, Confined};

const PROBE: &str = "AMETHYSTORA_CONFINE_PROBE";

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Runs `operation` in a copy of this test that confined itself first. The copy is given a folder with a file in it, made before it
/// confined itself and its own to change: an operation that was not stopped would succeed on it.
fn confined(test: &str, operation: fn(&str, Confined)) {
    if let Ok(state) = std::env::var(PROBE) {
        let held = confine();
        // Where the checks are required (the apps layer sets it, as for the verifiers), a part that did not take hold is a failure
        // and not a skip: the test would otherwise pass on a kernel or sandbox with neither
        if std::env::var_os("VAULT_VERIFIERS_REQUIRED").is_some() {
            assert!(held.held(), "the job process was not confined: {held:?}");
        }
        operation(&state, held);
        println!("confined: {held:?}, Landlock ABI {}", landlock_abi());
        return;
    }
    let state = std::env::temp_dir().join(format!("amethystora-confine-{test}-{}", std::process::id()));
    std::fs::create_dir_all(&state).unwrap();
    std::fs::write(state.join("account"), b"sealed").unwrap();
    let me = std::env::current_exe().unwrap();
    let out = Command::new(me).args(["--exact", test, "--nocapture", "--test-threads=1"]).env(PROBE, &state).output().unwrap();
    let _ = std::fs::remove_dir_all(&state);
    print!("{}", String::from_utf8_lossy(&out.stdout).lines().filter(|line| line.starts_with("confined:")).collect::<String>());
    assert!(out.status.success(), "{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
}

fn path(state: &str, name: &str) -> CString {
    CString::new(format!("{state}/{name}")).unwrap()
}

/// What was stopped: the call failed with a refusal (seccomp's EPERM, or Landlock's EACCES)
fn refused(result: libc::c_long, what: &str) {
    assert_eq!(result, -1, "{what} was not stopped");
    assert!(matches!(errno(), libc::EPERM | libc::EACCES), "{what}: errno {}", errno());
}

/// Whether the part of the confinement that stops this was in force
fn held_any(held: Confined) -> bool {
    held.files || held.calls
}

#[test]
fn a_job_cannot_open_the_state_or_write_anywhere() {
    confined("a_job_cannot_open_the_state_or_write_anywhere", |state, held| {
        if !held.files {
            return;
        }
        // SAFETY: plain calls with valid arguments, made to see them refused
        unsafe {
            assert_eq!(libc::open(path(state, "account").as_ptr(), libc::O_RDONLY), -1);
            assert_eq!(errno(), libc::EACCES, "the state");
            assert_eq!(libc::open(c"/etc/amethystora-confine-test".as_ptr(), libc::O_WRONLY | libc::O_CREAT, 0o600), -1);
            let fd = libc::open(c"/usr".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
            assert!(fd >= 0, "/usr is read");
            libc::close(fd);
        }
    });
}

#[test]
fn a_job_cannot_reach_a_socket_or_another_program() {
    confined("a_job_cannot_reach_a_socket_or_another_program", |_, held| {
        if !held.calls {
            return;
        }
        // SAFETY: plain calls with valid arguments, made to see them refused
        unsafe {
            assert_eq!(libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0), -1);
            assert_eq!(errno(), libc::EPERM, "a socket");
            let shell = CString::new("/bin/true").unwrap();
            let argv = [shell.as_ptr(), std::ptr::null()];
            assert_eq!(libc::execv(shell.as_ptr(), argv.as_ptr()), -1);
            assert_eq!(errno(), libc::EPERM, "another program");
            assert_eq!(libc::ptrace(libc::PTRACE_ATTACH, libc::getppid(), 0, 0), -1);
            assert_eq!(errno(), libc::EPERM, "ptrace");
        }
    });
}

#[test]
fn a_job_cannot_change_a_files_mode() {
    confined("a_job_cannot_change_a_files_mode", |state, held| {
        if !held.calls {
            return;
        }
        let file = path(state, "account");
        // SAFETY: plain calls with valid arguments, made to see them refused
        unsafe {
            refused(libc::chmod(file.as_ptr(), 0o666).into(), "chmod");
            refused(libc::syscall(libc::SYS_fchmodat, libc::AT_FDCWD, file.as_ptr(), 0o666, 0), "fchmodat");
            refused(libc::syscall(452, libc::AT_FDCWD, file.as_ptr(), 0o666, 0), "fchmodat2");
            refused(libc::fchmod(1, 0o666).into(), "fchmod");
        }
        assert_ne!(std::os::unix::fs::MetadataExt::mode(&std::fs::metadata(format!("{state}/account")).unwrap()) & 0o777, 0o666);
    });
}

#[test]
fn a_job_cannot_change_a_files_owner() {
    confined("a_job_cannot_change_a_files_owner", |state, held| {
        if !held.calls {
            return;
        }
        let file = path(state, "account");
        // SAFETY: plain calls with valid arguments, made to see them refused
        unsafe {
            refused(libc::chown(file.as_ptr(), libc::getuid(), libc::getgid()).into(), "chown");
            refused(libc::lchown(file.as_ptr(), libc::getuid(), libc::getgid()).into(), "lchown");
            refused(libc::fchownat(libc::AT_FDCWD, file.as_ptr(), libc::getuid(), libc::getgid(), 0).into(), "fchownat");
            refused(libc::fchown(1, libc::getuid(), libc::getgid()).into(), "fchown");
        }
    });
}

#[test]
fn a_job_cannot_truncate_a_file() {
    confined("a_job_cannot_truncate_a_file", |state, held| {
        if !held_any(held) {
            return;
        }
        let file = path(state, "account");
        // SAFETY: plain calls with valid arguments, made to see them refused
        unsafe {
            refused(libc::truncate(file.as_ptr(), 0).into(), "truncate");
            // Opening it to write is refused too, and with it every way of emptying it
            assert_eq!(libc::open(file.as_ptr(), libc::O_WRONLY | libc::O_TRUNC), -1);
            if held.calls {
                refused(libc::ftruncate(0, 0).into(), "ftruncate");
            }
        }
        assert_eq!(std::fs::metadata(format!("{state}/account")).map(|metadata| metadata.len()).unwrap_or(6), 6);
    });
}

#[test]
fn a_job_cannot_set_attributes_or_times() {
    confined("a_job_cannot_set_attributes_or_times", |state, held| {
        if !held.calls {
            return;
        }
        let file = path(state, "account");
        let value = [0u8; 4];
        let times = [libc::timespec { tv_sec: 1, tv_nsec: 0 }, libc::timespec { tv_sec: 1, tv_nsec: 0 }];
        // SAFETY: plain calls with valid arguments, made to see them refused
        unsafe {
            refused(libc::setxattr(file.as_ptr(), c"user.test".as_ptr(), value.as_ptr().cast(), value.len(), 0).into(), "setxattr");
            refused(libc::lsetxattr(file.as_ptr(), c"user.test".as_ptr(), value.as_ptr().cast(), value.len(), 0).into(), "lsetxattr");
            refused(libc::fsetxattr(1, c"user.test".as_ptr(), value.as_ptr().cast(), value.len(), 0).into(), "fsetxattr");
            refused(libc::removexattr(file.as_ptr(), c"user.test".as_ptr()).into(), "removexattr");
            refused(libc::lremovexattr(file.as_ptr(), c"user.test".as_ptr()).into(), "lremovexattr");
            refused(libc::fremovexattr(1, c"user.test".as_ptr()).into(), "fremovexattr");
            refused(libc::utimensat(libc::AT_FDCWD, file.as_ptr(), times.as_ptr(), 0).into(), "utimensat");
            refused(libc::futimens(1, times.as_ptr()).into(), "futimens");
        }
        assert_ne!(std::fs::metadata(format!("{state}/account")).unwrap().modified().unwrap(), std::time::UNIX_EPOCH + std::time::Duration::from_secs(1));
    });
}

#[test]
fn a_job_cannot_rename_link_or_remove_a_file() {
    confined("a_job_cannot_rename_link_or_remove_a_file", |state, held| {
        if !held_any(held) {
            return;
        }
        let file = path(state, "account");
        let other = path(state, "other");
        // SAFETY: plain calls with valid arguments, made to see them refused
        unsafe {
            refused(libc::rename(file.as_ptr(), other.as_ptr()).into(), "rename");
            refused(libc::syscall(libc::SYS_renameat2, libc::AT_FDCWD, file.as_ptr(), libc::AT_FDCWD, other.as_ptr(), 0), "renameat2");
            refused(libc::link(file.as_ptr(), other.as_ptr()).into(), "link");
            refused(libc::symlink(file.as_ptr(), other.as_ptr()).into(), "symlink");
            refused(libc::unlink(file.as_ptr()).into(), "unlink");
            refused(libc::mkdir(other.as_ptr(), 0o700).into(), "mkdir");
            refused(libc::rmdir(CString::new(state).unwrap().as_ptr()).into(), "rmdir");
        }
        assert!(std::path::Path::new(&format!("{state}/account")).exists());
        assert!(!std::path::Path::new(&format!("{state}/other")).exists());
    });
}

#[test]
fn a_job_cannot_signal_another_process() {
    confined("a_job_cannot_signal_another_process", |_, held| {
        if !held.calls {
            return;
        }
        // SAFETY: signal 0 only asks whether the call is allowed; each is made to see it refused
        unsafe {
            let parent = libc::getppid();
            refused(libc::kill(parent, 0).into(), "kill");
            refused(libc::syscall(libc::SYS_tkill, parent, 0), "tkill");
            refused(libc::syscall(libc::SYS_tgkill, parent, parent, 0), "tgkill");
            let pidfd = libc::syscall(libc::SYS_pidfd_open, parent, 0);
            // pidfd_open is refused as well, so there is no descriptor to signal through; the call itself is refused whatever it is given
            assert_eq!(pidfd, -1);
            refused(libc::syscall(libc::SYS_pidfd_send_signal, 0, 0, 0, 0), "pidfd_send_signal");
        }
    });
}

#[test]
fn a_job_runs_only_when_both_parts_took_hold() {
    assert!(Confined { files: true, calls: true }.held());
    assert!(!Confined { files: false, calls: true }.held());
    assert!(!Confined { files: true, calls: false }.held());
}
