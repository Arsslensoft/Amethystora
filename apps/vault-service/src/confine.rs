//! What `amethystora-vault-work` shuts itself off from before it reads its job. The child shares the service's user, and so its
//! state folder (every account's sealed vaults) and the right to ask systemd-creds for the chip's secrets: it has no need of
//! either, since a job arrives on standard input and its answer leaves on standard output, and what parses a stranger's key,
//! certificate or sync answer in libcrypto must not be able to reach them if it goes wrong.
//!
//! Two things, both with raw system calls (no crate): Landlock lets it read only `/usr`, `/etc`, `/dev`, `/proc` and `/sys`
//! (libcrypto's libraries, providers and configuration, the kernel's random numbers) and write nothing, so `/var/lib` (the state),
//! `/run` (the sockets, systemd-creds') and `/tmp` are closed to it, nor can it make, remove, rename, link or truncate a file, or
//! signal a process outside its own; and a seccomp filter takes away the calls that would reach the chip or the service by another
//! road (sockets, running programs, ptrace, other processes' memory and descriptors) and the ones no Landlock right covers (a
//! file's mode, owner, attributes and times, and signals to any process). Landlock's ABI is asked of the kernel at run time and
//! every right it knows is handled, up to ABI 6. `Confined` says which part held, and the job refuses to run unless both did
//! (`work.rs`). The service's own unit already has `NoNewPrivileges`.

use std::ffi::CString;

/// Which parts took hold
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Confined {
    pub files: bool,
    pub calls: bool,
}

impl Confined {
    /// Whether the process may be handed bytes to parse
    pub fn held(&self) -> bool {
        self.files && self.calls
    }
}

/// Landlock's first ABI: every file access it knows
const HANDLED_V1: u64 = (1 << 13) - 1;
/// ABI 2: `REFER` (moving or linking a file between folders); ABI 3: `TRUNCATE`; ABI 5: `IOCTL_DEV`
const REFER: u64 = 1 << 13;
const TRUNCATE: u64 = 1 << 14;
const IOCTL_DEV: u64 = 1 << 15;
/// ABI 6: `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL`: no abstract socket and no signal reaches outside the process's own domain
const SCOPES: u64 = 1 | (1 << 1);
/// The newest ABI this file knows the rights of
const NEWEST_ABI: i64 = 6;
/// `LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR`
const READ: u64 = (1 << 2) | (1 << 3);
const LANDLOCK_CREATE_RULESET_VERSION: libc::c_long = 1;
/// What libcrypto and the dynamic loader read
const READABLE: [&str; 5] = ["/usr", "/etc", "/dev", "/proc", "/sys"];

const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;
const LANDLOCK_RULE_PATH_BENEATH: libc::c_long = 1;

/// `struct landlock_ruleset_attr`, as far as the kernel's ABI goes (ABI 4 added the network field, ABI 6 the scopes)
#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

#[repr(C, packed)]
struct PathBeneath {
    allowed_access: u64,
    parent_fd: i32,
}

/// One instruction of a classic BPF program (`struct sock_filter`)
#[repr(C)]
#[derive(Clone, Copy)]
struct Instruction {
    code: u16,
    jump_true: u8,
    jump_false: u8,
    constant: u32,
}

/// `struct sock_fprog`
#[repr(C)]
struct Program {
    length: u16,
    filter: *const Instruction,
}

const LOAD_WORD: u16 = 0x20;
const JUMP_EQUAL: u16 = 0x15;
const JUMP_SET: u16 = 0x45;
const RETURN: u16 = 0x06;
const ALLOW: u32 = 0x7fff_0000;
const KILL: u32 = 0x8000_0000;
const FAIL_WITH_PERMISSION: u32 = 0x0005_0000 | 1;
const X32_BIT: u32 = 0x4000_0000;

#[cfg(target_arch = "x86_64")]
const ARCHITECTURE: Option<u32> = Some(0xC000_003E);
#[cfg(target_arch = "aarch64")]
const ARCHITECTURE: Option<u32> = Some(0xC000_00B7);
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const ARCHITECTURE: Option<u32> = None;

/// The calls a job never makes, which each failed with EPERM: a way to the chip's secrets or the service, or out of the job
fn denied() -> Vec<u32> {
    let mut calls = vec![
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_pidfd_open,
        libc::SYS_pidfd_getfd,
        libc::SYS_io_uring_setup,
        libc::SYS_open_by_handle_at,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        // What no Landlock right covers: a file's mode, owner, extended attributes, times and size
        libc::SYS_fchmod,
        libc::SYS_fchmodat,
        libc::SYS_fchown,
        libc::SYS_fchownat,
        libc::SYS_truncate,
        libc::SYS_ftruncate,
        libc::SYS_setxattr,
        libc::SYS_lsetxattr,
        libc::SYS_fsetxattr,
        libc::SYS_removexattr,
        libc::SYS_lremovexattr,
        libc::SYS_fremovexattr,
        libc::SYS_utimensat,
        // Making, removing, renaming and linking, which Landlock refuses too: the filter does not depend on it
        libc::SYS_renameat,
        libc::SYS_renameat2,
        libc::SYS_linkat,
        libc::SYS_unlinkat,
        libc::SYS_symlinkat,
        libc::SYS_mkdirat,
        libc::SYS_mknodat,
        // Signals to any process: a job ends by returning, and its alarm is the kernel's
        libc::SYS_kill,
        libc::SYS_tkill,
        libc::SYS_tgkill,
        libc::SYS_rt_sigqueueinfo,
        libc::SYS_rt_tgsigqueueinfo,
        libc::SYS_pidfd_send_signal,
    ];
    // Newer than the libc crate's names, and the same number on both architectures: fchmodat2, setxattrat, removexattrat and file_setattr
    calls.extend([452, 463, 466, 469]);
    // Only x86_64 has the older forms of these (aarch64 starts at the *at calls above)
    #[cfg(target_arch = "x86_64")]
    calls.extend([
        libc::SYS_chmod,
        libc::SYS_chown,
        libc::SYS_lchown,
        libc::SYS_utime,
        libc::SYS_utimes,
        libc::SYS_futimesat,
        libc::SYS_rename,
        libc::SYS_link,
        libc::SYS_unlink,
        libc::SYS_rmdir,
        libc::SYS_mkdir,
        libc::SYS_mknod,
        libc::SYS_symlink,
    ]);
    calls.iter().map(|number| *number as u32).collect()
}

/// The filter's program: the wrong architecture and x32 are killed, the calls above fail, the rest pass
fn program(architecture: u32, denied: &[u32]) -> Vec<Instruction> {
    let step = |code, jump_true, jump_false, constant| Instruction { code, jump_true, jump_false, constant };
    // `seccomp_data`: the call's number at 0 and the architecture at 4
    let mut filter = vec![step(LOAD_WORD, 0, 0, 4), step(JUMP_EQUAL, 1, 0, architecture), step(RETURN, 0, 0, KILL), step(LOAD_WORD, 0, 0, 0)];
    if cfg!(target_arch = "x86_64") {
        filter.push(step(JUMP_SET, 0, 1, X32_BIT));
        filter.push(step(RETURN, 0, 0, KILL));
    }
    for number in denied {
        filter.push(step(JUMP_EQUAL, 0, 1, *number));
        filter.push(step(RETURN, 0, 0, FAIL_WITH_PERMISSION));
    }
    filter.push(step(RETURN, 0, 0, ALLOW));
    filter
}

fn seccomp() -> bool {
    let Some(architecture) = ARCHITECTURE else { return false };
    let filter = program(architecture, &denied());
    let program = Program { length: filter.len() as u16, filter: filter.as_ptr() };
    // SAFETY: prctl with a filter that lives through the call; it only restricts this process and what it starts
    unsafe { libc::prctl(libc::PR_SET_SECCOMP, 2, &raw const program, 0, 0) == 0 }
}

/// The Landlock ABI the kernel speaks, or 0 for none
pub fn landlock_abi() -> i64 {
    // SAFETY: no ruleset is given and only the version is asked
    let version = unsafe { libc::syscall(SYS_LANDLOCK_CREATE_RULESET, std::ptr::null::<RulesetAttr>(), 0, LANDLOCK_CREATE_RULESET_VERSION) };
    i64::from(version).max(0)
}

/// What a kernel of this ABI is asked to refuse: every file access it knows, and the scopes, and how much of the attribute it reads
fn ruleset_for(abi: i64) -> (RulesetAttr, usize) {
    let mut handled = HANDLED_V1;
    for (since, right) in [(2, REFER), (3, TRUNCATE), (5, IOCTL_DEV)] {
        if abi >= since {
            handled |= right;
        }
    }
    let size = match abi {
        ..=3 => 8,
        4..=5 => 16,
        _ => 24,
    };
    (RulesetAttr { handled_access_fs: handled, handled_access_net: 0, scoped: if abi >= 6 { SCOPES } else { 0 } }, size)
}

fn landlock() -> bool {
    let version = landlock_abi().min(NEWEST_ABI);
    if version < 1 {
        return false;
    }
    let (attr, size) = ruleset_for(version);
    // SAFETY: the call reads `size` bytes of `attr`, which are the fields this ABI has; what it returns is a descriptor or an error
    let ruleset = unsafe { libc::syscall(SYS_LANDLOCK_CREATE_RULESET, &raw const attr, size, 0) };
    if ruleset < 0 {
        return false;
    }
    let ruleset = ruleset as libc::c_int;
    for path in READABLE {
        let Ok(path) = CString::new(path) else { continue };
        // SAFETY: a plain open of a path, whose descriptor is closed below
        let parent = unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if parent < 0 {
            continue;
        }
        let rule = PathBeneath { allowed_access: READ, parent_fd: parent };
        // SAFETY: `rule` is the struct the call reads for a rule of this kind
        unsafe {
            libc::syscall(SYS_LANDLOCK_ADD_RULE, ruleset, LANDLOCK_RULE_PATH_BENEATH, &raw const rule, 0);
            libc::close(parent);
        }
    }
    // SAFETY: restricts this process alone, from a ruleset it holds
    let held = unsafe { libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset, 0) } == 0;
    // SAFETY: the ruleset's descriptor is ours and no longer needed
    unsafe { libc::close(ruleset) };
    held
}

/// Takes the job's process off the state, the sockets and every other program. Call it first, before libcrypto has read anything.
pub fn confine() -> Confined {
    // SAFETY: no new privileges for this process and what it starts, which both parts need and the unit asks for anyway
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Confined { files: false, calls: false };
    }
    Confined { files: landlock(), calls: seccomp() }
}
