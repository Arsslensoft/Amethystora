//! The service that holds Amethystora Vault's keys, and what its command line shares with it (plans/done/PLAN-vault.md). No GTK
//! and no GLib: it speaks to the system bus itself (`bus.rs`), and its memory budget is 8 MB.

pub mod alloc;
pub mod bus;
pub mod confine;
pub mod desktop;
pub mod outside;
pub mod peer;
pub mod plugs;
pub mod server;
pub mod service;
pub mod sync;
pub mod sync_kemlock;
pub mod ssh;
pub mod protect;
pub mod credentials;

#[global_allocator]
static WIPING: alloc::Wiping = alloc::Wiping;

/// For the command line and the credential helpers, first thing: what they hold (a password typed, a recovery key, a login
/// handed to git) is never written in a core file, and output nobody can take any more (a terminal closed, a full disk) ends
/// the program with 74 rather than an abort. The limit, which systemd-coredump honours, goes to what `run` starts too; not
/// PR_SET_DUMPABLE, under which `run` could not write its namespace's user map.
pub fn quiet_client() {
    let none = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: setrlimit reads the struct it is given and changes this process's limit only
    unsafe {
        libc::setrlimit(libc::RLIMIT_CORE, &raw const none);
    }
    let usual = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let said = info.payload().downcast_ref::<String>().map(String::as_str).or_else(|| info.payload().downcast_ref::<&str>().copied());
        if said.is_some_and(|said| said.starts_with("failed printing to std")) {
            std::process::exit(74);
        }
        usual(info);
    }));
}
