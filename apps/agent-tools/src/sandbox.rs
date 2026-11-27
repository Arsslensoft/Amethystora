//! An agent that can change its project and nothing else (plans/done/PLAN-agent-sandbox.md), and a profile's folders bound over
//! the home's for the agents with no variable of their own (plans/done/PLAN-agent-accounts.md, way 2): one recipe, built here and
//! nowhere else, printed by `ame agent sandbox show` and run by `amethystora-agent` exactly as printed.
//!
//! A sandbox starts from the whole machine and takes away: bubblewrap, with everything read-only, the project and the agent's
//! own folder writable, the build caches behind a layer of the launch's own that is thrown away when it ends, the keys and
//! logins hidden (an empty folder or file in their place), a /run, /tmp and /dev of its own, its own processes, and a seccomp
//! filter. A permission is a mount, nothing is a promise. It fails closed: what cannot be set up stops the launch, which never
//! starts plain instead.

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicI32, Ordering};

use serde_json::{Value, json};

use crate::agents::{self, AgentPaths, Map, Table, Way, DEFAULT};
use crate::policy;

pub const BWRAP: &str = "/usr/bin/bwrap";
/// The filter build-apps.sh writes with libseccomp (seccomp/gen.c's agent mode): typing into the terminal, the kernel's
/// keyring, BPF and perf refused; namespaces of the agent's own allowed
pub const FILTER: &str = "/usr/share/amethystora/agent-sandbox.bpf";
pub const SANDBOX_VAR: &str = "AMETHYSTORA_AGENT_SANDBOX";
pub const PROJECT_VAR: &str = "AMETHYSTORA_AGENT_SANDBOX_PROJECT";
/// This program, as the sandbox sees it: the forwarder that stands in front of a command held to a list of hosts
const TOOLS: &str = "/usr/libexec/amethystora-agent-tools";
/// Where the sandbox sees its proxy's socket, and the loopback port programs are told (HTTPS_PROXY)
const PROXY_INSIDE: &str = "/run/amethystora-agent-proxy.sock";
pub const SHIM_PORT: u16 = 3128;
/// Connections open at once through the proxy: a package install opens many
const PROXY_CONNECTIONS: usize = 256;
/// The descriptor the filter is handed to bubblewrap on, as the plugins' is
const FILTER_FD: i32 = 9;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// No sandbox: a profile's folders bound over the home's, and nothing else changed
    Profile,
    /// The home read-only, its secrets hidden
    Open,
    /// None of the home but the project, the agent's folder, the caches and the toolchains
    Closed,
}

impl Mode {
    pub fn word(self) -> &'static str {
        match self {
            Mode::Profile => "profile",
            Mode::Open => "open",
            Mode::Closed => "closed",
        }
    }

    pub fn parse(word: &str) -> Option<Mode> {
        match word {
            "open" => Some(Mode::Open),
            "closed" => Some(Mode::Closed),
            _ => None,
        }
    }
}

/// What a folder may be given beyond the default, each by the person in a terminal (ame agent sandbox allow)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Permission {
    /// A second place it may write: another repository, a path dependency built in place
    Write(PathBuf),
    /// A hidden place shown read-only: a kubeconfig for one project
    Show(PathBuf),
    /// The ssh agent's socket: it can then log in with every key the agent holds, without reading one
    SshAgent,
    /// The graphics card's devices
    Gpu,
    /// One more host (or *.name) the sandbox may reach while its network is held to a list
    Network(String),
}

impl Permission {
    /// A permission as the folder's rule keeps it, read strictly: a path is a real one, inside the home or the machine's
    /// own folders, never the home itself or a folder above it
    pub fn parse(text: &str, home: &Path) -> Result<Permission, String> {
        match text {
            "ssh-agent" => return Ok(Permission::SshAgent),
            "gpu" => return Ok(Permission::Gpu),
            _ => {}
        }
        let (kind, path) = text.split_once('=').ok_or_else(|| format!("{text} is not a permission: write=PATH, show=PATH, network=HOST, ssh-agent or gpu"))?;
        if kind == "network" {
            // A name, or the subdomains of one: never an address, a port or a path
            return if amethystora_net_proxy::valid_host(path) {
                Ok(Permission::Network(path.to_string()))
            } else {
                Err(format!("{path} is not a host's name: example.org, or *.example.org for its subdomains"))
            };
        }
        let path = match path.strip_prefix("~/") {
            Some(rest) => home.join(rest),
            None => PathBuf::from(path),
        };
        if !path.is_absolute() {
            return Err(format!("{} is not a whole path", path.display()));
        }
        let real = std::fs::canonicalize(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        if real == Path::new("/") || home.starts_with(&real) {
            return Err(format!("{} is the home or a folder above it, which a sandbox is never given", real.display()));
        }
        match kind {
            "write" => Ok(Permission::Write(real)),
            "show" => Ok(Permission::Show(real)),
            _ => Err(format!("{text} is not a permission: write=PATH, show=PATH, ssh-agent or gpu")),
        }
    }

    pub fn word(&self) -> String {
        match self {
            Permission::Write(path) => format!("write={}", path.display()),
            Permission::Show(path) => format!("show={}", path.display()),
            Permission::SshAgent => "ssh-agent".into(),
            Permission::Gpu => "gpu".into(),
            Permission::Network(host) => format!("network={host}"),
        }
    }

    /// What it gives away, said before it is asked
    pub fn cost(&self) -> String {
        match self {
            Permission::Write(path) => format!("The agent can change everything in {}, as it can its project.", path.display()),
            Permission::Show(path) => format!("The agent can read {}, which is hidden from it otherwise, and send what it reads.", path.display()),
            Permission::SshAgent => "The agent can log in, as you, with every key your ssh agent holds (git push, ssh to servers), without reading the keys.".into(),
            Permission::Gpu => "The agent's programs can use the graphics card, as any program of yours can.".into(),
            Permission::Network(host) => format!("While this folder's network is held to a list, the agent can also reach {host} over HTTPS, and send it whatever it can read."),
        }
    }
}

/// The project a launch works on: the top of the git repository it was made in, else the folder itself
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Project {
    pub top: PathBuf,
    /// The repository's own folder (.git, or a worktree's), and the folder it shares with its worktrees
    pub git: Option<PathBuf>,
    pub common: Option<PathBuf>,
}

/// A folder named in a .git file or commondir: relative to the folder it is written in
fn git_path(base: &Path, text: &str) -> Option<PathBuf> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    let path = if Path::new(text).is_absolute() { PathBuf::from(text) } else { base.join(text) };
    std::fs::canonicalize(path).ok()
}

/// The project of a launch made in DIR, read without running git (a repository's own settings could run something): the
/// nearest folder up to the home (never the home's own repository, a dotfiles one) with a .git in it
pub fn project_of(dir: &Path, home: &Path) -> Result<Project, String> {
    let dir = std::fs::canonicalize(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    let mut at = dir.as_path();
    loop {
        if at == home || at == Path::new("/") {
            break;
        }
        let dot = at.join(".git");
        if let Ok(meta) = std::fs::symlink_metadata(&dot) {
            let git = if meta.is_dir() {
                std::fs::canonicalize(&dot).ok()
            } else {
                std::fs::read_to_string(&dot).ok().and_then(|text| text.strip_prefix("gitdir:").and_then(|rest| git_path(at, rest)))
            };
            let common = git.as_ref().map(|git| {
                std::fs::read_to_string(git.join("commondir")).ok().and_then(|text| git_path(git, &text)).unwrap_or_else(|| git.clone())
            });
            return check(Project { top: at.to_path_buf(), git, common }, home);
        }
        let Some(up) = at.parent() else { break };
        at = up;
    }
    check(Project { top: dir.clone(), git: None, common: None }, home)
}

/// A project may not be the home, a folder above it, a dot-folder of the home, or a place a sandbox replaces
fn check(project: Project, home: &Path) -> Result<Project, String> {
    let top = &project.top;
    if home.starts_with(top) {
        return Err(format!("{} is your home or a folder above it: start the agent in a project's folder", top.display()));
    }
    if let Ok(inside) = top.strip_prefix(home) {
        if inside.components().next().is_some_and(|first| first.as_os_str().to_string_lossy().starts_with('.')) {
            return Err(format!("{} is in a hidden folder of your home, which is not a project", top.display()));
        }
    }
    for place in ["/tmp", "/var/tmp", "/run", "/proc", "/sys", "/dev", "/usr", "/etc", "/boot"] {
        if top.starts_with(place) {
            return Err(format!("{} is in {place}, which a sandbox has its own of", top.display()));
        }
    }
    Ok(project)
}

/// What a launch asks for
#[derive(Debug, Clone)]
pub struct Request {
    pub agent: String,
    pub profile: String,
    pub mode: Mode,
    pub project: Option<Project>,
    pub allow: Vec<Permission>,
    pub home: PathBuf,
    pub uid: u32,
    /// The launch's own folder: its /tmp, its copies
    pub run: PathBuf,
    /// Where the agent starts
    pub dir: PathBuf,
    /// The network held to a list: the hosts it may reach over HTTPS, through the launch's proxy. None is the machine's network
    pub hosts: Option<Vec<String>>,
}

/// The launch's proxy's socket: in the account's runtime folder, which no sandbox sees (its /run is its own), so that one sandbox
/// cannot use another launch's proxy and its list
fn proxy_socket(request: &Request) -> PathBuf {
    let name = request.run.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
    crate::history::sessions_dir().with_file_name("agent-proxy").join(format!("{name}.sock"))
}

/// Something made before the launch, where it is not there already
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Make {
    /// A folder kept afterwards (an agent's own, and its empty settings folders)
    Dir(PathBuf),
    /// A file with its default contents, kept afterwards (an agent's settings file, empty)
    File(PathBuf, &'static str),
    /// An empty folder in the project or the agent's folder, taken away afterwards if it is still empty
    Placeholder(PathBuf),
    /// An empty file in the agent's folder, bound read-only where a later plain session would run or read a file that is not
    /// there yet (a script its settings name, an @file, an instructions file of its own): taken away afterwards if still empty,
    /// so that an empty instructions file is never left to stand in for none
    PlaceholderFile(PathBuf),
}

/// One recipe: bubblewrap's options and the environment, and what to make first
#[derive(Debug, Clone, Default)]
pub struct Recipe {
    pub args: Vec<String>,
    pub env: Vec<(String, Option<String>)>,
    pub make: Vec<Make>,
    /// Files copied into the launch's folder, each bound over the original: what the agent writes there is never written back
    pub copies: Vec<(PathBuf, PathBuf)>,
    /// Files in the project that are not there, which a write would make: looked at when the launch ends
    pub watched: Vec<PathBuf>,
    pub hidden: Vec<PathBuf>,
    pub writable: Vec<PathBuf>,
    /// Places it sees and writes through a layer of the launch's own, thrown away when it ends (the build caches, its memory):
    /// nothing written there is ever seen outside
    pub layers: Vec<PathBuf>,
}

/// Variables of the session's sockets, which a sandbox never passes on
const SOCKETS: &[&str] = &[
    "DBUS_SESSION_BUS_ADDRESS", "DBUS_SYSTEM_BUS_ADDRESS", "SSH_AUTH_SOCK", "SSH_AGENT_PID", "GPG_AGENT_INFO", "GNUPGHOME",
    "WAYLAND_DISPLAY", "WAYLAND_SOCKET", "DISPLAY", "XAUTHORITY", "XAUTHLOCALHOSTNAME", "PULSE_SERVER", "PIPEWIRE_REMOTE",
    "DOCKER_HOST", "CONTAINER_HOST", "KRB5CCNAME", "SESSION_MANAGER", "GNOME_KEYRING_CONTROL", "KITTY_LISTEN_ON", "TMUX",
    "NOTIFY_SOCKET", "LISTEN_FDS", "LISTEN_PID", "LISTEN_FDNAMES", "INVOCATION_ID", "JOURNAL_STREAM", "SYSTEMD_EXEC_PID",
    "MANAGERPID", "ATSPI_BUS_ADDRESS", "AT_SPI_BUS_ADDRESS", "VAULT_ADDR",
];

/// Whether a variable's name says it holds a secret, which a sandbox never passes on but for the agent's own. A password
/// in a short form (MYSQL_PWD, SMTP_PASS), a database's address (DATABASE_URL), a webhook's, a password manager's open
/// session (Bitwarden's BW_SESSION, 1Password's OP_SESSION_*) and a registry's login (NPM_CONFIG__AUTH) are secrets too.
/// PWD, OLDPWD, DESKTOP_SESSION, GIT_AUTHOR_NAME and SSH_ASKPASS are not.
pub fn secret_name(name: &str) -> bool {
    let name = name.to_ascii_uppercase();
    ["TOKEN", "SECRET", "PASSWORD", "PASSWD", "PASSPHRASE", "CREDENTIAL", "COOKIE", "PRIVATE", "WEBHOOK", "JWT"].iter().any(|word| name.contains(word))
        || ["_KEY", "APIKEY", "_PWD", "_PASS", "_AUTH", "_DSN", "DATABASE_URL"].iter().any(|end| name.ends_with(end))
        || name.contains("_KEY_")
        || ["AWS_", "OP_SESSION_"].iter().any(|start| name.starts_with(start))
        || ["BW_SESSION", "DOCKER_AUTH_CONFIG"].contains(&name.as_str())
}

/// Whether a variable's value carries a login: an address with a password in it (postgres://app:password@db/x,
/// https://user:token@registry). One with a user's name and no password (https://git@host) does not
pub fn secret_value(value: &str) -> bool {
    let Some((_, rest)) = value.split_once("://") else { return false };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    authority.rsplit_once('@').is_some_and(|(user, _)| user.split_once(':').is_some_and(|(_, password)| !password.is_empty()))
}

/// A proxy's variable: its login, if it has one, is left, since the agent reaches nothing through that proxy without it
fn proxy_name(name: &str) -> bool {
    name.to_ascii_uppercase().ends_with("_PROXY")
}

fn s(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// A path's contents for a file made where an agent's settings file is not there: what each reads as nothing set
fn default_contents(path: &Path) -> Option<&'static str> {
    let name = path.file_name()?.to_string_lossy().to_string();
    if name.ends_with(".json") || name.ends_with(".jsonc") {
        Some("{}\n")
    } else if name.contains('.') && !name.starts_with('.') {
        Some("")
    } else {
        None
    }
}

/// The paths of a list that are not inside another one of it, so that no mount is made under a folder already hidden
fn outermost(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let sorted: BTreeSet<PathBuf> = paths.into_iter().collect();
    let mut kept: Vec<PathBuf> = Vec::new();
    for path in sorted {
        if !kept.iter().any(|outer| path.starts_with(outer)) {
            kept.push(path);
        }
    }
    kept
}

/// The home's secret places that are there: the table's hidden lines (* within a name for each one there is, for a name
/// with a space in it) and every credential-files pattern
fn home_secrets(table: &Table, home: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = Vec::new();
    for line in table.hidden.iter().filter(|path| !path.starts_with('/')) {
        if line.contains('*') {
            found.extend(agents::expand(home, line));
        } else {
            found.push(home.join(line));
        }
    }
    for glob in agents::credential_globs() {
        found.extend(agents::expand(home, &glob));
    }
    found.into_iter().filter(|path| std::fs::symlink_metadata(path).is_ok()).collect()
}

/// Hides one place: an empty folder of its own, made read-only at the end, or an empty file
fn hide_place(recipe: &mut Recipe, remount: &mut Vec<PathBuf>, path: PathBuf, is_dir: bool) {
    if is_dir {
        recipe.args.extend(["--tmpfs".into(), s(&path)]);
        remount.push(path.clone());
    } else {
        recipe.args.extend(["--ro-bind".into(), "/dev/null".into(), s(&path)]);
    }
    recipe.hidden.push(path);
}

/// A project's folder as Claude Code names it in its folder of projects: every character but a letter or a digit made -
/// (seen on 2026-11-26: D:\code\site is d--code-site; an underscore, a letter that is not ASCII and a path of more than 200
/// characters are unverified). A name that does not match only costs the transcript, which then goes with the layer
fn project_name(path: &Path) -> String {
    s(path).chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect()
}

/// Whether a settings key holds a command or what a command is given: a command (Claude Code's hooks and status line, an MCP
/// server's, Gemini CLI's discoveryCommand), a helper (apiKeyHelper), its args and env, and Codex's notify
fn command_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("command") || key.contains("helper") || ["args", "env", "notify", "awsauthrefresh", "awscredentialexport"].contains(&key.as_str())
}

/// The words of a command, as a shell would split them well enough to find a path: NAME=PATH and --option=PATH give PATH
fn split_words(text: &str, words: &mut Vec<String>) {
    // A colon too, so that each folder of a PATH-like value (~/.claude/bin:/usr/bin) is a word of its own
    for word in text.split(|c: char| c.is_whitespace() || "\"'`;|&<>(){}[],:".contains(c)) {
        let word = word.split_once('=').map_or(word, |(_, after)| after);
        if !word.is_empty() {
            words.push(word.to_string());
        }
    }
}

fn walk_commands(value: &Value, command: bool, words: &mut Vec<String>) {
    match value {
        Value::String(text) if command => split_words(text, words),
        Value::Array(items) => items.iter().for_each(|item| walk_commands(item, command, words)),
        Value::Object(map) => map.iter().for_each(|(key, item)| walk_commands(item, command || command_key(key), words)),
        _ => {}
    }
}

/// What a file of the agent's own names that a later session runs or reads: in settings (JSON, or TOML, or JSON with comments,
/// read line by line) the words of each command; in an instructions file (Markdown) each @file it brings in
fn named_words(path: &Path, text: &str) -> Vec<String> {
    let mut words = Vec::new();
    let name = path.file_name().map(|name| name.to_string_lossy().to_lowercase()).unwrap_or_default();
    if name.ends_with(".md") {
        for word in text.split_whitespace() {
            if let Some(rest) = word.strip_prefix('@') {
                let rest = rest.trim_end_matches(['.', ',', ';', ':', '!', '?', ')', ']', '`', '"', '\'']);
                if !rest.is_empty() {
                    words.push(rest.to_string());
                }
            }
        }
        return words;
    }
    if let Ok(value) = serde_json::from_str::<Value>(text) {
        walk_commands(&value, false, &mut words);
        return words;
    }
    // KEY = VALUE (TOML) or "KEY": VALUE, a list running on to its ], and every key of a table of variables ([...env])
    let (mut open, mut variables) = (false, false);
    for line in text.lines().map(str::trim) {
        if open {
            split_words(line, &mut words);
            open = !line.contains(']');
            continue;
        }
        if line.starts_with('[') && !line.contains('=') {
            variables = line.trim_matches(['[', ']', ' ']).rsplit('.').next() == Some("env");
            continue;
        }
        let Some(at) = line.find(['=', ':']) else { continue };
        let (key, value) = (line[..at].trim().trim_matches(['"', '\'']), &line[at + 1..]);
        if variables || command_key(key) {
            split_words(value, &mut words);
            open = value.trim_start().starts_with('[') && !value.contains(']');
        }
    }
    words
}

/// A path written without . or .., or nothing for one that leaves the root
fn normal(path: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            Component::RootDir => out.push("/"),
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() || out.as_os_str().is_empty() {
                    return None;
                }
            }
            Component::Normal(name) => out.push(name),
            Component::Prefix(_) => return None,
        }
    }
    out.is_absolute().then_some(out)
}

/// A word as the path the agent would find there: whole, from the home (~/, $HOME/) or from one of the agent's variables
/// ($CLAUDE_CONFIG_DIR/); for an @file, also relative to the file that names it. Anything else is not a path of the agent's
fn word_path(word: &str, base: &Path, home: &Path, vars: &[(String, PathBuf)], relative: bool) -> Option<PathBuf> {
    let mut starts: Vec<(String, PathBuf)> = vec![("~".into(), home.to_path_buf()), ("$HOME".into(), home.to_path_buf()), ("${HOME}".into(), home.to_path_buf())];
    for (name, dir) in vars {
        starts.push((format!("${name}"), dir.clone()));
        starts.push((format!("${{{name}}}"), dir.clone()));
    }
    let path = if word.starts_with('/') {
        PathBuf::from(word)
    } else if let Some(path) = starts.iter().find_map(|(start, dir)| word.strip_prefix(start.as_str()).and_then(|rest| rest.strip_prefix('/')).map(|rest| dir.join(rest))) {
        path
    } else if relative && !word.contains('$') && !word.starts_with('~') {
        base.join(word)
    } else {
        return None;
    };
    normal(&path)
}

/// The agent's folders for this launch: the profile's copy of each, at the place the agent will look for it
fn agent_folders(table: &Table, request: &Request) -> Result<Vec<(PathBuf, PathBuf)>, String> {
    let paths = table.agent(&request.agent)?;
    let root = agents::profile_root(&request.home, &request.profile);
    Ok(paths
        .dirs
        .iter()
        .map(|dir| {
            let source = root.join(dir);
            // A profile of way 1 is looked for where its variable points (inside the profile); of way 2, over the home's
            let dest = match (&paths.way, request.profile.as_str()) {
                (_, DEFAULT) | (Some(Way::Variable { .. }), _) => source.clone(),
                _ => request.home.join(dir),
            };
            (source, dest)
        })
        .collect())
}

/// The recipe of a launch. Pure but for looking at what is there: nothing is made, so that `show` prints what `run` would run.
pub fn recipe(table: &Table, request: &Request) -> Result<Recipe, String> {
    let home = &request.home;
    let paths: &AgentPaths = table.agent(&request.agent)?;
    let mut recipe = Recipe::default();
    let folders = agent_folders(table, request)?;
    if request.profile != DEFAULT && !table.has_profiles(&request.agent) {
        return Err(format!("{} has no profiles: it keeps its login in the keyring, which no folder isolates", agents::title(&request.agent)));
    }
    let args = &mut recipe.args;
    let mut push = |words: &[&str]| args.extend(words.iter().map(|word| word.to_string()));

    if request.mode == Mode::Profile {
        // Way 2: the machine as it is, the profile's folders over the home's. Nothing setuid runs inside (no sudo)
        push(&["--unshare-user", "--dev-bind", "/", "/", "--die-with-parent"]);
        for (source, dest) in &folders {
            recipe.make.push(Make::Dir(source.clone()));
            recipe.make.push(Make::Dir(dest.clone()));
            recipe.args.extend(["--bind".into(), s(source), s(dest)]);
            recipe.writable.push(dest.clone());
        }
        recipe.args.extend(["--chdir".into(), s(&request.dir)]);
        recipe.env = agents::environment(table, home, &request.agent, &request.profile);
        return Ok(recipe);
    }

    let project = request.project.as_ref().ok_or("a sandbox needs a project")?;
    let runtime = format!("/run/user/{}", request.uid);
    let tmp = request.run.join("tmp");
    let vartmp = request.run.join("var-tmp");
    // Its own processes, IPC and user namespace (in which nothing is setuid); the machine's network
    push(&["--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-cgroup-try", "--die-with-parent"]);
    push(&["--ro-bind", "/", "/", "--dev", "/dev", "--tmpfs", "/dev/shm", "--proc", "/proc"]);
    // No bus, no display, no keyring, no agent: an empty /run but for the resolver, and a runtime folder of its own
    push(&["--tmpfs", "/run", "--ro-bind-try", "/run/systemd/resolve", "/run/systemd/resolve", "--perms", "0700", "--dir", &runtime]);
    recipe.args.extend(["--bind".into(), s(&tmp), "/tmp".into(), "--bind".into(), s(&vartmp), "/var/tmp".into()]);
    if request.hosts.is_some() {
        // A network of its own with nothing but loopback: the one way out is the launch's proxy, on a socket bound in
        recipe.args.extend(["--unshare-net".into(), "--bind".into(), s(&proxy_socket(request)), PROXY_INSIDE.into()]);
    }

    // Hidden: the machine's own secret places always; in an open sandbox the home's secrets, the other agents' folders and
    // the other profiles (all of them: this launch's own is bound in again below)
    let mut hide: Vec<PathBuf> = table.hidden.iter().filter(|path| path.starts_with('/')).map(PathBuf::from).collect();
    let mut remount: Vec<PathBuf> = Vec::new();
    if request.mode == Mode::Closed {
        recipe.args.extend(["--tmpfs".into(), s(home)]);
        remount.push(home.clone());
    } else {
        hide.extend(home_secrets(table, home));
        for (other, other_paths) in &table.agents {
            if other != &request.agent {
                hide.extend(other_paths.dirs.iter().map(|dir| home.join(dir)));
            }
        }
        // On a profile of way 1, the home's own folders and files of this agent are the home's profile, another account
        if request.profile != DEFAULT && matches!(paths.way, Some(Way::Variable { .. })) {
            hide.extend(paths.dirs.iter().chain(paths.copies.iter()).map(|path| home.join(path)));
        }
    }
    // A shown place stays out of what is hidden: it is bound read-only below
    let shown: Vec<PathBuf> = request.allow.iter().filter_map(|permission| match permission {
        Permission::Show(path) => Some(path.clone()),
        _ => None,
    }).collect();
    let hide: Vec<PathBuf> = hide.into_iter().filter(|path| std::fs::symlink_metadata(path).is_ok()).collect();
    for path in outermost(hide) {
        let Ok(meta) = std::fs::metadata(&path) else { continue };
        if project.top.starts_with(&path) {
            return Err(format!("{} is in a hidden place, which is never a project", project.top.display()));
        }
        hide_place(&mut recipe, &mut remount, path, meta.is_dir());
    }

    // Writable: the project (and a worktree's repository), the agent's folder, and what was allowed
    let mut writable = vec![project.top.clone()];
    if let Some(common) = &project.common {
        if !common.starts_with(&project.top) {
            writable.push(common.clone());
        }
    }
    for (source, dest) in &folders {
        recipe.make.push(Make::Dir(source.clone()));
        if source != dest {
            recipe.make.push(Make::Dir(dest.clone()));
        }
    }
    for permission in &request.allow {
        if let Permission::Write(path) = permission {
            writable.push(path.clone());
        }
    }
    for path in &writable {
        if recipe.hidden.iter().any(|hidden| path.starts_with(hidden)) && !path.starts_with(home.join(agents::PROFILES)) {
            return Err(format!("{} is a hidden place, which a sandbox never makes writable", path.display()));
        }
        recipe.args.extend(["--bind".into(), s(path), s(path)]);
    }
    for (source, dest) in &folders {
        recipe.args.extend(["--bind".into(), s(source), s(dest)]);
        writable.push(dest.clone());
    }
    // The places of the agent's own that it writes and a later plain session runs or loads (below): each the machine's path
    // and the agent's, the folder's and each second place it was allowed
    let held: Vec<(PathBuf, PathBuf)> = folders.iter().cloned().chain(request.allow.iter().filter_map(|permission| match permission {
        Permission::Write(path) => Some((path.clone(), path.clone())),
        _ => None,
    })).collect();
    recipe.writable = writable;

    // The build caches that are there, behind a layer of the launch's own (layer(), on disk in the launch's folder): the agent
    // reads what is cached and writes what it fetches, and none of it is seen outside, since a build script, a package or a
    // browser changed in a cache would run at the developer's next plain build or test, with no diff to read. What it fetches
    // is fetched again at each launch. A layer that cannot be made stops the launch, which never makes a cache writable instead
    for cache in &table.caches {
        let path = home.join(cache);
        // A cache inside a place the person allowed it to write (write=PATH) is written as that place is
        if !path.is_dir() || held.iter().any(|(_, dest)| path.starts_with(dest)) {
            continue;
        }
        if recipe.hidden.iter().any(|hidden| path.starts_with(hidden)) {
            return Err(format!("{} is a hidden place, which a sandbox never shows", path.display()));
        }
        // The layer is read from the machine's own cache, so that a hidden place inside it would be shown again, and the
        // project or a second place it may write inside it would have every change thrown away when the launch ends
        if let Some(hidden) = recipe.hidden.iter().find(|hidden| hidden.starts_with(&path)) {
            return Err(format!("{} is hidden but inside the build cache {}, which a sandbox would show again", hidden.display(), path.display()));
        }
        if let Some(place) = held.iter().map(|(_, dest)| dest).chain(std::iter::once(&project.top)).find(|place| place.starts_with(&path)) {
            return Err(format!(
                "{} is inside the build cache {}, whose changes a sandbox throws away when it ends: start the agent in a project outside the cache",
                place.display(),
                path.display()
            ));
        }
        layer(&mut recipe, &request.run, &path, &path);
    }

    // Closed: the toolchains, read-only
    if request.mode == Mode::Closed {
        let mut tools: Vec<PathBuf> = Vec::new();
        for tool in &table.tools {
            let path = home.join(tool);
            if std::fs::symlink_metadata(&path).is_ok() {
                recipe.args.extend(["--ro-bind".into(), s(&path), s(&path)]);
                tools.push(path);
            }
        }
        // A secret kept inside a toolchain's folder (git's credentials in ~/.config/git) is hidden over it again
        for path in outermost(home_secrets(table, home)) {
            if tools.iter().any(|tool| path.starts_with(tool) && &path != tool) {
                let is_dir = std::fs::metadata(&path).is_ok_and(|meta| meta.is_dir());
                hide_place(&mut recipe, &mut remount, path, is_dir);
            }
        }
    }

    // Read-only inside what is writable: what a command outside would run later. The repository's hooks and settings
    // (a hook, core.fsmonitor, core.sshCommand or an alias written there runs at the developer's next git command), its
    // submodules' and worktrees' too, and every agent's settings in the project
    // Each repository folder is a mount of its own, so that it cannot be moved away and made again with settings of the agent's
    let mut gits: Vec<PathBuf> = project.git.iter().chain(project.common.iter()).cloned().collect();
    gits.sort();
    gits.dedup();
    let mut read_only: Vec<PathBuf> = Vec::new();
    // A submodule's work tree's .git is a file naming its repository too, read by a plain git status at the top (it recurses
    // into each submodule), wherever it is (vendor/, node_modules/): each .git file of the project is read-only, and each folder
    // on the way to it from the top a mount of its own, bound before the repositories so that it covers none of them, so that
    // none can be moved away and made again with another gitdir in it. One made new is said when the launch ends (gitguard.rs)
    let pointers = crate::gitguard::pointers(&project.top, &gits);
    let ways: BTreeSet<PathBuf> = pointers
        .iter()
        .filter_map(|path| path.parent())
        .flat_map(|parent| parent.ancestors().take_while(|folder| *folder != project.top.as_path() && folder.starts_with(&project.top)).map(Path::to_path_buf))
        .collect();
    for folder in &ways {
        recipe.args.extend(["--bind".into(), s(folder), s(folder)]);
    }
    read_only.extend(pointers);
    for git in &gits {
        recipe.args.extend(["--bind".into(), s(git), s(git)]);
        // commondir and gitdir name another repository's folder, whose settings and hooks git would take instead
        for name in ["hooks", "config", "config.worktree", "info/attributes", "commondir", "gitdir"] {
            read_only.push(git.join(name));
        }
        // A submodule's repository and a worktree's are mounts of their own too, so that neither can be moved away and made
        // again, and a worktree's commondir and gitdir are read-only as the repository's own are. What is made new in them
        // cannot be held without breaking git: it is said when the launch ends (gitguard.rs)
        let mut inner: Vec<PathBuf> = Vec::new();
        if let Ok(modules) = walk_modules(&git.join("modules")) {
            inner.extend(modules.iter().filter(|path| path.ends_with("config")).filter_map(|path| path.parent().map(Path::to_path_buf)));
            read_only.extend(modules);
        }
        if let Ok(entries) = std::fs::read_dir(git.join("worktrees")) {
            for entry in entries.flatten().filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir())).take(256) {
                let worktree = entry.path();
                read_only.extend(["commondir", "gitdir", "config.worktree"].map(|name| worktree.join(name)));
                inner.push(worktree);
            }
        }
        inner.sort();
        for path in inner.iter().filter(|path| !gits.contains(path)) {
            recipe.args.extend(["--bind".into(), s(path), s(path)]);
        }
    }
    // A worktree's .git is a file naming its repository: another name would be another repository's hooks
    let dot_git = project.top.join(".git");
    if std::fs::symlink_metadata(&dot_git).is_ok_and(|meta| meta.is_file()) {
        read_only.push(dot_git);
    }
    for path in dedup(read_only) {
        match std::fs::symlink_metadata(&path) {
            Ok(_) => recipe.args.extend(["--ro-bind".into(), s(&path), s(&path)]),
            Err(_) if path.file_name().is_some_and(|name| name == "hooks") => {
                recipe.make.push(Make::Placeholder(path.clone()));
                recipe.args.extend(["--ro-bind".into(), s(&path), s(&path)]);
            }
            // A file git reads only when the read-only settings say so
            Err(_) => {}
        }
    }
    let mut lines: Vec<PathBuf> = table.project.iter().chain(table.agents.values().flat_map(|paths| paths.project.iter())).map(|line| project.top.join(line)).collect();
    lines = dedup(lines);
    for path in lines {
        if std::fs::symlink_metadata(&path).is_ok() {
            recipe.args.extend(["--ro-bind".into(), s(&path), s(&path)]);
        } else if is_folder_line(&path) {
            // A settings folder that is not there is made empty, read-only, and taken away afterwards if it still is
            recipe.make.push(Make::Placeholder(path.clone()));
            recipe.args.extend(["--ro-bind".into(), s(&path), s(&path)]);
        } else {
            // A file would be made where every agent can see it (git status): it is looked at when the launch ends instead
            recipe.watched.push(path);
        }
    }
    // The agent's own settings, commands and hooks, read-only, made empty first where they are not there
    let root = agents::profile_root(home, &request.profile);
    let place_of = |line: &str| -> PathBuf {
        let path = root.join(line);
        // A way-2 profile's copy is seen at the home's place
        for (source, dest) in &folders {
            if let Ok(rest) = path.strip_prefix(source) {
                return dest.join(rest);
            }
        }
        path
    };
    // The machine's path of a place the agent sees: a way-2 profile's copy of its folder is seen at the home's place
    let host_of = |place: &Path| -> PathBuf {
        for (source, dest) in &held {
            if let Ok(rest) = place.strip_prefix(dest) {
                return source.join(rest);
            }
        }
        place.to_path_buf()
    };
    // bubblewrap reads a bind's source from the machine's own tree: the profile's file, put where the agent looks
    let mut protect: Vec<(PathBuf, PathBuf)> = Vec::new();
    for line in &paths.ro {
        let (source, place) = (root.join(line), place_of(line));
        if std::fs::symlink_metadata(&source).is_err() {
            // Settings an empty file means nothing to ({} for JSON) are kept; an instructions file or a folder is taken away
            // again while empty, since an empty one may stand in for the agent's own default (an override of AGENTS.md)
            recipe.make.push(match default_contents(&source) {
                Some("") => Make::PlaceholderFile(source.clone()),
                Some(contents) => Make::File(source.clone(), contents),
                None => Make::Placeholder(source.clone()),
            });
        }
        protect.push((source, place));
    }
    // The files it rewrites that name commands or that a later session reads as instructions, each given a private copy below.
    // Only where the agent would look: for an agent whose variable moves its folder, the home's file on the home's profile and
    // the folder's own on another (Claude Code's ~/.claude.json, or .claude.json inside CLAUDE_CONFIG_DIR)
    let copies: Vec<(usize, PathBuf, PathBuf)> = paths
        .copies
        .iter()
        .enumerate()
        .filter(|(_, line)| match &paths.way {
            Some(Way::Variable { dir, .. }) => (request.profile == DEFAULT) != Path::new(line.as_str()).starts_with(dir),
            _ => true,
        })
        .map(|(number, line)| (number, root.join(line), place_of(line)))
        .collect();

    // What those files run (a hook's script, the status line's, an MCP server's, a key helper) and what the instructions bring
    // in (CLAUDE.md's @file, and that file's own): read-only too wherever it lies in a place the agent can write, since a later
    // plain session runs or reads it. A word that is no path there is passed over
    let vars: Vec<(String, PathBuf)> = match &paths.way {
        Some(Way::Variable { name, dir }) => vec![(name.clone(), place_of(dir))],
        _ => Vec::new(),
    };
    let mut queue: Vec<(PathBuf, PathBuf, usize)> = Vec::new();
    for (source, place) in protect.iter().cloned().chain(copies.iter().map(|(_, source, place)| (source.clone(), place.clone()))) {
        if source.is_dir() {
            // A link in a read-only folder (a hook that is a link to a script elsewhere) cannot be changed, but where it leads
            // can, when that is a place the agent writes: refused, as a link on the way to one is
            for (link, seen) in links_in(&source, &place) {
                let Ok(target) = std::fs::canonicalize(&link) else { continue };
                let writes = held.iter().any(|(host, _)| target.starts_with(host)) || target.starts_with(&project.top)
                    || recipe.writable.iter().any(|path| target.starts_with(path));
                if writes {
                    return Err(format!(
                        "{} is a link to {}, which the agent can change, and a later session outside the sandbox would run or read it. Put the file itself in its place, then start again",
                        seen.display(),
                        target.display()
                    ));
                }
            }
            queue.extend(files_in(&source, &place));
        } else {
            queue.push((source, place, 0));
        }
    }
    let mut read: BTreeSet<PathBuf> = BTreeSet::new();
    let mut named: Vec<(PathBuf, PathBuf)> = Vec::new();
    // Named files that are not there yet, which the agent could make: an empty placeholder each, read-only
    let mut missing: BTreeSet<PathBuf> = BTreeSet::new();
    while let Some((source, place, depth)) = queue.pop() {
        if read.len() > 512 || !read.insert(source.clone()) {
            continue;
        }
        let Ok(meta) = std::fs::metadata(&source) else { continue };
        if !meta.is_file() || meta.len() > 4 << 20 {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&source) else { continue };
        let markdown = place.extension().is_some_and(|ext| ext == "md");
        let base = place.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("/"));
        for word in named_words(&source, &text) {
            let Some(path) = word_path(&word, &base, home, &vars, markdown) else { continue };
            let file = host_of(&path);
            if std::fs::symlink_metadata(&file).is_err() {
                // Not there yet: the agent could make it where it writes, and a later plain session would run or read it
                if !path.starts_with(&project.top) && held.iter().any(|(_, dest)| path.starts_with(dest) && &path != dest) {
                    missing.insert(file.clone());
                    named.push((file, path));
                }
                continue;
            }
            if markdown && depth < 5 && path.extension().is_some_and(|ext| ext == "md") {
                queue.push((file.clone(), path.clone(), depth + 1));
            }
            // A file only: a folder a command names may be one the agent must write (an MCP server's folder to work in)
            let is_file = std::fs::metadata(&file).is_ok_and(|meta| meta.is_file());
            if is_file && !path.starts_with(&project.top) && held.iter().any(|(_, dest)| path.starts_with(dest) && &path != dest) {
                named.push((file, path));
            }
        }
    }

    // Its places that a later plain session runs or reads as instructions but that it must still write (its memory, its
    // shell's snapshots): a layer of the launch's own over each, thrown away when it ends. Inside one, this project's own
    // folder is the real one again (its transcripts); the other sessions' places are an empty folder of its own
    let names: Vec<String> = dedup(vec![project.top.clone(), request.dir.clone()]).iter().map(|path| project_name(path)).collect();
    let mut own: Vec<(PathBuf, PathBuf, &str)> = Vec::new();
    for (kind, lines) in [("layer", &paths.layers), ("keep", &paths.keeps), ("empty", &paths.empties)] {
        for line in lines {
            let expanded: Vec<String> =
                if line.contains("{project}") { names.iter().map(|name| line.replace("{project}", name)).collect() } else { vec![line.clone()] };
            for line in expanded {
                own.push((place_of(&line), root.join(&line), kind));
            }
        }
    }
    own.sort();
    own.dedup();
    let empties: Vec<PathBuf> = own.iter().filter(|(_, _, kind)| *kind == "empty").map(|(place, _, _)| place.clone()).collect();

    // Each place held read-only once, never inside an empty folder of its own (which would show what it stands in for), and
    // never its login, which it renews, or a file it has a private copy of
    let logins: Vec<PathBuf> = paths.logins.iter().map(|line| place_of(line)).collect();
    // Inside a layer of its own (the deepest of its places that holds it says: a kept folder in a layer is real again) what it
    // writes is thrown away, so nothing there needs holding
    let thrown = |place: &Path| {
        recipe.layers.iter().any(|layer| place.starts_with(layer))
            || own.iter().filter(|(own_place, _, _)| place.starts_with(own_place)).max_by_key(|(own_place, _, _)| own_place.components().count())
                .is_some_and(|(_, _, kind)| *kind == "layer")
    };
    named.retain(|(_, place)| !logins.contains(place) && !copies.iter().any(|(_, _, copy)| copy == place) && !thrown(place));
    protect.extend(named);
    protect.retain(|(_, place)| !empties.iter().any(|empty| place.starts_with(empty)));
    protect.sort_by(|a, b| a.1.cmp(&b.1));
    protect.dedup_by(|a, b| a.1 == b.1);
    let mut kept: Vec<(PathBuf, PathBuf)> = Vec::new();
    for item in protect {
        if !kept.iter().any(|(_, outer)| item.1.starts_with(outer)) {
            kept.push(item);
        }
    }
    // The folders on the way to each, a mount of its own first, so that none can be moved away and made again with what
    // the agent wrote; a link on the way stops the launch
    let mut pins: BTreeMap<PathBuf, PathBuf> = BTreeMap::new();
    let places = kept.iter().map(|(_, place)| place).chain(copies.iter().map(|(_, _, place)| place)).chain(own.iter().map(|(place, _, _)| place));
    for place in places {
        // A layer or a kept folder on the way is a mount of its own already
        for (source, folder) in way_to(&held, place)? {
            if !own.iter().any(|(own_place, _, _)| own_place == &folder) {
                pins.insert(folder, source);
            }
        }
    }
    // A folder on the way that lies inside one of its own places (a kept folder) is pinned after that place is mounted, which
    // would otherwise cover it; the others before, so that they cover none of them
    let inside_own = |folder: &Path| own.iter().any(|(own_place, _, _)| folder.starts_with(own_place) && folder != own_place.as_path());
    for (folder, source) in pins.iter().filter(|(folder, _)| !inside_own(folder)) {
        recipe.args.extend(["--bind".into(), s(source), s(folder)]);
    }
    for (place, source, kind) in &own {
        match *kind {
            "layer" => {
                if std::fs::symlink_metadata(source).is_err() {
                    recipe.make.push(Make::Placeholder(source.clone()));
                }
                layer(&mut recipe, &request.run, source, place);
            }
            "keep" => {
                recipe.make.push(Make::Dir(source.clone()));
                recipe.args.extend(["--bind".into(), s(source), s(place)]);
            }
            _ => recipe.args.extend(["--tmpfs".into(), s(place)]),
        }
    }
    for (folder, source) in pins.iter().filter(|(folder, _)| inside_own(folder)) {
        recipe.args.extend(["--bind".into(), s(source), s(folder)]);
    }
    for (source, _) in &kept {
        if missing.contains(source) {
            recipe.make.push(Make::PlaceholderFile(source.clone()));
        }
    }
    for (source, place) in &kept {
        recipe.args.extend(["--ro-bind".into(), s(source), s(place)]);
    }
    // The files it rewrites that name commands: a private copy each, which goes with the launch
    for (number, source, place) in copies {
        if std::fs::symlink_metadata(&source).is_err() {
            recipe.make.push(Make::File(source.clone(), default_contents(&source).unwrap_or("{}\n")));
        }
        let copy = request.run.join("copies").join(number.to_string());
        recipe.copies.push((source, copy.clone()));
        recipe.args.extend(["--bind".into(), s(&copy), s(&place)]);
    }

    // The agent's own program, where its installer keeps it in its folder: read-only, since the next plain launch runs it, and
    // there even when the folder is hidden (on another profile)
    for line in &paths.programs {
        let path = home.join(line);
        if std::fs::symlink_metadata(&path).is_ok() {
            recipe.args.extend(["--ro-bind".into(), s(&path), s(&path)]);
        }
    }

    // What the folder was allowed beyond the default
    let mut env = agents::environment(table, home, &request.agent, &request.profile);
    for path in &shown {
        recipe.args.extend(["--ro-bind".into(), s(path), s(path)]);
    }
    for permission in &request.allow {
        match permission {
            Permission::SshAgent => {
                let socket = std::env::var("SSH_AUTH_SOCK").map_err(|_| "ssh-agent was allowed, but no ssh agent runs (SSH_AUTH_SOCK)".to_string())?;
                let inside = format!("{runtime}/ssh-agent");
                recipe.args.extend(["--bind".into(), socket, inside.clone()]);
                env.push(("SSH_AUTH_SOCK".into(), Some(inside)));
            }
            Permission::Gpu => recipe.args.extend(["--dev-bind-try".into(), "/dev/dri".into(), "/dev/dri".into()]),
            _ => {}
        }
    }
    for path in remount {
        recipe.args.extend(["--remount-ro".into(), s(&path)]);
    }
    recipe.args.extend(["--seccomp".into(), FILTER_FD.to_string(), "--chdir".into(), s(&request.dir)]);

    // The environment: the session's sockets and every secret-looking variable out, by its name or by an address with a
    // password in its value, but for the agent's own
    for (name, value) in std::env::vars_os().filter_map(|(name, value)| Some((name.into_string().ok()?, value))) {
        let kept = paths.env.contains(&name) || (name == "SSH_AUTH_SOCK" && request.allow.contains(&Permission::SshAgent));
        let login = !proxy_name(&name) && value.to_str().is_some_and(secret_value);
        if !kept && (SOCKETS.contains(&name.as_str()) || secret_name(&name) || login) {
            env.push((name, None));
        }
    }
    if std::env::var("TMPDIR").is_ok_and(|dir| !dir.starts_with("/tmp") && !dir.starts_with("/var/tmp")) {
        env.push(("TMPDIR".into(), None));
    }
    if request.hosts.is_some() {
        let proxy = format!("http://127.0.0.1:{SHIM_PORT}");
        for name in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
            env.push((name.into(), Some(proxy.clone())));
        }
        for name in ["NO_PROXY", "no_proxy"] {
            env.push((name.into(), Some("localhost,127.0.0.1,::1".into())));
        }
        env.push(("ALL_PROXY".into(), None));
        env.push(("all_proxy".into(), None));
    }
    env.push(("XDG_RUNTIME_DIR".into(), Some(runtime)));
    env.push((SANDBOX_VAR.into(), Some(request.mode.word().into())));
    env.push((PROJECT_VAR.into(), Some(s(&project.top))));
    // Amethystora's own tools, started inside with the agent, only read: a sandboxed agent works on a project, it does not
    // administer the machine
    env.push(("AMETHYSTORA_READ_ONLY".into(), Some("1".into())));
    recipe.env = env;
    Ok(recipe)
}

/// Whether a project line names a folder (an agent's settings folder: a dot and no other dot) rather than a file
fn is_folder_line(path: &Path) -> bool {
    let name = path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
    name.starts_with('.') && !name[1..].contains('.') && name != ".envrc"
}

fn dedup(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = BTreeSet::new();
    paths.into_iter().filter(|path| seen.insert(path.clone())).collect()
}

/// The files of a folder of the agent's settings (its hooks, commands, plugins), three folders deep and 256 at most: each
/// the machine's path, the agent's, and how many @files deep it was reached (none)
fn files_in(source: &Path, place: &Path) -> Vec<(PathBuf, PathBuf, usize)> {
    let mut found = Vec::new();
    let mut stack = vec![(source.to_path_buf(), place.to_path_buf(), 0)];
    while let Some((at, seen, depth)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&at) else { continue };
        for entry in entries.flatten() {
            if found.len() >= 256 {
                return found;
            }
            let Ok(kind) = entry.file_type() else { continue };
            let (path, inside) = (entry.path(), seen.join(entry.file_name()));
            if kind.is_dir() && depth < 3 {
                stack.push((path, inside, depth + 1));
            } else if kind.is_file() {
                found.push((path, inside, 0));
            }
        }
    }
    found
}

/// The links in a folder of the agent's settings, as deep as files_in looks: each the machine's path and the agent's
fn links_in(source: &Path, place: &Path) -> Vec<(PathBuf, PathBuf)> {
    let mut found = Vec::new();
    let mut stack = vec![(source.to_path_buf(), place.to_path_buf(), 0)];
    while let Some((at, seen, depth)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&at) else { continue };
        for entry in entries.flatten() {
            if found.len() >= 256 {
                return found;
            }
            let Ok(kind) = entry.file_type() else { continue };
            let (path, inside) = (entry.path(), seen.join(entry.file_name()));
            if kind.is_symlink() {
                found.push((path, inside));
            } else if kind.is_dir() && depth < 3 {
                stack.push((path, inside, depth + 1));
            }
        }
    }
    found
}

/// The folders on the way to PLACE from the place of the agent's own that holds it (its folder, a second place it may
/// write), each the machine's path and the agent's: each is made a mount of its own, so that none can be moved away and made
/// again with what the agent wrote. A link on the way stops the launch, since a mount cannot hold a link: the agent could
/// change it to lead to its own file, which a later session outside the sandbox would run
fn way_to(held: &[(PathBuf, PathBuf)], place: &Path) -> Result<Vec<(PathBuf, PathBuf)>, String> {
    let Some((source, dest)) = held.iter().filter(|(_, dest)| place.starts_with(dest) && place != dest).max_by_key(|(_, dest)| dest.components().count()) else {
        return Ok(Vec::new());
    };
    let Ok(rest) = place.strip_prefix(dest) else { return Ok(Vec::new()) };
    let parts: Vec<Component> = rest.components().collect();
    let (mut host, mut seen) = (source.clone(), dest.clone());
    let mut folders = Vec::new();
    for (number, part) in parts.iter().enumerate() {
        host.push(part);
        seen.push(part);
        if std::fs::symlink_metadata(&host).is_ok_and(|meta| meta.file_type().is_symlink()) {
            return Err(format!(
                "{} is a link inside the agent's own folder, which a sandbox cannot hold read-only: the agent could change where it leads, and a later session outside the sandbox would run or read that. Put the file or folder itself in its place, then start again",
                seen.display()
            ));
        }
        if number + 1 < parts.len() {
            folders.push((host.clone(), seen.clone()));
        }
    }
    Ok(folders)
}

/// A repository's submodules keep a repository of their own, with its hooks and settings, under modules/
fn walk_modules(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    let mut stack = vec![(dir.to_path_buf(), 0)];
    while let Some((at, depth)) = stack.pop() {
        if depth > 6 || found.len() > 400 {
            break;
        }
        let Ok(entries) = std::fs::read_dir(&at) else { continue };
        for entry in entries.flatten() {
            if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                continue;
            }
            let path = entry.path();
            if path.join("config").is_file() && path.join("HEAD").exists() {
                found.extend([path.join("hooks"), path.join("config")]);
                stack.push((path.join("modules"), depth + 1));
            } else {
                stack.push((path, depth + 1));
            }
        }
    }
    Ok(found)
}

// --- Running it --------------------------------------------------------------------------------------------------------

/// The launch's folder, in the account's cache, removed when it ends; one a launch that was killed left is taken away by the next
pub fn runs_dir(home: &Path) -> PathBuf {
    let base = std::env::var_os("XDG_CACHE_HOME").filter(|dir| !dir.is_empty()).map(PathBuf::from).unwrap_or_else(|| home.join(".cache"));
    base.join("amethystora/agent-sandbox")
}

fn sweep(home: &Path) {
    let Ok(entries) = std::fs::read_dir(runs_dir(home)) else { return };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let pid = name.split('-').next().unwrap_or("");
        if pid.bytes().all(|b| b.is_ascii_digit()) && !Path::new("/proc").join(pid).exists() {
            take_back(&entry.path());
            remove_run(&entry.path());
        }
    }
}

/// A layer of the launch's own over PLACE, read from SOURCE (bubblewrap's --overlay, 0.10): what the agent writes there goes
/// to the launch's own folder on disk, never to memory (a build fetches gigabytes), and is removed with that folder when the
/// launch ends. The upper and work folders are made first, on one filesystem as overlayfs needs, and empty. (unverified: that
/// bubblewrap mounts it with userxattr in the user namespace on the home's filesystem, as it does --tmp-overlay; the lab says)
fn layer(recipe: &mut Recipe, run: &Path, source: &Path, place: &Path) {
    let at = run.join("layers").join(recipe.layers.len().to_string());
    let (upper, work) = (at.join("upper"), at.join("work"));
    recipe.make.push(Make::Dir(upper.clone()));
    recipe.make.push(Make::Dir(work.clone()));
    recipe.args.extend(["--overlay-src".into(), s(source), "--overlay".into(), s(&upper), s(&work), s(place)]);
    recipe.layers.push(place.to_path_buf());
}

/// The launch's folder taken away whole: overlayfs leaves a folder of mode 0 in each work folder, which remove_dir_all cannot
/// read, so every folder in it is made the account's to open first (all of it is the account's own, never a link followed)
fn remove_run(run: &Path) {
    let mut stack = vec![run.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if !std::fs::symlink_metadata(&dir).is_ok_and(|meta| meta.is_dir()) {
            continue;
        }
        let _ = std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700));
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                stack.push(entry.path());
            }
        }
    }
    let _ = std::fs::remove_dir_all(run);
}

/// The empty folders and files a launch made, as it noted them, taken away while still empty
fn take_back(run: &Path) {
    for line in std::fs::read_to_string(run.join("made")).unwrap_or_default().lines() {
        match std::fs::symlink_metadata(line) {
            Ok(meta) if meta.is_file() && meta.len() == 0 => {
                let _ = std::fs::remove_file(line);
            }
            Ok(meta) if meta.is_dir() => {
                let _ = std::fs::remove_dir(line);
            }
            _ => {}
        }
    }
}

/// Makes what the recipe needs: its folders and files where they are not there, the launch's folder and its copies
pub fn prepare(recipe: &Recipe, run: &Path) -> Result<(), String> {
    let folder = |path: &Path| std::fs::DirBuilder::new().recursive(true).mode(0o700).create(path).map_err(|error| format!("{}: {error}", path.display()));
    folder(&run.join("tmp"))?;
    folder(&run.join("var-tmp"))?;
    folder(&run.join("copies"))?;
    std::fs::set_permissions(run.join("tmp"), std::os::unix::fs::PermissionsExt::from_mode(0o1777)).map_err(|error| error.to_string())?;
    let mut made = String::new();
    for make in &recipe.make {
        match make {
            Make::Dir(path) => folder(path)?,
            Make::Placeholder(path) => {
                if std::fs::symlink_metadata(path).is_err() {
                    folder(path)?;
                    made.push_str(&format!("{}\n", path.display()));
                }
            }
            Make::PlaceholderFile(path) => {
                if std::fs::symlink_metadata(path).is_err() {
                    if let Some(parent) = path.parent() {
                        folder(parent)?;
                    }
                    std::fs::OpenOptions::new().create_new(true).write(true).mode(0o600).open(path).map_err(|error| format!("{}: {error}", path.display()))?;
                    made.push_str(&format!("{}\n", path.display()));
                }
            }
            Make::File(path, contents) => {
                if std::fs::symlink_metadata(path).is_err() {
                    if let Some(parent) = path.parent() {
                        folder(parent)?;
                    }
                    let mut file = std::fs::OpenOptions::new().create_new(true).write(true).mode(0o600).open(path)
                        .map_err(|error| format!("{}: {error}", path.display()))?;
                    std::io::Write::write_all(&mut file, contents.as_bytes()).map_err(|error| error.to_string())?;
                }
            }
        }
    }
    std::fs::write(run.join("made"), made).map_err(|error| error.to_string())?;
    for (source, copy) in &recipe.copies {
        std::fs::copy(source, copy).map_err(|error| format!("{}: {error}", source.display()))?;
        std::fs::set_permissions(copy, std::os::unix::fs::PermissionsExt::from_mode(0o600)).map_err(|error| error.to_string())?;
    }
    Ok(())
}

/// The command line, as a shell would need it, for `show`
pub fn command_line(recipe: &Recipe, command: &[String]) -> String {
    let mut words = vec![BWRAP.to_string()];
    words.extend(recipe.args.iter().cloned());
    words.push("--".into());
    words.extend(command.iter().cloned());
    words.iter().map(|word| crate::history::quote(word)).collect::<Vec<_>>().join(" ")
}

static CHILD: AtomicI32 = AtomicI32::new(0);

// Only what a signal handler may do: the person's Stop (SIGTERM to this runner) ends the sandbox's first process, which takes
// everything in it (bubblewrap's --die-with-parent)
extern "C" fn pass_on(signal: libc::c_int) {
    let child = CHILD.load(Ordering::SeqCst);
    if child > 0 {
        unsafe { libc::kill(child, signal) };
    }
}

/// The session's file in the account's runtime folder, for the pill, `ame agent profile running` and Stop: the tool server
/// inside a sandbox cannot see that folder, so the runner writes it, under its own process number
fn session_file(row: &Value) -> Option<PathBuf> {
    let dir = crate::history::sessions_dir();
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir).ok()?;
    let path = dir.join(crate::history::host_pid().to_string());
    let mut file = std::fs::OpenOptions::new().create(true).truncate(true).write(true).mode(0o600).open(&path).ok()?;
    std::io::Write::write_all(&mut file, format!("{row}\n").as_bytes()).ok()?;
    Some(path)
}

/// Runs COMMAND under the recipe: bubblewrap as a child, waited for, so that the launch's folder, the empty folders it made
/// and its session's file go when it ends. Its exit is the command's.
pub fn run(recipe: &Recipe, request: &Request, command: &[String]) -> Result<i32, String> {
    sweep(&request.home);
    if !Path::new(BWRAP).exists() {
        return Err("bubblewrap is not there, so the agent cannot be held in a sandbox".into());
    }
    let filter = if request.mode == Mode::Profile {
        None
    } else {
        Some(std::fs::File::open(FILTER).map_err(|error| format!("the sandbox's filter {FILTER} cannot be read ({error}), so nothing starts"))?)
    };
    prepare(recipe, &request.run).inspect_err(|_| {
        take_back(&request.run);
        remove_run(&request.run);
    })?;
    let session = (request.mode != Mode::Profile).then(|| {
        session_file(&json!({"pid": crate::history::host_pid(), "started": crate::history::now(), "agent": request.agent, "profile": request.profile,
            "sandboxed": request.mode.word(), "project": request.project.as_ref().map(|project| s(&project.top)), "now": null, "recent": []}))
    }).flatten();
    // The network held to a list: the proxy listens on a socket of the launch's folder, which the recipe binds in, and the
    // command starts behind the forwarder that takes the sandbox's loopback to it
    let mut inside: Vec<String> = Vec::new();
    if let Some(hosts) = &request.hosts {
        let socket = proxy_socket(request);
        if let Some(folder) = socket.parent() {
            let _ = std::fs::DirBuilder::new().recursive(true).mode(0o700).create(folder);
        }
        let _ = std::fs::remove_file(&socket);
        let listener = std::os::unix::net::UnixListener::bind(&socket).map_err(|error| {
            take_back(&request.run);
            remove_run(&request.run);
            format!("the sandbox's proxy could not listen ({error}), so nothing starts")
        })?;
        let hosts = hosts.clone();
        let proxy = amethystora_net_proxy::proxy::Proxy::system(
            Box::new(move || amethystora_net_proxy::proxy::Policy { allowed: hosts.clone(), unlimited: true, ..Default::default() }),
            Box::new(|_| {}),
        );
        proxy.max_connections.store(PROXY_CONNECTIONS, Ordering::Relaxed);
        std::thread::spawn(move || proxy.serve(listener));
        inside = vec![TOOLS.into(), "net-shim".into(), PROXY_INSIDE.into(), "--".into()];
    }
    let watched: Vec<PathBuf> = recipe.watched.iter().filter(|path| std::fs::symlink_metadata(path).is_err()).cloned().collect();
    // What git would read as settings or run as a hook, anywhere in the project, looked at again when the launch ends
    let git_before = crate::gitguard::snapshot(request);
    let mut child = Command::new(BWRAP);
    child.args(&recipe.args).arg("--").args(&inside).args(command);
    for (name, value) in &recipe.env {
        match value {
            Some(value) => child.env(name, value),
            None => child.env_remove(name),
        };
    }
    if let Some(filter) = &filter {
        let fd = std::os::fd::AsRawFd::as_raw_fd(filter);
        unsafe {
            child.pre_exec(move || {
                if libc::dup2(fd, FILTER_FD) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let spawned = child.spawn();
    // Ctrl+C and a closed terminal are the agent's to answer: this runner waits for it, and cleans up after. Ignored only once
    // the child is started, which would otherwise inherit the ignoring
    for signal in [libc::SIGINT, libc::SIGQUIT, libc::SIGHUP] {
        unsafe { libc::signal(signal, libc::SIG_IGN) };
    }
    let code = match spawned {
        Ok(mut process) => {
            CHILD.store(process.id() as i32, Ordering::SeqCst);
            unsafe { libc::signal(libc::SIGTERM, pass_on as extern "C" fn(libc::c_int) as libc::sighandler_t) };
            let status = process.wait();
            CHILD.store(0, Ordering::SeqCst);
            status.map(|status| status.code().unwrap_or_else(|| 128 + std::os::unix::process::ExitStatusExt::signal(&status).unwrap_or(1))).unwrap_or(1)
        }
        Err(error) => {
            take_back(&request.run);
            remove_run(&request.run);
            if let Some(path) = &session {
                let _ = std::fs::remove_file(path);
            }
            return Err(format!("bubblewrap did not start: {error}"));
        }
    };
    take_back(&request.run);
    remove_run(&request.run);
    if request.hosts.is_some() {
        let _ = std::fs::remove_file(proxy_socket(request));
    }
    if let Some(path) = &session {
        let _ = std::fs::remove_file(path);
    }
    // A settings file the sandbox made in the project is the next plain launch's to read: said, never run or removed
    for path in watched.iter().filter(|path| std::fs::symlink_metadata(path).is_ok()) {
        eprintln!("The sandboxed agent made {}, which an agent reads when it next starts in this project, outside a sandbox: read it first.", path.display());
    }
    // So is a .git, a commondir or a repository's settings or hook it made or changed: git uses it at the next command there
    for line in git_before.map(|before| crate::gitguard::warnings(&before, request)).unwrap_or_default() {
        eprintln!("{line}");
    }
    Ok(code)
}

/// "amethystora-agent-tools net-shim SOCKET -- COMMAND...", inside a sandbox whose network is held to a list: takes the
/// sandbox's loopback port to the proxy's socket, then runs the command and waits for it. With no forwarder nothing runs.
pub fn net_shim(args: &[String]) -> i32 {
    let (Some(socket), Some("--"), Some(program)) = (args.first(), args.get(1).map(String::as_str), args.get(2)) else {
        eprintln!("usage: amethystora-agent-tools net-shim SOCKET -- COMMAND...");
        return 64;
    };
    if let Err(error) = amethystora_net_proxy::shim::listen(socket, SHIM_PORT) {
        eprintln!("the sandbox's way to its list of hosts could not be set up ({error}), so nothing starts");
        return 2;
    }
    let spawned = Command::new(program).args(&args[3..]).spawn();
    // Ctrl+C is the command's to answer; this waits for it (ignored only once it is started, or it would inherit that)
    for signal in [libc::SIGINT, libc::SIGQUIT] {
        unsafe { libc::signal(signal, libc::SIG_IGN) };
    }
    match spawned.and_then(|mut child| child.wait()) {
        Ok(status) => status.code().unwrap_or_else(|| 128 + std::os::unix::process::ExitStatusExt::signal(&status).unwrap_or(1)),
        Err(error) => {
            eprintln!("{program}: {error}");
            127
        }
    }
}

// --- What a launch gets ----------------------------------------------------------------------------------------------------

/// What `agent-run` was asked for
#[derive(Debug, Clone, Default)]
pub struct Asked {
    pub agent: String,
    pub profile: Option<String>,
    /// open, closed, no, or None for the folder's rule
    pub sandbox: Option<String>,
    pub dir: Option<PathBuf>,
    /// list for this launch, or None for the folder's rule
    pub network: Option<String>,
}

/// The decision for one launch, worked out when it starts and belonging to it alone
#[derive(Debug, Clone)]
pub struct Plan {
    pub request: Request,
    pub why: &'static str,
    /// Whether anything is wrapped: a sandbox, or a way-2 profile
    pub wrapped: bool,
}

impl Plan {
    pub fn json(&self, table: &Table) -> Value {
        let request = &self.request;
        let login = table.agents.get(&request.agent).and_then(|paths| paths.logins.first()).map(|login| {
            let root = agents::profile_root(&request.home, &request.profile);
            s(root.join(login).strip_prefix(&request.home).unwrap_or(Path::new(login)))
        });
        json!({
            "agent": request.agent,
            "profile": request.profile,
            "why": self.why,
            "sandbox": (request.mode != Mode::Profile).then(|| request.mode.word()),
            "project": request.project.as_ref().map(|project| s(&project.top)),
            "allow": request.allow.iter().map(Permission::word).collect::<Vec<_>>(),
            "network": if request.mode == Mode::Profile { Value::Null } else if request.hosts.is_some() { json!("list") } else { json!("open") },
            "hosts": request.hosts,
            "wrapped": self.wrapped,
            "login": login,
            "env": agents::environment(table, &request.home, &request.agent, &request.profile).into_iter()
                .filter_map(|(name, value)| value.map(|value| (name, Value::String(value)))).collect::<serde_json::Map<_, _>>(),
        })
    }
}

/// The folder's sandbox rule, if it has one: its mode and what it was allowed
pub fn rule_of(home: &Path, dir: &Path) -> Result<Option<(String, Mode, Vec<Permission>)>, String> {
    Ok(rule_with_network(home, dir)?.map(|(folder, mode, allow, _)| (folder, mode, allow)))
}

/// The same, with whether the rule holds the network to a list
pub fn rule_with_network(home: &Path, dir: &Path) -> Result<Option<(String, Mode, Vec<Permission>, bool)>, String> {
    let map = Map::read(&agents::sandbox_map_path())?;
    let dir = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    let Some((folder, rule)) = map.find(&dir) else { return Ok(None) };
    if rule.get("mode").and_then(Value::as_str) == Some("off") {
        return Ok(None);
    }
    let mode = rule.get("mode").and_then(Value::as_str).and_then(Mode::parse).unwrap_or(Mode::Open);
    let allow = rule
        .get("allow")
        .and_then(Value::as_array)
        .map(|list| list.iter().filter_map(Value::as_str).map(|text| Permission::parse(text, home)).collect::<Result<Vec<_>, _>>())
        .transpose()
        .map_err(|why| format!("{}: {why}", agents::sandbox_map_path().display()))?
        .unwrap_or_default();
    Ok(Some((folder.to_string(), mode, allow, rule.get("network").and_then(Value::as_str) == Some("list"))))
}

/// The hosts a sandbox held to a list may reach: the shipped ones for its agent and for everyone, and the folder's own
pub fn hosts_for(agent: &str, allow: &[Permission]) -> Vec<String> {
    let mut hosts = agents::network_hosts(agent);
    hosts.extend(allow.iter().filter_map(|permission| match permission {
        Permission::Network(host) => Some(host.clone()),
        _ => None,
    }));
    hosts.sort();
    hosts.dedup();
    hosts
}

/// Works out a launch: its profile, whether it is sandboxed and how, from what was asked, the terminal's pin, the folder's
/// rules and the administrator's SANDBOX
pub fn plan(table: &Table, asked: &Asked) -> Result<Plan, String> {
    let home = agents::real_home();
    if !agents::agent_name(&asked.agent) && asked.agent != agents::NO_AGENT {
        return Err(format!("{} is not an agent amethystora-agent offers", asked.agent));
    }
    let dir = match &asked.dir {
        Some(dir) => dir.clone(),
        None => std::env::current_dir().map_err(|error| error.to_string())?,
    };
    let dir = std::fs::canonicalize(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    let pin = std::env::var(agents::PIN).ok();
    let (profile, why) = if asked.agent == agents::NO_AGENT {
        (DEFAULT.to_string(), "no agent's")
    } else {
        agents::which(&home, asked.profile.as_deref(), pin.as_deref(), &dir)?
    };
    if profile != DEFAULT && !table.has_profiles(&asked.agent) {
        return Err(format!("{} has no profiles: it keeps its login in the keyring, which no folder isolates", agents::title(&asked.agent)));
    }
    let always = policy::Conf::read(Path::new(policy::CONF)).sandbox_always;
    let rule = rule_with_network(&home, &dir)?;
    let rule_list = rule.as_ref().is_some_and(|(_, _, _, list)| *list);
    let has_project = project_of(&dir, &home).is_ok();
    let (mode, allow) = match asked.sandbox.as_deref() {
        Some("no") if always && has_project => {
            return Err("an administrator has every agent started in a project sandboxed on this machine (SANDBOX=always)".into());
        }
        Some("no") => (Mode::Profile, Vec::new()),
        Some(word) => {
            let mode = Mode::parse(word).ok_or_else(|| format!("{word} is not a sandbox: open or closed"))?;
            (mode, rule.map(|(_, _, allow, _)| allow).unwrap_or_default())
        }
        None => match rule {
            Some((_, mode, allow, _)) => (mode, allow),
            None if always && has_project => (Mode::Open, Vec::new()),
            None => (Mode::Profile, Vec::new()),
        },
    };
    let project = if mode == Mode::Profile { None } else { Some(project_of(&dir, &home)?) };
    // Held to a list by the folder's rule, or for this launch; never loosened by a launch where the rule says list
    let list = match asked.network.as_deref() {
        Some("list") => true,
        Some("open") | None => rule_list,
        Some(word) => return Err(format!("{word} is not a network: list or open")),
    };
    let hosts = (mode != Mode::Profile && list).then(|| hosts_for(&asked.agent, &allow));
    let wrapped = mode != Mode::Profile || (profile != DEFAULT && matches!(table.agent(&asked.agent)?.way, Some(Way::Mount)));
    let run = runs_dir(&home).join(format!("{}-{}", std::process::id(), crate::history::new_id()));
    Ok(Plan {
        request: Request { agent: asked.agent.clone(), profile, mode, project, allow, home, uid: unsafe { libc::getuid() }, run, dir, hosts },
        why,
        wrapped,
    })
}

/// What the person is told at the start of a sandboxed launch: the project, what is hidden, that the network is open
pub fn say(plan: &Plan) -> Vec<String> {
    let request = &plan.request;
    let Some(project) = &request.project else { return Vec::new() };
    let tilde = |path: &Path| match path.strip_prefix(&request.home) {
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => path.display().to_string(),
    };
    let mut lines = vec![format!(
        "{} is sandboxed{} to {}: it can change this project and nothing else.",
        agents::title(&request.agent),
        if request.mode == Mode::Closed { ", closed," } else { "" },
        tilde(&project.top)
    )];
    lines.push(if request.mode == Mode::Closed {
        "It sees nothing of your home but the project, its own folder, the build caches and your toolchains.".into()
    } else {
        "Your keys and logins, the other agents' folders and the bus are hidden from it; the rest of your home it can only read.".into()
    });
    lines.push(match &request.hosts {
        Some(hosts) => format!(
            "The network is held to a list of {} hosts over HTTPS (its maker, the package registries, the code hosts): a program that uses no proxy reaches nothing, and this machine's own services (localhost) are out of reach. It can still send what it reads to an account on one of those hosts. Nothing in it can become root.",
            hosts.len()
        ),
        None => "The network is open: it can still send what it reads. Nothing in it can become root.".into(),
    });
    for permission in &request.allow {
        lines.push(format!("This folder allows it more: {}", permission.word()));
    }
    lines
}

/// `amethystora-agent-tools agent-run --agent A [--profile P] [--sandbox open|closed|no] [--dir D] [--quiet] -- COMMAND...`
pub fn agent_run(args: &[String]) -> i32 {
    let Some(split) = args.iter().position(|arg| arg == "--") else {
        eprintln!("usage: amethystora-agent-tools agent-run --agent AGENT [--profile NAME] [--sandbox open|closed|no] [--dir DIR] -- COMMAND...");
        return 64;
    };
    let (options, command) = (&args[..split], &args[split + 1..]);
    if command.is_empty() {
        eprintln!("agent-run: there is no command");
        return 64;
    }
    let asked = match asked_of(options) {
        Ok(asked) => asked,
        Err(why) => {
            eprintln!("{why}");
            return 64;
        }
    };
    let quiet = options.iter().any(|arg| arg == "--quiet");
    let table = match Table::load() {
        Ok(table) => table,
        Err(why) => {
            eprintln!("{why}");
            return 70;
        }
    };
    let plan = match plan(&table, &asked) {
        Ok(plan) => plan,
        Err(why) => {
            eprintln!("{why}");
            return 2;
        }
    };
    let words = agents::session_words(&json!({"agent": plan.request.agent, "profile": plan.request.profile,
        "sandboxed": (plan.request.mode != Mode::Profile).then(|| plan.request.mode.word())}));
    // The terminal's title says the account and the sandbox of the agent running in it, fixed at its start
    if unsafe { libc::isatty(2) } == 1 {
        eprint!("\x1b]2;{}\x07", words.replace(['\x1b', '\x07'], ""));
        if !quiet {
            for line in say(&plan) {
                eprintln!("{line}");
            }
        }
    }
    // The agent's own key variables of the shell, which a launch on another profile is never given: said, so that a missing key
    // is not a mystery
    if !quiet {
        if let Some(line) = agents::withheld_words(&table, &plan.request.agent, &plan.request.profile) {
            eprintln!("{line}");
        }
    }
    if !plan.wrapped {
        // A profile of way 1, or the home's: nothing to wrap, only the environment
        let mut process = Command::new(&command[0]);
        process.args(&command[1..]);
        for (name, value) in agents::environment(&table, &plan.request.home, &plan.request.agent, &plan.request.profile) {
            match value {
                Some(value) => process.env(name, value),
                None => process.env_remove(name),
            };
        }
        let error = process.exec();
        eprintln!("{}: {error}", command[0]);
        return 127;
    }
    let recipe = match recipe(&table, &plan.request) {
        Ok(recipe) => recipe,
        Err(why) => {
            eprintln!("{why}");
            return 2;
        }
    };
    match run(&recipe, &plan.request, command) {
        Ok(code) => code,
        Err(why) => {
            eprintln!("{why}");
            2
        }
    }
}

fn asked_of(options: &[String]) -> Result<Asked, String> {
    let mut asked = Asked::default();
    let mut at = 0;
    while at < options.len() {
        let value = || options.get(at + 1).cloned().ok_or_else(|| format!("{} needs a value", options[at]));
        match options[at].as_str() {
            "--agent" => asked.agent = value()?,
            "--profile" => asked.profile = Some(value()?),
            "--sandbox" => asked.sandbox = Some(value()?),
            "--dir" => asked.dir = Some(PathBuf::from(value()?)),
            "--network" => asked.network = Some(value()?),
            "--quiet" => {
                at += 1;
                continue;
            }
            other => return Err(format!("agent-run: unknown option {other}")),
        }
        at += 2;
    }
    if asked.agent.is_empty() {
        return Err("agent-run needs --agent".into());
    }
    Ok(asked)
}

/// `amethystora-agent-tools agent-plan` (the same options): what a launch would get, as JSON, for the launcher; and `sandbox show`
pub fn agent_plan(args: &[String], show: bool) -> i32 {
    let options: Vec<String> = args.iter().take_while(|arg| *arg != "--").cloned().collect();
    let command: Vec<String> = args.iter().skip_while(|arg| *arg != "--").skip(1).cloned().collect();
    let json_out = options.iter().any(|arg| arg == "--json");
    let options: Vec<String> = options.into_iter().filter(|arg| arg != "--json").collect();
    let result = asked_of(&options).and_then(|asked| {
        let table = Table::load()?;
        let plan = plan(&table, &asked)?;
        Ok((table, plan))
    });
    let (table, plan) = match result {
        Ok(found) => found,
        Err(why) => {
            if json_out {
                println!("{}", json!({"error": why}));
            } else {
                eprintln!("{why}");
            }
            return 2;
        }
    };
    if !show {
        println!("{}", plan.json(&table));
        return 0;
    }
    let mut value = plan.json(&table);
    let recipe = if plan.wrapped { Some(recipe(&table, &plan.request)) } else { None };
    if let Some(Err(why)) = &recipe {
        value["refused"] = json!(why);
    }
    if let Some(Ok(recipe)) = &recipe {
        let mut command = if command.is_empty() { vec![plan.request.agent.clone()] } else { command };
        if plan.request.hosts.is_some() {
            command.splice(0..0, [TOOLS.to_string(), "net-shim".into(), PROXY_INSIDE.into(), "--".into()]);
        }
        value["hidden"] = json!(recipe.hidden.iter().map(|path| s(path)).collect::<Vec<_>>());
        value["writable"] = json!(recipe.writable.iter().map(|path| s(path)).collect::<Vec<_>>());
        value["command"] = json!(command_line(recipe, &command));
    }
    if json_out {
        println!("{value:#}");
        return 0;
    }
    for line in say(&plan) {
        println!("{line}");
    }
    println!("Profile: {} ({})", plan.request.profile, plan.why);
    if let Some(why) = value["refused"].as_str() {
        println!("Refused: {why}");
        return 2;
    }
    if !plan.wrapped {
        println!("Not sandboxed: the agent starts as it always does here.");
        return 0;
    }
    for (title, key) in [("Writable", "writable"), ("Hidden", "hidden"), ("Hosts it may reach, over HTTPS", "hosts")] {
        println!("{title}:");
        for path in value[key].as_array().into_iter().flatten().filter_map(Value::as_str) {
            println!("  {path}");
        }
    }
    println!("The command:\n  {}", value["command"].as_str().unwrap_or(""));
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A home of the test's own, never under /tmp, which a sandbox replaces and so never takes a project from
    fn temp(name: &str) -> PathBuf {
        // HOME only where it is a real folder: in the image's build it is /root, a link to a /var/roothome that is not there
        let base = std::env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|home| home.is_dir() && !home.starts_with("/tmp"))
            .unwrap_or_else(|| PathBuf::from("/var/lib/amethystora-test"));
        let dir = base.join(format!("amethystora-sandbox-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::canonicalize(&dir).unwrap()
    }

    fn table() -> Table {
        let mut text = String::new();
        for agent in agents::AGENTS {
            text.push_str(&match agent {
                "claude" => "way claude var CLAUDE_CONFIG_DIR .claude\ndir claude .claude\nlogin claude .claude/.credentials.json\n\
                    copy claude .claude.json\ncopy claude .claude/.claude.json\nro claude .claude/settings.json\nro claude .claude/hooks\n\
                    project claude .claude\nproject claude .mcp.json\nenv claude ANTHROPIC_API_KEY\nro claude .claude/CLAUDE.md\n\
                    layer claude .claude/shell-snapshots\nlayer claude .claude/projects\nkeep claude .claude/projects/{project}\n\
                    layer claude .claude/projects/{project}/memory\nempty claude .claude/ide\n".to_string(),
                "cursor-agent" => "way cursor-agent mount\ndir cursor-agent .cursor\n".to_string(),
                other => format!("way {other} none\ndir {other} .{other}\n"),
            });
        }
        text.push_str("hidden - .ssh\nhidden - .local/share/amethystora/agent-profiles\nhidden - /var/home/.snapshots\ncache - .cargo/registry\ntool - .cargo/bin\n");
        text.push_str("tool - .config/git\nhidden - .config/git/credentials\nhidden - .config/Bitwarden*CLI\n");
        Table::parse(&text).unwrap()
    }

    fn request(home: &Path, project: &Path, mode: Mode, profile: &str, agent: &str) -> Request {
        Request {
            agent: agent.into(),
            profile: profile.into(),
            mode,
            project: Some(project_of(project, home).unwrap()),
            allow: Vec::new(),
            home: home.to_path_buf(),
            uid: 1000,
            run: home.join(".cache/amethystora/agent-sandbox/1-x"),
            dir: project.to_path_buf(),
            hosts: None,
        }
    }

    /// The position of a mount of PATH with OPTION in the recipe
    fn at(recipe: &Recipe, option: &str, path: &Path) -> Option<usize> {
        let path = s(path);
        recipe.args.windows(3).position(|w| w[0] == option && w[2] == path)
            .or_else(|| recipe.args.windows(2).position(|w| w[0] == option && w[1] == path))
    }

    /// The position of a layer over PATH, read from PATH itself, in the recipe
    fn layer_at(recipe: &Recipe, path: &Path) -> Option<usize> {
        let path = s(path);
        recipe.args.windows(6).position(|w| w[0] == "--overlay-src" && w[1] == path && w[2] == "--overlay" && w[5] == path)
    }

    #[test]
    fn a_project_is_the_repository_and_never_the_home() {
        let home = temp("project");
        std::fs::create_dir_all(home.join("code/site/.git/hooks")).unwrap();
        std::fs::create_dir_all(home.join("code/site/src")).unwrap();
        std::fs::create_dir_all(home.join(".config/x")).unwrap();
        std::fs::create_dir_all(home.join("loose")).unwrap();
        assert_eq!(project_of(&home.join("code/site/src"), &home).unwrap().top, home.join("code/site"));
        assert_eq!(project_of(&home.join("loose"), &home).unwrap().top, home.join("loose"));
        assert!(project_of(&home, &home).is_err());
        assert!(project_of(Path::new("/"), &home).is_err());
        assert!(project_of(&home.join(".config/x"), &home).is_err());
        // A dotfiles repository in the home is not every folder's project
        std::fs::create_dir_all(home.join(".git")).unwrap();
        assert_eq!(project_of(&home.join("loose"), &home).unwrap().top, home.join("loose"));
        // A worktree: its repository's folder is elsewhere
        std::fs::create_dir_all(home.join("code/site/.git/worktrees/wt")).unwrap();
        std::fs::write(home.join("code/site/.git/worktrees/wt/commondir"), "../..\n").unwrap();
        std::fs::create_dir_all(home.join("code/wt")).unwrap();
        std::fs::write(home.join("code/wt/.git"), format!("gitdir: {}\n", home.join("code/site/.git/worktrees/wt").display())).unwrap();
        let worktree = project_of(&home.join("code/wt"), &home).unwrap();
        assert_eq!(worktree.common, Some(home.join("code/site/.git")));
        std::fs::remove_dir_all(&home).unwrap();
    }

    #[test]
    fn nothing_writable_is_under_something_hidden_and_the_secrets_are_hidden() {
        let home = temp("recipe");
        for dir in [".ssh", ".cursor", "code/site/.git/hooks", ".cargo/registry", ".claude", ".local/share/amethystora/agent-profiles/work/.claude"] {
            std::fs::create_dir_all(home.join(dir)).unwrap();
        }
        std::fs::write(home.join(".ssh/id_ed25519"), "k").unwrap();
        std::fs::write(home.join("code/site/.git/config"), "[core]\n").unwrap();
        let project = home.join("code/site");
        let recipe = recipe(&table(), &request(&home, &project, Mode::Open, DEFAULT, "claude")).unwrap();
        // Hidden: the keys, the other agents' folders, the profiles
        let ssh = at(&recipe, "--tmpfs", &home.join(".ssh")).expect(".ssh hidden");
        assert!(at(&recipe, "--tmpfs", &home.join(".cursor")).is_some(), "another agent's folder");
        assert!(recipe.args.iter().any(|arg| arg == "--remount-ro"));
        // Writable after: the project, the cache, its own folder
        let project_at = at(&recipe, "--bind", &project).expect("the project");
        assert!(project_at > ssh);
        // The cache behind a layer of its own, never bound writable
        assert!(at(&recipe, "--bind", &home.join(".cargo/registry")).is_none());
        assert!(layer_at(&recipe, &home.join(".cargo/registry")).is_some());
        assert!(at(&recipe, "--bind", &home.join(".claude")).is_some());
        // Read-only after the project: the repository's hooks and settings
        assert!(at(&recipe, "--ro-bind", &project.join(".git/hooks")).unwrap() > project_at);
        assert!(at(&recipe, "--ro-bind", &project.join(".git/config")).unwrap() > project_at);
        // Its own settings read-only, made first; its .claude.json a private copy
        assert!(at(&recipe, "--ro-bind", &home.join(".claude/settings.json")).is_some());
        assert!(recipe.make.contains(&Make::File(home.join(".claude/settings.json"), "{}\n")));
        assert!(recipe.copies.iter().any(|(source, _)| source == &home.join(".claude.json")));
        // A settings folder of the project that is not there is made empty, and a file is watched
        assert!(recipe.make.contains(&Make::Placeholder(project.join(".claude"))));
        assert!(recipe.watched.contains(&project.join(".mcp.json")));
        // The filter, last before the folder it starts in
        let filter = recipe.args.iter().position(|arg| arg == "--seccomp").unwrap();
        assert_eq!(recipe.args[filter + 1], "9");
        assert!(recipe.env.contains(&("AMETHYSTORA_READ_ONLY".into(), Some("1".into()))));
        assert!(recipe.env.contains(&(SANDBOX_VAR.into(), Some("open".into()))));
        std::fs::remove_dir_all(&home).unwrap();
    }

    #[test]
    fn a_profile_is_the_agents_folder_and_the_others_stay_hidden() {
        let home = temp("profile");
        for dir in ["code/a", ".claude", ".local/share/amethystora/agent-profiles/work/.claude", ".local/share/amethystora/agent-profiles/home/.claude"] {
            std::fs::create_dir_all(home.join(dir)).unwrap();
        }
        let project = home.join("code/a");
        let recipe = recipe(&table(), &request(&home, &project, Mode::Open, "work", "claude")).unwrap();
        let profiles = home.join(agents::PROFILES);
        let hidden = at(&recipe, "--tmpfs", &profiles).expect("the profiles hidden");
        let own = at(&recipe, "--bind", &profiles.join("work/.claude")).expect("its own profile's folder");
        assert!(own > hidden);
        assert!(at(&recipe, "--bind", &profiles.join("home/.claude")).is_none());
        assert!(recipe.env.contains(&("CLAUDE_CONFIG_DIR".into(), Some(s(&profiles.join("work/.claude"))))));
        // The remount that makes the profiles' folder read-only comes after its own folder is bound in it
        let remount = recipe.args.windows(2).position(|w| w[0] == "--remount-ro" && w[1] == s(&profiles)).unwrap();
        assert!(remount > own);
        // Way 2, no sandbox: the profile's copy over the home's
        let mut way2 = request(&home, &project, Mode::Profile, "work", "cursor-agent");
        way2.project = None;
        let recipe = super::recipe(&table(), &way2).unwrap();
        assert_eq!(recipe.args[..5], ["--unshare-user", "--dev-bind", "/", "/", "--die-with-parent"]);
        assert!(at(&recipe, "--bind", &profiles.join("work/.cursor")).is_some());
        assert!(recipe.args.contains(&s(&home.join(".cursor"))));
        // An agent with no profiles has none
        assert!(super::recipe(&table(), &request(&home, &project, Mode::Open, "work", "copilot")).is_err());
        std::fs::remove_dir_all(&home).unwrap();
    }

    #[test]
    fn a_closed_sandbox_has_only_what_it_names() {
        let home = temp("closed");
        for dir in ["code/a", ".cargo/bin", ".ssh"] {
            std::fs::create_dir_all(home.join(dir)).unwrap();
        }
        let project = home.join("code/a");
        let recipe = recipe(&table(), &request(&home, &project, Mode::Closed, DEFAULT, "claude")).unwrap();
        let tmpfs = at(&recipe, "--tmpfs", &home).expect("the home replaced");
        assert!(at(&recipe, "--ro-bind", &home.join(".cargo/bin")).unwrap() > tmpfs);
        assert!(at(&recipe, "--bind", &project).unwrap() > tmpfs);
        assert!(recipe.args.windows(2).any(|w| w[0] == "--remount-ro" && w[1] == s(&home)));
        std::fs::remove_dir_all(&home).unwrap();
    }

    #[test]
    fn permissions_are_read_strictly_and_say_their_cost() {
        let home = temp("allow");
        std::fs::create_dir_all(home.join("shared")).unwrap();
        assert_eq!(Permission::parse("write=~/shared", &home).unwrap(), Permission::Write(home.join("shared")));
        assert_eq!(Permission::parse("gpu", &home).unwrap(), Permission::Gpu);
        assert!(Permission::parse("write=/", &home).is_err());
        assert!(Permission::parse(&format!("write={}", home.display()), &home).is_err());
        assert!(Permission::parse("write=relative", &home).is_err());
        assert!(Permission::parse("network=any", &home).is_err());
        assert!(Permission::parse("show=~/missing", &home).is_err());
        assert!(Permission::SshAgent.cost().contains("every key"));
        std::fs::remove_dir_all(&home).unwrap();
    }

    #[test]
    fn a_network_held_to_a_list_has_one_way_out() {
        let home = temp("network");
        std::fs::create_dir_all(home.join("code/a")).unwrap();
        let project = home.join("code/a");
        let mut held = request(&home, &project, Mode::Open, DEFAULT, "claude");
        held.hosts = Some(vec!["api.anthropic.com".into()]);
        let recipe = recipe(&table(), &held).unwrap();
        assert!(recipe.args.contains(&"--unshare-net".to_string()));
        assert!(at(&recipe, "--bind", Path::new(PROXY_INSIDE)).is_some(), "the proxy's socket bound in");
        assert!(recipe.env.contains(&("HTTPS_PROXY".into(), Some("http://127.0.0.1:3128".into()))));
        // Open, it keeps the machine's network and is told of no proxy
        let open = super::recipe(&table(), &request(&home, &project, Mode::Open, DEFAULT, "claude")).unwrap();
        assert!(!open.args.contains(&"--unshare-net".to_string()) && !open.env.iter().any(|(name, _)| name == "HTTPS_PROXY"));
        // A folder's own host is a name, never an address, a port or a path
        assert_eq!(Permission::parse("network=*.example.org", &home).unwrap(), Permission::Network("*.example.org".into()));
        for bad in ["network=10.0.0.1", "network=example.org:22", "network=localhost", "network=example.org/x", "network=any"] {
            assert!(Permission::parse(bad, &home).is_err(), "{bad}");
        }
        assert_eq!(hosts_for("none", &[Permission::Network("b.example.org".into()), Permission::Gpu]), vec!["b.example.org".to_string()]);
        assert_eq!(agents::hosts_in("# c\nclaude api.anthropic.com\ncodex api.openai.com\n- github.com\n- 10.0.0.1\nclaude a b\n", "claude"), vec!["api.anthropic.com".to_string(), "github.com".to_string()]);
        std::fs::remove_dir_all(&home).unwrap();
    }

    #[test]
    fn secret_looking_variables_are_not_passed_on() {
        for name in ["GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID", "NPM_TOKEN", "DB_PASSWORD", "STRIPE_API_KEY", "OPENAI_APIKEY", "MY_PRIVATE_THING"] {
            assert!(secret_name(name), "{name}");
        }
        for name in ["PATH", "HOME", "LANG", "TERM", "EDITOR", "KEYTIMEOUT", "CARGO_HOME"] {
            assert!(!secret_name(name), "{name}");
        }
        // A password in a short form, a database's address, a password manager's open session, a registry's login
        for name in ["DATABASE_URL", "TEST_DATABASE_URL", "MYSQL_PWD", "PGPASSWORD", "SMTP_PASS", "BORG_PASSPHRASE", "BW_SESSION", "OP_SESSION_my",
            "OP_SERVICE_ACCOUNT_TOKEN", "VAULT_TOKEN", "NPM_CONFIG__AUTH", "SENTRY_DSN", "SLACK_WEBHOOK_URL", "CI_JOB_JWT", "DOCKER_AUTH_CONFIG", "SOPS_AGE_KEY"] {
            assert!(secret_name(name), "{name}");
        }
        for name in ["PWD", "OLDPWD", "DESKTOP_SESSION", "XDG_SESSION_TYPE", "GIT_AUTHOR_NAME", "SSH_ASKPASS", "GIT_ASKPASS", "HTTPS_PROXY", "NO_PROXY", "KEYMAP"] {
            assert!(!secret_name(name), "{name}");
        }
        // By its value: an address with a password in it, and only that
        for value in ["postgres://app:hunter2@db.example/x", "https://user:ghp_x@github.com/o/r.git", "redis://:pw@cache:6379/0", "mysql://root:pw@localhost"] {
            assert!(secret_value(value), "{value}");
        }
        for value in ["https://github.com/o/r", "https://git@github.com/o/r", "user:pw", "http://[::1]:8080/a@b", "/usr/bin:/bin", "ssh://git@host:22/r", "postgres://app:@db/x"] {
            assert!(!secret_value(value), "{value}");
        }
        assert!(proxy_name("https_proxy") && proxy_name("HTTP_PROXY") && !proxy_name("DATABASE_URL"));
    }

    #[test]
    fn a_build_cache_is_a_layer_thrown_away_and_never_writable() {
        let home = temp("cache");
        for dir in ["code/a", ".cargo/registry/src", "shared"] {
            std::fs::create_dir_all(home.join(dir)).unwrap();
        }
        let project = home.join("code/a");
        for mode in [Mode::Open, Mode::Closed] {
            let recipe = recipe(&table(), &request(&home, &project, mode, DEFAULT, "claude")).unwrap();
            let cache = home.join(".cargo/registry");
            assert!(layer_at(&recipe, &cache).is_some(), "{mode:?}");
            assert!(at(&recipe, "--bind", &cache).is_none() && !recipe.writable.contains(&cache), "{mode:?}");
            assert!(recipe.layers.contains(&cache));
            // After the home is made and before the filter
            let filter = recipe.args.iter().position(|arg| arg == "--seccomp").unwrap();
            assert!(layer_at(&recipe, &cache).unwrap() < filter);
            if mode == Mode::Closed {
                assert!(layer_at(&recipe, &cache).unwrap() > at(&recipe, "--tmpfs", &home).unwrap());
            }
        }
        // A cache missing is not given a layer; one inside a place the person allowed it to write is written as that place
        let mut allowed = request(&home, &project, Mode::Open, DEFAULT, "claude");
        allowed.allow = vec![Permission::Write(home.join(".cargo"))];
        let recipe = recipe(&table(), &allowed).unwrap();
        assert!(layer_at(&recipe, &home.join(".cargo/registry")).is_none() && at(&recipe, "--bind", &home.join(".cargo")).is_some());
        std::fs::remove_dir_all(&home).unwrap();
    }

    #[test]
    fn what_its_settings_run_and_its_instructions_bring_in_is_read_only() {
        let home = temp("named");
        for dir in ["code/a/tools", ".claude/scripts", ".claude/more", ".claude/mcp"] {
            std::fs::create_dir_all(home.join(dir)).unwrap();
        }
        let project = home.join("code/a");
        let settings = r#"{
            "statusLine": {"type": "command", "command": "bash ~/.claude/statusline.sh"},
            "hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "$CLAUDE_CONFIG_DIR/scripts/guard.sh --log ~/.claude/.credentials.json"}]}]},
            "apiKeyHelper": "~/.claude/key.sh",
            "permissions": {"allow": ["Read(~/.claude/notes.txt)"]},
            "env": {"NODE_OPTIONS": "--require=/nowhere/x.js"}
        }"#;
        std::fs::write(home.join(".claude/settings.json"), settings).unwrap();
        std::fs::write(home.join(".claude.json"), format!(r#"{{"mcpServers": {{"x": {{"command": "node", "args": ["{}"]}}}}}}"#, home.join(".claude/mcp/server.js").display())).unwrap();
        std::fs::write(home.join(".claude/CLAUDE.md"), "Read @RTK.md first, and @~/code/a/tools/notes.md.\n").unwrap();
        std::fs::write(home.join(".claude/RTK.md"), "More in @more/deep.md\n").unwrap();
        for file in [".claude/statusline.sh", ".claude/scripts/guard.sh", ".claude/key.sh", ".claude/notes.txt", ".claude/.credentials.json", ".claude/more/deep.md",
            ".claude/mcp/server.js", "code/a/tools/notes.md"] {
            std::fs::write(home.join(file), "x").unwrap();
        }
        let recipe = recipe(&table(), &request(&home, &project, Mode::Open, DEFAULT, "claude")).unwrap();
        let own = at(&recipe, "--bind", &home.join(".claude")).unwrap();
        for file in [".claude/statusline.sh", ".claude/scripts/guard.sh", ".claude/key.sh", ".claude/RTK.md", ".claude/more/deep.md", ".claude/mcp/server.js"] {
            assert!(at(&recipe, "--ro-bind", &home.join(file)).is_some_and(|ro| ro > own), "{file} read-only");
        }
        // The folders on the way are mounts of their own, before what is read-only in them
        for (folder, file) in [(".claude/scripts", ".claude/scripts/guard.sh"), (".claude/more", ".claude/more/deep.md")] {
            let pin = at(&recipe, "--bind", &home.join(folder)).expect(folder);
            assert!(pin > own && pin < at(&recipe, "--ro-bind", &home.join(file)).unwrap(), "{folder}");
        }
        // Not a command's word, its login (which it renews), and the project (the diff the person reads) stay as they were
        // (held as itself: on an installed machine the login is also hidden, a /dev/null over it, from credential-files)
        for file in [".claude/notes.txt", ".claude/.credentials.json", "code/a/tools/notes.md"] {
            let path = s(&home.join(file));
            assert!(!recipe.args.windows(3).any(|w| w[0] == "--ro-bind" && w[1] == path && w[2] == path), "{file}");
        }
        std::fs::remove_dir_all(&home).unwrap();
    }

    #[test]
    fn a_layer_is_written_on_disk_in_the_launchs_folder_and_goes_with_it() {
        let home = temp("layer-disk");
        for dir in ["code/a", ".cargo/registry"] {
            std::fs::create_dir_all(home.join(dir)).unwrap();
        }
        let request = request(&home, &home.join("code/a"), Mode::Open, DEFAULT, "claude");
        let recipe = recipe(&table(), &request).unwrap();
        let cache = s(&home.join(".cargo/registry"));
        let at = recipe.args.windows(6).find(|w| w[0] == "--overlay-src" && w[1] == cache && w[2] == "--overlay").expect("the cache's layer");
        // Its upper and work folders in the launch's own folder, made first, and never a layer in memory
        assert!(at[3].starts_with(&s(&request.run)) && at[4].starts_with(&s(&request.run)) && at[3] != at[4], "{at:?}");
        assert!(recipe.make.contains(&Make::Dir(PathBuf::from(&at[3]))) && recipe.make.contains(&Make::Dir(PathBuf::from(&at[4]))));
        assert!(!recipe.args.iter().any(|arg| arg == "--tmp-overlay"));
        // The folder overlayfs leaves in a work folder has mode 0: the launch's folder goes all the same
        let stuck = request.run.join("layers/0/work/work");
        std::fs::create_dir_all(stuck.join("inside")).unwrap();
        std::fs::set_permissions(&stuck, std::os::unix::fs::PermissionsExt::from_mode(0o000)).unwrap();
        remove_run(&request.run);
        assert!(!request.run.exists());
        std::fs::remove_dir_all(&home).unwrap();
    }

    #[test]
    fn what_its_settings_name_but_is_not_there_yet_is_held_empty_and_taken_back() {
        let home = temp("missing");
        for dir in ["code/a", ".claude"] {
            std::fs::create_dir_all(home.join(dir)).unwrap();
        }
        let project = home.join("code/a");
        std::fs::write(
            home.join(".claude/settings.json"),
            r#"{"statusLine": {"type": "command", "command": "~/.claude/statusline.sh"}, "env": {"PATH": "~/.claude/bin:/usr/bin"}}"#,
        )
        .unwrap();
        let recipe = recipe(&table(), &request(&home, &project, Mode::Open, DEFAULT, "claude")).unwrap();
        // A script and a PATH folder that are not there: an empty file each, read-only, taken back afterwards
        for file in [".claude/statusline.sh", ".claude/bin"] {
            let path = home.join(file);
            assert!(recipe.make.contains(&Make::PlaceholderFile(path.clone())), "{file} made empty");
            assert!(at(&recipe, "--ro-bind", &path).is_some(), "{file} read-only");
        }
        // A read-only folder of its own that is not there is made empty and taken back, never left behind
        assert!(recipe.make.contains(&Make::Placeholder(home.join(".claude/hooks"))));
        // What prepare made is taken back while still empty, and kept once something is in it
        let run = home.join(".cache/amethystora/agent-sandbox/1-x");
        prepare(&recipe, &run).unwrap();
        assert!(home.join(".claude/statusline.sh").is_file() && home.join(".claude/hooks").is_dir());
        std::fs::write(home.join(".claude/bin"), "kept").unwrap();
        take_back(&run);
        assert!(!home.join(".claude/statusline.sh").exists() && !home.join(".claude/hooks").exists());
        assert!(home.join(".claude/bin").is_file(), "a file with something in it is never removed");
        std::fs::remove_dir_all(&home).unwrap();
    }

    #[test]
    fn a_link_in_a_read_only_folder_to_where_it_writes_and_a_project_in_a_cache_stop_the_launch() {
        let home = temp("readonly-link");
        for dir in ["code/a", ".claude/hooks", ".claude/scripts", ".cargo/registry/src/x"] {
            std::fs::create_dir_all(home.join(dir)).unwrap();
        }
        std::fs::write(home.join(".claude/scripts/guard.sh"), "x").unwrap();
        std::os::unix::fs::symlink(home.join(".claude/scripts/guard.sh"), home.join(".claude/hooks/guard.sh")).unwrap();
        let refused = recipe(&table(), &request(&home, &home.join("code/a"), Mode::Open, DEFAULT, "claude")).unwrap_err();
        assert!(refused.contains("hooks/guard.sh") && refused.contains("link"), "{refused}");
        std::fs::remove_file(home.join(".claude/hooks/guard.sh")).unwrap();
        // A project inside a build cache would lose every change with the cache's layer
        let cached = home.join(".cargo/registry/src/x");
        let mut inside = request(&home, &home.join("code/a"), Mode::Open, DEFAULT, "claude");
        inside.project = Some(Project { top: cached.clone(), git: None, common: None });
        let refused = recipe(&table(), &inside).unwrap_err();
        assert!(refused.contains("inside the build cache"), "{refused}");
        std::fs::remove_dir_all(&home).unwrap();
    }

    #[test]
    fn a_link_in_the_agents_folder_that_must_be_read_only_stops_the_launch() {
        let home = temp("link");
        for dir in ["code/a", ".claude", "dotfiles"] {
            std::fs::create_dir_all(home.join(dir)).unwrap();
        }
        std::fs::write(home.join("dotfiles/settings.json"), "{}").unwrap();
        std::os::unix::fs::symlink(home.join("dotfiles/settings.json"), home.join(".claude/settings.json")).unwrap();
        let project = home.join("code/a");
        let refused = recipe(&table(), &request(&home, &project, Mode::Open, DEFAULT, "claude")).unwrap_err();
        assert!(refused.contains(".claude/settings.json") && refused.contains("link"), "{refused}");
        // ...and a script a command names, behind a link
        std::fs::remove_file(home.join(".claude/settings.json")).unwrap();
        std::fs::write(home.join("dotfiles/line.sh"), "x").unwrap();
        std::os::unix::fs::symlink(home.join("dotfiles/line.sh"), home.join(".claude/line.sh")).unwrap();
        std::fs::write(home.join(".claude/settings.json"), r#"{"statusLine": {"command": "~/.claude/line.sh"}}"#).unwrap();
        assert!(recipe(&table(), &request(&home, &project, Mode::Open, DEFAULT, "claude")).is_err());
        std::fs::remove_dir_all(&home).unwrap();
    }

    #[test]
    fn its_memory_and_its_shells_snapshots_are_layers_and_its_transcripts_stay() {
        let home = temp("memory");
        for dir in ["code/site", ".claude/projects/-elsewhere/memory"] {
            std::fs::create_dir_all(home.join(dir)).unwrap();
        }
        let project = home.join("code/site");
        let name = project_name(&project);
        assert!(name.starts_with('-') && !name.contains('/') && name.ends_with("-code-site"), "{name}");
        let recipe = recipe(&table(), &request(&home, &project, Mode::Open, DEFAULT, "claude")).unwrap();
        let projects = home.join(".claude/projects");
        let layer = layer_at(&recipe, &projects).expect("the projects a layer");
        let keep = at(&recipe, "--bind", &projects.join(&name)).expect("this project's folder the real one");
        let memory = layer_at(&recipe, &projects.join(&name).join("memory")).expect("its memory a layer");
        assert!(at(&recipe, "--bind", &home.join(".claude")).unwrap() < layer && layer < keep && keep < memory);
        assert!(layer_at(&recipe, &home.join(".claude/shell-snapshots")).is_some());
        assert!(recipe.make.contains(&Make::Dir(projects.join(&name))));
        assert!(recipe.make.contains(&Make::Placeholder(projects.join(&name).join("memory"))));
        assert!(recipe.make.contains(&Make::Placeholder(home.join(".claude/shell-snapshots"))));
        assert!(recipe.layers.contains(&projects.join(&name).join("memory")));
        // The editor's connection: an empty folder of its own
        assert!(at(&recipe, "--tmpfs", &home.join(".claude/ide")).is_some_and(|ide| ide > at(&recipe, "--bind", &home.join(".claude")).unwrap()));
        // Started below the top of the project, its folder for that place stays the real one too
        let mut below = request(&home, &project, Mode::Open, DEFAULT, "claude");
        std::fs::create_dir_all(project.join("src")).unwrap();
        below.dir = project.join("src");
        let recipe = super::recipe(&table(), &below).unwrap();
        assert!(at(&recipe, "--bind", &projects.join(project_name(&project.join("src")))).is_some());
        std::fs::remove_dir_all(&home).unwrap();
    }

    #[test]
    fn a_closed_sandbox_hides_a_secret_inside_a_toolchain_and_a_hidden_line_takes_a_glob() {
        let home = temp("toolsecret");
        for dir in ["code/a", ".config/git", ".config/Bitwarden CLI"] {
            std::fs::create_dir_all(home.join(dir)).unwrap();
        }
        std::fs::write(home.join(".config/git/config"), "[user]\n").unwrap();
        std::fs::write(home.join(".config/git/credentials"), "https://u:p@example.org\n").unwrap();
        std::fs::write(home.join(".config/Bitwarden CLI/data.json"), "{}").unwrap();
        let project = home.join("code/a");
        let closed = recipe(&table(), &request(&home, &project, Mode::Closed, DEFAULT, "claude")).unwrap();
        let tool = at(&closed, "--ro-bind", &home.join(".config/git")).expect("git's folder given");
        let credentials = home.join(".config/git/credentials");
        assert!(closed.args.windows(3).position(|w| w == ["--ro-bind", "/dev/null", s(&credentials).as_str()]).is_some_and(|hidden| hidden > tool));
        assert!(closed.hidden.contains(&credentials));
        let open = recipe(&table(), &request(&home, &project, Mode::Open, DEFAULT, "claude")).unwrap();
        assert!(open.hidden.contains(&credentials) && open.hidden.contains(&home.join(".config/Bitwarden CLI")));
        assert!(at(&open, "--tmpfs", &home.join(".config/Bitwarden CLI")).is_some());
        std::fs::remove_dir_all(&home).unwrap();
    }

    #[test]
    fn the_words_a_settings_file_runs_are_found_in_json_toml_and_markdown() {
        let toml = "model = \"x\"\nnotify = [\"python3\", \"/h/.codex/notify.py\"]\n[mcp_servers.docs]\ncommand = \"node\"\nargs = [\n  \"/h/.codex/docs.js\",\n]\n\
            [mcp_servers.docs.env]\nNODE_PATH = \"/h/.codex/lib\"\n[other]\npath = \"/h/.codex/not-a-command\"\n";
        let words = named_words(Path::new("/h/.codex/config.toml"), toml);
        for word in ["/h/.codex/notify.py", "/h/.codex/docs.js", "/h/.codex/lib"] {
            assert!(words.iter().any(|found| found == word), "{word} in {words:?}");
        }
        assert!(!words.iter().any(|found| found.contains("not-a-command")), "{words:?}");
        // JSON with comments, read line by line
        let jsonc = "{\n  // a comment\n  \"command\": \"bash $HOME/.cursor/hook.sh\",\n  \"name\": \"/h/.cursor/plain\"\n}\n";
        let words = named_words(Path::new("/h/.cursor/hooks.json"), jsonc);
        assert!(words.contains(&"$HOME/.cursor/hook.sh".to_string()) && !words.iter().any(|found| found.contains("plain")), "{words:?}");
        let words = named_words(Path::new("/h/.claude/CLAUDE.md"), "See @RTK.md, mail a@b and @~/x.md.");
        assert_eq!(words, vec!["RTK.md".to_string(), "~/x.md".to_string()]);
        // A word as a path: whole, from the home, from the agent's variable, relative only for an @file
        let (home, vars) = (Path::new("/h"), vec![("CLAUDE_CONFIG_DIR".to_string(), PathBuf::from("/p/.claude"))]);
        assert_eq!(word_path("~/a/../b.sh", Path::new("/x"), home, &vars, false), Some(PathBuf::from("/h/b.sh")));
        assert_eq!(word_path("${CLAUDE_CONFIG_DIR}/s.sh", Path::new("/x"), home, &vars, false), Some(PathBuf::from("/p/.claude/s.sh")));
        assert_eq!(word_path("$HOMEX/s.sh", Path::new("/x"), home, &vars, false), None);
        assert_eq!(word_path("s.sh", Path::new("/x"), home, &vars, false), None);
        assert_eq!(word_path("s.md", Path::new("/x"), home, &vars, true), Some(PathBuf::from("/x/s.md")));
        assert_eq!(word_path("/../etc", Path::new("/x"), home, &vars, false), None);
    }

    #[test]
    fn the_shipped_table_layers_claudes_memory_and_hides_the_new_secrets() {
        let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../system_files/shared/usr/share/amethystora/agent-paths"));
        let Ok(text) = text else { return };
        let table = Table::parse(&text).unwrap();
        let claude = &table.agents["claude"];
        for line in [".claude/projects", ".claude/projects/{project}/memory", ".claude/shell-snapshots"] {
            assert!(claude.layers.iter().any(|layer| layer == line), "{line}");
        }
        assert!(claude.keeps.iter().any(|keep| keep == ".claude/projects/{project}") && claude.empties.iter().any(|empty| empty == ".claude/ide"));
        for secret in [".config/git/credentials", ".cargo/credentials.toml", ".pgpass", ".my.cnf", ".config/glab-cli", ".vault-token", ".azure", ".config/hub",
            ".terraform.d/credentials.tfrc.json", ".config/op", ".config/Bitwarden*CLI"] {
            assert!(table.hidden.iter().any(|hidden| hidden == secret), "{secret}");
        }
        // No layer is a login, and every layer, kept place and empty folder is inside the agent's own folder
        for (agent, paths) in &table.agents {
            for line in paths.layers.iter().chain(&paths.keeps).chain(&paths.empties) {
                assert!(paths.dirs.iter().any(|dir| Path::new(line).starts_with(dir)) && !paths.logins.contains(line), "{agent} {line}");
            }
        }
    }
}
