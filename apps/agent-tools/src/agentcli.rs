//! The commands of profiles and sandboxes, which `ame agent profile ...` and `ame agent sandbox ...` run through
//! amethystora-agent. What asks the person (a removal, a permission) asks in the recipe's terminal before it comes here.
//!
//!   profile list [--json] | add NAME | use NAME [FOLDER] | which [FOLDER] [--agent AGENT] | running [--json]
//!   profile in-use NAME | ask NAME | ask-profile | root NAME | env --shell bash|zsh|fish [--dir DIR]
//!   sandbox list [--json] | use FOLDER [open|closed] | off FOLDER | allow FOLDER PERMISSION | disallow FOLDER PERMISSION
//!   sandbox cost PERMISSION [FOLDER] | show ... (agent-plan's options)

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::agents::{self, Map, Table, Way, DEFAULT};
use crate::sandbox::{self, Permission};

fn table() -> Result<Table, String> {
    Table::load()
}

fn folder_arg(arg: Option<&String>) -> Result<PathBuf, String> {
    match arg {
        Some(folder) => agents::real_folder(Path::new(folder)),
        None => std::env::current_dir().map_err(|error| error.to_string()).and_then(|dir| agents::real_folder(&dir)),
    }
}

fn out(result: Result<String, String>) -> i32 {
    match result {
        Ok(text) => {
            if !text.is_empty() {
                println!("{text}");
            }
            0
        }
        Err(why) => {
            eprintln!("{why}");
            1
        }
    }
}

/// A word for a shell, quoted as that shell reads it
fn quoted(word: &str) -> String {
    format!("'{}'", word.replace('\'', "'\\''"))
}

pub fn profile(args: &[String]) -> i32 {
    let home = agents::real_home();
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["list"] | [] | ["list", "--json"] => out(table().and_then(|table| agents::list(&table, &home)).map(|listed| {
            if words.contains(&"--json") {
                return listed.to_string();
            }
            let mut lines = Vec::new();
            for row in listed["profiles"].as_array().into_iter().flatten() {
                let agents: Vec<&str> = row["agents"].as_array().into_iter().flatten().filter_map(Value::as_str).map(agents::title).collect();
                let folders: Vec<&str> = row["folders"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
                lines.push(format!(
                    "{}{}: {}{}",
                    row["name"].as_str().unwrap_or("?"),
                    if row["ask"] == true { " (the pill's questions)" } else { "" },
                    if agents.is_empty() { "no agent signed in".to_string() } else { format!("signed in to {}", agents.join(", ")) },
                    if folders.is_empty() { String::new() } else { format!("; folders {}", folders.join(", ")) }
                ));
            }
            lines.join("\n")
        })),
        ["add", name] => out(agents::add(&home, name)),
        ["use", name] => out(folder_arg(None).and_then(|folder| agents::use_folder(&home, name, &folder))),
        ["use", name, folder] => out(agents::use_folder(&home, name, &PathBuf::from(folder))),
        ["which", rest @ ..] => {
            let mut folder = None;
            let mut agent = None;
            let mut at = 0;
            while at < rest.len() {
                if rest[at] == "--agent" {
                    agent = rest.get(at + 1).map(|agent| agent.to_string());
                    at += 2;
                } else {
                    folder = Some(rest[at].to_string());
                    at += 1;
                }
            }
            out(folder_arg(folder.as_ref()).and_then(|dir| {
                let pin = std::env::var(agents::PIN).ok();
                let (name, why) = agents::which(&home, None, pin.as_deref(), &dir)?;
                let mut said = format!("{name} ({why})");
                if let Some(agent) = agent {
                    let table = table()?;
                    if name != DEFAULT && !table.has_profiles(&agent) {
                        said.push_str(&format!(": {} has no profiles and starts on the home's", agents::title(&agent)));
                    }
                }
                if let Ok(Some((folder, mode, _))) = sandbox::rule_of(&home, &dir) {
                    said.push_str(&format!("; sandboxed ({}) by the rule of {folder}", mode.word()));
                }
                Ok(said)
            }))
        }
        ["running"] | ["running", "--json"] => {
            let rows = agents::running();
            if words.contains(&"--json") {
                println!("{}", Value::Array(rows));
                return 0;
            }
            if rows.is_empty() {
                println!("No agent runs now.");
            }
            for row in rows {
                let project = row["project"].as_str().map(|project| format!(", in {project}")).unwrap_or_default();
                println!("{}: {}{project}, since {}", row["pid"], agents::session_words(&row), crate::history::ago(row["started"].as_u64().unwrap_or(0)));
            }
            0
        }
        // For `remove`, which the recipe asks in a terminal and then moves to the trash: refused while a session runs on it
        ["in-use", name] => {
            if agents::in_use(name) {
                println!("yes");
                0
            } else {
                1
            }
        }
        ["root", name] if *name != DEFAULT && agents::exists(&home, name) => {
            println!("{}", agents::profile_root(&home, name).display());
            0
        }
        ["ask", name] => out(agents::set_ask(&home, name)),
        // A removed profile's folders, and the pill's questions if they went to it, follow the home's again
        ["forget", name] => out(agents::forget(name)),
        ["ask-profile"] => out(agents::ask_profile(&home)),
        ["env", rest @ ..] => env(rest, &home),
        _ => {
            eprintln!("usage: amethystora-agent-tools profile list|add|use|which|running|in-use|ask|ask-profile|root|env ...");
            64
        }
    }
}

/// A word for fish, whose single quotes take \\ and \' as escapes
fn fish_quoted(word: &str) -> String {
    format!("'{}'", word.replace('\\', "\\\\").replace('\'', "\\'"))
}

/// The hook's own variable, never exported: what could not be worked out, which the shell says once until it changes
const WARNING_VAR: &str = "__amethystora_agent_warning";

/// What a hooked shell evaluates before each prompt (and a pinned terminal once): each agent of way 1's variable for the
/// folder's profile, our own profile variable, and the words of the prompt's segment. A pinned shell keeps its pin, whatever
/// the folder. What cannot be worked out (the table or a map unreadable, a folder whose profile is gone) is said on standard
/// error and in the hook's own variable, the prompt says `agent ?`, the way-1 variables that point into a profile (the last
/// folder's) are taken away and our profile variable says `?`: `command claude`, an IDE started from that shell or a script
/// never goes on to the last folder's account. An agent typed there goes through agent-run, which refuses to start for the
/// same reason.
fn env(args: &[&str], home: &Path) -> i32 {
    let shell = args.windows(2).find(|pair| pair[0] == "--shell").map(|pair| pair[1]).unwrap_or("bash");
    let dir = args.windows(2).find(|pair| pair[0] == "--dir").map(|pair| PathBuf::from(pair[1]));
    let dir = dir.or_else(|| std::env::current_dir().ok()).unwrap_or_else(|| home.to_path_buf());
    let pin = std::env::var(agents::PIN).ok().filter(|pin| !pin.is_empty());
    let (set, problems) = env_lines(table(), home, pin.as_deref(), &dir, &|name: &str| std::env::var_os(name));
    for (name, value) in set {
        let line = match (shell, value) {
            ("fish", Some(value)) => format!("set -gx {name} {}", fish_quoted(&value)),
            ("fish", None) => format!("set -e {name}"),
            (_, Some(value)) => format!("export {name}={}", quoted(&value)),
            (_, None) => format!("unset {name}"),
        };
        println!("{line}");
    }
    let warning = problems.join(" ");
    for problem in &problems {
        eprintln!("{problem}");
    }
    match shell {
        "fish" => println!("set -g {WARNING_VAR} {}", fish_quoted(&warning)),
        _ => println!("{WARNING_VAR}={}", quoted(&warning)),
    }
    if problems.is_empty() { 0 } else { 1 }
}

/// The variables of way 1 in the shipped table (claude's and codex's), for when the table itself cannot be read
const WAY_VARIABLES: &[&str] = &["CLAUDE_CONFIG_DIR", "CODEX_HOME"];

/// The variables profile env sets (None: unset) for a shell in DIR, and what could not be worked out. LOOKUP reads the
/// shell's variables (the process's own environment, which the shell passed down)
fn env_lines(
    table: Result<Table, String>,
    home: &Path,
    pin: Option<&str>,
    dir: &Path,
    lookup: &dyn Fn(&str) -> Option<OsString>,
) -> (Vec<(String, Option<String>)>, Vec<String>) {
    // As agents::ours: a variable is ours when it points into the profiles' folder
    let ours = |name: &str| lookup(name).is_some_and(|value| Path::new(&value).starts_with(agents::profiles_dir(home)));
    let mut problems = Vec::new();
    let table = table.map_err(|why| problems.push(why)).ok();
    let profile = agents::which(home, None, pin, dir).map(|(profile, _)| profile).map_err(|why| problems.push(why)).ok();
    let rule = sandbox::rule_of(home, dir).map(|rule| rule.map(|(_, mode, _)| mode)).map_err(|why| problems.push(why)).ok();
    let mut set: Vec<(String, Option<String>)> = Vec::new();
    if let (Some(table), Some(profile)) = (&table, &profile) {
        for paths in table.agents.values() {
            if let Some(Way::Variable { name, dir }) = &paths.way {
                let value = (profile != DEFAULT).then(|| agents::profile_root(home, profile).join(dir).to_string_lossy().into_owned());
                // On the home's profile a variable is taken away only when it is ours (it points into a profile): one the
                // person set in their own shell files to a place of their own is theirs
                if value.is_some() || ours(name.as_str()) {
                    set.push((name.clone(), value));
                }
            }
        }
        set.push((agents::PROFILE_VAR.into(), Some(profile.clone())));
    } else {
        // The profile not known: what points into a profile (the last folder's, left by the last prompt) is taken away, so
        // that `command claude`, an IDE started from this shell or a script never works on the last folder's account. One
        // the person set to a place of their own stays theirs. Our own variable says it is not known, never the home's
        let names: Vec<String> = match &table {
            Some(table) => table
                .agents
                .values()
                .filter_map(|paths| match &paths.way {
                    Some(Way::Variable { name, .. }) => Some(name.clone()),
                    _ => None,
                })
                .collect(),
            None => WAY_VARIABLES.iter().map(|name| name.to_string()).collect(),
        };
        for name in names {
            if ours(name.as_str()) && !set.iter().any(|(each, _)| *each == name) {
                set.push((name, None));
            }
        }
        set.push((agents::PROFILE_VAR.into(), Some("?".into())));
    }
    if let Some(rule) = rule {
        set.push(("AMETHYSTORA_AGENT_SANDBOX_RULE".into(), rule.map(|mode| mode.word().to_string())));
    }
    let mut prompt: Vec<String> = Vec::new();
    if let Some(profile) = profile.as_ref().filter(|profile| *profile != DEFAULT) {
        prompt.push(profile.clone());
    }
    if rule.flatten().is_some() {
        prompt.push("sandboxed".into());
    }
    // Not known is said as such, never as the home's plain one
    if !problems.is_empty() {
        prompt = vec!["?".into()];
    }
    set.push(("AMETHYSTORA_AGENT_PROMPT".into(), (!prompt.is_empty()).then(|| prompt.join(" · "))));
    (set, problems)
}

pub fn sandbox_cmd(args: &[String]) -> i32 {
    let home = agents::real_home();
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    let map_path = agents::sandbox_map_path();
    let change = |folder: &str, edit: &dyn Fn(&mut serde_json::Map<String, Value>) -> Result<String, String>| -> Result<String, String> {
        let folder = agents::real_folder(Path::new(folder))?;
        let key = folder.to_string_lossy().into_owned();
        if home.starts_with(&folder) {
            return Err(format!("{key} is your home or a folder above it: a rule is for the folders your projects are in"));
        }
        let mut map = Map::read(&map_path)?;
        let mut rule = map.folders.get(&key).and_then(Value::as_object).cloned().unwrap_or_default();
        let said = edit(&mut rule)?;
        if rule.is_empty() {
            map.folders.remove(&key);
        } else {
            map.folders.insert(key, Value::Object(rule));
        }
        map.write(&map_path)?;
        Ok(said)
    };
    match words.as_slice() {
        [] | ["list"] | ["list", "--json"] => {
            let map = match Map::read(&map_path) {
                Ok(map) => map,
                Err(why) => {
                    eprintln!("{why}");
                    return 1;
                }
            };
            let running: Vec<Value> = agents::running().into_iter().filter(|row| row["sandboxed"].is_string()).collect();
            if words.contains(&"--json") {
                println!("{}", json!({"folders": map.folders, "running": running}));
                return 0;
            }
            if map.folders.is_empty() {
                println!("No folder has a sandbox rule: agents start as they always do, unless started with --sandbox.");
            }
            for (folder, rule) in &map.folders {
                let allow: Vec<&str> = rule["allow"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
                println!(
                    "{folder}: {}{}{}",
                    rule["mode"].as_str().unwrap_or("open"),
                    if rule["network"] == "list" { ", network held to a list" } else { "" },
                    if allow.is_empty() { String::new() } else { format!(", allowed {}", allow.join(", ")) }
                );
            }
            for row in running {
                println!("Running: {} in {}", agents::session_words(&row), row["project"].as_str().unwrap_or("?"));
            }
            0
        }
        ["use", folder] | ["use", folder, "open"] => out(change(folder, &|rule| {
            rule.insert("mode".into(), json!("open"));
            Ok(format!("Agents started in {folder}, or a folder in it, are sandboxed to their project"))
        })),
        ["use", folder, "closed"] => out(change(folder, &|rule| {
            rule.insert("mode".into(), json!("closed"));
            Ok(format!("Agents started in {folder}, or a folder in it, are sandboxed to their project and see nothing else of your home"))
        })),
        // `off` takes the rule away; a folder inside one with a rule can say off for itself
        ["off", folder] => out(change(folder, &|rule| {
            let inherited = rule.is_empty();
            rule.clear();
            if inherited {
                rule.insert("mode".into(), json!("off"));
            }
            Ok(format!("Agents started in {folder} start as they always do"))
        })),
        ["allow", folder, permission] => out(Permission::parse(permission, &home).and_then(|permission| {
            change(folder, &|rule| {
                let mut allow: Vec<Value> = rule.get("allow").and_then(Value::as_array).cloned().unwrap_or_default();
                let word = json!(permission.word());
                if !allow.contains(&word) {
                    allow.push(word);
                }
                rule.insert("allow".into(), Value::Array(allow));
                rule.entry("mode").or_insert(json!("open"));
                Ok(format!("{folder}'s sandbox allows {}", permission.word()))
            })
        })),
        ["disallow", folder, permission] => out(change(folder, &|rule| {
            if let Some(Value::Array(allow)) = rule.get_mut("allow") {
                allow.retain(|word| word.as_str() != Some(permission));
                if allow.is_empty() {
                    rule.remove("allow");
                }
            }
            Ok(format!("{folder}'s sandbox no longer allows {permission}"))
        })),
        // The network held to a list of hosts (the shipped ones and the folder's own), or the machine's again
        ["network", folder, "list"] => out(change(folder, &|rule| {
            rule.insert("network".into(), json!("list"));
            rule.entry("mode").or_insert(json!("open"));
            Ok(format!("Agents started in {folder} reach only their list of hosts, over HTTPS: ame agent sandbox show says which"))
        })),
        ["network", folder, "open"] => out(change(folder, &|rule| {
            rule.remove("network");
            Ok(format!("Agents started in {folder} have the machine's network again"))
        })),
        // What a permission gives away, for the recipe to say before it asks
        ["cost", permission] => out(Permission::parse(permission, &home).map(|permission| permission.cost())),
        ["show", rest @ ..] => sandbox::agent_plan(&rest.iter().map(|word| word.to_string()).collect::<Vec<_>>(), true),
        _ => {
            eprintln!("usage: amethystora-agent-tools sandbox list|use|off|network|allow|disallow|cost|show ...");
            64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table_of_two_ways() -> Table {
        Table::parse(
            &agents::AGENTS
                .iter()
                .map(|agent| match *agent {
                    "claude" => "way claude var CLAUDE_CONFIG_DIR .claude\ndir claude .claude\n".to_string(),
                    other => format!("way {other} mount\ndir {other} .{other}\n"),
                })
                .collect::<String>(),
        )
        .unwrap()
    }

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("amethystora-agentcli-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(agents::PROFILES).join("work")).unwrap();
        std::fs::canonicalize(&dir).unwrap()
    }

    fn value<'a>(set: &'a [(String, Option<String>)], name: &str) -> Option<&'a Option<String>> {
        set.iter().find(|(each, _)| each == name).map(|(_, value)| value)
    }

    #[test]
    fn fish_reads_its_quotes_back() {
        assert_eq!(fish_quoted("work"), "'work'");
        assert_eq!(fish_quoted("a'b\\"), "'a\\'b\\\\'");
        assert_eq!(quoted("a'b"), "'a'\\''b'");
    }

    /// A shell with no variable of its own
    fn none(_: &str) -> Option<OsString> {
        None
    }

    #[test]
    fn what_cannot_be_read_is_said_and_never_the_homes() {
        let home = temp("unread");
        // The table unread: nothing of a profile is set, and the prompt says it is not known
        let (set, problems) = env_lines(Err("agent-paths: unreadable".into()), &home, Some("work"), &home, &none);
        assert!(problems.iter().any(|problem| problem.contains("unreadable")));
        assert!(value(&set, "CLAUDE_CONFIG_DIR").is_none());
        assert_eq!(value(&set, agents::PROFILE_VAR), Some(&Some("?".to_string())));
        assert_eq!(value(&set, "AMETHYSTORA_AGENT_PROMPT"), Some(&Some("?".to_string())));
        // A pin on a profile that is not there: the same, not the home's
        let (set, problems) = env_lines(Ok(table_of_two_ways()), &home, Some("nope"), &home, &none);
        assert!(problems.iter().any(|problem| problem.contains("nope")));
        assert_eq!(value(&set, agents::PROFILE_VAR), Some(&Some("?".to_string())));
        assert_eq!(value(&set, "AMETHYSTORA_AGENT_PROMPT"), Some(&Some("?".to_string())));
        std::fs::remove_dir_all(&home).unwrap();
    }

    #[test]
    fn a_gone_profile_takes_away_the_last_folders_variables_and_keeps_the_persons() {
        let home = temp("gone");
        let last = agents::profile_root(&home, "work").join(".claude").into_os_string();
        let left_by_the_last_folder = |name: &str| match name {
            "CLAUDE_CONFIG_DIR" | "CODEX_HOME" => Some(last.clone()),
            agents::PROFILE_VAR => Some("work".into()),
            _ => None,
        };
        // A pin on a profile that is gone, the table read: the variable into the last profile goes, ours says not known
        let (set, problems) = env_lines(Ok(table_of_two_ways()), &home, Some("nope"), &home, &left_by_the_last_folder);
        assert!(!problems.is_empty());
        assert_eq!(value(&set, "CLAUDE_CONFIG_DIR"), Some(&None));
        assert_eq!(value(&set, agents::PROFILE_VAR), Some(&Some("?".to_string())));
        // CODEX_HOME is of way 2 in this table, so it is not ours to take away here
        assert!(value(&set, "CODEX_HOME").is_none());
        // The table unread: the shipped variables of way 1 that point into a profile go
        let (set, _) = env_lines(Err("agent-paths: unreadable".into()), &home, Some("work"), &home, &left_by_the_last_folder);
        assert_eq!(value(&set, "CLAUDE_CONFIG_DIR"), Some(&None));
        assert_eq!(value(&set, "CODEX_HOME"), Some(&None));
        assert_eq!(value(&set, agents::PROFILE_VAR), Some(&Some("?".to_string())));
        // One the person set to a place of their own is theirs, and stays
        let mine = home.join("mine").into_os_string();
        let their_own = |name: &str| (name == "CLAUDE_CONFIG_DIR").then(|| mine.clone());
        for table in [Ok(table_of_two_ways()), Err("agent-paths: unreadable".to_string())] {
            let (set, problems) = env_lines(table, &home, Some("nope"), &home, &their_own);
            assert!(!problems.is_empty());
            assert!(value(&set, "CLAUDE_CONFIG_DIR").is_none());
        }
        std::fs::remove_dir_all(&home).unwrap();
    }

    #[test]
    fn a_pinned_shell_gets_its_profiles_variable() {
        let home = temp("pinned");
        let (set, _) = env_lines(Ok(table_of_two_ways()), &home, Some("work"), &home, &none);
        let dir = agents::profile_root(&home, "work").join(".claude").to_string_lossy().into_owned();
        assert_eq!(value(&set, "CLAUDE_CONFIG_DIR"), Some(&Some(dir)));
        assert_eq!(value(&set, agents::PROFILE_VAR), Some(&Some("work".to_string())));
        std::fs::remove_dir_all(&home).unwrap();
    }
}
