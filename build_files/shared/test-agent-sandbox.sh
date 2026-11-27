#!/usr/bin/bash
# Profiles and the sandbox of the AI agents (plans/done/PLAN-agent-accounts.md, plans/done/PLAN-agent-sandbox.md), against a stand-in
# home, from 20-tests.sh. Nothing here runs bubblewrap, which the image's build may not give namespaces: the recipe is held to
# what it says (`sandbox show --json`, the same function `agent-run` runs), and tests/vm/suites/77-agent-sandbox.sh runs it.
set -euo pipefail

# Needs the tool program's newer subcommands (profile, sandbox, agent-run): in the Unit and Integration workflows, which run the last
# published image with only this change's system_files over it, this waits for the image that has them (tests/ci/in-image.sh)
if ! /usr/libexec/amethystora-agent-tools 2>&1 | grep -q agent-run; then
    echo "::warning::test-agent-sandbox.sh waits for an image whose amethystora-agent-tools has agent-run"
    exit 0
fi

TOOLS=/usr/libexec/amethystora-agent-tools
TABLE=/usr/share/amethystora/agent-paths
CREDENTIALS=/usr/share/amethystora/credential-files
fail() { echo "test-agent-sandbox: $*" >&2; exit 1; }

# The table names every agent the launcher offers, each with its way and its folder; every login is a credential the watcher
# watches and the sandbox hides; the watcher's rules read both files
mapfile -t agents < <(sed -n 's/^AGENTS=(\(.*\))$/\1/p' /usr/bin/amethystora-agent | tr ' ' '\n')
[[ ${#agents[@]} -eq 6 ]] || fail "the launcher's AGENTS"
for agent in "${agents[@]}"; do
    awk -v a="${agent}" '$1 == "way" && $2 == a { found = 1 } END { exit !found }' "${TABLE}" || fail "${agent} has no way line"
    awk -v a="${agent}" '$1 == "dir" && $2 == a { found = 1 } END { exit !found }' "${TABLE}" || fail "${agent} has no dir line"
done
while read -r login; do
    grep -qxF -- "${login}" "${CREDENTIALS}" || fail "${login} is in the table but not in credential-files"
done < <(awk '$1 == "login" { print $3 }' "${TABLE}")
grep -q '/usr/share/amethystora/credential-files' /usr/libexec/amethystora-audit-home-rules || fail "the watcher's rules do not read credential-files"
grep -q 'agent-profiles/\*/' /usr/libexec/amethystora-audit-home-rules || fail "the watcher's rules do not read each profile's logins"
test -s /usr/share/amethystora/agent-sandbox.bpf || fail "the sandbox's seccomp filter is missing"
test -x /usr/bin/bwrap || fail "bubblewrap is missing"
# The build caches and the agent's memory are each a layer of the launch's own, on disk (--overlay-src, --overlay: bubblewrap 0.10)
[[ "$(/usr/bin/bwrap --help 2>&1)" == *"--overlay RWSRC"* ]] || fail "bubblewrap has no --overlay, which the sandbox's layers need"

# A stand-in home, outside /tmp (which a sandbox has its own of, and never takes a project from). The image's build has no
# /var/lib yet: what this makes there is taken away again, /var/lib with it, so that nothing is left in /var
[[ -d /var/lib ]] && MADE_VAR_LIB=false || MADE_VAR_LIB=true
BASE=/var/lib/amethystora-agent-sandbox-test
mkdir -p "${BASE}"
H="$(mktemp -d -p "${BASE}" home.XXXXXX)"
trap 'rm -rf "${BASE}"; [[ ${MADE_VAR_LIB} == false ]] || rmdir /var/lib 2>/dev/null' EXIT
export HOME="${H}" XDG_CONFIG_HOME="${H}/.config" XDG_STATE_HOME="${H}/.local/state" XDG_CACHE_HOME="${H}/.cache" XDG_RUNTIME_DIR="${H}/run"
unset AMETHYSTORA_AGENT_PROFILE AMETHYSTORA_AGENT_PROFILE_PIN CLAUDE_CONFIG_DIR CODEX_HOME
mkdir -p "${H}/run" "${H}/work/api" "${H}/workshop" "${H}/code/site/.git/hooks" "${H}/code/site/src" "${H}/.ssh" "${H}/.cursor" "${H}/.config/x"
echo key >"${H}/.ssh/id_ed25519"
echo "[core]" >"${H}/code/site/.git/config"

# Profiles: made, bound to a folder, picked by the longest real path, never by a name that only begins the same
"${TOOLS}" profile add work >/dev/null
! "${TOOLS}" profile add default 2>/dev/null || fail "default became a profile"
! "${TOOLS}" profile add 'Bad/Name' 2>/dev/null || fail "a bad name became a profile"
"${TOOLS}" profile use work "${H}/work" >/dev/null
[[ "$("${TOOLS}" profile which "${H}/work/api")" == "work (the folder's)" ]] || fail "the folder's profile"
[[ "$("${TOOLS}" profile which "${H}/workshop")" == "default (the home's)" ]] || fail "a folder that only begins the same"
ln -s "${H}/work" "${H}/link"
[[ "$("${TOOLS}" profile which "${H}/link/api")" == "work (the folder's)" ]] || fail "a link into the folder"
[[ "$(AMETHYSTORA_AGENT_PROFILE_PIN=default "${TOOLS}" profile which "${H}/work/api")" == "default (the terminal's)" ]] || fail "the pin"
! AMETHYSTORA_AGENT_PROFILE_PIN=nope "${TOOLS}" profile which "${H}/work/api" 2>/dev/null || fail "a pin that is not a profile"
plan="$("${TOOLS}" agent-plan --agent claude --dir "${H}/work/api")"
jq -e --arg dir "${H}/.local/share/amethystora/agent-profiles/work/.claude" \
    '.profile == "work" and .env.CLAUDE_CONFIG_DIR == $dir and .login == ".local/share/amethystora/agent-profiles/work/.claude/.credentials.json" and .wrapped == false' \
    <<<"${plan}" >/dev/null || fail "the plan of a way-1 profile: ${plan}"
jq -e '.wrapped == true' <<<"$("${TOOLS}" agent-plan --agent cursor-agent --dir "${H}/work/api")" >/dev/null || fail "a way-2 profile is not wrapped"
! "${TOOLS}" agent-plan --agent copilot --dir "${H}/work/api" 2>/dev/null || fail "Copilot CLI got a profile"
# The hook's lines for a folder, quoted
"${TOOLS}" profile env --shell bash --dir "${H}/work/api" | grep -qx "export CLAUDE_CONFIG_DIR='${H}/.local/share/amethystora/agent-profiles/work/.claude'" ||
    fail "the hook's variable"
"${TOOLS}" profile env --shell fish --dir "${H}/work/api" | grep -qx "set -gx AMETHYSTORA_AGENT_PROMPT 'work'" || fail "the hook's prompt, for fish"
# ...and the shells' functions only while the hook is on
bash --norc --noprofile -ic "source /usr/share/amethystora/agent-hook/hook.sh; ! type -t claude >/dev/null" 2>/dev/null || fail "the hook ran while off"
touch "${H}/.config/amethystora/agent-hook"
[[ "$(cd "${H}/work/api" && bash --norc --noprofile -ic 'source /usr/share/amethystora/agent-hook/hook.sh; echo "$(type -t claude) ${CLAUDE_CONFIG_DIR}"' 2>/dev/null)" == "function ${H}/.local/share/amethystora/agent-profiles/work/.claude" ]] ||
    fail "the hook in bash"
# A running session on a profile keeps it from being removed; the session's own file says its agent and profile
mkdir -p "${H}/run/amethystora/agent-sessions"
echo "{\"pid\": $$, \"agent\": \"claude\", \"profile\": \"work\", \"started\": 1}" >"${H}/run/amethystora/agent-sessions/$$"
"${TOOLS}" profile in-use work >/dev/null || fail "a running session is not seen"
[[ "$("${TOOLS}" profile running)" == "$$: Claude Code · work, since"* ]] || fail "the running sessions"
rm "${H}/run/amethystora/agent-sessions/$$"
! "${TOOLS}" profile in-use work >/dev/null || fail "an ended session is still seen"
# The security reader reads a profile's settings as the home's, and names the profile
mkdir -p "${H}/.local/share/amethystora/agent-profiles/work/.claude"
echo '{"permissions": {"defaultMode": "bypassPermissions"}}' >"${H}/.local/share/amethystora/agent-profiles/work/.claude/settings.json"
/usr/libexec/amethystora-security-reader agent-config | jq -e 'select(.tactic == "Defense Evasion") | select(.text | startswith("~/.local/share/amethystora/agent-profiles/work/.claude/settings.json"))' \
    >/dev/null || fail "the reader did not look into the profile"

# The sandbox: the project is the repository, never the home, a dot-folder of it or a hidden place; its keys hidden, the other
# agents' folders hidden, the repository's hooks and settings read-only after the project is bound, the filter given
"${TOOLS}" sandbox use "${H}/code" >/dev/null
! "${TOOLS}" sandbox use "${H}" 2>/dev/null || fail "the home got a rule"
shown="$("${TOOLS}" sandbox show --agent claude --dir "${H}/code/site/src" --json)"
jq -e --arg h "${H}" '.sandbox == "open" and .project == "\($h)/code/site" and (.hidden | index("\($h)/.ssh")) and (.hidden | index("\($h)/.cursor"))
    and (.writable | index("\($h)/code/site")) and (.writable | index("\($h)/.claude"))' <<<"${shown}" >/dev/null || fail "the recipe's places: ${shown}"
command="$(jq -r .command <<<"${shown}")"
[[ ${command} == *"--bind ${H}/code/site ${H}/code/site "*"--ro-bind ${H}/code/site/.git/hooks ${H}/code/site/.git/hooks "* ]] || fail "hooks read-only after the project"
[[ ${command} == *"--ro-bind ${H}/code/site/.git/config ${H}/code/site/.git/config "* ]] || fail "the repository's settings"
[[ ${command} == *"--tmpfs ${H}/.ssh "*"--remount-ro ${H}/.ssh "* ]] || fail ".ssh hidden and read-only"
[[ ${command} == *" --seccomp 9 "* && ${command} == *" --unshare-pid "* && ${command} != *"--share-net"* ]] || fail "the filter and the namespaces"
[[ ${command} == *"--tmpfs /run "* && ${command} != *"/run/user/"*"/bus"* ]] || fail "the bus"
# A closed sandbox replaces the home
[[ "$("${TOOLS}" sandbox show --agent claude --dir "${H}/code/site" --sandbox closed --json | jq -r .command)" == *"--tmpfs ${H} "* ]] || fail "a closed sandbox"
# A build cache is a layer of the launch's own, never writable: a package changed there would run at the next plain build
mkdir -p "${H}/.cargo/registry"
shown="$("${TOOLS}" sandbox show --agent claude --dir "${H}/code/site/src" --json)"
command="$(jq -r .command <<<"${shown}")"
[[ ${command} == *"--overlay-src ${H}/.cargo/registry --overlay ${H}/.cache/amethystora/agent-sandbox/"*"/upper ${H}/.cache/amethystora/agent-sandbox/"*"/work ${H}/.cargo/registry "* ]] ||
    fail "the cache a layer on disk: ${command}"
[[ ${command} != *"--tmp-overlay"* ]] || fail "a layer in memory: ${command}"
[[ ${command} != *"--bind ${H}/.cargo/registry "* ]] || fail "the cache bound writable"
jq -e --arg h "${H}" '.writable | index("\($h)/.cargo/registry") | not' <<<"${shown}" >/dev/null || fail "the cache said writable"
# Claude Code's projects a layer, this project's folder in it (and the launch's) the real one, its memory a layer again, the
# shell's snapshots a layer, the editor's connection an empty folder of its own
name="${H}/code/site"
name="${name//[^a-zA-Z0-9]/-}"
below="${H}/code/site/src"
below="${below//[^a-zA-Z0-9]/-}"
P="${H}/.claude/projects"
[[ ${command} == *"--overlay-src ${P} --overlay "*"/work ${P} "*"--bind ${P}/${name} ${P}/${name} "*"--overlay-src ${P}/${name}/memory --overlay "*"/work ${P}/${name}/memory "* ]] ||
    fail "Claude Code's memory: ${command}"
[[ ${command} == *"--bind ${P}/${below} ${P}/${below} "* ]] || fail "the launch's own folder of projects"
[[ ${command} == *"--overlay-src ${H}/.claude/shell-snapshots --overlay "*"/work ${H}/.claude/shell-snapshots "* ]] || fail "the shell's snapshots"
[[ ${command} == *"--tmpfs ${H}/.claude/ide "* && ${command} == *"--tmpfs ${H}/.claude/sessions "* ]] || fail "the editor's connection and the other sessions"
# What its settings run and what its instructions bring in, read-only, the folder on the way a mount of its own first
mkdir -p "${H}/.claude/scripts"
echo x >"${H}/.claude/statusline.sh"
echo x >"${H}/.claude/scripts/guard.sh"
echo x >"${H}/.claude/RTK.md"
echo '{"statusLine": {"type": "command", "command": "bash ~/.claude/statusline.sh"}, "hooks": {"Stop": [{"hooks": [{"type": "command", "command": "$HOME/.claude/scripts/guard.sh"}]}]}}' \
    >"${H}/.claude/settings.json"
echo 'Read @RTK.md' >"${H}/.claude/CLAUDE.md"
command="$("${TOOLS}" sandbox show --agent claude --dir "${H}/code/site" --json | jq -r .command)"
for file in statusline.sh scripts/guard.sh RTK.md; do
    [[ ${command} == *"--ro-bind ${H}/.claude/${file} ${H}/.claude/${file} "* ]] || fail "${file}, which a later session runs or reads, is writable: ${command}"
done
[[ ${command} == *"--bind ${H}/.claude/scripts ${H}/.claude/scripts "*"--ro-bind ${H}/.claude/scripts/guard.sh "* ]] || fail "the folder on the way to a script"
# ...and a link there stops the launch, which a mount cannot hold
ln -s "${H}/.claude/scripts/guard.sh" "${H}/.claude/linked.sh"
echo '{"statusLine": {"command": "~/.claude/linked.sh"}}' >"${H}/.claude/settings.local.json"
jq -e '.refused | test("link")' <<<"$("${TOOLS}" sandbox show --agent claude --dir "${H}/code/site" --json)" >/dev/null || fail "a link to run was not refused"
rm -f "${H}/.claude/linked.sh" "${H}/.claude/settings.local.json"
# The secrets the table names hidden, in an open sandbox and inside a closed one's toolchains (git's own credentials file)
mkdir -p "${H}/.config/git" "${H}/.config/glab-cli" "${H}/.azure"
echo "[user]" >"${H}/.config/git/config"
for file in .config/git/credentials .pgpass .my.cnf .vault-token .cargo/credentials.toml .config/glab-cli/config.yml .azure/msal_token_cache.json; do
    echo secret >"${H}/${file}"
done
shown="$("${TOOLS}" sandbox show --agent claude --dir "${H}/code/site" --json)"
for place in .config/git/credentials .pgpass .my.cnf .vault-token .cargo/credentials.toml .config/glab-cli .azure; do
    jq -e --arg p "${H}/${place}" '.hidden | index($p)' <<<"${shown}" >/dev/null || fail "${place} is not hidden"
done
command="$("${TOOLS}" sandbox show --agent claude --dir "${H}/code/site" --sandbox closed --json | jq -r .command)"
[[ ${command} == *"--ro-bind ${H}/.config/git ${H}/.config/git "*"--ro-bind /dev/null ${H}/.config/git/credentials "* ]] ||
    fail "git's credentials inside a closed sandbox's toolchains: ${command}"
rm -rf "${H}/.config/git" "${H}/.config/glab-cli" "${H}/.azure" "${H}/.pgpass" "${H}/.my.cnf" "${H}/.vault-token" "${H}/.cargo/credentials.toml"
rm -f "${H}/.claude/settings.json" "${H}/.claude/CLAUDE.md" "${H}/.claude/RTK.md" "${H}/.claude/statusline.sh"
rm -rf "${H}/.claude/scripts"
# A script its settings name that is not there yet, and a folder of a PATH-like value, are held by an empty file read-only
# (made only at the launch, never by show); a link in a read-only folder to a place the agent writes stops the launch
echo '{"statusLine": {"command": "~/.claude/later.sh"}, "env": {"PATH": "~/.claude/bin:/usr/bin"}}' >"${H}/.claude/settings.json"
command="$("${TOOLS}" sandbox show --agent claude --dir "${H}/code/site" --json | jq -r .command)"
for file in later.sh bin; do
    [[ ${command} == *"--ro-bind ${H}/.claude/${file} ${H}/.claude/${file} "* ]] || fail "${file}, named but not there, is not held: ${command}"
done
[[ ! -e ${H}/.claude/later.sh ]] || fail "show made a file"
mkdir -p "${H}/.claude/hooks" "${H}/.claude/scripts"
echo x >"${H}/.claude/scripts/guard.sh"
ln -s "${H}/.claude/scripts/guard.sh" "${H}/.claude/hooks/guard.sh"
jq -e '.refused | test("link")' <<<"$("${TOOLS}" sandbox show --agent claude --dir "${H}/code/site" --json)" >/dev/null ||
    fail "a link in a read-only folder to where the agent writes was not refused"
rm -rf "${H}/.claude/hooks" "${H}/.claude/scripts" "${H}/.claude/settings.json"
# A project inside a build cache (Go's is not a dot-folder) would lose every change with the cache's layer: refused
mkdir -p "${H}/go/pkg/mod/example.org/x"
jq -e '.refused | test("inside the build cache")' <<<"$("${TOOLS}" sandbox show --agent claude --dir "${H}/go/pkg/mod/example.org/x" --sandbox open --json)" >/dev/null ||
    fail "a project inside a build cache"
rm -rf "${H}/go"
# Never a project that is the home, a dot-folder of it, or above it
! "${TOOLS}" agent-plan --agent claude --sandbox open --dir "${H}" 2>/dev/null || fail "the home as a project"
! "${TOOLS}" agent-plan --agent claude --sandbox open --dir "${H}/.config/x" 2>/dev/null || fail "a dot-folder as a project"
! "${TOOLS}" agent-plan --agent claude --sandbox open --dir / 2>/dev/null || fail "/ as a project"
# Permissions say what they give away, and an unknown one is refused
"${TOOLS}" sandbox cost ssh-agent | grep -q "every key" || fail "ssh-agent's cost"
! "${TOOLS}" sandbox allow "${H}/code" network=any 2>/dev/null || fail "an unknown permission"
"${TOOLS}" sandbox allow "${H}/code" gpu >/dev/null
[[ "$("${TOOLS}" sandbox show --agent claude --dir "${H}/code/site" --json | jq -r .command)" == *"--dev-bind-try /dev/dri /dev/dri "* ]] || fail "gpu"
# The network held to a list: a network of its own, the proxy's socket bound in, the command behind the forwarder, the shipped hosts
# for the agent and the folder's own, each a name and never an address
"${TOOLS}" sandbox network "${H}/code" list >/dev/null
! "${TOOLS}" sandbox allow "${H}/code" network=10.0.0.1 2>/dev/null || fail "an address as a host"
"${TOOLS}" sandbox allow "${H}/code" "network=*.example.org" >/dev/null
held="$("${TOOLS}" sandbox show --agent claude --dir "${H}/code/site" --json)"
jq -e '.network == "list" and (.hosts | index("api.anthropic.com")) and (.hosts | index("github.com")) and (.hosts | index("*.example.org"))
    and (.hosts | index("api.openai.com") | not)' <<<"${held}" >/dev/null || fail "the hosts of a held network: ${held}"
command="$(jq -r .command <<<"${held}")"
[[ ${command} == *" --unshare-net "* && ${command} == *" /run/amethystora-agent-proxy.sock "* ]] || fail "a held network is not its own"
[[ ${command} == *"-- /usr/libexec/amethystora-agent-tools net-shim /run/amethystora-agent-proxy.sock -- claude" ]] || fail "the forwarder in front of the command"
while read -r who host; do
    [[ ${host} =~ ^(\*\.)?[a-z0-9-]+(\.[a-z0-9-]+)+$ && ! ${host} =~ ^[0-9.]+$ ]] || fail "${host} in agent-network-hosts is not a name"
    [[ ${who} == - || " ${agents[*]} " == *" ${who} "* ]] || fail "${who} in agent-network-hosts is not an agent"
done < <(grep -v -e "^#" -e "^[[:space:]]*$" /usr/share/amethystora/agent-network-hosts)
"${TOOLS}" sandbox network "${H}/code" open >/dev/null
jq -e '.network == "open"' <<<"$("${TOOLS}" sandbox show --agent claude --dir "${H}/code/site" --json)" >/dev/null || fail "the network given back"
"${TOOLS}" sandbox off "${H}/code" >/dev/null
jq -e '.wrapped == false' <<<"$("${TOOLS}" agent-plan --agent claude --dir "${H}/code/site")" >/dev/null || fail "a rule taken off"
echo "test-agent-sandbox: ok"
