#!/usr/bin/bash
# Several accounts of one agent (plans/done/PLAN-agent-accounts.md) and an agent held to its project (plans/done/PLAN-agent-sandbox.md),
# as the test account, with a stand-in agent that tries each thing and prints what happened. One phase:
#   - the sandbox: the project, a cache and its own folder writable; the home, .git's hooks and settings and its own settings
#     not; ~/.ssh empty; no bus, no runtime folder, no other process; sudo refused; TIOCSTI refused; a nested namespace
#     cannot unmount what is hidden; .git cannot be moved away; the session's file while it runs and Stop by its number
#   - with user namespaces turned off the launch is refused and nothing starts
#   - profiles: a folder's profile, two agents at once on two profiles each seeing only its own folder, a way-2 profile's
#     folder bound over the home's, the reader and the watcher's rules looking into a profile, the shells' hook
#   - SANDBOX=always: --no-sandbox refused in a project
# vmlab-paths: apps/agent-tools/* @sf/usr/bin/amethystora-agent @sf/usr/share/amethystora/agent-paths @sf/usr/share/amethystora/credential-files @sf/usr/share/amethystora/agent-hook/* @sf/usr/libexec/amethystora-security-reader @sf/usr/libexec/amethystora-audit-home-rules @sf/usr/share/amethystora/just/agent.just
source "$(dirname "$0")/lib.sh"

if ! wait_for 300 has_session; then
    skip "no session for ${TEST_USER} (10-account.sh)"
    finish
fi
H="/var/home/${TEST_USER}"
TOOLS=/usr/libexec/amethystora-agent-tools
CONF=/etc/amethystora/agent.conf
OWN=/run/vmlab-agent-sandbox
mkdir -p "${OWN}"
chmod 0755 "${OWN}"
cp -a "${CONF}" "${OWN}/agent.conf.before" 2>/dev/null || true

# A command as the account, on its user manager's bus
as_account() { user_bus env HOME="${H}" "$@"; }

# A script run as the account, on its user manager's bus, its output kept
user_script() {
    local name="$1"
    cat >"${OWN}/${name}.sh"
    chmod 0755 "${OWN}/${name}.sh"
    user_bus env HOME="${H}" bash "${OWN}/${name}.sh" 2>&1
}

# --- The sandbox --------------------------------------------------------------------------------------------------------
out="$(user_script sandbox <<EOF
set +e
mkdir -p ~/vmlab-code/site/src ~/.ssh ~/.cargo/registry
echo KEY >~/.ssh/id_vmlab; chmod 600 ~/.ssh/id_vmlab
cd ~/vmlab-code/site && git init -q 2>/dev/null
${TOOLS} agent-run --agent claude --sandbox open --quiet -- bash -c '
try() { if eval "\$2" >/dev/null 2>&1; then echo "\$1=yes"; else echo "\$1=no"; fi; }
try project "echo x >~/vmlab-code/site/ok"
try cache "echo x >~/.cargo/registry/vmlab"
try own "echo x >~/.claude/vmlab"
try home "echo x >~/vmlab-nope"
try hooks "echo x >~/vmlab-code/site/.git/hooks/pre-commit"
try gitconfig "echo x >>~/vmlab-code/site/.git/config"
try settings "echo x >>~/.claude/settings.json"
try key "test -s ~/.ssh/id_vmlab"
try bus "test -e /run/user/\$(id -u)/bus"
try dbus "test -n \"\${DBUS_SESSION_BUS_ADDRESS:-}\""
try sudo "sudo -n true"
try procs "test \$(ls /proc | grep -c ^[0-9]) -lt 8"
try unmount "unshare -Urm umount -l ~/.ssh"
try movegit "mv ~/vmlab-code/site/.git ~/vmlab-code/site/.git2"
try tiocsti "python3 -c \"import fcntl,termios,pty,os; m,s=pty.openpty(); fcntl.ioctl(s, termios.TIOCSTI, b\\\"x\\\")\""
try readonly "test \"\${AMETHYSTORA_READ_ONLY:-}\" = 1 && test \"\${AMETHYSTORA_AGENT_SANDBOX:-}\" = open"
'
EOF
)"
expect() {
    local key="$1" want="$2" what="$3"
    if grep -qx "${key}=${want}" <<<"${out}"; then ok "${what}"; else not_ok "${what}" "${out}"; fi
}
expect project yes "sandboxed: it writes in its project"
expect cache yes "sandboxed: it writes in a build cache"
expect own yes "sandboxed: it writes in its own folder"
expect home no "sandboxed: it cannot write in the home"
expect hooks no "sandboxed: .git/hooks is read-only"
expect gitconfig no "sandboxed: .git/config is read-only"
expect settings no "sandboxed: its own settings are read-only"
expect key no "sandboxed: ~/.ssh's key is hidden"
expect bus no "sandboxed: the session bus is not there"
expect dbus no "sandboxed: nothing says where the bus is"
expect sudo no "sandboxed: sudo refuses"
expect procs yes "sandboxed: only its own processes"
expect unmount no "sandboxed: a nested namespace cannot unmount what is hidden"
expect movegit no "sandboxed: .git cannot be moved away"
expect tiocsti no "sandboxed: typing into a terminal (TIOCSTI) is refused"
expect readonly yes "sandboxed: Amethystora's tools only read, and the agent is told it is sandboxed"
check "sandboxed: the placeholder folders it made in the project are gone" \
    bash -c "[[ ! -e ${H}/vmlab-code/site/.claude && ! -e ${H}/vmlab-code/site/.cursor ]]"
check "sandboxed: the launch's folder is gone" bash -c "[[ -z \"\$(ls -A ${H}/.cache/amethystora/agent-sandbox 2>/dev/null)\" ]]"

# What a later plain session would run or read, which the sandbox writes: a build cache and Claude Code's memory and shell
# snapshots behind a layer thrown away (this project's transcript kept), the scripts its settings run and the files its
# instructions bring in read-only, the editor's connection not there, the new secrets hidden and their variables not passed
out="$(user_script layers <<'EOF'
set +e
TOOLS=/usr/libexec/amethystora-agent-tools
mkdir -p ~/.cargo/registry ~/.claude/vmlab-dir ~/.claude/shell-snapshots ~/.claude/ide ~/.config/git ~/vmlab-code/site
echo before >~/.cargo/registry/vmlab-before
echo before >~/.claude/shell-snapshots/login-path-vmlab.sh
echo lock >~/.claude/ide/vmlab.lock
echo 'echo status' >~/.claude/vmlab-status.sh
echo 'echo guard' >~/.claude/vmlab-dir/guard.sh
echo 'Be careful.' >~/.claude/vmlab-rtk.md
cp -a ~/.claude/settings.json ~/.claude/settings.json.vmlab 2>/dev/null
cp -a ~/.claude/CLAUDE.md ~/.claude/CLAUDE.md.vmlab 2>/dev/null
echo '{"statusLine": {"type": "command", "command": "bash ~/.claude/vmlab-status.sh"}, "hooks": {"Stop": [{"hooks": [{"type": "command", "command": "~/.claude/vmlab-dir/guard.sh"}]}]}}' >~/.claude/settings.json
echo 'Read @vmlab-rtk.md' >~/.claude/CLAUDE.md
echo 'https://u:p@example.org' >~/.config/git/credentials
echo 'db:5432:*:u:p' >~/.pgpass
cd ~/vmlab-code/site || exit 1
name="$(pwd -P | sed 's/[^a-zA-Z0-9]/-/g')"
VMLAB_NAME="${name}" DATABASE_URL=postgres://u:p@db/x BW_SESSION=vmlab ${TOOLS} agent-run --agent claude --sandbox open --quiet -- bash -c '
try() { if eval "$2" >/dev/null 2>&1; then echo "$1=yes"; else echo "$1=no"; fi; }
try cacheread "grep -q before ~/.cargo/registry/vmlab-before"
try cachewrite "echo x >~/.cargo/registry/vmlab-layer && echo changed >~/.cargo/registry/vmlab-before"
try memory "mkdir -p ~/.claude/projects/$VMLAB_NAME/memory && echo x >~/.claude/projects/$VMLAB_NAME/memory/MEMORY.md"
try transcript "echo x >~/.claude/projects/$VMLAB_NAME/vmlab.jsonl"
try othermemory "mkdir -p ~/.claude/projects/-vmlab-other/memory && echo x >~/.claude/projects/-vmlab-other/memory/MEMORY.md"
try snapshot "echo changed >~/.claude/shell-snapshots/login-path-vmlab.sh"
try ide "test -e ~/.claude/ide/vmlab.lock"
try status "echo x >>~/.claude/vmlab-status.sh"
try hook "echo x >>~/.claude/vmlab-dir/guard.sh"
try movehook "mv ~/.claude/vmlab-dir ~/.claude/vmlab-dir2"
try import "echo x >>~/.claude/vmlab-rtk.md"
try gitcredentials "test -s ~/.config/git/credentials"
try pgpass "test -s ~/.pgpass"
try dburl "test -n \"${DATABASE_URL:-}\""
try bwsession "test -n \"${BW_SESSION:-}\""
try path "test -n \"${PATH:-}\""
'
echo "aftercache=$(cat ~/.cargo/registry/vmlab-before)$(test -e ~/.cargo/registry/vmlab-layer && echo +layer)"
echo "aftermemory=$(test -e ~/.claude/projects/"${name}"/memory/MEMORY.md && echo kept || echo gone)"
echo "aftertranscript=$(test -e ~/.claude/projects/"${name}"/vmlab.jsonl && echo kept || echo gone)"
echo "afterother=$(test -e ~/.claude/projects/-vmlab-other && echo kept || echo gone)"
echo "aftersnapshot=$(cat ~/.claude/shell-snapshots/login-path-vmlab.sh)"
echo "afterhook=$(cat ~/.claude/vmlab-dir/guard.sh 2>/dev/null)"
mv -f ~/.claude/settings.json.vmlab ~/.claude/settings.json 2>/dev/null || rm -f ~/.claude/settings.json
mv -f ~/.claude/CLAUDE.md.vmlab ~/.claude/CLAUDE.md 2>/dev/null || rm -f ~/.claude/CLAUDE.md
rm -rf ~/.cargo/registry/vmlab-before ~/.cargo/registry/vmlab-layer ~/.claude/vmlab-dir ~/.claude/vmlab-dir2 ~/.claude/vmlab-status.sh ~/.claude/vmlab-rtk.md \
    ~/.claude/ide/vmlab.lock ~/.claude/shell-snapshots/login-path-vmlab.sh ~/.claude/projects/"${name}"/vmlab.jsonl ~/.claude/projects/-vmlab-other \
    ~/.config/git/credentials ~/.pgpass
EOF
)"
expect cacheread yes "sandboxed: it reads a build cache"
expect cachewrite yes "sandboxed: it writes in a build cache, in a layer of its own"
expect aftercache before "sandboxed: nothing it wrote in a build cache is seen outside"
expect memory yes "sandboxed: Claude Code can write its memory"
expect aftermemory gone "sandboxed: the memory it wrote is thrown away, never read by a plain session"
expect transcript yes "sandboxed: Claude Code writes this project's transcript"
expect aftertranscript kept "sandboxed: this project's transcript stays"
expect othermemory yes "sandboxed: another project's folder can be written, in the layer"
expect afterother gone "sandboxed: another project's memory it made is thrown away"
expect snapshot yes "sandboxed: a shell snapshot can be written, in the layer"

# A script its settings name but that is not there yet: the agent cannot make it, and the empty file that held its place is
# taken back when the launch ends, so nothing is left in the agent's folder
out="$(user_script missing <<EOF
set +e
mkdir -p ~/vmlab-code/site ~/.claude
cp -a ~/.claude/settings.json ~/.claude/settings.json.vmlab 2>/dev/null
echo '{"statusLine": {"command": "~/.claude/vmlab-later.sh"}}' >~/.claude/settings.json
cd ~/vmlab-code/site && ${TOOLS} agent-run --agent claude --sandbox open --quiet -- bash -c 'if echo x >~/.claude/vmlab-later.sh 2>/dev/null; then echo later=yes; else echo later=no; fi'
if test -e ~/.claude/vmlab-later.sh; then echo left=yes; else echo left=no; fi
rm -f ~/.claude/settings.json ~/.claude/vmlab-later.sh
mv ~/.claude/settings.json.vmlab ~/.claude/settings.json 2>/dev/null
EOF
)"
expect later no "sandboxed: a script its settings name but that is not there cannot be made"
expect left no "sandboxed: the empty file that held its place is taken back"
expect aftersnapshot before "sandboxed: a shell snapshot the next session sources is unchanged"
expect ide no "sandboxed: the editor's connection and its key are not there"
expect status no "sandboxed: the status line's script is read-only"
expect hook no "sandboxed: a hook's script is read-only"
expect movehook no "sandboxed: a hook's folder cannot be moved away and made again"
expect afterhook "echo guard" "sandboxed: the hook's script is unchanged"
expect import no "sandboxed: a file CLAUDE.md brings in is read-only"
expect gitcredentials no "sandboxed: ~/.config/git/credentials is hidden"
expect pgpass no "sandboxed: ~/.pgpass is hidden"
expect dburl no "sandboxed: an address with a password in it is not passed on"
expect bwsession no "sandboxed: a password manager's session is not passed on"
expect path yes "sandboxed: PATH is passed on"

# The session's file while it runs, and Stop by its number ends the sandbox and everything in it
user_script long <<EOF >/dev/null &
cd ~/vmlab-code/site && exec ${TOOLS} agent-run --agent claude --sandbox open --quiet -- sleep 300
EOF
sleep 4
runner="$(cd "/run/user/$(id -u "${TEST_USER}")/amethystora/agent-sessions" 2>/dev/null && for f in [0-9]*; do
    jq -e '.sandboxed == "open" and .agent == "claude"' "${f}" >/dev/null 2>&1 && echo "${f}"; done | head -n 1)"
if [[ -n "${runner}" ]]; then
    ok "a sandbox's runner names its session: agent, profile and sandboxed"
    if as_account "${TOOLS}" profile running | grep -q 'Claude Code · sandboxed'; then
        ok "the running sessions list it"
    else
        not_ok "the running sessions list it" "$(as_account "${TOOLS}" profile running 2>&1)"
    fi
    user_bus env HOME="${H}" amethystora-agent stop "${runner}" >/dev/null 2>&1
    sleep 2
    check "Stop ends the sandbox and everything in it" bash -c "! pgrep -u ${TEST_USER} -f 'sleep 300' >/dev/null"
else
    not_ok "a sandbox's runner names its session: agent, profile and sandboxed" "$(ls -la "/run/user/$(id -u "${TEST_USER}")/amethystora/agent-sessions" 2>&1)"
fi
pkill -u "${TEST_USER}" -f 'sleep 300' 2>/dev/null || true
wait 2>/dev/null || true

# The network held to a list: an allowed host answers, another is refused by the proxy, and nothing goes round it
out="$(user_script network <<EOF
${TOOLS} sandbox use ~/vmlab-code >/dev/null; ${TOOLS} sandbox network ~/vmlab-code list >/dev/null
cd ~/vmlab-code/site && ${TOOLS} agent-run --agent claude --quiet -- bash -c '
echo "allowed=\$(curl -s -o /dev/null -m 25 -w %{http_code} https://api.github.com/zen)"
echo "denied=\$(curl -s -o /dev/null -m 25 -w %{http_code} https://example.com/)"
echo "direct=\$(curl -s --noproxy "*" -o /dev/null -m 8 -w %{http_code} https://api.github.com/zen)"
echo "plain=\$(curl -s -o /dev/null -m 10 -w %{http_code} http://example.com/)"'
${TOOLS} sandbox off ~/vmlab-code >/dev/null
EOF
)"
if curl -s -o /dev/null -m 15 https://api.github.com/zen; then
    expect allowed 200 "held to a list: a host on the list answers"
    expect denied 000 "held to a list: a host off it is refused"
    expect direct 000 "held to a list: nothing goes round the proxy"
    expect plain 403 "held to a list: plain HTTP is refused"
else
    skip "the lab has no network, so the list of hosts was not tried"
fi

# What git would use outside that a mount cannot stop (a commondir, a repository in a subfolder or in a package folder): named
# when the launch ends, a folder's escape sequence written out. A submodule's work tree's .git file, in a package folder, that
# a plain git status at the top reads: read-only
out="$(user_script gitguard <<EOF
cd ~/vmlab-code/site || exit 1
mkdir -p .git/modules/lib/hooks vendor/lib
echo "ref: refs/heads/main" >.git/modules/lib/HEAD
printf "[core]\n\tworktree = ../../../vendor/lib\n" >.git/modules/lib/config
printf "[submodule \"lib\"]\n\tpath = vendor/lib\n" >.gitmodules
echo "gitdir: ../../.git/modules/lib" >vendor/lib/.git
${TOOLS} agent-run --agent claude --sandbox open --quiet -- bash -c '
echo vmlab-elsewhere >~/vmlab-code/site/.git/commondir
mkdir -p ~/vmlab-code/site/sub/.git && printf "[core]\n\tfsmonitor = /usr/bin/true\n" >~/vmlab-code/site/sub/.git/config
mkdir -p ~/vmlab-code/site/node_modules/pkg/.git
mkdir -p ~/vmlab-code/site/"\$(printf "esc\033]0;x\007")"/.git
if echo "gitdir: ../../evil" >~/vmlab-code/site/vendor/lib/.git 2>/dev/null; then echo "rewrote=yes"; else echo "rewrote=no"; fi'
echo "pointer=\$(cat vendor/lib/.git)"
EOF
)"
rm -rf "${H}/vmlab-code/site/.git/commondir" "${H}/vmlab-code/site/sub" "${H}/vmlab-code/site/node_modules" "${H}/vmlab-code/site/esc"* \
    "${H}/vmlab-code/site/vendor" "${H}/vmlab-code/site/.gitmodules" "${H}/vmlab-code/site/.git/modules/lib"
for made in .git/commondir sub/.git node_modules/pkg/.git; do
    grep -qF "The sandboxed agent made ${H}/vmlab-code/site/${made}, which git" <<<"${out}" &&
        ok "sandboxed: a new ${made} is named when the launch ends" || not_ok "sandboxed: a new ${made} is named when the launch ends" "${out}"
done
grep -qF "The sandboxed agent made ${H}/vmlab-code/site/esc\\x1b]0;x\\x07/.git, which git" <<<"${out}" && ! grep -qF $'esc\033' <<<"${out}" &&
    ok "sandboxed: a folder's escape sequence is written out, never sent to the terminal" ||
    not_ok "sandboxed: a folder's escape sequence is written out, never sent to the terminal" "${out//$'\033'/<ESC>}"
grep -qx "rewrote=no" <<<"${out}" && grep -qx "pointer=gitdir: ../../.git/modules/lib" <<<"${out}" &&
    ok "sandboxed: a submodule's .git file cannot be rewritten" || not_ok "sandboxed: a submodule's .git file cannot be rewritten" "${out}"

# No namespaces: the launch is refused, and the command never runs plain
before="$(sysctl -n user.max_user_namespaces)"
sysctl -q -w user.max_user_namespaces=0
out="$(user_script nonamespace <<EOF
cd ~/vmlab-code/site && ${TOOLS} agent-run --agent claude --sandbox open --quiet -- touch ~/vmlab-ran-plain; echo "exit=\$?"
EOF
)"
sysctl -q -w user.max_user_namespaces="${before}"
check "with no namespaces the sandboxed launch fails" bash -c "grep -q 'exit=[1-9]' <<<'${out//\'/}'"
check "...and the command never ran plain" bash -c "[[ ! -e ${H}/vmlab-ran-plain ]]"

# --- Profiles -----------------------------------------------------------------------------------------------------------
out="$(user_script profiles <<EOF
set +e
ame agent profile add vmlab-work >/dev/null
ame agent profile add vmlab-home >/dev/null
mkdir -p ~/vmlab-work/api ~/vmlab-personal
ame agent profile use vmlab-work ~/vmlab-work >/dev/null
ame agent profile use vmlab-home ~/vmlab-personal >/dev/null
echo "which=\$(ame agent profile which ~/vmlab-work/api)"
# Two stand-in agents at once, each on its own profile, each seeing its own folder: a way-1 agent by its variable
cd ~/vmlab-work/api && ${TOOLS} agent-run --agent claude --quiet -- bash -c 'echo "work=\$CLAUDE_CONFIG_DIR"; sleep 2' &
cd ~/vmlab-personal && ${TOOLS} agent-run --agent claude --quiet -- bash -c 'echo "home=\$CLAUDE_CONFIG_DIR"; sleep 2' &
wait
# ...and a way-2 agent, its profile's folder bound over the home's
mkdir -p ~/.cursor && touch ~/.cursor/vmlab-home-file
cd ~/vmlab-work/api && ${TOOLS} agent-run --agent cursor-agent --quiet -- bash -c 'touch ~/.cursor/vmlab-made; ls ~/.cursor | tr "\n" " "; echo'
echo "homecursor=\$(ls ~/.cursor | tr '\n' ' ')"
# A profile in a sandbox: its own folder writable, the home's own folder of the agent hidden
cd ~/vmlab-work/api && ${TOOLS} agent-run --agent claude --sandbox open --quiet -- bash -c 'test -e ~/.claude/vmlab && echo "sees-home-claude=yes" || echo "sees-home-claude=no"; echo x >"\$CLAUDE_CONFIG_DIR/vmlab" && echo "writes-profile=yes"'
EOF
)"
grep -q "which=vmlab-work (the folder's)" <<<"${out}" && ok "a folder picks its profile" || not_ok "a folder picks its profile" "${out}"
grep -q "work=${H}/.local/share/amethystora/agent-profiles/vmlab-work/.claude" <<<"${out}" &&
    grep -q "home=${H}/.local/share/amethystora/agent-profiles/vmlab-home/.claude" <<<"${out}" &&
    ok "two agents at once, each on its own profile" || not_ok "two agents at once, each on its own profile" "${out}"
check "a way-2 profile's folder is its own" bash -c "[[ -e ${H}/.local/share/amethystora/agent-profiles/vmlab-work/.cursor/vmlab-made && ! -e ${H}/.cursor/vmlab-made ]]"
grep -q "sees-home-claude=no" <<<"${out}" && ok "sandboxed on a profile, the home's own Claude folder is hidden" ||
    not_ok "sandboxed on a profile, the home's own Claude folder is hidden" "${out}"
grep -q "writes-profile=yes" <<<"${out}" && ok "sandboxed on a profile, its own profile is writable" ||
    not_ok "sandboxed on a profile, its own profile is writable" "${out}"
if ! as_account "${TOOLS}" profile in-use vmlab-home >/dev/null; then
    ok "a profile no session runs on is free to remove"
else
    not_ok "a profile no session runs on is free to remove"
fi
# The reader and the watcher's rules look into a profile
mkdir -p "${H}/.local/share/amethystora/agent-profiles/vmlab-work/.claude"
echo '{"permissions": {"defaultMode": "bypassPermissions"}}' >"${H}/.local/share/amethystora/agent-profiles/vmlab-work/.claude/settings.json"
echo '{}' >"${H}/.local/share/amethystora/agent-profiles/vmlab-work/.claude/.credentials.json"
chown -R "${TEST_USER}:" "${H}/.local/share/amethystora/agent-profiles"
check "the security reader reads a profile's settings and names it" bash -c "
    runuser -u ${TEST_USER} -- env HOME=${H} /usr/libexec/amethystora-security-reader agent-config | grep -q 'agent-profiles/vmlab-work/.claude/settings.json turns'"
# Each table login, under every profile, as the watcher's rules glob it, finds the one planted there
found=""
while read -r login; do
    for file in "${H}"/.local/share/amethystora/agent-profiles/*/${login}; do [[ -f ${file} ]] && found+="${file} "; done
done < <(awk '$1 == "login" { print $3 }' /usr/share/amethystora/agent-paths)
if [[ ${found} == *vmlab-work/.claude/.credentials.json* ]] && grep -q 'agent-profiles/\*/' /usr/libexec/amethystora-audit-home-rules; then
    ok "the watcher's credential rules take a profile's login"
else
    not_ok "the watcher's credential rules take a profile's login" "${found}"
fi
# The shells' hook
out="$(user_script hook <<'EOF'
ame agent hook on >/dev/null
cd ~/vmlab-work/api && bash -ic 'echo "bash=$CLAUDE_CONFIG_DIR $(type -t claude)"' 2>/dev/null | tail -n 1
cd ~/vmlab-work/api && zsh -ic 'echo "zsh=$CLAUDE_CONFIG_DIR"' 2>/dev/null | tail -n 1
cd ~/vmlab-work/api && fish -ic 'echo "fish=$CLAUDE_CONFIG_DIR"' 2>/dev/null | tail -n 1
ame agent hook off >/dev/null
cd ~/vmlab-work/api && bash -ic 'echo "off=${CLAUDE_CONFIG_DIR:-none}"' 2>/dev/null | tail -n 1
EOF
)"
for shell in bash zsh fish; do
    grep -q "${shell}=${H}/.local/share/amethystora/agent-profiles/vmlab-work/.claude" <<<"${out}" &&
        ok "the hook in ${shell} follows the folder" || not_ok "the hook in ${shell} follows the folder" "${out}"
done
grep -q "bash=.* function" <<<"${out}" && ok "the hook wraps an agent's command" || not_ok "the hook wraps an agent's command" "${out}"
grep -q "off=none" <<<"${out}" && ok "off, the hook does nothing" || not_ok "off, the hook does nothing" "${out}"
# Profiles fail closed, with a stand-in claude that says what it was given: a key from the shell never reaches a launch on
# another profile, a folder whose profile is gone starts nothing, and with the hook on a profile given to the folder holds
# for the next command typed there, with no cd
out="$(user_script failclosed <<'EOF'
mkdir -p ~/vmlab-bin ~/vmlab-later ~/vmlab-gone
printf '#!/usr/bin/bash\necho "standin=${AMETHYSTORA_AGENT_NAME:-plain} key=${ANTHROPIC_API_KEY:-none} dir=${CLAUDE_CONFIG_DIR:-none}"\n' >~/vmlab-bin/claude
chmod 0755 ~/vmlab-bin/claude
export PATH=~/vmlab-bin:${PATH}
cd ~/vmlab-work/api && ANTHROPIC_API_KEY=vmlab-key /usr/libexec/amethystora-agent-tools agent-run --agent claude --quiet -- claude | sed 's/^/work-/'
cd ~/vmlab-later && ANTHROPIC_API_KEY=vmlab-key /usr/libexec/amethystora-agent-tools agent-run --agent claude --quiet -- claude | sed 's/^/home-/'
ame agent profile add vmlab-gone >/dev/null
ame agent profile use vmlab-gone ~/vmlab-gone >/dev/null
rm -rf ~/.local/share/amethystora/agent-profiles/vmlab-gone
cd ~/vmlab-gone && /usr/libexec/amethystora-agent-tools agent-run --agent claude --quiet -- claude 2>&1 | sed 's/^/gone-/'
echo "gone-status=${PIPESTATUS[0]}"
# A hooked shell that goes from a profile's folder into one whose profile is gone keeps nothing of the last one's account, and
# keeps a CLAUDE_CONFIG_DIR of the person's own
ame agent hook on >/dev/null
cd ~/vmlab-work/api && bash -ic 'echo "stale-before=${CLAUDE_CONFIG_DIR:-none}"; cd ~/vmlab-gone; __amethystora_agent_follow
echo "stale-dir=${CLAUDE_CONFIG_DIR:-none} profile=${AMETHYSTORA_AGENT_PROFILE:-none}"
export CLAUDE_CONFIG_DIR=~/vmlab-mine; __amethystora_agent_follow; echo "stale-own=${CLAUDE_CONFIG_DIR:-none}"' 2>/dev/null | grep "^stale-"
ame agent hook off >/dev/null
ame agent profile use default ~/vmlab-gone >/dev/null
ame agent hook on >/dev/null
cd ~/vmlab-later && bash -ic 'PATH=~/vmlab-bin:${PATH}; export ANTHROPIC_API_KEY=vmlab-key
claude | sed "s/^/before-/"
ame agent profile use vmlab-work . >/dev/null
claude | sed "s/^/after-/"
ame agent profile use default . >/dev/null' 2>/dev/null
ame agent hook off >/dev/null
rm -rf ~/vmlab-bin ~/vmlab-later ~/vmlab-gone
EOF
)"
WORK_CLAUDE="${H}/.local/share/amethystora/agent-profiles/vmlab-work/.claude"
grep -qx "work-standin=claude key=none dir=${WORK_CLAUDE}" <<<"${out}" &&
    ok "a key from the shell is not given to a launch on another profile" || not_ok "a key from the shell is not given to a launch on another profile" "${out}"
grep -qx "home-standin=claude key=vmlab-key dir=none" <<<"${out}" &&
    ok "the home's profile keeps the shell's key" || not_ok "the home's profile keeps the shell's key" "${out}"
grep -qx "gone-status=2" <<<"${out}" && grep -q "^gone-.*ame agent profile use default" <<<"${out}" && ! grep -q "^gone-standin" <<<"${out}" &&
    ok "a folder on a removed profile starts nothing" || not_ok "a folder on a removed profile starts nothing" "${out}"
grep -qx "stale-before=${WORK_CLAUDE}" <<<"${out}" && grep -qx "stale-dir=none profile=?" <<<"${out}" && grep -qx "stale-own=${H}/vmlab-mine" <<<"${out}" &&
    ok "a hooked shell in a folder on a removed profile keeps nothing of the last folder's account" ||
    not_ok "a hooked shell in a folder on a removed profile keeps nothing of the last folder's account" "${out}"
grep -qx "before-standin=claude key=vmlab-key dir=none" <<<"${out}" && grep -qx "after-standin=claude key=none dir=${WORK_CLAUDE}" <<<"${out}" &&
    ok "with the hook on, a profile given to the folder holds for the next typed command" ||
    not_ok "with the hook on, a profile given to the folder holds for the next typed command" "${out}"

# --- SANDBOX=always -----------------------------------------------------------------------------------------------------
echo "SANDBOX=always" >>"${CONF}"
out="$(user_script always <<EOF
cd ~/vmlab-code/site && ${TOOLS} agent-plan --agent claude --dir . | jq -r .sandbox
cd ~/vmlab-code/site && ${TOOLS} agent-plan --agent claude --sandbox no --dir . >/dev/null 2>&1; echo "no=\$?"
cd ~ && ${TOOLS} agent-plan --agent claude --dir . | jq -r '.sandbox // "plain"'
EOF
)"
cp -a "${OWN}/agent.conf.before" "${CONF}" 2>/dev/null || sed -i '/^SANDBOX=always$/d' "${CONF}"
[[ "$(sed -n 1p <<<"${out}")" == open ]] && ok "SANDBOX=always sandboxes a launch in a project" || not_ok "SANDBOX=always sandboxes a launch in a project" "${out}"
grep -q "no=2" <<<"${out}" && ok "SANDBOX=always refuses --no-sandbox in a project" || not_ok "SANDBOX=always refuses --no-sandbox in a project" "${out}"
[[ "$(sed -n 3p <<<"${out}")" == plain ]] && ok "SANDBOX=always leaves a launch from the home plain" || not_ok "SANDBOX=always leaves a launch from the home plain" "${out}"

# Everything put back
user_script cleanup <<'EOF' >/dev/null
rm -rf ~/vmlab-code ~/vmlab-work ~/vmlab-personal ~/.ssh/id_vmlab ~/.cursor/vmlab-home-file ~/.claude/vmlab
rm -rf ~/.local/share/amethystora/agent-profiles/vmlab-work ~/.local/share/amethystora/agent-profiles/vmlab-home
rm -f ~/.config/amethystora/agent-profiles.json ~/.config/amethystora/agent-sandbox.json ~/.config/amethystora/agent-hook
EOF
finish
