#!/usr/bin/bash
# What git would use outside a sandbox that a mount cannot stop (plans/done/PLAN-agent-sandbox.md, apps/agent-tools/src/gitguard.rs),
# against a stand-in home, from 20-tests.sh. The recipe is held to what it says (`sandbox show --json`): a worktree's and a
# submodule's repository are mounts of their own, a worktree's commondir and gitdir read-only, and a submodule's work tree's .git
# file (in vendor/) read-only with the folders on the way to it held in place. Where the image's build gives bubblewrap its
# namespaces, a launch is run too: a commondir, a repository in a subfolder and one in a package folder it made are named when it
# ends, a folder's escape sequence written out, the submodule's .git file not rewritten, and a launch that changed nothing of
# git's says nothing. Where it does not, tests/vm/suites/77-agent-sandbox.sh runs that.
set -euo pipefail

TOOLS=/usr/libexec/amethystora-agent-tools
fail() { echo "test-agent-gitguard: $*" >&2; exit 1; }

# A stand-in home, outside /tmp, taken away again (and /var/lib with it, where the build had none), as test-agent-sandbox.sh does
[[ -d /var/lib ]] && MADE_VAR_LIB=false || MADE_VAR_LIB=true
BASE=/var/lib/amethystora-agent-gitguard-test
mkdir -p "${BASE}"
H="$(mktemp -d -p "${BASE}" home.XXXXXX)"
trap 'rm -rf "${BASE}"; [[ ${MADE_VAR_LIB} == false ]] || rmdir /var/lib 2>/dev/null' EXIT
export HOME="${H}" XDG_CONFIG_HOME="${H}/.config" XDG_STATE_HOME="${H}/.local/state" XDG_CACHE_HOME="${H}/.cache" XDG_RUNTIME_DIR="${H}/run"
unset AMETHYSTORA_AGENT_PROFILE AMETHYSTORA_AGENT_PROFILE_PIN CLAUDE_CONFIG_DIR CODEX_HOME
SITE="${H}/code/site"
GIT="${SITE}/.git"
mkdir -p "${H}/run" "${SITE}/src" "${GIT}/hooks" "${GIT}/objects" "${GIT}/refs" "${GIT}/worktrees/wt" "${GIT}/modules/lib/hooks"
echo "ref: refs/heads/main" >"${GIT}/HEAD"
echo "[core]" >"${GIT}/config"
echo "../.." >"${GIT}/worktrees/wt/commondir"
echo "${H}/code/wt/.git" >"${GIT}/worktrees/wt/gitdir"
echo "ref: refs/heads/main" >"${GIT}/modules/lib/HEAD"
printf '[core]\n\tworktree = ../../../vendor/lib\n' >"${GIT}/modules/lib/config"
# The submodule checked out in a package folder, as git submodule add leaves it: its work tree's .git file names its repository
mkdir -p "${SITE}/vendor/lib"
printf '[submodule "lib"]\n\tpath = vendor/lib\n' >"${SITE}/.gitmodules"
echo "gitdir: ../../.git/modules/lib" >"${SITE}/vendor/lib/.git"

# The recipe: each repository folder bound in place before what is read-only in it
command="$("${TOOLS}" sandbox show --agent claude --dir "${SITE}" --sandbox open --json | jq -r .command)"
[[ ${command} == *"--bind ${GIT}/worktrees/wt ${GIT}/worktrees/wt "*"--ro-bind ${GIT}/worktrees/wt/commondir ${GIT}/worktrees/wt/commondir "* ]] ||
    fail "a worktree's repository in place, its commondir read-only: ${command}"
[[ ${command} == *"--ro-bind ${GIT}/worktrees/wt/gitdir ${GIT}/worktrees/wt/gitdir "* ]] || fail "a worktree's gitdir read-only"
[[ ${command} == *"--bind ${GIT}/modules/lib ${GIT}/modules/lib "*"--ro-bind ${GIT}/modules/lib/config ${GIT}/modules/lib/config "* ]] ||
    fail "a submodule's repository in place, its settings read-only"
[[ ${command} != *"--ro-bind ${GIT}/commondir "* ]] || fail "a commondir that is not there was bound"
# A submodule's work tree's .git file read-only, each folder on the way to it a mount of its own, bound before the repository
[[ ${command} == *"--bind ${SITE}/vendor ${SITE}/vendor "*"--bind ${SITE}/vendor/lib ${SITE}/vendor/lib "*"--bind ${GIT} ${GIT} "* ]] ||
    fail "the way to a submodule's work tree held in place, before the repository: ${command}"
[[ ${command} == *"--ro-bind ${SITE}/vendor/lib/.git ${SITE}/vendor/lib/.git "* ]] || fail "a submodule's .git file read-only: ${command}"

# A launch, where bubblewrap can make one here: what the command did to git's settings is said when it ends, by its path, with
# what a folder's name could do to the terminal written out
out="$("${TOOLS}" agent-run --agent claude --sandbox open --dir "${SITE}" --quiet -- bash -c '
echo elsewhere >.git/commondir
mkdir -p sub/.git && echo "[core]" >sub/.git/config
mkdir -p node_modules/pkg/.git && echo "[core]" >node_modules/pkg/.git/config
mkdir -p "$(printf "esc\033]0;x\007")/.git"
echo "gitdir: ../../evil" >vendor/lib/.git 2>/dev/null && touch rewrote
touch ran' 2>&1)" || true
if [[ -e ${SITE}/ran ]]; then
    for made in .git/commondir sub/.git node_modules/pkg/.git; do
        grep -qF "The sandboxed agent made ${SITE}/${made}, which git" <<<"${out}" || fail "a new ${made} was not named: ${out}"
    done
    ! grep -qF "${SITE}/sub/.git/config" <<<"${out}" || fail "a new repository was named file by file: ${out}"
    grep -qF "The sandboxed agent made ${SITE}/esc\\x1b]0;x\\x07/.git, which git" <<<"${out}" || fail "a folder's escape sequence was not written out: ${out}"
    ! grep -qF $'esc\033' <<<"${out}" || fail "a folder's escape sequence reached the terminal: ${out}"
    [[ ! -e ${SITE}/rewrote ]] || fail "the submodule's .git file could be rewritten"
    grep -qx "gitdir: ../../.git/modules/lib" "${SITE}/vendor/lib/.git" || fail "the submodule's .git file changed"
    rm -rf "${GIT}/commondir" "${SITE}/sub" "${SITE}/node_modules" "${SITE}/esc"* "${SITE}/rewrote" "${SITE}/ran"
    out="$("${TOOLS}" agent-run --agent claude --sandbox open --dir "${SITE}" --quiet -- bash -c 'echo x >src/main.rs; touch ran' 2>&1)" || true
    [[ -e ${SITE}/ran ]] || fail "the second launch did not run: ${out}"
    ! grep -qF "which git reads" <<<"${out}" || fail "a launch that changed nothing of git's said something: ${out}"
else
    echo "test-agent-gitguard: bubblewrap cannot make a sandbox here, so a launch was not run (tests/vm/suites/77-agent-sandbox.sh runs one)"
fi
echo "test-agent-gitguard: ok"
