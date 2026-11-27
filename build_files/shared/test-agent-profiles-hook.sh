#!/usr/bin/bash
# Profiles that fail closed (plans/done/PLAN-agent-accounts.md: work code sent to a personal account is the mistake to prevent),
# against a stand-in home and a stand-in agent that prints what it was given, from 20-tests.sh: a key from the shell never
# reaches a launch on another profile, a folder whose profile is gone starts nothing, the hook sends every agent typed in it
# through agent-run (so a rule given to the folder holds for the next command) and says what it cannot read. Nothing here is
# wrapped: the home's profile and a profile of way 1 only set the environment, so no bubblewrap runs.
set -euo pipefail

TOOLS=/usr/libexec/amethystora-agent-tools
HOOK=/usr/share/amethystora/agent-hook/hook.sh
FISH_HOOK=/usr/share/fish/vendor_conf.d/amethystora-agent-hook.fish
fail() { echo "test-agent-profiles-hook: $*" >&2; exit 1; }

# A stand-in home, outside /tmp, taken away again with /var/lib if this made it (as test-agent-sandbox.sh does)
[[ -d /var/lib ]] && MADE_VAR_LIB=false || MADE_VAR_LIB=true
BASE=/var/lib/amethystora-agent-profiles-test
mkdir -p "${BASE}"
H="$(mktemp -d -p "${BASE}" home.XXXXXX)"
trap 'rm -rf "${BASE}"; [[ ${MADE_VAR_LIB} == false ]] || rmdir /var/lib 2>/dev/null' EXIT
export HOME="${H}" XDG_CONFIG_HOME="${H}/.config" XDG_STATE_HOME="${H}/.local/state" XDG_CACHE_HOME="${H}/.cache" XDG_RUNTIME_DIR="${H}/run"
unset AMETHYSTORA_AGENT_PROFILE AMETHYSTORA_AGENT_PROFILE_PIN AMETHYSTORA_AGENT_NAME CLAUDE_CONFIG_DIR CODEX_HOME
unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN CLAUDE_CODE_OAUTH_TOKEN OPENAI_API_KEY CODEX_API_KEY
mkdir -p "${H}/run" "${H}/work/api" "${H}/plain" "${H}/gone" "${H}/bin" "${H}/.config/amethystora"
WORK="${H}/.local/share/amethystora/agent-profiles/work/.claude"

# The stand-in agent: what it was started with. AMETHYSTORA_AGENT_NAME is set by agent-run alone, so name=claude says it went
# through agent-run
cat >"${H}/bin/claude" <<'EOF'
#!/usr/bin/bash
echo "name=${AMETHYSTORA_AGENT_NAME:-none} profile=${AMETHYSTORA_AGENT_PROFILE:-none} key=${ANTHROPIC_API_KEY:-none} dir=${CLAUDE_CONFIG_DIR:-none} args=$*"
exit 7
EOF
chmod 0755 "${H}/bin/claude"
export PATH="${H}/bin:${PATH}"
# agent-run, its status kept (the stand-in ends with 7), in DIR
run() {
    local dir="$1"
    shift
    (cd "${dir}" && "$@" "${TOOLS}" agent-run --agent claude -- claude a 'b c') || true
}

"${TOOLS}" profile add work >/dev/null
"${TOOLS}" profile use work "${H}/work" >/dev/null

# A key from the shell: never given to a launch on another profile, the person's own on the home's
got="$(run "${H}/work/api" env ANTHROPIC_API_KEY=sk-personal CLAUDE_CODE_OAUTH_TOKEN=personal)"
[[ ${got} == "name=claude profile=work key=none dir=${WORK} args=a b c" ]] || fail "a launch on work got the shell's key: ${got}"
got="$(cd "${H}/work/api" && env CLAUDE_CODE_OAUTH_TOKEN=personal "${TOOLS}" agent-run --agent claude -- bash -c 'echo "${CLAUDE_CODE_OAUTH_TOKEN:-none}"' 2>/dev/null)"
[[ ${got} == none ]] || fail "a launch on work got the shell's OAuth token: ${got}"
got="$(run "${H}/plain" env ANTHROPIC_API_KEY=sk-personal)"
[[ ${got} == "name=claude profile=default key=sk-personal dir=none args=a b c" ]] || fail "a launch on default lost the shell's key: ${got}"
# ...and the same for one asked for by name, and for the terminal's pin
got="$(run "${H}/plain" env ANTHROPIC_API_KEY=sk-personal AMETHYSTORA_AGENT_PROFILE_PIN=work)"
[[ ${got} == *" key=none "* ]] || fail "a pinned launch got the shell's key: ${got}"
got="$(cd "${H}/plain" && ANTHROPIC_API_KEY=sk-personal "${TOOLS}" agent-run --agent claude --profile work -- claude || true)"
[[ ${got} == *" key=none "* ]] || fail "a launch with --profile got the shell's key: ${got}"
# The status of the command is the agent's own, as a plain launch's
code=0
(cd "${H}/plain" && "${TOOLS}" agent-run --agent claude -- claude >/dev/null) || code=$?
[[ ${code} -eq 7 ]] || fail "the status of the agent was not its own: ${code}"

# A folder variable of the person's own is theirs on the home's profile, even in a hooked shell; one into a profile is ours
got="$(run "${H}/plain" env CLAUDE_CONFIG_DIR="${H}/mine" AMETHYSTORA_AGENT_PROFILE=default)"
[[ ${got} == *" dir=${H}/mine "* ]] || fail "the person's own CLAUDE_CONFIG_DIR was taken away: ${got}"
got="$(run "${H}/plain" env CLAUDE_CONFIG_DIR="${WORK}" AMETHYSTORA_AGENT_PROFILE=work)"
[[ ${got} == *" dir=none "* ]] || fail "a profile's CLAUDE_CONFIG_DIR reached a launch on default: ${got}"
lines="$(CLAUDE_CONFIG_DIR="${H}/mine" AMETHYSTORA_AGENT_PROFILE=default "${TOOLS}" profile env --shell bash --dir "${H}/plain")"
! grep -q "CLAUDE_CONFIG_DIR" <<<"${lines}" || fail "the hook takes away the person's own CLAUDE_CONFIG_DIR: ${lines}"
lines="$(CLAUDE_CONFIG_DIR="${WORK}" "${TOOLS}" profile env --shell bash --dir "${H}/plain")"
grep -qx "unset CLAUDE_CONFIG_DIR" <<<"${lines}" || fail "the hook leaves a profile's CLAUDE_CONFIG_DIR on default: ${lines}"

# A folder whose profile is gone (taken away by hand, so its line is still in the map) starts nothing, and says how back
"${TOOLS}" profile add old >/dev/null
"${TOOLS}" profile use old "${H}/gone" >/dev/null
rm -rf "${H}/.local/share/amethystora/agent-profiles/old"
said="$(cd "${H}/gone" && "${TOOLS}" agent-run --agent claude -- claude 2>&1)" && fail "a folder on a gone profile started: ${said}"
[[ ${said} != *name=* ]] || fail "the agent ran on a gone profile: ${said}"
[[ ${said} == *"ame agent profile use default ${H}/gone"* ]] || fail "the refusal says no way back: ${said}"
! "${TOOLS}" agent-plan --agent claude --dir "${H}/gone" >/dev/null 2>&1 || fail "the plan of a folder on a gone profile"
said="$("${TOOLS}" profile which "${H}/gone" 2>&1)" && fail "which took a gone profile: ${said}"
[[ ${said} == *"uses the profile old, which is not there any more"* ]] || fail "which does not say the profile is gone: ${said}"
lines="$("${TOOLS}" profile env --shell bash --dir "${H}/gone" 2>/dev/null)" && fail "profile env took a gone profile"
grep -qx "export AMETHYSTORA_AGENT_PROMPT='?'" <<<"${lines}" || fail "the prompt of a gone profile: ${lines}"
grep -q "^__amethystora_agent_warning='.*not there any more" <<<"${lines}" || fail "the hook's warning of a gone profile: ${lines}"
said="$("${TOOLS}" profile env --shell bash --dir "${H}/gone" 2>&1 >/dev/null)" || true
[[ ${said} == *"not there any more"* ]] || fail "profile env said nothing on standard error: ${said}"
# ...and takes away what the last folder left pointing into a profile, so that `command claude` or an IDE started there never
# works on the last folder's account; a CLAUDE_CONFIG_DIR of the person's own stays theirs
lines="$(CLAUDE_CONFIG_DIR="${WORK}" AMETHYSTORA_AGENT_PROFILE=work "${TOOLS}" profile env --shell bash --dir "${H}/gone" 2>/dev/null)" &&
    fail "profile env took a gone profile"
grep -qx "unset CLAUDE_CONFIG_DIR" <<<"${lines}" || fail "the hook leaves the last folder's CLAUDE_CONFIG_DIR on a gone profile: ${lines}"
grep -qx "export AMETHYSTORA_AGENT_PROFILE='?'" <<<"${lines}" || fail "the hook leaves the last folder's profile on a gone profile: ${lines}"
lines="$(CLAUDE_CONFIG_DIR="${WORK}" "${TOOLS}" profile env --shell fish --dir "${H}/gone" 2>/dev/null)" && fail "profile env took a gone profile"
grep -qx "set -e CLAUDE_CONFIG_DIR" <<<"${lines}" || fail "the fish hook leaves the last folder's CLAUDE_CONFIG_DIR on a gone profile: ${lines}"
lines="$(CLAUDE_CONFIG_DIR="${H}/mine" "${TOOLS}" profile env --shell bash --dir "${H}/gone" 2>/dev/null)" && fail "profile env took a gone profile"
! grep -q "CLAUDE_CONFIG_DIR" <<<"${lines}" || fail "the hook takes away the person's own CLAUDE_CONFIG_DIR on a gone profile: ${lines}"
"${TOOLS}" profile use default "${H}/gone" >/dev/null
[[ "$("${TOOLS}" profile which "${H}/gone")" == "default (the home's)" ]] || fail "the way back it says"
# ...and one removed as `ame agent profile remove` does (forget) follows the home's again
"${TOOLS}" profile add later >/dev/null
"${TOOLS}" profile use later "${H}/gone" >/dev/null
rm -rf "${H}/.local/share/amethystora/agent-profiles/later"
"${TOOLS}" profile forget later
[[ "$("${TOOLS}" profile which "${H}/gone")" == "default (the home's)" ]] || fail "a removed profile's folder"
# The pill's question never goes to the home's in place of a profile that is gone
"${TOOLS}" profile add asked >/dev/null
"${TOOLS}" profile ask asked >/dev/null
rm -rf "${H}/.local/share/amethystora/agent-profiles/asked"
! "${TOOLS}" profile ask-profile >/dev/null 2>&1 || fail "the pill's question went to the home's in place of a gone profile"
"${TOOLS}" profile ask default >/dev/null

# A map that cannot be read: said, the prompt not known, and no launch
cp "${H}/.config/amethystora/agent-profiles.json" "${H}/profiles.json"
echo "not json" >"${H}/.config/amethystora/agent-sandbox.json"
lines="$("${TOOLS}" profile env --shell fish --dir "${H}/plain" 2>/dev/null)" && fail "profile env took an unreadable map"
grep -qx "set -gx AMETHYSTORA_AGENT_PROMPT '?'" <<<"${lines}" || fail "the fish prompt of an unreadable map: ${lines}"
grep -q "^set -g __amethystora_agent_warning '.*agent-sandbox.json" <<<"${lines}" || fail "the fish warning of an unreadable map: ${lines}"
said="$(cd "${H}/plain" && "${TOOLS}" agent-run --agent claude -- claude 2>&1)" && fail "a launch with an unreadable map started: ${said}"
[[ ${said} != *name=* ]] || fail "the agent ran with an unreadable map"
echo "not json" >"${H}/.config/amethystora/agent-profiles.json"
said="$(cd "${H}/plain" && "${TOOLS}" agent-run --agent claude -- claude 2>&1)" && fail "a launch with an unreadable profile map started: ${said}"
rm "${H}/.config/amethystora/agent-sandbox.json"
mv "${H}/profiles.json" "${H}/.config/amethystora/agent-profiles.json"

# The hook, in each shell there is: every agent typed goes through agent-run, which looks at the folder as the command starts:
# a profile given to the folder holds for the next command with no cd, and the prompt follows at the next prompt
touch "${H}/.config/amethystora/agent-hook"
got="$(cd "${H}/plain" && bash --norc --noprofile -ic "source ${HOOK}
export ANTHROPIC_API_KEY=sk-personal
claude a 'b c'; echo \"status=\$?\"
${TOOLS} profile use work . >/dev/null
claude
__amethystora_agent_follow; echo \"prompt=\${AMETHYSTORA_AGENT_PROMPT:-none}\"
command claude
${TOOLS} profile use default . >/dev/null" 2>/dev/null)"
expected="name=claude profile=default key=sk-personal dir=none args=a b c
status=7
name=claude profile=work key=none dir=${WORK} args=
prompt=work
name=none profile=work key=sk-personal dir=${WORK} args="
[[ ${got} == "${expected}" ]] || fail "the hook in bash: ${got}"
# Its warning, said once until it changes; the agent typed then refused
echo "not json" >"${H}/.config/amethystora/agent-sandbox.json"
got="$(cd "${H}/plain" && bash --norc --noprofile -ic "source ${HOOK}
__amethystora_agent_follow; __amethystora_agent_follow
echo \"prompt=\${AMETHYSTORA_AGENT_PROMPT:-none}\"
claude || echo refused" 2>&1)"
[[ "$(grep -c "^ame agent: .*agent-sandbox.json" <<<"${got}")" -eq 1 ]] || fail "the hook's warning in bash, once: ${got}"
grep -qx "prompt=?" <<<"${got}" && grep -qx refused <<<"${got}" && ! grep -q "name=" <<<"${got}" || fail "the hook with an unreadable map: ${got}"
rm "${H}/.config/amethystora/agent-sandbox.json"
if command -v zsh >/dev/null; then
    got="$(cd "${H}/plain" && zsh -f -ic "source ${HOOK}
${TOOLS} profile use work . >/dev/null
claude
${TOOLS} profile use default . >/dev/null" 2>/dev/null)"
    [[ ${got} == "name=claude profile=work key=none dir=${WORK} args=" ]] || fail "the hook in zsh: ${got}"
fi
if command -v fish >/dev/null; then
    got="$(cd "${H}/plain" && fish --no-config -ic "source ${FISH_HOOK}
${TOOLS} profile use work . >/dev/null
claude
${TOOLS} profile use default . >/dev/null" 2>/dev/null)"
    [[ ${got} == "name=claude profile=work key=none dir=${WORK} args=" ]] || fail "the hook in fish: ${got}"
fi
rm "${H}/.config/amethystora/agent-hook"
echo "test-agent-profiles-hook: ok"
