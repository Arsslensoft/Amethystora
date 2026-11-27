# shellcheck shell=bash
# The shells follow the folder for the AI agent (ame agent hook, plans/done/PLAN-agent-accounts.md and PLAN-agent-sandbox.md):
# before each prompt, claude's and codex's own variables point at the folder's profile and the prompt says the profile and
# whether the folder is sandboxed, from the maps as they are then (one small program a prompt). Each agent's command typed
# here goes through amethystora-agent-tools agent-run, which works the profile and the sandbox out again as it starts: a rule
# or a profile given to this folder holds for the next command without a cd, and a map that cannot be read, or a folder whose
# profile is gone, stops the launch instead of starting it on the home's account. A convenience, not a lock: `command claude`
# goes round it. Off, nothing here runs but the test below. Sourced by /etc/profile.d/92-amethystora-agent-hook.sh (bash)
# and by /etc/zsh/zshrc (zsh); fish has its own, /usr/share/fish/vendor_conf.d/amethystora-agent-hook.fish.
[[ $- == *i* && -e ${XDG_CONFIG_HOME:-${HOME}/.config}/amethystora/agent-hook ]] || return 0

__amethystora_agent_warning=
__amethystora_agent_said=
__amethystora_agent_follow() {
    # The last command's status is the prompt's to show, never ours
    local __amethystora_agent_code=$?
    # What it prints is our own export and unset lines, each value quoted, and in __amethystora_agent_warning what could not
    # be worked out (the prompt then says agent ?), said here once until it changes
    eval "$(/usr/libexec/amethystora-agent-tools profile env --shell bash --dir "${PWD}" 2>/dev/null)"
    if [[ -n ${__amethystora_agent_warning} && ${__amethystora_agent_warning} != "${__amethystora_agent_said}" ]]; then
        printf 'ame agent: %s\n' "${__amethystora_agent_warning}" >&2
    fi
    __amethystora_agent_said="${__amethystora_agent_warning}"
    return "${__amethystora_agent_code}"
}

# An agent typed here: always through agent-run, which starts it plain when the folder has neither a profile nor a sandbox
# rule, and refuses when what it needs cannot be read
__amethystora_agent_run() {
    local name="$1"
    shift
    /usr/libexec/amethystora-agent-tools agent-run --agent "${name}" -- "${name}" "$@"
}
claude() { __amethystora_agent_run claude "$@"; }
codex() { __amethystora_agent_run codex "$@"; }
opencode() { __amethystora_agent_run opencode "$@"; }
agy() { __amethystora_agent_run agy "$@"; }
copilot() { __amethystora_agent_run copilot "$@"; }
cursor-agent() { __amethystora_agent_run cursor-agent "$@"; }

# This shell on one profile wherever it goes (agent-profile NAME), back to the folder's (agent-profile off), or which (alone)
agent-profile() {
    case "${1:-}" in
        "") echo "${AMETHYSTORA_AGENT_PROFILE:-default}" ;;
        off) unset AMETHYSTORA_AGENT_PROFILE_PIN ;;
        *)
            if [[ $1 != default ]] && ! /usr/libexec/amethystora-agent-tools profile root "$1" >/dev/null 2>&1; then
                echo "there is no profile $1 (ame agent profile list)" >&2
                return 1
            fi
            export AMETHYSTORA_AGENT_PROFILE_PIN="$1"
            ;;
    esac
    __amethystora_agent_follow
}

if [[ -n ${BASH_VERSION:-} ]]; then
    # First, so that the prompt (starship) sees the folder's profile; at every prompt, so that it never shows one gone stale
    PROMPT_COMMAND=(__amethystora_agent_follow "${PROMPT_COMMAND[@]}")
elif [[ -n ${ZSH_VERSION:-} ]]; then
    autoload -Uz add-zsh-hook
    add-zsh-hook precmd __amethystora_agent_follow
fi
__amethystora_agent_follow
