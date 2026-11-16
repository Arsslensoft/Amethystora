#!/usr/bin/env sh

# KEEP THIS POSIX - Needs to work on Bash and ZSH

# Check if bling has already been sourced so that we dont break atuin. https://github.com/atuinsh/atuin/issues/380#issuecomment-1594014644
[ "${BLING_SOURCED:-0}" -eq 1 ] && return
BLING_SOURCED=1

# Homebrew's folder belongs to one account, so everything in it is that account's program (/etc/profile.d/brew.sh).
# Any other account uses a tool only from outside it, and runs nothing from it by opening a shell.
__bling_has() {
    __bling_found="$(command -v "$1")" || return 1
    [ -O /home/linuxbrew/.linuxbrew ] && return 0
    case "${__bling_found}" in
        /home/linuxbrew/.linuxbrew/*) return 1 ;;
    esac
    return 0
}

# ls aliases
if __bling_has eza; then
    alias ll='eza -l --icons=auto --group-directories-first'
    alias l.='eza -d .*'
    alias ls='eza'
    alias l1='eza -1'
fi

# ugrep for grep
if __bling_has ug; then
    alias grep='ug'
    alias egrep='ug -E'
    alias fgrep='ug -F'
    alias xzgrep='ug -z'
    alias xzegrep='ug -zE'
    alias xzfgrep='ug -zF'
fi

# bat for cat
if __bling_has bat; then
    alias cat='bat --style=plain --pager=never'
fi

# set ATUIN_INIT_FLAGS in your ~/.bashrc before amethystora-bling is sourced.
# Atuin allows these flags: "--disable-up-arrow" and/or "--disable-ctrl-r"
ATUIN_INIT_FLAGS="${ATUIN_INIT_FLAGS:-}"

BLING_SHELL="$(basename "$(readlink /proc/$$/exe)")"

# Initialize direnv before bash-preexec to avoid PROMPT_COMMAND conflicts
# See: https://github.com/rcaloras/bash-preexec/pull/143
if [ "${BLING_SHELL}" = "bash" ]; then
    [ -f "/etc/profile.d/bash-preexec.sh" ] && . "/etc/profile.d/bash-preexec.sh"
    [ -f "/usr/share/bash-prexec" ] && . "/usr/share/bash-prexec"
    [ -f "/usr/share/bash-prexec.sh" ] && . "/usr/share/bash-prexec.sh"
    [ -f "${HOMEBREW_PREFIX}/etc/profile.d/bash-preexec.sh" ] && . "${HOMEBREW_PREFIX}/etc/profile.d/bash-preexec.sh"
fi

__bling_has direnv && eval "$(direnv hook "${BLING_SHELL}")"
# Atuin shell integration is disabled by default
# The atuin binary is still installed and available for manual use
# To enable shell integration, uncomment the following line or add it to your shell config:
# [ "$(command -v atuin)" ] && eval "$(atuin init "${BLING_SHELL}" ${ATUIN_INIT_FLAGS})"
__bling_has starship && eval "$(starship init "${BLING_SHELL}")"
__bling_has zoxide && eval "$(zoxide init "${BLING_SHELL}")"

if __bling_has mise; then
  # Check for Bash
  if [ "${BLING_SHELL}" = "bash" ]; then
    if [ "$MISE_BASH_AUTO_ACTIVATE" != "0" ]; then
      eval "$(mise activate bash)"
    fi

    # Check for Zsh
  elif [ "${BLING_SHELL}" = "zsh" ]; then
    if [ "$MISE_ZSH_AUTO_ACTIVATE" != "0" ]; then
      eval "$(mise activate zsh)"
    fi
  fi
fi

unset -f __bling_has
unset __bling_found
