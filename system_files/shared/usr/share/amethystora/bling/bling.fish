#!/usr/bin/env fish

if status is-interactive
    test "$BLING_SOURCED" = 1; and return; or set -g BLING_SOURCED 1

    function __bling_abbr -d "Create an abbreviation or alias"
        test "$BLING_USE_ABBR" != 0; and abbr -a $argv; or alias $argv
    end

    # Homebrew's folder belongs to one account, so everything in it is that account's program (amethystora-brew.fish).
    # Any other account uses a tool only from outside it, and runs nothing from it by opening a shell.
    function __bling_has -d "A tool this account may use"
        type -q $argv[1]; or return 1
        test -O /home/linuxbrew/.linuxbrew; and return 0
        string match -q -- "/home/linuxbrew/.linuxbrew/*" "$(type -p $argv[1])"; and return 1
        return 0
    end

    # ls aliases
    if __bling_has eza
        __bling_abbr ll 'eza -l --icons=auto --group-directories-first'
        __bling_abbr l. 'eza -d .*'
        __bling_abbr ls 'eza'
        __bling_abbr l1 'eza -1'
    end

    # ugrep for grep
    if __bling_has ug
        __bling_abbr grep 'ug'
        __bling_abbr egrep 'ug -E'
        __bling_abbr fgrep 'ug -F'
        __bling_abbr xzgrep 'ug -z'
        __bling_abbr xzegrep 'ug -zE'
        __bling_abbr xzfgrep 'ug -zF'
    end

    # bat for cat
    if __bling_has bat
        __bling_abbr cat 'bat --style=plain --pager=never'
    end

    __bling_has direnv; and direnv hook fish | source

    # Atuin shell integration is disabled by default
    # The atuin binary is still installed and available for manual use
    # To enable shell integration, uncomment the following line or add it to your config.fish:
    # type -q atuin; and atuin init fish $ATUIN_INIT_FLAGS | source

    __bling_has starship; and starship init fish | source

    __bling_has zoxide; and zoxide init fish | source

    __bling_has mise; and test "$MISE_FISH_AUTO_ACTIVATE" != 0; and mise activate fish | source

    functions -e __bling_has
end
