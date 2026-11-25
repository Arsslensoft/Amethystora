#!/usr/bin/bash
# amethystora-clean-copy tells the person which kinds of hidden data it took out, from the names of the fields mat2 lists.
# Each name falls in the first kind whose patterns match it, so a broad kind tried too early hides a narrower one: a
# Word or LibreOffice file's "last modified by" is a person's name, and its "total time" is how long it was edited, so
# they are an author and edit history, never a time. Runs the real kinds() and needs no more than bash.
set -euo pipefail

CLEAN="${1:-/usr/libexec/amethystora-clean-copy}"

# FOUND and kinds(), cut out of the script by their own lines
FUNCTIONS="$(mktemp)"
trap 'rm -f "${FUNCTIONS}"' EXIT
sed -n '/^declare -A FOUND/,/^}/p' "${CLEAN}" >"${FUNCTIONS}"
# shellcheck disable=SC1090
source "${FUNCTIONS}"

kind_of() { # NAME: the kinds it is counted as, sorted
    FOUND=()
    kinds <<<"$1"
    printf '%s\n' "${!FOUND[@]}" | sort | paste -sd ' '
}
expect() { # NAME KIND
    local got
    got="$(kind_of "$1")"
    [[ "${got}" == "$2" ]] || { echo "test-clean-copy-kinds: ${1} is counted as '${got}', not '${2}'" >&2; exit 1; }
}

# Names that a broader time pattern would take
expect 'cp:lastModifiedBy' author
expect 'TotalTime' history
# Each kind still finds its own
expect 'GPSLatitude' place
expect 'Model' camera
expect 'dcterms:modified' time
expect 'CreateDate' time
expect 'meta:creation-date' time
expect 'dc:creator' author
expect 'meta:initial-creator' author
expect 'meta:editing-cycles' history
expect 'xmpMM:DocumentID' history
expect 'Producer' program
expect 'ColorSpace' ''
expect 'SomethingElse' other
echo "clean copy kinds: ok"
