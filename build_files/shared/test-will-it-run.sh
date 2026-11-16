#!/usr/bin/bash
# amethystora-will-it-run against a fixture list: each of the list's five states and what each is told as, a game the list
# lacks, a name that only resembles an entry (shown as the closest entry and never answered), the id mode the Windows programs
# handler uses, a name from standard input, and text in the list or in the question that tries to act (escape sequences,
# new lines). Then the list the image ships: the shape its reader needs, every `game` of windows-programs.json an id in it,
# and the file the SOURCE beside its licence describes. Run by 20-tests.sh; needs jq and gettext.
set -euo pipefail

HELPER="${1:-/usr/libexec/amethystora-will-it-run}"
SHIPPED="${2:-/usr/share/amethystora/anticheat-list.json}"
MAP="${3:-/usr/share/amethystora/windows-programs.json}"
SOURCE="${4:-/usr/share/licenses/areweanticheatyet/SOURCE}"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
export LANGUAGE=C
fail() { echo "test-will-it-run: $*" >&2; exit 1; }
same() { [[ "$2" == "$3" ]] || fail "$1: expected '$3', found '$2'"; }
has() { grep -qF -- "$2" <<<"$1" || fail "$3: '$2' is not in: $1"; }
lacks() { ! grep -qF -- "$2" <<<"$1" || fail "$3: '$2' is in: $1"; }

# Text from the list goes through the security cleaner: the image's own, or a stand-in that only cuts
if [[ -x "${HELPER%/*}/amethystora-security-text" ]]; then
    export AMETHYSTORA_SECURITY_TEXT="${HELPER%/*}/amethystora-security-text"
else
    mkdir "${WORK}/bin"
    printf '#!/usr/bin/bash\nshift 2\nprintf "%%s\\n" "$*" | tr -d "\\033\\n"\n' >"${WORK}/bin/security-text"
    chmod +x "${WORK}/bin/security-text"
    export AMETHYSTORA_SECURITY_TEXT="${WORK}/bin/security-text"
fi

ESC=$'\033'
LIST="${WORK}/list.json"
export AMETHYSTORA_ANTICHEAT_LIST="${LIST}"
jq -n --arg evil "Evil ${ESC}[31mGame${ESC}]0;title"$'\a' --arg ac "Guard${ESC}[2J"$'\nFORGED LINE' '{
    source: "https://example.org", commit: "0000000000000000000000000000000000000000", updated: "2026-10-24", license: "MIT License",
    entries: [
        ["alpha", "Alpha Quest", "supported", ["Guard One"], "2024-09-02"],
        ["beta", "Beta Arena", "running", ["Guard One", "Guard Two"], "2025-01-15"],
        ["gamma", "Gamma Front", "planned", ["Guard Two"], "2025-02-01"],
        ["delta", "Delta Siege", "broken", ["Guard Three"], "2023-11-30"],
        ["epsilon", "Epsilon: Ultimate Knockout™", "denied", [], ""],
        ["zeta", "Zeta Online", "supported", ["Guard One"], "2024-1-1"],
        ["hostile", $evil, "broken", [$ac], "2024-05-05"],
        ["s%26box", "s&box", "supported", ["VAC"], "2026-01-01"],
        ["ab", "Ab", "supported", [], "2026-01-01"]
    ]}' >"${LIST}"

# Each state, by id and by name, and what it is told as
check_state() { # ID STATE ANSWER DATE WORDS
    local out
    out="$("${HELPER}" --json "$1")"
    same "${1} state" "$(jq -r .state <<<"${out}")" "$2"
    same "${1} answer" "$(jq -r .answer <<<"${out}")" "$3"
    same "${1} date" "$(jq -r '.date // "none"' <<<"${out}")" "$4"
    same "${1} match" "$(jq -r .match <<<"${out}")" exact
    out="$("${HELPER}" "$1")"
    has "${out}" "$5" "${1}'s words"
    lacks "${out}" "it will work" "${1} is never promised"
    lacks "${out}" "will run" "${1} is never promised"
}
check_state alpha supported runs 2024-09-02 "The list says it runs on Linux"
check_state beta running runs 2025-01-15 "without harm to online play"
check_state gamma planned blocked 2025-02-01 "plans to support Linux, and has not yet"
check_state delta broken blocked 2023-11-30 "does not run online on Linux"
check_state epsilon denied blocked none "will not turn its anti-cheat on for Linux"
out="$("${HELPER}" alpha)"
has "${out}" "Alpha Quest" "the name is shown"
has "${out}" "Anti-cheat: Guard One" "the anti-cheat is shown"
has "${out}" "The list changed this entry on 2024-09-02." "the entry's date is shown"
has "${out}" "This copy of the list is from 2026-10-24" "the list's date is shown"
out="$("${HELPER}" beta)"
has "${out}" "Anti-cheat: Guard One, Guard Two" "two anti-cheats"
out="$("${HELPER}" epsilon)"
has "${out}" "The list names no anti-cheat for it." "no anti-cheat named"
has "${out}" "The list gives no date for this entry." "no date given"
# A date that is not a day in the list's format is not shown
out="$("${HELPER}" --json zeta)"
same "a malformed date" "$(jq -r '.date // "none"' <<<"${out}")" none

# By name: case, spaces and punctuation set aside, several words as one name, and from standard input
same "name, upper case" "$("${HELPER}" --json "ALPHA QUEST" | jq -r .id)" alpha
same "name, no space" "$("${HELPER}" --json alphaquest | jq -r .id)" alpha
same "name, words" "$("${HELPER}" --json Beta Arena | jq -r .id)" beta
same "name with a symbol" "$("${HELPER}" --json "epsilon ultimate knockout" | jq -r .id)" epsilon
same "name, as written" "$("${HELPER}" --json "s&box" | jq -r .id)" "s%26box"
same "id, as written" "$("${HELPER}" --json "s%26box" | jq -r .id)" "s%26box"
same "name from standard input" "$(printf 'Delta Siege\n' | "${HELPER}" --json --stdin | jq -r .id)" delta
same "an id is not case-sensitive" "$("${HELPER}" --json GAMMA | jq -r .id)" gamma

# A game the list lacks: it does not say, and does not guess
out="$("${HELPER}" --json "Nonexistent Game Title")"
same "a missing entry" "$(jq -r '.match + " " + .answer' <<<"${out}")" "none unknown"
same "a missing entry's closest" "$(jq -c .closest <<<"${out}")" null
out="$("${HELPER}" "Nonexistent Game Title")"
has "${out}" "The list does not say." "a missing entry"
lacks "${out}" "closest" "no entry is close to it"

# A name that only resembles an entry: shown as the closest entry, never as the answer
out="$("${HELPER}" --json "Alph")"
same "a part of a name" "$(jq -r '.match + " " + .answer + " " + .closest.id' <<<"${out}")" "closest unknown alpha"
for field in state date anticheats name id; do
    [[ "$(jq "has(\"${field}\")" <<<"${out}")" == false ]] || fail "a closest entry carries ${field}, which only an answer does"
done
out="$("${HELPER}" "Gamma Front Online Edition")"
has "${out}" "The list does not say." "a longer name"
has "${out}" "The closest entry in the list is Gamma Front (id gamma)" "a longer name's closest entry"
lacks "${out}" "plans to support" "a closest entry is not told as an answer"
lacks "${out}" "Anti-cheat:" "a closest entry shows no anti-cheat as the answer"
# Two letters match nothing by resemblance, and a short name inside a long question is no entry
same "a short word" "$("${HELPER}" --json "ab c" | jq -r .match)" none
same "an entry of two letters, asked exactly" "$("${HELPER}" --json "ab" | jq -r .match)" exact

# The handler's mode: the id alone, silent and failing when the list lacks it, and never a resemblance
out="$("${HELPER}" --id alpha)"
has "${out}" "Alpha Quest" "--id"
[[ -z "$("${HELPER}" --id "Alpha Quest" 2>&1 || true)" ]] || fail "--id took a name"
"${HELPER}" --id nonexistent >/dev/null 2>&1 && fail "--id answered for an id the list lacks"
"${HELPER}" --id alph >/dev/null 2>&1 && fail "--id answered for a part of an id"

# Text somebody else wrote only ever reads: no control character reaches the output, in the list or in the question
for form in "" --json; do
    out="$("${HELPER}" ${form:+"${form}"} hostile)"
    [[ "${out}" != *"${ESC}"* && "${out}" != *$'\a'* ]] || fail "a control character reached the output (${form:-text})"
    if [[ "${form}" == --json ]]; then
        jq -e . <<<"${out}" >/dev/null || fail "hostile text broke the JSON"
        [[ "$(jq '.anticheats | length' <<<"${out}")" == 1 ]] || fail "the forged line became a second anti-cheat"
    else
        [[ "$(grep -c '^FORGED LINE' <<<"${out}")" == 0 ]] || fail "a forged line was shown as a line of its own"
        has "${out}" "Evil" "the name is still shown"
    fi
done
out="$("${HELPER}" "Evil${ESC}[31m ${ESC}]0;x"$'\a'"Quest")"
[[ "${out}" != *"${ESC}"* && "${out}" != *$'\a'* ]] || fail "a control character of the question reached the output"
out="$(printf 'Nothing%s[2Jhere\nsecond line' "${ESC}" | "${HELPER}" --stdin)"
[[ "${out}" != *"${ESC}"* ]] || fail "an escape from standard input reached the output"
has "${out}" "The list does not say." "a name with an escape"

# Bad calls and a list that is not there
"${HELPER}" >/dev/null 2>&1 && fail "a call with no name was answered"
"${HELPER}" --no-such-option x >/dev/null 2>&1 && fail "an unknown option was taken"
"${HELPER}" "$(printf 'x%.0s' $(seq 150))" >/dev/null 2>&1 && fail "a name of 150 characters was taken"
AMETHYSTORA_ANTICHEAT_LIST="${WORK}/missing.json" "${HELPER}" alpha >/dev/null 2>&1 && fail "a missing list was answered from"
printf '{"entries": 3}' >"${WORK}/broken.json"
AMETHYSTORA_ANTICHEAT_LIST="${WORK}/broken.json" "${HELPER}" alpha >/dev/null 2>&1 && fail "a list of the wrong shape was answered from"

# The list the image ships (skipped where there is none, as in a checkout)
if [[ -f "${SHIPPED}" ]]; then
    export AMETHYSTORA_ANTICHEAT_LIST="${SHIPPED}"
    jq -e '.source == "https://github.com/AreWeAntiCheatYet/AreWeAntiCheatYet" and (.commit | test("^[0-9a-f]{40}$")) and (.updated | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}$"))
        and (.license | startswith("MIT License")) and (.entries | length > 500 and length <= 20000)
        and all(.entries[]; length == 5 and (.[0] | type == "string" and length > 0) and (.[1] | type == "string" and length > 0)
            and (.[2] | IN("supported", "running", "planned", "broken", "denied")) and (.[3] | type == "array" and all(type == "string"))
            and (.[4] | test("^([0-9]{4}-[0-9]{2}-[0-9]{2})?$")))
        and ([.entries[][0]] | length == (unique | length))' "${SHIPPED}" >/dev/null || fail "the shipped list is not the shape its reader takes"
    (($(stat -c %s "${SHIPPED}") < 1024 * 1024)) || fail "the shipped list is past a megabyte"
    if [[ -f "${SOURCE}" ]]; then
        grep -q "$(sha256sum "${SHIPPED}" | cut -d' ' -f1)" "${SOURCE}" || fail "the shipped list is not the file its SOURCE describes"
        grep -q "$(jq -r .commit "${SHIPPED}")" "${SOURCE}" || fail "the shipped list's commit is not the one its SOURCE names"
    fi
    # A game the list is known to hold answers, one it surely lacks does not
    same "a game of the shipped list" "$("${HELPER}" --json valorant | jq -r .match)" exact
    same "a game that is not in it" "$("${HELPER}" --json "no such game zzqx" | jq -r .match)" none
    # Every game the Windows programs map names is an id of this list, and an id of its own shape
    if [[ -f "${MAP}" ]]; then
        jq -e --slurpfile list "${SHIPPED}" '[.[].game // empty] as $games | ($list[0].entries | map(.[0])) as $ids
            | all($games[]; type == "string" and test("^[a-z0-9-]+$") and IN($ids[]))' "${MAP}" >/dev/null ||
            fail "windows-programs.json names a game that is not an id of the list"
        for game in $(jq -r '.[].game // empty' "${MAP}"); do
            "${HELPER}" --id "${game}" >/dev/null || fail "--id ${game} found nothing"
        done
    fi
fi
echo "test-will-it-run: ok"
