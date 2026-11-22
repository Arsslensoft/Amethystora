#!/usr/bin/bash
# What the snapshots and the backup leave out, for 20-tests.sh, against stand-ins.
#
# amethystora-snapshot-exclude (root's): a folder left out becomes a subvolume with its files as they were, the list gains
# it, and snapshotting it again makes it a plain folder with the same files; a folder that is a link, a file, the home
# itself, the snapshots, one inside or around a folder already left out, and one a program holds are refused; only root
# changes anything, and anyone else lists their own home's folders only. The stand-in btrfs makes a "subvolume" a folder
# with a mark in it (AMETHYSTORA_SNAPSHOT_TEST), which VM suite 70 tries for real.
#
# amethystora-backup-exclude (the account's): the image's list until the first change, which copies it; a path inside the
# home or a pattern added once, removed as written, and the image's list again after reset; nothing outside the home.
#   bash test-snapshot-exclude.sh [SNAPSHOT-HELPER [BACKUP-HELPER]]

set -euo pipefail

SNAP="${1:-/usr/libexec/amethystora-snapshot-exclude}"
BACK="${2:-/usr/libexec/amethystora-backup-exclude}"
T="$(realpath "$(mktemp -d)")"
trap 'rm -rf "${T}"' EXIT
chmod 0755 "${T}"
fail() { echo "test-snapshot-exclude: $*" >&2; exit 1; }

# --- The snapshots --------------------------------------------------------------------------------------------------------------

H="${T}/home"
mkdir -p "${T}/bin" "${T}/etc" "${H}/alice/Games/Library" "${H}/alice/Docs" "${H}/.snapshots/2026-10-10_1200"
echo "save" >"${H}/alice/Games/Library/save.dat"
echo "readme" >"${H}/alice/Games/readme"
ln -s Games "${H}/alice/Link"
echo "a file" >"${H}/alice/file"
cat >"${T}/bin/btrfs" <<'EOF'
#!/usr/bin/bash
# subvolume create|delete -- PATH
[[ "$1" == subvolume && "$3" == -- ]] || exit 2
case "$2" in
    create) mkdir -- "$4" && : >"$4/.amethystora-test-subvolume" ;;
    delete) rm -rf -- "$4" ;;
    *) exit 2 ;;
esac
EOF
cat >"${T}/bin/what-uses" <<EOF
#!/usr/bin/bash
# Holds what ${T}/held names
if [[ -f "${T}/held" && "\$4" == "\$(cat "${T}/held")" ]]; then
    echo '{"targets": [], "holders": [{"pid": 7, "name": "steam", "essential": false}], "truncated": false}'
else
    echo '{"targets": [], "holders": [], "truncated": false}'
fi
EOF
chmod 0755 "${T}/bin/btrfs" "${T}/bin/what-uses"
export AMETHYSTORA_SNAPSHOT_HOMES="${H}" AMETHYSTORA_SNAPSHOT_EXCLUDES="${T}/etc/snapshot-excludes" \
    AMETHYSTORA_WHAT_USES="${T}/bin/what-uses" AMETHYSTORA_SNAPSHOT_TEST=1 PATH="${T}/bin:${PATH}"
unset SUDO_UID PKEXEC_UID

snap() { env -u SUDO_UID -u PKEXEC_UID "${SNAP}" "$@"; }
refused() {
    local want="$1"
    shift
    local said
    if said="$(snap "$@" 2>&1)"; then fail "not refused: $* (${said})"; fi
    grep -qF -- "${want}" <<<"${said}" || fail "refused for another reason: $*: ${said}"
}

[[ "$(snap list)" == "Nothing is left out of the hourly snapshots." ]] || fail "an empty list"
snap list --json | jq -e '.version == 1 and .possible and .excluded == []' >/dev/null || fail "an empty list as JSON"

snap add "${H}/alice/Games" >/dev/null || fail "leaving Games out"
[[ -e "${H}/alice/Games/.amethystora-test-subvolume" ]] || fail "Games is not a subvolume"
[[ "$(cat "${H}/alice/Games/Library/save.dat")" == save && "$(cat "${H}/alice/Games/readme")" == readme ]] || fail "Games lost its files"
[[ -z "$(find "${H}/alice" -maxdepth 1 -name '.Games.amethystora-*')" ]] || fail "the swap left something behind"
grep -qxF "${H}/alice/Games" "${T}/etc/snapshot-excludes" || fail "the list lacks Games"
[[ "$(stat -c %a "${T}/etc/snapshot-excludes")" == 644 ]] || fail "the list is not readable by the accounts"
snap list --json | jq -e --arg p "${H}/alice/Games" '.excluded == [{path: $p, rel: "alice/Games", left_out: true}]' >/dev/null ||
    fail "the list as JSON: $(snap list --json)"
[[ "$(snap add "${H}/alice/Games")" == *"already left out"* ]] || fail "leaving Games out twice"
[[ "$(grep -c "^${H}/" "${T}/etc/snapshot-excludes")" == 1 ]] || fail "Games listed twice"

refused "is inside ${H}/alice/Games" add "${H}/alice/Games/Library"
refused "goes through a link" add "${H}/alice/Link"
refused "is not a folder" add "${H}/alice/file"
refused "is not inside a home folder" add "${H}/alice"
refused "is not inside a home folder" add "${T}/etc"
refused "The snapshots themselves" add "${H}/.snapshots/2026-10-10_1200"
refused "There is no folder" add "${H}/alice/Nothing"
refused "Name a folder" add "-r"
echo "${H}/alice/Docs" >"${T}/held"
refused "Close what is using ${H}/alice/Docs first: steam" add "${H}/alice/Docs"
[[ ! -e "${H}/alice/Docs/.amethystora-test-subvolume" ]] || fail "Docs was changed while held"
rm -f "${T}/held"

# Only root changes it; anyone else reads their own home's folders
if command -v setpriv >/dev/null; then
    chmod -R a+rX "${T}"
    as_nobody() { setpriv --reuid=65534 --regid=65534 --clear-groups -- env HOME="$1" "${SNAP}" "${@:2}"; }
    if said="$(as_nobody "${H}/alice" add "${H}/alice/Docs" 2>&1)"; then fail "an account changed the list: ${said}"; fi
    grep -qF "This needs root" <<<"${said}" || fail "refused an account for another reason: ${said}"
    as_nobody "${H}/alice" list --json | jq -e '.excluded | length == 1 and .[0].rel == "Games"' >/dev/null || fail "the account's own list"
    mkdir -p "${H}/bob"
    as_nobody "${H}/bob" list --json | jq -e '.excluded == []' >/dev/null || fail "another account's folders were listed"
fi

snap remove "${H}/alice/Games" >/dev/null || fail "snapshotting Games again"
[[ ! -e "${H}/alice/Games/.amethystora-test-subvolume" ]] || fail "Games is still a subvolume"
[[ "$(cat "${H}/alice/Games/Library/save.dat")" == save ]] || fail "Games lost its files on the way back"
! grep -qxF "${H}/alice/Games" "${T}/etc/snapshot-excludes" || fail "the list still has Games"
refused "is not left out" remove "${H}/alice/Games"

# A folder listed but made a plain folder again by hand is said so, and taking it off the list changes no file
echo "${H}/alice/Docs" >>"${T}/etc/snapshot-excludes"
snap list --json | jq -e '.excluded == [{path: "'"${H}"'/alice/Docs", rel: "alice/Docs", left_out: false}]' >/dev/null || fail "a listed plain folder"
snap remove "${H}/alice/Docs" >/dev/null || fail "taking a plain folder off the list"
[[ -d "${H}/alice/Docs" ]] || fail "the plain folder went"

# --- The backup -----------------------------------------------------------------------------------------------------------------

B="${H}/bob"
mkdir -p "${B}/Videos"
printf '# The image'"'"'s\n\n**/.cache\n**/node_modules\n' >"${T}/shipped"
back() { env -u XDG_CONFIG_HOME HOME="${B}" AMETHYSTORA_BACKUP_EXCLUDES_SHIPPED="${T}/shipped" "${BACK}" "$@"; }
OWN="${B}/.config/amethystora/backup-excludes"

back list --json | jq -e '.own == false and .entries == [{pattern: "**/.cache", shipped: true}, {pattern: "**/node_modules", shipped: true}]' >/dev/null ||
    fail "the image's list: $(back list --json)"
[[ ! -e "${OWN}" ]] || fail "listing wrote a file"
back add "~/Videos" >/dev/null || fail "leaving ~/Videos out"
grep -qxF "# The image's" "${OWN}" || fail "the first change did not start from the image's list"
back list --json | jq -e --arg v "${B}/Videos" '.own and (.entries | map(.pattern) == ["**/.cache", "**/node_modules", $v])
    and (.entries[2].shipped | not)' >/dev/null || fail "the account's list: $(back list --json)"
[[ "$(back add "${B}/Videos/")" == "Already left out"* ]] || fail "leaving ~/Videos out twice"
back add '**/build' >/dev/null || fail "a pattern"
for bad in /etc "${B}/../alice" '#comment' '-x' '~' ''; do
    if back add "${bad}" >/dev/null 2>&1; then fail "added ${bad}"; fi
done
back remove '**/.cache' >/dev/null || fail "backing up the cache again"
! grep -qxF '**/.cache' "${OWN}" || fail "the cache is still left out"
grep -qxF '**/node_modules' "${OWN}" || fail "removing one pattern took another"
if back remove '**/.cache' >/dev/null 2>&1; then fail "removed a pattern twice"; fi
back reset >/dev/null
[[ ! -e "${OWN}" ]] || fail "reset kept the account's list"
back list --json | jq -e '.own == false' >/dev/null || fail "the image's list again"

echo "test-snapshot-exclude: ok"
