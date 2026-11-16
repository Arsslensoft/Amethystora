#!/usr/bin/bash
# `ame apps kit` (/usr/libexec/amethystora-kit) and the kits it names (/usr/share/amethystora/kits), for 20-tests.sh.
# Every kit is a setup file with its apps part only, which amethystora-setup's own check reads, plus an about file that
# gives it a name, what it is for, and a name and a reason for each app: the two name the same apps, 5 to 10 of them, from
# Flathub alone, with nothing else in the setup file. Against stand-ins for flatpak, Homebrew and GNOME (as test-setup.sh
# has them): list and show say what a kit holds and touch nothing, add shows, asks and installs exactly the kit's list in
# one flatpak call and nothing else, with no terminal or a no it installs nothing, remove asks about each of the kit's apps
# that is installed and never about another, a kit with a key the format does not know or a name that is no app is
# refused before anything runs, and a name that is no kit's is refused.
#
#   test-kits.sh [HELPER [SETUP [KITS_DIR]]]

set -euo pipefail

HELPER="${1:-/usr/libexec/amethystora-kit}"
SETUP="${2:-/usr/libexec/amethystora-setup}"
KITS="${3:-/usr/share/amethystora/kits}"
T="$(mktemp -d)"
trap 'rm -rf "${T}"' EXIT
mkdir -p "${T}/bin" "${T}/home"
export HOME="${T}/home" XDG_CONFIG_HOME="${T}/home/.config" XDG_DATA_HOME="${T}/home/.local/share"
export XDG_STATE_HOME="${T}/home/.local/state"
export PATH="${T}/bin:${PATH}" LOG="${T}/log" STATE="${T}/state" YES="${T}/yes"
export AMETHYSTORA_KITS="${KITS}" AMETHYSTORA_SETUP="${SETUP}" AMETHYSTORA_UNINSTALL="${T}/bin/amethystora-uninstall"
export LANGUAGE=C LC_ALL=C
: >"${LOG}"
: >"${STATE}"
: >"${YES}"

fail() {
    echo "kits: $*" >&2
    exit 1
}

# --- The kits' files ---------------------------------------------------------------------------------------------------

mapfile -t ids < <(find "${KITS}" -maxdepth 1 -name '*.json' -printf '%f\n' | sed 's/\.json$//' | sort)
[[ ${#ids[@]} -ge 7 ]] || fail "fewer than the seven kits: ${ids[*]}"
# The first seven are the plan's; a maintainer may add more
for id in electronics cad-3d-printing music-production streaming game-development data-science security-lab; do
    [[ -f "${KITS}/${id}.json" && -f "${KITS}/about/${id}.json" ]] || fail "the kit ${id} is missing"
done
# Every file of about/ belongs to a kit
for file in "${KITS}"/about/*.json; do
    [[ -f "${KITS}/$(basename "${file}")" ]] || fail "$(basename "${file}") in about has no kit"
done
for id in "${ids[@]}"; do
    [[ "${id}" =~ ^[a-z][a-z0-9-]*$ ]] || fail "${id} is not a kit's name"
    # The setup file: version 1, flatpaks.system and nothing else, each app from Flathub, sorted, 5 to 10, no repeat
    jq -e '(keys == ["flatpaks", "version"]) and .version == 1 and (.flatpaks | keys == ["system"])
        and (.flatpaks.system | length >= 5 and length <= 10 and (map(.app) | (. == sort) and (unique | length) == length)
            and all(.[]; keys == ["app", "origin"] and .origin == "flathub"
                and (.app | test("^[A-Za-z][A-Za-z0-9_-]*([.][A-Za-z0-9_-]+)+$"))))' "${KITS}/${id}.json" >/dev/null ||
        fail "${id}.json is not a setup file with the apps of one to ten Flathub apps and nothing else"
    # Its words: a name, what it is for, and a name and a reason for each app, the apps the setup file's
    jq -e --slurpfile setup "${KITS}/${id}.json" '(keys == ["apps", "description", "name"])
        and (.name | type == "string" and length > 0 and length <= 40) and (.description | type == "string" and length > 0 and length <= 120)
        and (.apps | all(.[]; keys == ["app", "name", "why"] and (.name | length > 0 and length <= 40) and (.why | length > 0 and length <= 120)))
        and ([.apps[].app] | sort) == ($setup[0].flatpaks.system | map(.app) | sort)' "${KITS}/about/${id}.json" >/dev/null ||
        fail "about/${id}.json does not name the same apps as ${id}.json, or a name or a reason is missing or long"
    # The words go through gettext as they are, in the list's fast path and in a shell: no quote, dollar, backquote or backslash,
    # and no em dash
    jq -r '.name, .description, .apps[].name, .apps[].why' "${KITS}/about/${id}.json" | grep -q '["$`\\—]' &&
        fail "about/${id}.json has a quote, a dollar, a backquote, a backslash or an em dash in its words"
    # A kit changes nothing but the apps: no key but those two, no address, no script
    grep -qiE 'https?://|brew|settings|containers|extensions|theme' "${KITS}/${id}.json" && fail "${id}.json names more than apps"
done
# No app twice in a kit and none that is not on the preinstall list of another kind (a Gtk theme is no app)
[[ -z "$(jq -r '.flatpaks.system[].app' "${KITS}"/*.json | grep -E 'Gtk3theme|Platform|Sdk')" ]] || fail "a kit names a runtime or a theme"

# --- Stand-ins ---------------------------------------------------------------------------------------------------------

cat >"${T}/bin/stub" <<'EOF'
#!/usr/bin/bash
case "${0##*/}" in
    flatpak)
        case "$*" in
            "list --app --columns=application,installation") cat "${STATE}" ;;
            "list --system --app --columns=application,origin") awk -F'\t' '$2 == "system" { print $1 "\tflathub" }' "${STATE}" ;;
            "list --user --app --columns=application,origin") awk -F'\t' '$2 == "user" { print $1 "\tflathub" }' "${STATE}" ;;
            "remotes --system --columns=name") echo flathub ;;
            remotes*) ;;
            "install --system --noninteractive flathub "*)
                echo "flatpak $*" >>"${LOG}"
                shift 4
                for app in "$@"; do printf '%s\tsystem\n' "${app}" >>"${STATE}"; done
                ;;
            *) echo "flatpak $*" >>"${LOG}" ;;
        esac
        ;;
    gum)
        echo "gum $*" >>"${LOG}"
        while IFS= read -r word; do
            [[ -z "${word}" ]] || case "$*" in *"${word}"*) exit 0 ;; esac
        done <"${YES}"
        exit 1
        ;;
    amethystora-uninstall)
        echo "uninstall $*" >>"${LOG}"
        awk -F'\t' -v id="$2" '$1 != id' "${STATE}" >"${STATE}.new"
        mv "${STATE}.new" "${STATE}"
        ;;
    gsettings | dconf | gnome-extensions | brew | amethystora-theme | amethystora-pkg)
        # What only reads says what an empty machine says; anything that sets, installs, enables or makes is logged
        case "$*" in
            "containers list --json" | "templates list --json" | "managers list --json") echo '[]' ;;
            get* | range* | list* | read* | "bundle dump --file=-" | current | --version) ;;
            *) echo "${0##*/} $*" >>"${LOG}.other" ;;
        esac
        ;;
    *) echo "${0##*/} $*" >>"${LOG}" ;;
esac
EOF
chmod +x "${T}/bin/stub"
for command in flatpak gum amethystora-uninstall gsettings dconf gnome-extensions brew amethystora-theme amethystora-pkg; do
    ln -s stub "${T}/bin/${command}"
done
# What a person at a terminal sees, and answers through the stand-in gum
in_terminal() {
    python3 -I -c 'import os, pty, sys; sys.exit(os.waitstatus_to_exitcode(pty.spawn(sys.argv[1:])))' "$@" </dev/null | tr -d '\r'
}
reset() {
    : >"${LOG}"
    : >"${STATE}"
    : >"${YES}"
}
ELECTRONICS="$(jq -r '.flatpaks.system[].app' "${KITS}/electronics.json" | xargs)"

# --- list and show say, and touch nothing --------------------------------------------------------------------------------

out="$("${HELPER}" list)"
for id in "${ids[@]}"; do
    grep -q "^${id} " <<<"${out}" || fail "list does not name ${id}"
done
grep -q "^electronics .*Electronics" <<<"${out}" || fail "list does not say the name of electronics: ${out}"
[[ "$("${HELPER}" list --json | jq -r 'map(.id) | join(" ")')" == "${ids[*]}" ]] || fail "list --json does not name the kits"
out="$("${HELPER}" show electronics)"
for app in ${ELECTRONICS}; do
    grep -qF "(${app})" <<<"${out}" || fail "show does not name ${app}"
done
grep -q "KiCad (org.kicad.KiCad)" <<<"${out}" && grep -q "Schematics, circuit boards" <<<"${out}" || fail "show does not give an app's name and reason: ${out}"
grep -q "ame apps kit add electronics" <<<"${out}" || fail "show does not say how to add it"
[[ "$("${HELPER}" show electronics --json | jq -r '.apps | map(.app) | join(" ")')" == "${ELECTRONICS}" ]] || fail "show --json"
# ...and says which are installed
printf 'org.kicad.KiCad\tsystem\n' >"${STATE}"
out="$("${HELPER}" show electronics)"
grep -q "KiCad (org.kicad.KiCad), installed" <<<"${out}" || fail "show does not mark an installed app"
[[ "$("${HELPER}" list | grep -A2 '^electronics ' | tail -1)" == *"1 of them installed here"* ]] || fail "list does not count what is installed"
[[ ! -s "${LOG}" ]] || fail "list or show called something that changes a machine: $(cat "${LOG}")"
reset

# A name that is no kit's, or none, or one that reads as an option, is refused before anything runs
for bad in nonesuch ../electronics -x 'electronics;id' ELECTRONICS ''; do
    if "${HELPER}" show "${bad}" >/dev/null 2>&1; then fail "show took ${bad}"; fi
    if "${HELPER}" add "${bad}" >/dev/null 2>&1; then fail "add took ${bad}"; fi
done
"${HELPER}" >/dev/null 2>&1 && fail "no command is a command"
[[ $("${HELPER}" show 2>/dev/null; echo $?) == 64 ]] || fail "show without a kit is a usage error (64)"
[[ ! -s "${LOG}" ]] || fail "a refused name called something: $(cat "${LOG}")"

# --- add: shows, asks, installs the kit's list and nothing else -------------------------------------------------------------

# With no terminal there is no question to ask, so nothing is installed; --yes is not taken
if "${HELPER}" add electronics </dev/null >"${T}/out" 2>&1; then fail "add went ahead without a terminal"; fi
grep -q "needs a terminal" "${T}/out" || fail "add without a terminal does not say why: $(cat "${T}/out")"
if "${HELPER}" add electronics --yes >/dev/null 2>&1; then fail "add took --yes"; fi
! grep -q '^flatpak install' "${LOG}" || fail "something was installed without a terminal"
reset

# A no installs nothing, and the list was shown first (the machine has an app of its own, which the kit does not mention)
printf 'org.gnome.Calculator\tsystem\n' >"${STATE}"
out="$(in_terminal "${HELPER}" add electronics)"
grep -q "KiCad (org.kicad.KiCad)" <<<"${out}" || fail "add did not show the apps first: ${out}"
grep -q "Schematics, circuit boards" <<<"${out}" || fail "add did not show why an app is there"
grep -q '^gum confirm.*Go ahead' "${LOG}" || fail "the person was not asked: $(cat "${LOG}")"
! grep -q '^flatpak install' "${LOG}" || fail "installed after a no"
grep -q "Left as they are" <<<"${out}" && fail "add talks about the rest of the machine: ${out}"
reset

# A yes installs exactly the kit's apps, from Flathub, in one call, and touches nothing else
printf 'org.gnome.Calculator\tsystem\n' >"${STATE}"
echo "Go ahead" >"${YES}"
out="$(in_terminal "${HELPER}" add electronics)"
[[ "$(grep -c '^flatpak ' "${LOG}")" == 1 ]] || fail "add made other calls than one install: $(cat "${LOG}")"
[[ "$(sed -n 's/^flatpak install --system --noninteractive flathub //p' "${LOG}")" == "${ELECTRONICS}" ]] ||
    fail "add did not install exactly the kit's apps: $(cat "${LOG}")"
! grep -qE 'uninstall|--remove' "${LOG}" || fail "add took something away: $(cat "${LOG}")"
[[ ! -e "${LOG}.other" ]] || fail "add set or installed something besides apps: $(cat "${LOG}.other")"
[[ -z "$(find "${HOME}" -type f)" ]] || fail "add wrote a file: $(find "${HOME}" -type f)"
grep -q "^Done" <<<"${out}" || fail "add did not say it was done: ${out}"
grep -q "Left as they are" <<<"${out}" && fail "add talks about the rest of the machine: ${out}"
# A second time there is nothing to do
: >"${LOG}"
out="$(in_terminal "${HELPER}" add electronics)"
grep -q "^Nothing to do" <<<"${out}" || fail "a kit added twice was not left alone: ${out}"
! grep -q '^flatpak install' "${LOG}" || fail "an installed kit was installed again"
# An app installed already is not asked for again, and the rest of the kit still comes
reset
printf 'org.kicad.KiCad\tuser\n' >"${STATE}"
echo "Go ahead" >"${YES}"
in_terminal "${HELPER}" add electronics >/dev/null
[[ "$(sed -n 's/^flatpak install --system --noninteractive flathub //p' "${LOG}")" == "$(sed 's/org.kicad.KiCad //; s/ org.kicad.KiCad$//' <<<"${ELECTRONICS}")" ]] ||
    fail "add installed an app that was installed already, or left one out: $(cat "${LOG}")"
reset

# --- remove: each of the kit's apps that is installed, asked about on its own ------------------------------------------------

out="$(in_terminal "${HELPER}" remove electronics)"
grep -q "None of this kit's apps is installed" <<<"${out}" || fail "remove of an absent kit: ${out}"
printf 'org.kicad.KiCad\tsystem\ncc.arduino.IDE2\tuser\norg.gnome.Calculator\tsystem\norg.inkscape.Inkscape\tsystem\n' >"${STATE}"
if "${HELPER}" remove electronics </dev/null >/dev/null 2>&1; then fail "remove went ahead without a terminal"; fi
! grep -q '^uninstall' "${LOG}" || fail "remove took something away without a terminal"
echo "cc.arduino.IDE2" >"${YES}"
out="$(in_terminal "${HELPER}" remove electronics)"
[[ "$(grep -c '^gum confirm' "${LOG}")" == 2 ]] || fail "remove did not ask about exactly the kit's two installed apps: $(cat "${LOG}")"
grep -q "Calculator\|Inkscape" "${LOG}" && fail "remove asked about an app of no electronics kit: $(cat "${LOG}")"
[[ "$(grep '^uninstall' "${LOG}")" == "uninstall remove cc.arduino.IDE2 --user" ]] || fail "remove took away the wrong app, or not by the helper that keeps the data: $(cat "${LOG}")"
grep -q "^org.kicad.KiCad" "${STATE}" && grep -q "^org.gnome.Calculator" "${STATE}" || fail "remove took away an app that was not said yes to"
grep -q "undo-uninstall" <<<"${out}" || fail "remove does not say the data can come back: ${out}"
# Every no says so
reset
printf 'org.kicad.KiCad\tsystem\n' >"${STATE}"
out="$(in_terminal "${HELPER}" remove electronics)"
grep -q "Nothing was removed" <<<"${out}" || fail "remove after only no did not say so: ${out}"
! grep -q '^uninstall' "${LOG}" || fail "remove after a no took something away"
reset

# --- A kit that is not a setup file, or names what no kit may, is refused before anything runs --------------------------------

BAD="${T}/kits"
mkdir -p "${BAD}/about"
cp "${KITS}/electronics.json" "${BAD}/electronics.json"
cp "${KITS}/about/electronics.json" "${BAD}/about/electronics.json"
export AMETHYSTORA_KITS="${BAD}"
echo "Go ahead" >"${YES}"
for change in '. + {"unknown": 1}' '. + {"brew": {"formulae": ["ripgrep"]}}' '.flatpaks.system += [{"app": "--from=https://example.com/x.flatpakref", "origin": "flathub"}]' \
    '.flatpaks.system += [{"app": "com.example.App", "origin": "https://example.com/repo"}]' '.version = 2'; do
    jq "${change}" "${KITS}/electronics.json" >"${BAD}/electronics.json"
    out="$(in_terminal "${HELPER}" add electronics 2>&1 || true)"
    ! grep -q '^flatpak install' "${LOG}" || fail "a kit with ${change} was installed: $(cat "${LOG}")"
    # Either the helper (a kit holds apps and nothing else) or amethystora-setup's own check (what an app or a version may be)
    grep -qE "not a setup file|There is no kit" <<<"${out}" || fail "a kit with ${change} was not refused: ${out}"
    reset
done
echo "kits: ok"
