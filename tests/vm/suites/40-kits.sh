#!/usr/bin/bash
# Kits (ame apps kit, plans/done/PLAN-kits.md) on a machine as a person has it: the seven kits the image names, what
# `ame apps kit list` and `show` say, Control's Kits group (a row for each kit, whose Show and Add are `ame apps kit` in a
# terminal), and one small kit of the suite's own (a single app from Flathub, which the first Flatpak suite proved reachable)
# added through the setup file's own question, found complete the second time, and taken away app by app, the app's data
# going to the trash. Each kit's Flathub IDs are the weekly workflow's (check-windows-programs.yml): the lab does not ask
# Flathub for forty-odd apps, nor install a kit's real apps. Not done here: drawing Control's rows (the rows card is
# suite 80's), and a local remote in place of Flathub, which would need the Sdk to build an app to put in it.
# vmlab-paths: @sf/usr/libexec/amethystora-kit @sf/usr/share/amethystora/kits/* @sf/usr/share/amethystora/kits/about/* @sf/usr/share/amethystora/just/apps.just @sf/usr/libexec/amethystora-control-list @sf/usr/libexec/amethystora-setup @sf/usr/libexec/amethystora-uninstall @sf/usr/share/amethystora/manual/kits.md
source "$(dirname "$0")/lib.sh"

HOME_DIR="$(realpath "$(getent passwd "${TEST_USER}" | cut -d: -f6)")"
# The kit of the suite's own is in the account's home, which the account reads (the lab's state folder is root's alone)
KITS="${HOME_DIR}/vmlab-kits"
KITS_IMAGE=/usr/share/amethystora/kits

# A terminal in the session, as Ptyxis opens one: in the account's user manager, which polkit takes for the seat's session
# (so that Flatpak installs for the machine as for the person at it), on a pseudo-terminal of its own (as 40-setup.sh does)
session_terminal() {
    local uid steps=()
    uid="$(id -u "${TEST_USER}")"
    while [[ $# -gt 0 && "$1" != -- ]]; do steps+=("$1"); shift; done
    shift
    in_terminal "${steps[@]}" -- runuser -u "${TEST_USER}" -- env XDG_RUNTIME_DIR="/run/user/${uid}" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${uid}/bus" \
        systemd-run --user --pty --wait --quiet --collect -- /usr/bin/bash -lc "$*"
}
verdict() { if [[ "$2" == 0 && -z "$3" ]]; then ok "$1"; else not_ok "$1" "exit status $2" "$3" "$(tail -n 15 <<<"$4")"; fi; }

if ! wait_for 300 has_session; then
    skip "no session for ${TEST_USER} (10-account.sh)"
    finish
fi

# --- The kits the image names ------------------------------------------------------------------------------------
IDS=(electronics cad-3d-printing music-production streaming game-development data-science security-lab)
out="$(in_session "ame apps kit list" 2>&1)"
status=$?
problems="$(for id in "${IDS[@]}"; do grep -q "^${id} " <<<"${out}" || echo "list does not name ${id}"; done)"
verdict "ame apps kit list names the seven kits, each with what it is for and how much of it is installed" "${status}" "${problems}" "${out}"
out="$(in_session "ame apps kit show electronics" 2>&1)"
status=$?
problems="$(
    for app in $(jq -r '.flatpaks.system[].app' "${KITS_IMAGE}/electronics.json"); do
        grep -qF "(${app})" <<<"${out}" || echo "show does not name ${app}"
    done
    grep -q "Schematics, circuit boards" <<<"${out}" || echo "show does not say why KiCad is there"
    grep -q "ame apps kit add electronics" <<<"${out}" || echo "show does not say how to add the kit"
)"
verdict "ame apps kit show electronics names every app of the kit, each with the reason it is there" "${status}" "${problems}" "${out}"
out="$(in_session "ame apps kit show nonesuch" 2>&1)"
status=$?
if [[ ${status} != 0 && "${out}" == *"There is no kit called nonesuch"* ]]; then
    ok "a name that is no kit's is refused, and says so"
else
    not_ok "ame apps kit show nonesuch did not refuse" "exit status ${status}" "${out}"
fi

# --- Control's Kits group ----------------------------------------------------------------------------------------
list="$(user_bus /usr/libexec/amethystora-control-list --json 2>/dev/null)"
problems="$(
    jq -e '[.items[] | select(.id == "kits" and .kind == "rows" and .page == "apps" and .group != null and .manual == "kits")] | length == 1' \
        <<<"${list}" >/dev/null 2>&1 || echo "no Kits card on the Apps page"
    for id in "${IDS[@]}"; do
        jq -e --arg id "${id}" '.items[] | select(.id == "kits") | .rows[] | select(.id == $id) | (.title | length > 0) and (.text | length > 0)
            and ([.actions[] | [.id, .terminal, .command] ] == [["show", true, ["ame", "apps", "kit", "show", $id]],
                ["add", true, ["ame", "apps", "kit", "add", $id]]])' <<<"${list}" >/dev/null 2>&1 || echo "no row for ${id}, with Show and Add in a terminal"
    done
)"
verdict "Control's list has a Kits card with a row for each kit, whose Show and Add are ame apps kit in a terminal" 0 "${problems}" ""

# --- One small kit, added, found complete, and taken away ---------------------------------------------------------------
# An app that is small and on a runtime the default apps brought already, so that only it downloads (as 40-setup.sh picks)
runtimes="$(flatpak list --system --runtime --columns=ref)"
APP=""
for candidate in org.gnome.Sudoku org.gnome.Mahjongg org.gnome.Tetravex org.gnome.Mines org.gnome.design.Palette; do
    flatpak info --system "${candidate}" >/dev/null 2>&1 && continue
    runtime="$(LC_ALL=C flatpak remote-info --system flathub "${candidate}" 2>/dev/null | sed -n 's/^ *Runtime: //p')"
    [[ -n "${runtime}" ]] && grep -qxF "${runtime}" <<<"${runtimes}" && { APP="${candidate}"; break; }
done
if [[ -z "${APP}" ]]; then
    skip "adding a kit: no small app on Flathub shares a runtime installed here, or Flathub is not reachable"
    finish
fi
echo "# the app of the suite's own kit: ${APP}"
mkdir -p "${KITS}/about"
jq -n --arg app "${APP}" '{version: 1, flatpaks: {system: [{app: $app, origin: "flathub"}]}}' >"${KITS}/small.json"
jq -n --arg app "${APP}" '{name: "Small", description: "One small app, for the lab.", apps: [{app: $app, name: "The app", why: "It is small."}]}' >"${KITS}/about/small.json"
chown -R "${TEST_USER}:" "${KITS}"
RUN="AMETHYSTORA_KITS=${KITS}"

out="$(in_session "${RUN} ame apps kit add small" 2>&1)"
status=$?
if [[ ${status} != 0 && "${out}" == *"needs a terminal"* ]] && ! flatpak info --system "${APP}" >/dev/null 2>&1; then
    ok "without a terminal, add shows the kit, asks nothing and installs nothing"
else
    not_ok "add without a terminal went on, or did not say why" "exit status ${status}" "${out}"
fi
start=${SECONDS}
out="$(session_terminal 900 'Go ahead\?' y -- "${RUN} ame apps kit add small")"
status=$?
echo "# ame apps kit add took $((SECONDS - start)) s, with ${APP} to download"
problems="$(
    grep -qF "The app (${APP})" <<<"${out}" || echo "it did not show the app first"
    grep -q "It is small." <<<"${out}" || echo "it did not show why the app is there"
    grep -qx "  + the app ${APP}, from flathub" <<<"${out}" || echo "setup's list did not name the app"
    grep -q "^Done\." <<<"${out}" || echo "it did not say it was done"
    grep -q "Left as they are" <<<"${out}" && echo "it spoke of the rest of the machine"
)"
verdict "ame apps kit add shows the app and why, then the list of ame setup apply, asks, and installs" "${status}" "${problems}" "${out}"
check "${APP} is installed for the machine, from flathub" flatpak info --system "${APP}"
out="$(in_session "${RUN} ame apps kit add small" 2>&1)"
status=$?
verdict "run again, add finds nothing to do" "${status}" "$(grep -q "^Nothing to do" <<<"${out}" || echo "it did not say there was nothing to do")" "${out}"
out="$(in_session "${RUN} ame apps kit list" 2>&1)"
grep -q "^small .*" <<<"${out}" && grep -q "1 app, 1 of them installed here" <<<"${out}" && ok "list counts the kit's installed app" ||
    not_ok "list does not count the installed app" "${out}"

# A no keeps the app, and a yes takes it away through the uninstall helper, its data going to the trash
out="$(session_terminal 300 'Remove .*\?' n -- "${RUN} ame apps kit remove small")"
if flatpak info --system "${APP}" >/dev/null 2>&1 && grep -q "Nothing was removed" <<<"${out}"; then
    ok "remove asks about the app, and a no keeps it"
else
    not_ok "remove after a no took the app, or did not say it kept it" "${out}"
fi
out="$(session_terminal 300 'Remove .*\?' y -- "${RUN} ame apps kit remove small")"
status=$?
problems="$(flatpak info --system "${APP}" >/dev/null 2>&1 && echo "${APP} is still installed")"
verdict "remove asks about the app, and a yes uninstalls it" "${status}" "${problems}" "${out}"
out="$(in_session "${RUN} ame apps kit remove small" 2>&1)"
grep -q "None of this kit's apps is installed" <<<"${out}" && ok "remove of a kit with nothing installed says so" ||
    not_ok "remove of an absent kit" "${out}"

# --- As it was ---------------------------------------------------------------------------------------------------
flatpak uninstall --system --noninteractive "${APP}" >/dev/null 2>&1
rm -rf "${KITS}" "${HOME_DIR}/.var/app/${APP}"
finish
