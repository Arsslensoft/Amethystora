#!/usr/bin/bash
# The small helpers of a session that no other test covers, against stand-ins for what each starts: the terminal's
# greeting (amethystora-greeting), Super+Return's terminal in the workspace's folder (amethystora-workspace-terminal),
# the repository `ame report` names (amethystora-image-repo), a failure notice's Ask the agent
# (amethystora-agent-notice) and the sessions' buses told to read their configuration again
# (amethystora-reload-session-buses, which needs root for setpriv and is skipped without it). Run by 20-tests.sh and
# the Integration workflow; LIBEXEC names another folder of the helpers.
set -euo pipefail

LIBEXEC="${LIBEXEC:-/usr/libexec}"
T="$(mktemp -d)"
trap 'rm -rf "${T}"' EXIT
mkdir -p "${T}/bin"
export LOG="${T}/log"
: >"${LOG}"

fail() {
    echo "test-session-helpers: $*"
    exit 1
}
stand_in() {
    printf '#!/usr/bin/bash\n%s\n' "$2" >"${T}/bin/$1"
    chmod +x "${T}/bin/$1"
}

# --- The greeting ------------------------------------------------------------------------------------------------
stand_in amethystora-fetch 'echo "FETCH $*"'
stand_in amethystora-fastfetch 'echo "FASTFETCH $*"'
stand_in glow 'echo "GLOW $*"; cat'
greet() { env PATH="${T}/bin:${PATH}" "$@"; }

# Not a terminal: the plain line, with no escape sequence, and --short stops after it
out="$(greet TERM=xterm-256color "${LIBEXEC}/amethystora-greeting" --short)"
[[ "${out}" == $'\nWelcome to Amethystora' ]] || fail "the short greeting is: $(od -c <<<"${out}" | head -3)"
out="$(greet TERM=xterm-256color "${LIBEXEC}/amethystora-greeting")"
[[ "${out}" != *$'\e'* ]] || fail "the greeting colours what is not a terminal"
grep -qx 'FETCH ' <<<"${out}" || fail "the greeting did not show the summary: ${out}"
# The banner with the image and a tip put in, every placeholder filled, in the greeting's own style
grep -q "^GLOW -s /usr/share/amethystora/greeting/style.json -w 78 -$" <<<"${out}" || fail "the banner was not drawn in its style: ${out}"
[[ "${out}" != *%IMAGE%* && "${out}" != *%TIP%* ]] || fail "a placeholder was left in the banner: ${out}"
if [[ -r /usr/share/amethystora/image-info.json ]]; then
    image="$(jq -r '."image-ref"' /usr/share/amethystora/image-info.json)"
    [[ "${out}" == *"${image##*://}"* ]] || fail "the banner does not name the image ${image##*://}"
fi
# The text console draws the logo in its own colours
out="$(greet TERM=linux "${LIBEXEC}/amethystora-greeting")"
grep -qx 'FASTFETCH --logo /usr/share/amethystora/logos/console/amethystora' <<<"${out}" ||
    fail "the text console did not get its own logo: ${out}"
test -e /usr/share/amethystora/logos/console/amethystora || [[ ! -d /usr/share/amethystora ]] ||
    fail "the console's logo is not in the image"

# --- Super+Return's terminal -------------------------------------------------------------------------------------
stand_in xdg-terminal-exec 'echo "$PWD|$*"'
run="${T}/run"
mkdir -p "${run}/amethystora" "${T}/folder with space" "${T}/elsewhere"
term() { (cd "${T}/elsewhere" && env PATH="${T}/bin:${PATH}" XDG_RUNTIME_DIR="${run}" "${LIBEXEC}/amethystora-workspace-terminal" "$@"); }
[[ "$(term)" == "${T}/elsewhere|" ]] || fail "with no workspace folder the terminal opened in $(term)"
printf '%s' "${T}/folder with space" >"${run}/amethystora/workspace-folder"
[[ "$(term -e true)" == "${T}/folder with space|-e true" ]] || fail "the terminal opened as $(term -e true)"
printf '%s' "${T}/gone" >"${run}/amethystora/workspace-folder"
[[ "$(term)" == "${T}/elsewhere|" ]] || fail "a folder that is gone moved the terminal: $(term)"

# --- The repository ----------------------------------------------------------------------------------------------
[[ "$("${LIBEXEC}/amethystora-image-repo")" == arsslensoft/amethystora ]] || fail "the image's repository is not ours"
[[ "$("${LIBEXEC}/amethystora-image-repo" --default x/y amethystora-dx beta)" == arsslensoft/amethystora ]] ||
    fail "the repository changes with the arguments"

# --- A failure notice's Ask the agent ----------------------------------------------------------------------------
notice() { env PATH="${T}/bin:${PATH}" "${LIBEXEC}/amethystora-agent-notice" "$@"; }
stand_in notify-send 'echo "notify-send $*" >>"${LOG}"; echo "${ANSWER:-}"'
for unit in "" "foo" "a b.service" "../x.service" "x.service;id"; do
    set +e
    notice "${unit}" -a Amethystora "Failed" >/dev/null 2>&1
    status=$?
    set -e
    [[ "${status}" == 64 ]] || fail "the unit \"${unit}\" was taken (exit ${status})"
done
[[ ! -s "${LOG}" ]] || fail "a notice was raised for a unit refused: $(cat "${LOG}")"
# Dismissed, or another button: nothing more is started
out="$(ANSWER=default notice amethystora-update-check.service -a Amethystora -A agent=Ask "It failed" 2>&1)" ||
    fail "a dismissed notice failed"
[[ -z "${out}" ]] || fail "a dismissed notice started something: ${out}"
grep -qx 'notify-send --wait -a Amethystora -A agent=Ask It failed' "${LOG}" || fail "the notice was raised as: $(cat "${LOG}")"

# --- The sessions' buses -----------------------------------------------------------------------------------------
if [[ "$(id -u)" == 0 ]] && command -v python3 >/dev/null && command -v setpriv >/dev/null; then
    users="${T}/users"
    mkdir -p "${users}/0" "${users}/4242"
    for uid in 0 4242; do
        python3 -c 'import socket, sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "${users}/${uid}/bus"
    done
    # root has a bus, 65534 has none, 4242 has one but no account, and "gdm-greeter" is no number
    stand_in loginctl 'printf "%s\n" "0 root no active" "65534 nobody no closing" "4242 ghost no active" "gdm-greeter x"'
    stand_in busctl 'echo "busctl $(id -u) ${XDG_RUNTIME_DIR} ${DBUS_SESSION_BUS_ADDRESS} $*" >>"${LOG}"; exit 1'
    : >"${LOG}"
    env PATH="${T}/bin:${PATH}" AMETHYSTORA_RUN_USER="${users}" "${LIBEXEC}/amethystora-reload-session-buses" ||
        fail "a bus that did not answer failed the run"
    [[ "$(cat "${LOG}")" == "busctl 0 ${users}/0 unix:path=${users}/0/bus --user call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus ReloadConfig" ]] ||
        fail "the buses told: $(cat "${LOG}")"
else
    echo "test-session-helpers: skipping the sessions' buses (needs root, python3 and setpriv)"
fi

echo "test-session-helpers: ok"
