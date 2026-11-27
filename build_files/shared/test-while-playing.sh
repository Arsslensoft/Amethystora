#!/usr/bin/bash
# The mark of the pill's While you play, against a stand-in for busctl and systemctl: while it is there, written by a GNOME
# Shell that still runs, and under six hours old, the account's timed backup and containers' upgrade wait (a backup to a disk of
# this machine too), the first wait of each is remembered so that the end of the game starts it, and nothing else waits: a run
# a person started, the system update, a mark left by a shell that is gone, a mark six hours old or from the future, and the
# mark's absence all go as before.
#   test-while-playing.sh /path/to/amethystora-metered
set -euo pipefail

METERED="${1:?the helper}"
WORK="$(mktemp -d)"
trap 'kill "${SHELL_PID:-0}" 2>/dev/null || true; rm -rf -- "${WORK}"' EXIT
mkdir -p "${WORK}/bin" "${WORK}/run/amethystora" "${WORK}/state" "${WORK}/config/amethystora" "${WORK}/disk"
cat >"${WORK}/bin/busctl" <<'STANDIN'
#!/usr/bin/bash
case "$*" in
    *org.freedesktop.UPower*) echo "${STANDIN_BATTERY:-b false}" ;;
    *) echo "${STANDIN_METERED:-u 2}" ;;
esac
STANDIN
cat >"${WORK}/bin/systemctl" <<'STANDIN'
#!/usr/bin/bash
echo "$*" >>"${STANDIN_LOG:?}"
STANDIN
chmod +x "${WORK}/bin/busctl" "${WORK}/bin/systemctl"
# A process that calls itself gnome-shell, as the shell that writes the mark does
cp "$(command -v sleep)" "${WORK}/bin/gnome-shell"
"${WORK}/bin/gnome-shell" 300 &
SHELL_PID=$!
LOG="${WORK}/systemctl.log"
: >"${LOG}"

run() {
    env PATH="${WORK}/bin:${PATH}" XDG_RUNTIME_DIR="${WORK}/run" XDG_STATE_HOME="${WORK}/state" \
        XDG_CONFIG_HOME="${WORK}/config" STANDIN_LOG="${LOG}" "$@"
}
expect() {
    local what="$1" want="$2" got=0
    shift 2
    run "$@" >/dev/null 2>&1 || got=$?
    [[ "${got}" == "${want}" ]] || { echo "test-while-playing: ${what}: exit ${got}, expected ${want}"; exit 1; }
}
fail() {
    echo "test-while-playing: $1"
    exit 1
}
MARK="${WORK}/run/amethystora/playing"
WAITED="${WORK}/run/amethystora/playing-waited"
STAMP="${WORK}/state/amethystora/metered"
TIMED=(TRIGGER_UNIT=x.timer)
now() { date +%s; }
write_mark() { printf '%s %s\n' "$1" "$2" >"${MARK}"; }

# No mark: all as before
expect "no mark: the backup runs" 0 "${TIMED[@]}" "${METERED}" wait backup
expect "no mark: the containers run" 0 "${TIMED[@]}" "${METERED}" wait containers

# The mark holds the process number of whoever wrote it and the time, in a folder only the account enters
rm -rf -- "${WORK}/run/amethystora"
mine="$(run bash -c '"$0" playing on; echo $$' "${METERED}")"
[[ "$(cut -d' ' -f1 "${MARK}")" == "${mine}" ]] || fail "the mark is not the caller's process"
[[ "$(cut -d' ' -f2 "${MARK}")" =~ ^[0-9]+$ ]] || fail "the mark has no time"
[[ "$(stat -c %a "${WORK}/run/amethystora")" == 700 ]] || fail "the mark's folder is not the account's alone"
# The time the game began is kept while the same shell asks again, as an unlock's does: a bash that calls itself gnome-shell asks twice
mkdir -p "${WORK}/second"
cp "$(command -v bash)" "${WORK}/second/gnome-shell"
rm -f -- "${MARK}"
# shellcheck disable=SC2016
run "${WORK}/second/gnome-shell" -c '"$0" playing on; cp -- "$1" "$1.first"; sleep 1.2; "$0" playing on; true' "${METERED}" "${MARK}"
[[ "$(cat "${MARK}")" == "$(cat "${MARK}.first")" ]] || fail "the same shell asking again began the six hours again"
rm -f -- "${MARK}.first"

# A mark left by a process that is not a GNOME Shell (gone, or another program's number) is ignored
write_mark 999999 "$(now)"
expect "a mark of a shell that is gone: the backup runs" 0 "${TIMED[@]}" "${METERED}" wait backup
write_mark "$$" "$(now)"
expect "a mark of another program: the backup runs" 0 "${TIMED[@]}" "${METERED}" wait backup
printf 'x\n' >"${MARK}"
expect "a mark with no number: the containers run" 0 "${TIMED[@]}" "${METERED}" wait containers
write_mark "${SHELL_PID}" x
expect "a mark with no time: the containers run" 0 "${TIMED[@]}" "${METERED}" wait containers
write_mark "${SHELL_PID}" "$(($(now) + 3600))"
expect "a mark from the future: the backup runs" 0 "${TIMED[@]}" "${METERED}" wait backup

# While a game is registered: the account's own timed runs wait, and nothing is counted in the week's stamps
write_mark "${SHELL_PID}" "$(now)"
expect "playing: the backup waits" 1 "${TIMED[@]}" "${METERED}" wait backup
expect "playing: the containers wait" 1 "${TIMED[@]}" "${METERED}" wait containers
expect "playing: the backup to the other computer waits" 1 "${TIMED[@]}" "${METERED}" wait backup-other
[[ ! -e "${STAMP}/backup" && ! -e "${STAMP}/containers" ]] || fail "a wait for a game was counted in the week's stamp"
for what in backup containers backup-other; do
    [[ -e "${WAITED}/${what}" ]] || fail "the wait of ${what} was not remembered"
done
[[ "$(stat -c %a "${WAITED}")" == 700 ]] || fail "what waited is not the account's alone"
expect "playing: a run a person started goes" 0 TRIGGER_UNIT= "${METERED}" wait backup
# As root, the system update is never an account's file's to hold
if [[ "$(id -u)" == 0 ]]; then
    expect "playing: the system update is not held" 0 "${TIMED[@]}" "${METERED}" wait system
fi
# A backup to a disk of this machine reads and writes the disk the game is on: it waits too
printf 'export RESTIC_REPOSITORY="%s"\n' "${WORK}/disk" >"${WORK}/config/amethystora/backup.env"
expect "playing: a backup to this machine's disk waits" 1 "${TIMED[@]}" "${METERED}" wait backup
rm -f -- "${WORK}/config/amethystora/backup.env"
# On the battery or on mains is no matter, and a metered connection does not make it longer than the six hours
expect "playing, on battery: the backup waits" 1 STANDIN_BATTERY="b true" "${TIMED[@]}" "${METERED}" wait backup
[[ ! -e "${STAMP}/backup" ]] || fail "the week's stamp was started by a wait for a game"
# A run the connection holds back anyway keeps that reason, its stamp and its week, and is not remembered for the game's end
rm -rf -- "${WAITED}"
expect "playing, metered: the backup waits" 1 STANDIN_METERED="u 1" "${TIMED[@]}" "${METERED}" wait backup
[[ -s "${STAMP}/backup" ]] || fail "the metered wait was not counted in its stamp"
[[ ! -e "${WAITED}/backup" ]] || fail "a run the connection holds back was remembered for the game's end"
rm -f -- "${STAMP}/backup"
# ...nor one that Get me through holds back (a mark of the shell that is there, on the battery)
printf '%s\n' "${SHELL_PID}" >"${WORK}/run/amethystora/get-through"
expect "playing, Get me through: the containers wait" 1 STANDIN_BATTERY="b true" "${TIMED[@]}" "${METERED}" wait containers
[[ -s "${STAMP}/containers" ]] || fail "the Get me through wait was not counted in its stamp"
[[ ! -e "${WAITED}/containers" ]] || fail "a run Get me through holds back was remembered for the game's end"
rm -f -- "${WORK}/run/amethystora/get-through" "${STAMP}/containers"

# Six hours at most, from the mark's own time
write_mark "${SHELL_PID}" "$(($(now) - 6 * 3600 + 120))"
expect "six hours less two minutes: still waiting" 1 "${TIMED[@]}" "${METERED}" wait backup
write_mark "${SHELL_PID}" "$(($(now) - 6 * 3600 - 5))"
expect "six hours: it runs" 0 "${TIMED[@]}" "${METERED}" wait backup
expect "six hours: the containers run" 0 "${TIMED[@]}" "${METERED}" wait containers

# A run that worked forgets what waited; the end of a game starts only what waited, once, and a lock's off starts nothing
write_mark "${SHELL_PID}" "$(now)"
: >"${LOG}"
rm -rf -- "${WAITED}"
expect "playing: the backup waits again" 1 "${TIMED[@]}" "${METERED}" wait backup
expect "playing: the containers wait again" 1 "${TIMED[@]}" "${METERED}" wait containers
run "${METERED}" "done" containers
[[ ! -e "${WAITED}/containers" ]] || fail "a run that worked left its wait"
run "${METERED}" playing off
[[ ! -e "${MARK}" ]] || fail "off left the mark"
[[ ! -s "${LOG}" ]] || fail "a lock's off started something: $(cat "${LOG}")"
expect "the mark gone: the backup runs" 0 "${TIMED[@]}" "${METERED}" wait backup
write_mark "${SHELL_PID}" "$(now)"
run "${METERED}" playing off ended
[[ ! -e "${MARK}" ]] || fail "off ended left the mark"
[[ "$(cat "${LOG}")" == "--user start --no-block amethystora-backup.service" ]] ||
    fail "the end of a game started the wrong things: $(cat "${LOG}")"
: >"${LOG}"
run "${METERED}" playing off ended
[[ ! -s "${LOG}" ]] || fail "the same wait was started twice"

# The end of a game starts only what the timer's own waits would let run now: a connection that counts data at that moment still
# holds it (its stamp is kept, the week runs from there), and the containers' own checks are asked for (amethystora-pkg)
write_mark "${SHELL_PID}" "$(now)"
: >"${LOG}"
rm -rf -- "${WAITED}" "${STAMP}"
expect "a game: the backup waits" 1 "${TIMED[@]}" "${METERED}" wait backup
expect "a game: the containers wait" 1 "${TIMED[@]}" "${METERED}" wait containers
run STANDIN_METERED="u 1" "${METERED}" playing off ended
[[ ! -s "${LOG}" ]] || fail "the end of a game started what a metered connection holds back: $(cat "${LOG}")"
[[ -s "${STAMP}/backup" && -s "${STAMP}/containers" ]] || fail "the wait at the end of the game was not counted in the stamps"
[[ ! -e "${WAITED}/backup" && ! -e "${WAITED}/containers" ]] || fail "what a metered connection holds back is still remembered"
rm -rf -- "${STAMP}" "${WAITED}"
write_mark "${SHELL_PID}" "$(now)"
expect "a game: the containers wait again" 1 "${TIMED[@]}" "${METERED}" wait containers
run "${METERED}" playing off ended
[[ "$(cat "${LOG}")" == "--user start --no-block amethystora-pkg-upgrade.service" ]] || fail "the containers were not started: $(cat "${LOG}")"
[[ -e "${WAITED}/started-containers" ]] || fail "the containers' own checks were not asked for"
run "${METERED}" "done" containers
[[ ! -e "${WAITED}/started-containers" && ! -d "${WAITED}" ]] || fail "a finished run left its marks"

# Words it does not know
expect "a word it does not know" 2 "${METERED}" playing maybe
expect "playing alone" 2 "${METERED}" playing
expect "off with a stranger" 2 "${METERED}" playing off later
expect "on with more" 2 "${METERED}" playing on ended
echo "test-while-playing: passed"
