#!/usr/bin/bash
# vmlab-vm: while-playing
# While you play (plans/everybody/PLAN-while-you-play.md), in the test account's session, asked of GNOME Shell itself through
# Eval, which a lab-only extension of the test account opens (never in the image). GameMode's daemon is stood in for on the
# session bus (gamemodestandin.py: its name, ClientCount, GameRegistered and GameUnregistered), and UPower on the system bus
# (upower-standin.py: on the battery until SIGUSR1 plugs it in), since the lab has no battery:
#   - the key is off by default, ame desktop while-playing sets and flips it and refuses a word, and with it off a game
#     registered holds nothing and the part is not there;
#   - on, with GameMode absent, nothing is watched; with it on the bus, its name only (three signals, count 0);
#   - a game registered holds banners (a normal one waits, an urgent one shows), puts the Playing mark in the pill and writes
#     the account's mark: the timed backup and containers' upgrade wait, a run a person started goes, and the system update
#     (as root) is not held;
#   - the power mode: not held on the battery; plugged in, power-profiles-daemon's hold on performance (where the machine has
#     the mode); unplugged, given back;
#   - a second game, and one of two leaving, change nothing; the last leaving gives all of it back and starts what waited;
#   - the stand-in leaving the bus, Let them run (which stays given back until the count has been to zero), the key off,
#     and a screen lock each give it back, and an unlock reads the count again;
#   - six hours from the mark's own time and the wait ends, whatever GameMode says;
#   - ten disables and enables of Amethystora UI leave one hold, one mark and three signals; Control lists the entry, and
#     the setup file knows the key.
# It leaves the account as it found it: the key off, no mark, no game, the real UPower back.
# vmlab-paths: @ui/extension.js @ui/*power* @ui/*pill* @sf/usr/libexec/amethystora-metered @sf/*just/desktop.just @sf/usr/libexec/amethystora-control-list @sf/usr/libexec/amethystora-setup @sf/usr/libexec/amethystora-setup-manifest
source "$(dirname "$0")/lib.sh"

UUID=amethystora-ui@arsslensoft.github.io
HERE="$(dirname "$(readlink -f "$0")")"
HOME_DIR="/var/home/${TEST_USER}"
WORK=/run/vmlab-77
POWER=org.gnome.shell.extensions.amethystora-ui.power
UID_N="$(id -u "${TEST_USER}")"
MARK="/run/user/${UID_N}/amethystora/playing"
WAITED="/run/user/${UID_N}/amethystora/playing-waited"
METERED=/usr/libexec/amethystora-metered
GAMEMODE=(--session --dest com.feralinteractive.GameMode --object-path /com/feralinteractive/GameMode)
ev() {
    user_bus gdbus call --session --dest org.gnome.Shell --object-path /org/gnome/Shell --method org.gnome.Shell.Eval "$1" |
        python3 -c '
import ast, json, sys
text = sys.stdin.read().strip()
if not text.startswith("("):
    print("ERROR")
    sys.exit(1)
ok, value = ast.literal_eval("(" + ("True" if text.startswith("(true") else "False") + text[text.index(","):])
if not ok:
    print("ERROR: " + value, file=sys.stderr)
    print("ERROR")
    sys.exit(1)
try:
    value = json.loads(value) if value else ""
except ValueError:
    pass
print(value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, separators=(",", ":")))'
}
gs() { in_session "gsettings $*" 2>/dev/null; }
same() { if [[ "$2" == "$3" ]]; then ok "$1"; else not_ok "$1" "expected: $3" "found: $2"; fi; }
UI="Main.extensionManager.lookup('${UUID}').stateObj.modules"
PLAYING="${UI}.get('power')?.playing"
P="${UI}.get('pill')"
# One field of the part's state, and of the pill's, as JSON
pst() { ev "JSON.stringify(${PLAYING}?.state()$1 ?? null)"; }
ppst() { ev "JSON.stringify(${P}.state()$1)"; }
is() { [[ "$(ev "$1")" == "$2" ]]; }
gm() { user_bus gdbus call "${GAMEMODE[@]}" --method "com.feralinteractive.GameMode.$1" "${@:2}" >/dev/null; }
# What the machine's power-profiles-daemon (tuned-ppd here: the image has no powerprofilesctl) holds now, as busctl prints it
PPD=(--system get-property org.freedesktop.UPower.PowerProfiles /org/freedesktop/UPower/PowerProfiles org.freedesktop.UPower.PowerProfiles)
holds() { user_bus busctl "${PPD[@]}" ActiveProfileHolds 2>/dev/null; }
reason_held() { [[ "$(holds)" == *'Playing a game'* ]]; }
held_performance() { [[ "$(holds)" == *performance* ]]; }
no_performance() { [[ "$(holds)" != *performance* ]]; }
timed() { user_bus env TRIGGER_UNIT=x.timer "${METERED}" wait "$1" >/dev/null 2>&1; echo $?; }
shell_pid() { pgrep -u "${TEST_USER}" -x gnome-shell | head -n1; }
upower_swapped=""
cleanup() {
    gs reset "${POWER}" while-playing
    pkill -f gamemodestandin.py 2>/dev/null
    pkill -f upower-standin.py 2>/dev/null
    systemctl stop vmlab-77-upower.service vmlab-77-gamemode.service 2>/dev/null
    if [[ -n "${upower_swapped}" ]]; then
        systemctl unmask --runtime upower.service >/dev/null 2>&1
        systemctl start upower.service 2>/dev/null
    fi
    rm -f "${MARK}" "${MARK}.new"
    rm -rf "${WAITED}" "${WORK}"
}
trap cleanup EXIT
mkdir -p "${WORK}"

# --- The session and its Eval ---------------------------------------------------------------------------------------
if ! has_session; then
    bash "${HERE}/10-account.sh" >/dev/null
fi
if ! wait_for 300 has_session; then
    not_ok "no session for ${TEST_USER}"
    finish
fi
if ! is "1 + 1" 2; then
    install -d -o "${TEST_USER}" -g "${TEST_USER}" "${HOME_DIR}/.local/share/gnome-shell/extensions/vmlab-eval@lab"
    cat >"${HOME_DIR}/.local/share/gnome-shell/extensions/vmlab-eval@lab/metadata.json" <<'EOF'
{"uuid": "vmlab-eval@lab", "name": "VM lab", "description": "The lab's Eval", "shell-version": ["49", "50", "51"]}
EOF
    cat >"${HOME_DIR}/.local/share/gnome-shell/extensions/vmlab-eval@lab/extension.js" <<'EOF'
export default class { enable() { global.context.unsafe_mode = true; } disable() {} }
EOF
    chown -R "${TEST_USER}:" "${HOME_DIR}/.local/share/gnome-shell"
    enabled="$(user_bus gsettings get org.gnome.shell enabled-extensions)"
    [[ ${enabled} == *vmlab-eval@lab* ]] || user_bus gsettings set org.gnome.shell enabled-extensions "${enabled%]*}, 'vmlab-eval@lab']"
    loginctl unlock-sessions
    systemctl restart gdm
    wait_for 240 has_session
    wait_for 120 is "typeof ${P}?.state" function
fi
wait_for 60 is "typeof ${P}?.state" function
wait_for 30 is "Main.layoutManager._startingUp" false
ev "Main.overview.hide(); 'hidden'" >/dev/null
SESSION="$(loginctl show-user "${TEST_USER}" -p Display --value)"
gs reset "${POWER}" while-playing
rm -f "${MARK}"
rm -rf "${WAITED}"

# --- 1. The key and its command ---------------------------------------------------------------------------------------
same "1 while-playing is off by default" "$(gs get "${POWER}" while-playing)" false
in_session "ame desktop while-playing on" >/dev/null
same "1 ame desktop while-playing on" "$(gs get "${POWER}" while-playing)" true
in_session "ame desktop while-playing" >/dev/null
same "1 without a word it flips" "$(gs get "${POWER}" while-playing)" false
in_session "ame desktop while-playing off" >/dev/null
same "1 off" "$(gs get "${POWER}" while-playing)" false
rc=0
in_session "ame desktop while-playing maybe" >/dev/null 2>&1 || rc=$?
same "1 a word it does not know is refused (64)" "${rc}" 64

# --- 2. The lab's machine: a battery, and a GameMode ------------------------------------------------------------------
cp "${HERE}/upower-standin.py" "${HERE}/gamemodestandin.py" "${WORK}/"
chmod 0755 "${WORK}"
chmod 0644 "${WORK}"/*.py
systemctl stop upower.service
systemctl mask --runtime upower.service >/dev/null && upower_swapped=1
: >/run/upower-standin.log
systemd-run --collect --unit=vmlab-77-upower python3 "${WORK}/upower-standin.py" >/dev/null
sleep 2
UPOWER_PID="$(systemctl show -p MainPID --value vmlab-77-upower)"
start_gamemode() {
    systemd-run --collect --unit=vmlab-77-gamemode --uid="${TEST_USER}" \
        --setenv=XDG_RUNTIME_DIR="/run/user/${UID_N}" --setenv=DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${UID_N}/bus" \
        python3 "${WORK}/gamemodestandin.py" >/dev/null
    wait_for 20 user_bus busctl --user status com.feralinteractive.GameMode
}
stop_gamemode() { systemctl stop vmlab-77-gamemode.service 2>/dev/null; sleep 1; }

# --- 3. With the key off a game holds nothing -------------------------------------------------------------------------
start_gamemode
gm RegisterGame 4242
sleep 3
same "3 the key off: the part is not there" "$(ev "${PLAYING} ? 'there' : 'gone'")" gone
same "3 ...no banner is held for it" "$(ppst .quiet.on)" false
check "3 ...and no mark is written" test ! -e "${MARK}"
gm UnregisterGame 4242
stop_gamemode

# --- 4. On, and nothing on the bus costs nothing ----------------------------------------------------------------------
gs set "${POWER}" while-playing true
check "4 the part starts" wait_for 20 is "typeof ${PLAYING}?.state" function
same "4 GameMode absent: no game" "$(pst .count)" 0
same "4 ...and no signal is listened to" "$(pst .watching)" 0
same "4 ...nor UPower" "$(pst .following)" 0

# --- 5. GameMode on the bus, no game: its name only -------------------------------------------------------------------
start_gamemode
check "5 GameMode appears: its three signals are heard" wait_for 20 is "${PLAYING}.state().watching" 3
same "5 ...no game yet" "$(pst .count)" 0
same "5 ...and UPower is still not followed" "$(pst .following)" 0
check "5 ...no mark" test ! -e "${MARK}"

# --- 6. A game registered, on the battery -----------------------------------------------------------------------------
gm RegisterGame 4242
check "6 the part counts one game" wait_for 20 is "${PLAYING}.state().count" 1
same "6 ...and says it plays" "$(pst .playing)" true
same "6 banners are held: the hold's reason is playing" "$(ppst .quiet.reason)" '"playing"'
same "6 the pill's mark is Playing" "$(ppst .playing)" true
same "6 ...and is the pill's activity" "$(ppst .activity)" '"playing"'
user_bus notify-send -a vmlab-77 "A banner" "held" >/dev/null 2>&1
check "6 a banner waits" wait_for 20 is "${P}.state().quiet.held >= 1" true
held_before="$(ppst .quiet.held)"
user_bus notify-send -a vmlab-77 -u critical "Urgent" "comes through" >/dev/null 2>&1
sleep 3
same "6 an urgent one is not held" "$(ppst .quiet.held)" "${held_before}"
check "6 the account's mark is written" wait_for 10 test -s "${MARK}"
same "6 ...with GNOME Shell's number" "$(cut -d' ' -f1 "${MARK}")" "$(shell_pid)"
check "6 ...and the mark has the time of the start" grep -qE '^[0-9]+ [0-9]+$' "${MARK}"
same "6 the part says the mark is written" "$(pst .marked)" true
same "6 the timed backup waits" "$(timed backup)" 1
same "6 the containers' upgrade waits" "$(timed containers)" 1
check "6 what waited is remembered" test -e "${WAITED}/backup"
same "6 a run the person started goes" "$(user_bus env TRIGGER_UNIT= "${METERED}" wait backup >/dev/null 2>&1; echo $?)" 0
same "6 the system update (root's) is not held" "$(TRIGGER_UNIT=x.timer "${METERED}" wait system >/dev/null 2>&1; echo $?)" 0
same "6 the power mode is not held on the battery" "$(pst .performance)" false
check "6 ...and the daemon holds nothing" no_performance
same "6 UPower is followed while a game counts" "$(pst .following)" 1
same "6 it is known to be on the battery" "$(pst .onBattery)" true

# --- 7. Plugged in: the performance mode, where the machine has it ----------------------------------------------------
has_performance() { [[ "$(user_bus busctl "${PPD[@]}" Profiles 2>/dev/null)" == *performance* ]]; }
kill -USR1 "${UPOWER_PID}"
check "7 plugged in, the part knows it" wait_for 20 is "${PLAYING}.state().onBattery" false
if has_performance; then
    check "7 the performance mode is held" wait_for 20 held_performance
    check "7 ...with the reason a person reads" reason_held
    same "7 the part holds one cookie" "$(ev "${PLAYING}.state().cookie > 0")" true
    kill -USR2 "${UPOWER_PID}"
    check "7 unplugged, it is given back" wait_for 20 no_performance
    same "7 ...and nothing else was given back" "$(pst .playing)" true
    same "7 ...the mark stays" "$(test -s "${MARK}" && echo yes)" yes
    kill -USR1 "${UPOWER_PID}"
    check "7 plugged in again, held again" wait_for 20 held_performance
else
    skip "7 this machine's power-profiles-daemon has no performance mode: its hold is not tried"
fi

# --- 8. A second game, and one leaving ---------------------------------------------------------------------------------
gm RegisterGame 4343
check "8 two games" wait_for 20 is "${PLAYING}.state().count" 2
same "8 still one mark" "$(grep -c . "${MARK}")" 1
gm UnregisterGame 4242
check "8 one leaving: one game" wait_for 20 is "${PLAYING}.state().count" 1
same "8 ...still playing" "$(pst .playing)" true
same "8 ...banners still held" "$(ppst .quiet.reason)" '"playing"'
same "8 ...the backup still waits" "$(timed backup)" 1

# --- 9. The last game leaving gives all of it back, and starts what waited ---------------------------------------------
gm UnregisterGame 4343
check "9 no game" wait_for 20 is "${PLAYING}.state().count" 0
same "9 not playing" "$(pst .playing)" false
same "9 banners are not held" "$(ppst .quiet.on)" false
same "9 the pill's mark is gone" "$(ppst .playing)" false
check "9 the mark is gone" test ! -e "${MARK}"
check "9 the daemon holds nothing" no_performance
same "9 UPower is not followed" "$(pst .following)" 0
check "9 what waited was started, once" test ! -e "${WAITED}/backup"
same "9 the timed backup runs again" "$(timed backup)" 0

# --- 9b. A game that comes and goes at once leaves no mark behind -----------------------------------------------------------
# The helper's on and off are two processes: off must never finish before the on that came first
for _ in 1 2 3 4 5 6; do
    gm RegisterGame 6060
    gm UnregisterGame 6060
done
sleep 5
same "9b the count is zero" "$(pst .count)" 0
check "9b no mark was left by a start that raced its end" test ! -e "${MARK}"
same "9b the timed backup runs" "$(timed backup)" 0

# --- 10. GameMode leaving the bus -----------------------------------------------------------------------------------
gm RegisterGame 4444
check "10 a game again" wait_for 20 is "${PLAYING}.state().playing" true
stop_gamemode
check "10 GameMode leaving gives it all back" wait_for 20 is "${PLAYING}.state().playing" false
same "10 ...the count is zero" "$(pst .count)" 0
same "10 ...no signal is listened to" "$(pst .watching)" 0
check "10 ...no mark" test ! -e "${MARK}"
check "10 ...no hold" no_performance
start_gamemode

# --- 11. Let them run -------------------------------------------------------------------------------------------------
gm RegisterGame 5151
check "11 playing" wait_for 20 is "${PLAYING}.state().playing" true
ev "${PLAYING}.letRun(); 'ok'" >/dev/null
check "11 Let them run gives it back with the game still on" wait_for 20 is "${PLAYING}.state().playing" false
same "11 ...the count is still one" "$(pst .count)" 1
check "11 ...no mark" test ! -e "${MARK}"
same "11 ...banners are not held" "$(ppst .quiet.on)" false
gm RegisterGame 5252
sleep 3
same "11 another game does not hold it again" "$(pst .playing)" false
gm UnregisterGame 5151
gm UnregisterGame 5252
check "11 the count back at zero" wait_for 20 is "${PLAYING}.state().count" 0
gm RegisterGame 5353
check "11 the next game holds again" wait_for 20 is "${PLAYING}.state().playing" true

# --- 12. The key off --------------------------------------------------------------------------------------------------
same "12 a timed backup waits for the game" "$(timed backup)" 1
check "12 ...and is remembered" test -e "${WAITED}/backup"
gs set "${POWER}" while-playing false
check "12 the key off, like the game's end, starts what waited" wait_for 20 test ! -e "${WAITED}/backup"
check "12 the key off gives it back" wait_for 20 is "${P}.state().quiet.on" false
check "12 ...no mark" test ! -e "${MARK}"
check "12 ...no hold" no_performance
same "12 ...and the part is gone" "$(ev "${PLAYING} ? 'there' : 'gone'")" gone
gs set "${POWER}" while-playing true
check "12 on again, the game that is still there holds" wait_for 20 is "${PLAYING}.state().playing" true

# --- 13. A lock gives it back, and the unlock reads the count -------------------------------------------------------------
locked_is() { [[ "$(ev "Main.screenShield?.locked ?? false")" == "$1" ]]; }
loginctl lock-session "${SESSION}"
check "13 the screen locks" wait_for 30 locked_is true
sleep 2
check "13 locked: no mark" test ! -e "${MARK}"
check "13 locked: no hold" no_performance
loginctl unlock-session "${SESSION}"
check "13 the screen unlocks" wait_for 30 locked_is false
check "13 the extension is up again" wait_for 60 is "typeof ${PLAYING}?.state" function
check "13 the unlock reads the count: playing again" wait_for 30 is "${PLAYING}.state().playing" true
check "13 ...the mark is back" wait_for 10 test -s "${MARK}"
same "13 ...the backup waits again" "$(timed backup)" 1

# --- 14. Six hours at most -----------------------------------------------------------------------------------------
printf '%s %s\n' "$(shell_pid)" "$(($(date +%s) - 6 * 3600 - 30))" >"${MARK}"
chown "${TEST_USER}:" "${MARK}"
same "14 six hours after the mark's own time the backup runs, a game still registered" "$(timed backup)" 0
same "14 ...the containers too" "$(timed containers)" 0
printf '%s %s\n' "$(shell_pid)" "$(($(date +%s) - 3600))" >"${MARK}"
chown "${TEST_USER}:" "${MARK}"
same "14 an hour in, it still waits" "$(timed backup)" 1

# --- 15. Ten disables and enables ------------------------------------------------------------------------------------
for _ in 1 2 3 4 5 6 7 8 9 10; do
    in_session "gnome-extensions disable ${UUID}" >/dev/null 2>&1
    sleep 0.5
    in_session "gnome-extensions enable ${UUID}" >/dev/null 2>&1
    wait_for 30 is "typeof ${PLAYING}?.state" function
done
check "15 still playing, from what GameMode says" wait_for 30 is "${PLAYING}.state().playing" true
same "15 three signals, not thirty" "$(pst .watching)" 3
same "15 one mark" "$(grep -c . "${MARK}")" 1
if has_performance; then
    check "15 one performance hold" wait_for 20 held_performance
    same "15 ...exactly one" "$(holds | grep -o 'Playing a game' | wc -l)" 1
fi
gm UnregisterGame 5353
check "15 the game ends" wait_for 20 is "${PLAYING}.state().playing" false

# --- 16. Control and the setup file ---------------------------------------------------------------------------------
list="$(user_bus /usr/libexec/amethystora-control-list --json 2>/dev/null)"
same "16 Control lists the entry once" "$(jq '[.. | objects | select(.id? == "while-playing")] | length' <<<"${list}")" 1
same "16 ...as a switch with its command" "$(jq -r '[.. | objects | select(.id? == "while-playing")][0] | [.kind, (.usage // "")] | join(" ")' <<<"${list}")" "switch ame desktop while-playing on|off"
check "16 the setup file's table knows the key" bash -c "grep -q '\"while-playing\": \\[\"b\"\\]' /usr/libexec/amethystora-setup"

finish
