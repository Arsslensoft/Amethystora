#!/usr/bin/bash
# Pull the key (ame security pull-key), on the machine as a person would use it: a QEMU USB stick with a serial number of its own
# (run.mjs, usb_next) chosen, the key turned on, and the stick pulled out.
#
#   1.   The key is off as shipped and the report says so; the stick is plugged in.
#   2.   The stick is offered by its serial number; `ame security pull-key lock` in a terminal asks, and turns the key on (the
#        explanation shown first); one udev rule is written, in the shape the security watcher accepts, and the report says on.
#        A removal event for the stick that is still plugged in (udevadm trigger) starts the service, which waits a second,
#        finds the stick and does nothing: the screen stays unlocked. Then the stick is pulled out, as QEMU does it.
#   3.   The screen locks (LockedHint), the journal says why.
#   4.   The stick plugged in again: the screen stays locked (plugging it back unlocks nothing); unlocked by hand.
#        `poweroff`: the stick is pulled out again, and the machine powers itself off (run.mjs waits and starts it).
#   5.   The journal of the boot that powered off says why; the key off takes the rule away and the report says off.
#
# Not here: a suspend with the device re-enumerated (the lab cannot suspend the VM): test-pull-key.sh holds the service's
# answer to a computer going to sleep or just woken against a stand-in login manager and journal.
# vmlab-paths: @sf/usr/libexec/amethystora-pull-key @sf/usr/lib/systemd/system/amethystora-pull-key.service @sf/usr/libexec/amethystora-security-config @sf/usr/share/amethystora/just/security.just
source "$(dirname "$0")/lib.sh"

HELPER=/usr/libexec/amethystora-pull-key
CONFIG=/usr/libexec/amethystora-security-config
RULES=/etc/udev/rules.d/90-amethystora-pull-key.rules
UID_TEST="$(id -u "${TEST_USER}")"
same() { if [[ "$2" == "$3" ]]; then ok "$1"; else not_ok "$1" "expected: $3" "found: $2"; fi; }
if ! wait_for 300 has_session; then
    not_ok "no session for ${TEST_USER}" "$(loginctl list-sessions --no-legend)"
    finish
fi
SESSION="$(loginctl show-user "${TEST_USER}" -p Display --value)"
locked() { [[ "$(loginctl show-session "${SESSION}" -p LockedHint --value)" == yes ]]; }
unlocked() { ! locked; }
record() { runuser -u "${TEST_USER}" -- env HOME="$(getent passwd "${TEST_USER}" | cut -d: -f6)" /usr/libexec/amethystora-security-status --json 2>/dev/null |
    jq -c --arg id "$1" '[.. | objects | select(.id? == $id)][0] | {state, text}'; }
# The sysfs folder of the stick, by its serial number
stick() {
    local dev
    for dev in /sys/bus/usb/devices/*; do
        [[ "$(cat "${dev}/serial" 2>/dev/null)" == VMLAB-STICK-1 ]] && { echo "${dev}"; return 0; }
    done
    return 1
}
plugged() { stick >/dev/null; }
# This boot's journal: what the service said may have been said between two phases, before this one began
since() { journalctl -b --no-pager -o cat "$@" 2>/dev/null; }
# A command on a terminal of its own in the account's session, each EXPECT answered with SEND (term.py)
session_terminal() {
    local steps=()
    while [[ $# -gt 0 && "$1" != -- ]]; do steps+=("$1"); shift; done
    shift
    in_terminal "${steps[@]}" -- runuser -u "${TEST_USER}" -- env XDG_RUNTIME_DIR="/run/user/${UID_TEST}" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${UID_TEST}/bus" \
        systemd-run --user --pty --wait --quiet --collect -- /usr/bin/bash -lc "$*"
}
SUDO=('\[sudo\] password for' "${TEST_USER}"$'\r')
runuser -u "${TEST_USER}" -- sudo -n true 2>/dev/null && SUDO=()

# --- 1. Off as shipped, the stick plugged in --------------------------------------------------------------------------
if [[ "${SUITE_PHASE}" == 1 ]]; then
    same "the key is off as the image ships" "$("${CONFIG}" PULL_KEY)" off
    [[ ! -e "${RULES}" ]] && ok "no rule while it is off" || not_ok "a rule while it is off" "$(cat "${RULES}")"
    same "the report says it is off" "$(record pull-key | jq -r .state)" off
    check "its unit is the image's" systemctl cat amethystora-pull-key.service
    usb_next '{"plug": ["stick"]}'
    continue_phase
fi

# --- 2. Chosen, turned on, a removal that is no pull -----------------------------------------------------------------
if [[ "${SUITE_PHASE}" == 2 ]]; then
    check "the stick shows up" wait_for 60 plugged
    udevadm settle
    LIST="$("${HELPER}" list)"
    if grep -qP '^[0-9a-f]{4}:[0-9a-f]{4}:VMLAB-STICK-1\t' <<<"${LIST}"; then ok "the stick is offered by its serial number"; else
        not_ok "the stick is not offered" "${LIST}"; fi
    ID="$(grep -oP '^[0-9a-f]{4}:[0-9a-f]{4}:VMLAB-STICK-1(?=\t)' <<<"${LIST}" | head -n1)"
    if grep -qE '^1d6b:' <<<"${LIST}"; then not_ok "a root hub was offered" "${LIST}"; else ok "no hub is offered"; fi
    "${HELPER}" choose "${ID}" && ok "the stick is chosen" || not_ok "the stick was not chosen"
    [[ ! -e "${RULES}" ]] && ok "choosing with the key off writes no rule" || not_ok "a rule with the key off" "$(cat "${RULES}")"
    # What the recipe asks, in a terminal: the explanation, then the question
    out="$(session_terminal 300 'Turn it on, knowing that\?' y "${SUDO[@]}" -- ame security pull-key lock 2>&1)"
    rc=$?
    if [[ ${rc} -eq 0 ]]; then ok "ame security pull-key lock"; else not_ok "ame security pull-key lock (exit ${rc})" "$(tail -n 20 <<<"${out}")"; fi
    grep -q "tether" <<<"${out}" && ok "the explanation is shown first" || not_ok "no explanation was shown" "$(tail -n 20 <<<"${out}")"
    same "the key is lock" "$("${CONFIG}" PULL_KEY)" lock
    check "the rule is written" test -f "${RULES}"
    same "it is the vendor and the product in hexadecimal, not the serial number" \
        "$(sed -n 2p "${RULES}" | grep -oE 'ENV\{PRODUCT\}=="[0-9a-f]+/[0-9a-f]+/\*"')" \
        "ENV{PRODUCT}==\"$(printf '%x/%x' "0x$(cut -d: -f1 <<<"${ID}")" "0x$(cut -d: -f2 <<<"${ID}")")/*\""
    ! grep -q VMLAB-STICK "${RULES}" && ok "the serial number is not in the rule" || not_ok "the serial number reached the rule"
    check "udev takes the rule" udevadm verify "${RULES}"
    check "the watcher accepts it as written" bash -c "eval \"\$(sed -n '/^pull_key_rule_as_written() {\$/,/^}\$/p' /usr/libexec/amethystora-security-watch)\"; pull_key_rule_as_written ${RULES}"
    same "the report says it is on" "$(record pull-key | jq -r .state)" on
    # A removal event for a stick that is still there: the service starts, waits a second, finds it and does nothing
    DEV="$(stick)"
    udevadm trigger --action=remove "${DEV}"
    if wait_for 30 sh -c "journalctl -b --no-pager -o cat -u amethystora-pull-key.service | grep -q 'the device is back'"; then
        ok "a removal that is not one: the service waited, found the stick and did nothing"
    else
        not_ok "the rule did not start the service, or it did not find the stick" "$(since -u amethystora-pull-key.service | tail -n 10)" \
            "$(since _COMM=systemd-udevd | tail -n 5)"
    fi
    sleep 3
    unlocked && ok "the screen stayed unlocked" || not_ok "the screen locked for a stick that was still plugged in"
    udevadm trigger --action=add "${DEV}"
    udevadm settle
    usb_next '{"unplug": ["stick"]}'
    continue_phase
fi

# --- 3. Pulled out: the screen locks -----------------------------------------------------------------------------------
if [[ "${SUITE_PHASE}" == 3 ]]; then
    check "the stick is gone" sh -c '! grep -qs VMLAB-STICK-1 /sys/bus/usb/devices/*/serial'
    if wait_for 60 locked; then ok "the screen locked when the stick was pulled out"; else
        not_ok "the screen did not lock" "$(since -u amethystora-pull-key.service | tail -n 10)" "$(loginctl show-session "${SESSION}" -p LockedHint)"; fi
    since -u amethystora-pull-key.service | grep -q 'the chosen device was pulled out, locking every session' &&
        ok "the journal says why" || not_ok "the journal does not say why" "$(since -u amethystora-pull-key.service | tail -n 10)"
    usb_next '{"plug": ["stick"]}'
    continue_phase
fi

# --- 4. Plugged back in: nothing unlocks. poweroff ----------------------------------------------------------------------
if [[ "${SUITE_PHASE}" == 4 ]]; then
    check "the stick is back" wait_for 60 plugged
    sleep 10
    locked && ok "plugging the stick back in unlocked nothing" || not_ok "the screen unlocked when the stick came back"
    loginctl unlock-session "${SESSION}"
    check "unlocked by hand" wait_for 60 unlocked
    "${CONFIG}" set PULL_KEY poweroff
    "${HELPER}" apply
    check "the rule is still there with poweroff" test -f "${RULES}"
    same "the report says it is on" "$(record pull-key | jq -r .state)" on
    # The stick pulled out as the machine powers off: run.mjs unplugs it and waits for the power off, then starts the machine
    usb_next '{"unplug": ["stick"]}'
    next_boot '{"powers_off": true}'
    reboot_and_continue
fi

# --- 5. After the power off --------------------------------------------------------------------------------------------
if [[ "${SUITE_PHASE}" == 5 ]]; then
    if journalctl -b -1 --no-pager -o cat 2>/dev/null | grep -q 'pull-key: the chosen device was pulled out, powering off'; then
        ok "the machine powered off because the stick was pulled out, and the journal says so"
    else
        not_ok "the last boot's journal has no power off by the key" "$(journalctl -b -1 --no-pager -o cat -u amethystora-pull-key.service 2>&1 | tail -n 10)"
    fi
    same "the key is still poweroff" "$("${CONFIG}" PULL_KEY)" poweroff
    "${CONFIG}" set PULL_KEY off
    "${HELPER}" apply
    [[ ! -e "${RULES}" ]] && ok "off takes the rule away" || not_ok "off left the rule"
    same "the report says it is off" "$(record pull-key | jq -r .state)" off
    "${HELPER}" forget
    same "no device is chosen" "$("${HELPER}" status | jq -r .device)" null
fi
finish
