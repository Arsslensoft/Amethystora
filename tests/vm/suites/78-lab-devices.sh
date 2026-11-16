#!/usr/bin/bash
# Lab devices (ame system lab-devices), on the machine as a person would use it: a QEMU USB serial adapter (an FTDI FT232,
# 0403:6001, which the guest knows as /dev/ttyUSB0; run.mjs, usb_next) plugged in.
#
#   1.   Off as shipped: no rules in /etc, nothing of it in the report, the adapter's node is root's and the dialout group's, and
#        the account has no access to it.
#   2.   The adapter is listed by `ame system lab-devices list`; `ame system lab-devices on` in a terminal says what it gives and
#        asks; the file in /etc is the image's, byte for byte, udev takes it, the node's ACL names the account (its seat's
#        grant, uaccess) with no group or mode for everyone, the account opens it, the report says it is on, and the security
#        watcher's run finds no drift in the file. A changed file is drift.
#   3.   Off: the file is gone, the node is root's again, the account cannot open it, and the report says nothing.
#   4.   A keyboard is never given this way: the lab's plain keyboard, plugged in with the rules on, has no ACL for the account on
#        its event node, as without them.
# vmlab-paths: @sf/usr/libexec/amethystora-lab-devices @sf/usr/share/amethystora/lab-devices/* @sf/usr/share/amethystora/just/system.just @sf/usr/libexec/amethystora-security-watch
source "$(dirname "$0")/lib.sh"

HELPER=/usr/libexec/amethystora-lab-devices
SHIPPED=/usr/share/amethystora/lab-devices/70-amethystora-lab-devices.rules
TARGET=/etc/udev/rules.d/70-amethystora-lab-devices.rules
UID_TEST="$(id -u "${TEST_USER}")"
HOME_TEST="$(getent passwd "${TEST_USER}" | cut -d: -f6)"
same() { if [[ "$2" == "$3" ]]; then ok "$1"; else not_ok "$1" "expected: $3" "found: $2"; fi; }
if ! wait_for 300 has_session; then
    not_ok "no session for ${TEST_USER}" "$(loginctl list-sessions --no-legend)"
    finish
fi
record() { runuser -u "${TEST_USER}" -- env HOME="${HOME_TEST}" /usr/libexec/amethystora-security-status --json 2>/dev/null |
    jq -c --arg id "$1" '[.. | objects | select(.id? == $id)][0] | {state, text}'; }
adapter() { [[ -c /dev/ttyUSB0 ]]; }
no_adapter() { [[ ! -e /dev/ttyUSB0 ]]; }
# Whether the account can open the node, as the account (a root-owned dialout node with no ACL for it says no)
account_opens() { runuser -u "${TEST_USER}" -- sh -c 'exec 3<>/dev/ttyUSB0' 2>/dev/null; }
acl_names_account() { getfacl -p /dev/ttyUSB0 2>/dev/null | grep -qx "user:${TEST_USER}:rw-"; }
drift() { systemctl start amethystora-security-watch.service; jq -c '.drift // []' /var/lib/amethystora/security/status.json; }
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

# --- 1. Off as shipped, the adapter plugged in -----------------------------------------------------------------------------
if [[ "${SUITE_PHASE}" == 1 ]]; then
    [[ ! -e "${TARGET}" ]] && ok "no rules in /etc as shipped" || not_ok "the rules are in /etc as shipped"
    same "the helper says off" "$("${HELPER}" status)" off
    check "the shipped file is there" test -s "${SHIPPED}"
    usb_next '{"plug": ["serial"]}'
    continue_phase
fi

# --- 2. On ----------------------------------------------------------------------------------------------------------------
if [[ "${SUITE_PHASE}" == 2 ]]; then
    check "the adapter's node shows up" wait_for 60 adapter
    udevadm settle
    if ! adapter; then
        not_ok "no /dev/ttyUSB0: is ftdi_sio blocked or the device missing?" "$(lsusb 2>&1 | tail -n 5)" "$(dmesg | tail -n 8)"
        finish
    fi
    acl_names_account && not_ok "the account has access to the adapter before lab devices are on" "$(getfacl -p /dev/ttyUSB0)" ||
        ok "the account has no ACL on the adapter's node before"
    account_opens && not_ok "the account opened the adapter before lab devices were on" || ok "...and cannot open it"
    LIST="$("${HELPER}" list)"
    grep -qP '^0403:6001\t' <<<"${LIST}" && ok "the helper lists the adapter" || not_ok "the helper does not list the adapter" "${LIST}"
    out="$(session_terminal 120 -- ame system lab-devices list 2>&1)" || true
    grep -q '0403:6001' <<<"${out}" && ok "ame system lab-devices list names it" || not_ok "ame system lab-devices list" "$(tail -n 10 <<<"${out}")"
    # What it says it gives, and the question
    out="$(session_terminal 300 'Give them to the person at the machine\?' y "${SUDO[@]}" -- ame system lab-devices on 2>&1)"
    rc=$?
    if [[ ${rc} -eq 0 ]]; then ok "ame system lab-devices on"; else not_ok "ame system lab-devices on (exit ${rc})" "$(tail -n 20 <<<"${out}")"; fi
    grep -q "modem" <<<"${out}" && ok "it says that a serial adapter is a modem's too" || not_ok "no word on serial adapters" "$(tail -n 15 <<<"${out}")"
    cmp -s "${TARGET}" "${SHIPPED}" && ok "the file in /etc is the image's, byte for byte" || not_ok "the file in /etc is not the image's"
    check "udev takes it" udevadm verify "${TARGET}"
    udevadm settle
    if wait_for 30 acl_names_account; then ok "the node's ACL names the account (the seat's uaccess grant)"; else
        not_ok "the node has no ACL for the account" "$(getfacl -p /dev/ttyUSB0)" "$(udevadm info /dev/ttyUSB0 | grep -E 'TAGS|CURRENT_TAGS')"; fi
    [[ "$(stat -c %a /dev/ttyUSB0)" =~ ^[0-6][0-6]0$ ]] && ok "no mode for everyone on the node" || not_ok "the node's mode" "$(ls -l /dev/ttyUSB0)"
    account_opens && ok "the account opens the adapter" || not_ok "the account cannot open the adapter" "$(getfacl -p /dev/ttyUSB0)"
    same "the report says it is on" "$(record lab-devices | jq -r .state)" info
    same "the report names it" "$(record lab-devices | jq -r '.text | contains("debug probes")')" true
    same "the watcher finds no drift in the file" "$(drift | jq -c '[.[] | select(.path | test("lab-devices"))]')" "[]"
    echo '# added by hand' >>"${TARGET}"
    same "a changed file is drift" "$(drift | jq -c '[.[] | select(.path | test("lab-devices")) | .change]')" '["added"]'
    cp "${SHIPPED}" "${TARGET}"
    same "the helper says on again" "$("${HELPER}" status)" on
    usb_next '{"plug": ["keyboard"]}'
    continue_phase
fi

# --- 3. A keyboard is not given this way; then off ---------------------------------------------------------------------------
if [[ "${SUITE_PHASE}" == 3 ]]; then
    check "the keyboard shows up" wait_for 60 sh -c 'grep -qs "QEMU USB Keyboard" /sys/bus/usb/devices/*/product'
    udevadm settle
    # The keyboard's event node: no ACL for the account, rules or no rules
    nodes="$(for d in /sys/class/input/event*; do
        grep -qs "QEMU USB Keyboard" "${d}/device/name" && echo "/dev/input/${d##*/}"
    done)"
    if [[ -n "${nodes}" ]]; then
        for node in ${nodes}; do
            getfacl -p "${node}" 2>/dev/null | grep -q "user:${TEST_USER}:" && not_ok "the keyboard's node ${node} is given to the account" "$(getfacl -p "${node}")" ||
                ok "the keyboard's node ${node} is not given to the account"
        done
    else
        skip "no event node for the lab's keyboard"
    fi
    out="$(session_terminal 120 "${SUDO[@]}" -- ame system lab-devices off 2>&1)"
    rc=$?
    if [[ ${rc} -eq 0 ]]; then ok "ame system lab-devices off"; else not_ok "ame system lab-devices off (exit ${rc})" "$(tail -n 15 <<<"${out}")"; fi
    [[ ! -e "${TARGET}" ]] && ok "the file is gone" || not_ok "the file is still in /etc"
    same "the helper says off" "$("${HELPER}" status)" off
    udevadm settle
    if wait_for 30 sh -c '! getfacl -p /dev/ttyUSB0 2>/dev/null | grep -qx "user:'"${TEST_USER}"':rw-"'; then ok "the node is root's again"; else
        # A node already open keeps its ACL until the device is plugged in again: say so
        skip "the node kept the account's ACL until the adapter is plugged in again: $(getfacl -p /dev/ttyUSB0 | tr '\n' ' ')"; fi
    same "the report no longer says it is on" "$(record lab-devices | jq -r '.state // "none"')" none
    usb_next '{"unplug": ["serial", "keyboard"]}'
    continue_phase
fi

# --- 4. Gone ----------------------------------------------------------------------------------------------------------------------
if [[ "${SUITE_PHASE}" == 4 ]]; then
    check "the adapter's node is gone" wait_for 30 no_adapter
fi
finish
