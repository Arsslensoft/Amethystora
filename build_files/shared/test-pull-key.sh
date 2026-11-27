#!/usr/bin/bash
# Pull the key (ame security pull-key), for 20-tests.sh: the helper against a stand-in /sys, a stand-in login manager and
# journal, and a settings file in a temporary folder. Which devices it offers, what it refuses to choose, the one line it writes
# for udev and that the security watcher accepts exactly that, and what the service does with a removal: nothing when the
# device came back, when the computer is going to sleep or has just woken, or when the key is off; a lock or a power off when it
# is gone. Nothing here writes to /etc or /var.
#   bash test-pull-key.sh [HELPER [CONFIG [WATCHER [UNIT]]]]

set -euo pipefail

HELPER="${1:-/usr/libexec/amethystora-pull-key}"
CONFIG="${2:-/usr/libexec/amethystora-security-config}"
WATCH="${3:-/usr/libexec/amethystora-security-watch}"
UNIT="${4:-/usr/lib/systemd/system/amethystora-pull-key.service}"
T="$(realpath "$(mktemp -d)")"
trap 'rm -rf "${T}"' EXIT
chmod 0755 "${T}"
fail() { echo "test-pull-key: $*" >&2; exit 1; }

export AMETHYSTORA_PULLKEY_ROOT="${T}/root"
export AMETHYSTORA_PULLKEY_CONFIG="${CONFIG}"
export AMETHYSTORA_PULLKEY_WAIT=0
export AMETHYSTORA_PULLKEY_NOW_MS=1000000
export AMETHYSTORA_SECURITY_CONF="${T}/security.conf"
export AMETHYSTORA_SECURITY_NOTES="${T}/notes"
# The settings helper has the helper write or take away the rule when the key changes
export AMETHYSTORA_PULLKEY_HELPER="${HELPER}"
: >"${AMETHYSTORA_SECURITY_CONF}"
R="${AMETHYSTORA_PULLKEY_ROOT}"
USB="${R}/sys/bus/usb/devices"
RULES="${R}/etc/udev/rules.d/90-amethystora-pull-key.rules"
DEVICE="${R}/var/lib/amethystora/pull-key/device"
LOG="${T}/log"
mkdir -p "${R}/bin" "${USB}"
: >"${LOG}"

run() { python3 -I "${HELPER}" "$@"; }

# The programs the service calls, as stand-ins that say what they were asked
cat >"${R}/bin/loginctl" <<EOF
#!/usr/bin/bash
echo "loginctl \$*" >>"${LOG}"
EOF
cat >"${R}/bin/systemctl" <<EOF
#!/usr/bin/bash
echo "systemctl \$*" >>"${LOG}"
EOF
cat >"${R}/bin/busctl" <<EOF
#!/usr/bin/bash
[[ -e "${T}/sleeping" ]] && echo "b true" || echo "b false"
EOF
cat >"${R}/bin/journalctl" <<EOF
#!/usr/bin/bash
[[ " \$* " == *" MESSAGE_ID=8811e6df2a8e40f58a94cea26f8ebf14 "* ]] || exit 1
# Only root's record: an account can log the same message id
[[ " \$* " == *" _UID=0 "* ]] || exit 1
[[ -e "${T}/journal-fails" ]] && exit 1
[[ -e "${T}/wake-us" ]] && printf '{"__MONOTONIC_TIMESTAMP":"%s"}\n' "\$(<"${T}/wake-us")"
exit 0
EOF
chmod +x "${R}/bin/"*

# usb NAME VENDOR PRODUCT SERIAL PRODUCT-NAME [CLASS]: a device in the stand-in /sys
usb() {
    mkdir -p "${USB}/$1"
    echo "$2" >"${USB}/$1/idVendor"
    echo "$3" >"${USB}/$1/idProduct"
    [[ -z "$4" ]] || printf '%s\n' "$4" >"${USB}/$1/serial"
    echo "$5" >"${USB}/$1/product"
    echo "${6:-00}" >"${USB}/$1/bDeviceClass"
}
usb 1-1 0781 5581 4C530001230529101103 "Ultra Fit"
usb 1-2 046d c52b "" "USB Receiver"
usb 1-3 046d c534 "A B/c" "Fancy Receiver"
usb usb1 1d6b 0002 "0000:00:14.0" "xHCI Host Controller" 09
usb 1-4 05e3 0610 "HUBSERIAL1" "USB Hub" 09
usb 1-5 0781 5581 "OTHERSTICK2" "Ultra Fit"
STICK=0781:5581:4C530001230529101103

# --- What can be chosen: a serial number of its own, and nothing that stands for others -------------------------------------

LIST="$(run list)"
grep -qxP "${STICK}\tUltra Fit" <<<"${LIST}" || fail "the stick is not offered: ${LIST}"
grep -qxP "046d:c534:A_B_c\tFancy Receiver" <<<"${LIST}" || fail "a serial is not written as udev writes it: ${LIST}"
grep -q 'c52b' <<<"${LIST}" && fail "a device with no serial number was offered"
grep -qE '1d6b|05e3' <<<"${LIST}" && fail "a hub or a root hub was offered"
[[ "$(run status | jq -r '.device')" == null ]] || fail "a device is chosen before anyone chose one"

# --- The key, as the settings helper has it ---------------------------------------------------------------------------------

[[ "$("${CONFIG}" PULL_KEY)" == off ]] || fail "it is not off as shipped"
[[ "$("${CONFIG}" --list --json | jq -r '.settings[] | select(.key == "PULL_KEY") | "\(.group) \(.sends) \(.allowed | join(","))"')" == \
    "logins none off,lock,poweroff" ]] || fail "the key's group or values"
"${CONFIG}" --list --json | jq -e '.settings[] | select(.key == "PULL_KEY") | (.explain | length > 0) and (.text | length > 0)' >/dev/null ||
    fail "the key has no explanation"
"${CONFIG}" set PULL_KEY sometimes 2>/dev/null && fail "set took a value the key does not have"
"${CONFIG}" --is PULL_KEY lock poweroff && fail "--is says it is on"
# No profile but off and default touches it
"${CONFIG}" set PULL_KEY poweroff
for profile in light balanced thorough; do
    "${CONFIG}" profile "${profile}"
    [[ "$("${CONFIG}" PULL_KEY)" == poweroff ]] || fail "profile ${profile} changed it"
done
"${CONFIG}" profile off
[[ "$("${CONFIG}" PULL_KEY)" == off ]] || fail "profile off left it on"
"${CONFIG}" set PULL_KEY lock
"${CONFIG}" profile default
[[ "$("${CONFIG}" PULL_KEY)" == off ]] || fail "profile default did not put it back"

# --- Choosing -----------------------------------------------------------------------------------------------------------------

for bad in "" "nonsense" "0781:5581" "0781:5581:" "0781:5581:NOTPLUGGED" "0781:5581:4C530001230529101103\";RUN+=\"/tmp/evil" \
    "0781:5581:x y" "0781:5581:../x" "046d:c52b:" "1d6b:0002:0000:00:14.0" "05e3:0610:HUBSERIAL1" "0781:5581:$(printf 'A%.0s' {1..65})"; do
    if run choose "${bad}" 2>/dev/null; then fail "chose ${bad}"; fi
done
[[ ! -e "${DEVICE}" && ! -e "${RULES}" ]] || fail "a refused ID wrote something"
# Off: the device is kept, and no rule is written (off costs nothing)
run choose "${STICK}"
[[ "$(<"${DEVICE}")" == "${STICK}" ]] || fail "the device is not kept"
[[ ! -e "${RULES}" ]] || fail "a rule while the key is off"
[[ "$(run status | jq -c '[.key, .device, .name, .plugged_in, .rule]')" == '["off","'"${STICK}"'","Ultra Fit",true,false]' ]] ||
    fail "status: $(run status)"

# --- The rule -------------------------------------------------------------------------------------------------------------------

"${CONFIG}" set PULL_KEY lock
run apply
[[ -f "${RULES}" ]] || fail "no rule with the key on"
[[ "$(wc -l <"${RULES}")" == 3 ]] || fail "the rule is not two comments and a line: $(cat "${RULES}")"
[[ "$(sed -n 2p "${RULES}")" == "# device: ${STICK}" ]] || fail "the rule does not say which device it is for: $(sed -n 2p "${RULES}")"
[[ "$(sed -n 3p "${RULES}")" == 'ACTION=="remove", SUBSYSTEM=="usb", ENV{DEVTYPE}=="usb_device", ENV{PRODUCT}=="781/5581/*", RUN+="/usr/bin/systemctl --no-block start amethystora-pull-key.service"' ]] ||
    fail "the rule is not as the kernel writes PRODUCT: $(sed -n 3p "${RULES}")"
sed -n 3p "${RULES}" | grep -qF "4C530001230529101103" && fail "the serial number reached the rule line"
[[ "$(stat -c %a "${RULES}")" == 644 ]] || fail "the rule's mode"
# Zeros are dropped as the kernel drops them
usb 1-6 0000 0002 "ZEROSERIAL" "Odd"
run choose 0000:0002:ZEROSERIAL
grep -q 'ENV{PRODUCT}=="0/2/\*"' "${RULES}" || fail "zeros in PRODUCT: $(sed -n 3p "${RULES}")"
run choose "${STICK}"
# udev reads the line the way the kernel's removal says it
grep -q 'ENV{PRODUCT}=="781/5581/\*"' "${RULES}" || fail "the rule was not rewritten"
if command -v udevadm >/dev/null && udevadm verify --help >/dev/null 2>&1; then
    udevadm verify "${RULES}" >/dev/null 2>&1 || fail "udevadm verify refuses the rule"
fi

# The watcher accepts exactly what is written, and nothing added to it
eval "$(sed -n '/^pull_key_rule_as_written() {$/,/^}$/p' "${WATCH}")"
pull_key_rule_as_written "${RULES}" || fail "the watcher does not accept the rule as written"
cp "${RULES}" "${T}/bad"
printf 'ACTION=="add", RUN+="/tmp/evil"\n' >>"${T}/bad"
if pull_key_rule_as_written "${T}/bad"; then fail "the watcher took a line it should not"; fi
sed 's#start amethystora-pull-key.service"#start amethystora-pull-key.service ; /tmp/evil"#' "${RULES}" >"${T}/bad"
if pull_key_rule_as_written "${T}/bad"; then fail "the watcher took a changed command"; fi
sed 's#/usr/bin/systemctl#/tmp/evil#' "${RULES}" >"${T}/bad"
if pull_key_rule_as_written "${T}/bad"; then fail "the watcher took another program"; fi
sed 's#ENV{PRODUCT}=="781/5581/\*"#ENV{PRODUCT}=="*"#' "${RULES}" >"${T}/bad"
if pull_key_rule_as_written "${T}/bad"; then fail "the watcher took a rule for every device"; fi
sed 's#ENV{PRODUCT}=="781/5581/\*"#ENV{PRODUCT}=="781/5581/*|1/2/*"#' "${RULES}" >"${T}/bad"
if pull_key_rule_as_written "${T}/bad"; then fail "the watcher took two devices in one match"; fi
{ cat "${RULES}"; sed -n 3p "${RULES}"; } >"${T}/bad"
if pull_key_rule_as_written "${T}/bad"; then fail "the watcher took two rule lines"; fi
sed 's#^ACTION=="remove"#ACTION=="remove", ENV{ID_SERIAL_SHORT}=="x"#' "${RULES}" >"${T}/bad"
if pull_key_rule_as_written "${T}/bad"; then fail "the watcher took an extra match"; fi
# ...and it is the drift check's, which knows the file by name
grep -q 'udev/rules.d/90-amethystora-pull-key.rules \]\] && pull_key_rule_as_written' "${WATCH}" || fail "the drift check does not name the file"

# The rule is the record of the device: its comment and its PRODUCT must name the same one, in the helper's eyes and the watcher's
cp "${RULES}" "${T}/good"
[[ "$(run status | jq -r '.rule')" == true ]] || fail "status does not say the rule is the chosen device's: $(run status)"
sed 's#^ACTION=="remove"\(.*\)781/5581#ACTION=="remove"\11/2#' "${T}/good" >"${RULES}"
grep -q 'PRODUCT}=="1/2/' "${RULES}" || fail "the test's own edit of the rule"
[[ "$(run status | jq -r '.rule')" == false ]] || fail "a rule for another vendor and product than its comment is called the chosen device's"
if pull_key_rule_as_written "${RULES}"; then fail "the watcher took a rule whose PRODUCT is not its comment's device"; fi
sed 's#^\# device: 0781:5581:#\# device: 0781:5582:#' "${T}/good" >"${RULES}"
[[ "$(run status | jq -r '.rule')" == false ]] || fail "a comment for another product than the rule is called the chosen device's"
if pull_key_rule_as_written "${RULES}"; then fail "the watcher took a comment that is not the rule's device"; fi
sed '/^# device: /d' "${T}/good" >"${RULES}"
if pull_key_rule_as_written "${RULES}"; then fail "the watcher took a rule with no device comment"; fi
sed 's#^\# device: .*#\# device: 0781:5581:x y#' "${T}/good" >"${RULES}"
if pull_key_rule_as_written "${RULES}"; then fail "the watcher took a serial with a space"; fi
cp "${T}/good" "${RULES}"
pull_key_rule_as_written "${RULES}" || fail "the watcher no longer takes the rule as written"
# The service acts on the rule's device, not on the file in /var/lib: a device record changed to something always plugged in
# (a built-in webcam) leaves the rule, and the service, as they were
echo "046d:c534:A_B_c" >"${DEVICE}"
[[ "$(run status | jq -r '.rule')" == false ]] || fail "a record that is not the rule's device is called on"
echo "${STICK}" >"${DEVICE}"
[[ "$(run status | jq -r '.rule')" == true ]] || fail "the record put back"
# apply leaves a rule that is right alone: the same file, not written again
INODE="$(stat -c %i "${RULES}")"
run apply
[[ "$(stat -c %i "${RULES}")" == "${INODE}" ]] || fail "apply wrote a rule that was right already"

# --- Off, by any way, takes the rule away; the key's own commands do it ---------------------------------------------------------------
"${CONFIG}" set PULL_KEY off
[[ ! -e "${RULES}" ]] || fail "set PULL_KEY off left the rule (the settings helper applies it)"
"${CONFIG}" set PULL_KEY lock
[[ -f "${RULES}" ]] || fail "set PULL_KEY lock wrote no rule for the device chosen earlier"
"${CONFIG}" profile off
[[ ! -e "${RULES}" ]] || fail "profile off left the rule"
"${CONFIG}" set PULL_KEY poweroff
[[ -f "${RULES}" ]] || fail "set PULL_KEY poweroff wrote no rule"
"${CONFIG}" profile default
[[ ! -e "${RULES}" ]] || fail "profile default left the rule"
# A key turned off by hand: the rule stays until the service's stop step (apply) takes it away
"${CONFIG}" set PULL_KEY lock
[[ -f "${RULES}" ]] || fail "lock wrote no rule"
sed -i 's/^PULL_KEY=.*/PULL_KEY=off/' "${AMETHYSTORA_SECURITY_CONF}"
[[ -f "${RULES}" ]] || fail "the test's hand edit took the rule away"
run apply
[[ ! -e "${RULES}" ]] || fail "apply left the rule of a key that is off"
grep -qx 'ExecStopPost=-/usr/libexec/amethystora-pull-key apply' "${UNIT}" || fail "the unit does not take a stale rule away"
"${CONFIG}" set PULL_KEY lock

# --- Off takes the rule away, a hand-edited off leaves it but the service does nothing ---------------------------------------------
"${CONFIG}" set PULL_KEY off
run apply
[[ ! -e "${RULES}" ]] || fail "off left the rule"
[[ -e "${DEVICE}" ]] || fail "off forgot the device"
"${CONFIG}" set PULL_KEY lock
run apply
[[ -f "${RULES}" ]] || fail "on again wrote no rule"
run forget
[[ ! -e "${RULES}" && ! -e "${DEVICE}" ]] || fail "forget left something"
run choose "${STICK}"
[[ -f "${RULES}" ]] || fail "choosing with the key on writes the rule"

# --- The service: what a removal does ------------------------------------------------------------------------------------------
act() { : >"${LOG}"; run act; }

# The device is there: it came back, or it was another of its make
act
[[ ! -s "${LOG}" ]] || fail "it acted with the device plugged in: $(cat "${LOG}")"
# A removal of another device of the same make: the one chosen is still there, and 1-5 is not it
rm -rf "${USB}/1-5"
act
[[ ! -s "${LOG}" ]] || fail "it acted for another device of the same make: $(cat "${LOG}")"
usb 1-5 0781 5581 "OTHERSTICK2" "Ultra Fit"

# The chosen one is gone, and the other of its make is not it
rm -rf "${USB}/1-1"
act
[[ "$(<"${LOG}")" == "loginctl lock-sessions" ]] || fail "lock: $(cat "${LOG}")"
# ...once the stick is plugged in again, nothing
usb 1-1 0781 5581 4C530001230529101103 "Ultra Fit"
act
[[ ! -s "${LOG}" ]] || fail "it acted after the device came back: $(cat "${LOG}")"

# Power off: in order, without waiting for what holds it back
"${CONFIG}" set PULL_KEY poweroff
rm -rf "${USB}/1-1"
act
[[ "$(<"${LOG}")" == "systemctl poweroff -i" ]] || fail "poweroff: $(cat "${LOG}")"

# Going to sleep, and having just woken, are not pulls
touch "${T}/sleeping"
act
[[ ! -s "${LOG}" ]] || fail "it acted while the computer was going to sleep: $(cat "${LOG}")"
rm -f "${T}/sleeping"
echo $(((AMETHYSTORA_PULLKEY_NOW_MS - 3000) * 1000)) >"${T}/wake-us"
act
[[ ! -s "${LOG}" ]] || fail "it acted three seconds after waking: $(cat "${LOG}")"
echo $(((AMETHYSTORA_PULLKEY_NOW_MS - 60000) * 1000)) >"${T}/wake-us"
act
[[ "$(<"${LOG}")" == "systemctl poweroff -i" ]] || fail "it did nothing a minute after waking: $(cat "${LOG}")"
# A journal that cannot be read does not make a removal go unnoticed
touch "${T}/journal-fails"
act
[[ "$(<"${LOG}")" == "systemctl poweroff -i" ]] || fail "an unreadable journal ignored a removal: $(cat "${LOG}")"
rm -f "${T}/journal-fails" "${T}/wake-us"

# Off, whatever the rule says
"${CONFIG}" set PULL_KEY off
act
[[ ! -s "${LOG}" ]] || fail "it acted with the key off: $(cat "${LOG}")"
# No device chosen
"${CONFIG}" set PULL_KEY lock
run forget
act
[[ ! -s "${LOG}" ]] || fail "it acted with no device chosen: $(cat "${LOG}")"

# --- The unit ---------------------------------------------------------------------------------------------------------------------
grep -qx 'ExecCondition=/usr/libexec/amethystora-security-config --is PULL_KEY lock poweroff' "${UNIT}" || fail "the unit does not read its key"
grep -qx 'ExecStart=/usr/libexec/amethystora-pull-key act' "${UNIT}" || fail "the unit's command"
grep -q '^\[Install\]' "${UNIT}" && fail "the unit is enabled by something: only the rule starts it"
if [[ -x /usr/bin/systemd-analyze && -x /usr/libexec/amethystora-pull-key ]]; then
    systemd-analyze verify --man=no --recursive-errors=no "${UNIT}" >/dev/null 2>&1 || fail "systemd-analyze verify refuses the unit"
fi

echo "test-pull-key: choosing, the rule, the watcher's check and what a removal does"
