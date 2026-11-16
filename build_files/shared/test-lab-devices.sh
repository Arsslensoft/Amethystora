#!/usr/bin/bash
# Lab devices (ame system lab-devices), for 20-tests.sh: the file the image ships holds only `TAG+="uaccess"` rules by vendor and
# product (never a group, a mode, a link, a program to run, a keyboard's interface or an ID the system already gives), each with a
# comment saying what it is and where its ID comes from, and it sorts before the files that take a keyboard's grant back; and the
# helper against a stand-in root: on copies the file byte for byte, off takes it away, a changed file is said so, and which of the
# devices plugged in it covers.
#   bash test-lab-devices.sh [HELPER [RULES [WATCHER]]]

set -euo pipefail

HELPER="${1:-/usr/libexec/amethystora-lab-devices}"
RULES="${2:-/usr/share/amethystora/lab-devices/70-amethystora-lab-devices.rules}"
WATCH="${3:-/usr/libexec/amethystora-security-watch}"
T="$(realpath "$(mktemp -d)")"
trap 'rm -rf "${T}"' EXIT
chmod 0755 "${T}"
fail() { echo "test-lab-devices: $*" >&2; exit 1; }

# --- The shipped file ----------------------------------------------------------------------------------------------------------

[[ "$(basename "${RULES}")" == 70-amethystora-lab-devices.rules ]] || fail "the file's name"
grep -c . "${RULES}" >/dev/null
USB_RULE='^SUBSYSTEM=="usb", ENV\{DEVTYPE\}=="usb_device", ATTR\{idVendor\}=="[0-9a-f]{4}", ATTR\{idProduct\}=="[0-9a-f]{4}(\|[0-9a-f]{4})*", TAG\+="uaccess"$'
TTY_RULE='^SUBSYSTEM=="tty", ATTRS\{idVendor\}=="[0-9a-f]{4}", ATTRS\{idProduct\}=="[0-9a-f]{4}(\|[0-9a-f]{4})*", TAG\+="uaccess"$'
HID_RULE='^SUBSYSTEM=="hidraw", ATTRS\{idVendor\}=="[0-9a-f]{4}", ATTRS\{idProduct\}=="[0-9a-f]{4}(\|[0-9a-f]{4})*", TAG\+="uaccess"$'
previous=""
count=0
declare -A SEEN=()
while IFS= read -r line; do
    if [[ -z "${line}" || "${line}" == '#'* ]]; then
        [[ -n "${line}" ]] && previous="${line}" || previous=""
        continue
    fi
    count=$((count + 1))
    grep -qE "${USB_RULE}|${TTY_RULE}|${HID_RULE}" <<<"${line}" || fail "a line that is not a uaccess rule by vendor and product: ${line}"
    [[ "${previous}" == '# source: '?* ]] || fail "no source for the IDs of: ${line}"
    # No pair twice for the same node kind, and never the unprogrammed Cypress chip's own ID or a vendor with no product
    subsystem="$(sed -E 's/^SUBSYSTEM=="([a-z]+)".*/\1/' <<<"${line}")"
    vendor="$(grep -oE 'idVendor\}=="[0-9a-f]{4}"' <<<"${line}" | grep -oE '[0-9a-f]{4}')"
    for product in $(grep -oE 'idProduct\}=="[^"]+"' <<<"${line}" | sed -E 's/.*=="(.*)"/\1/' | tr '|' ' '); do
        [[ -z "${SEEN["${subsystem}:${vendor}:${product}"]+set}" ]] || fail "${subsystem} ${vendor}:${product} twice"
        SEEN["${subsystem}:${vendor}:${product}"]=1
        [[ "${vendor}:${product}" != 04b4:8613 ]] || fail "the unprogrammed FX2 chip's own ID, which other devices share"
    done
    previous=""
done <"${RULES}"
[[ "${count}" -ge 15 ]] || fail "only ${count} rules"
# Nothing that gives anything to a group, to everyone, by a class or a node's name, or runs something
if grep -vE '^[[:space:]]*(#|$)' "${RULES}" | grep -E 'MODE|GROUP|OWNER|SYMLINK|RUN|PROGRAM|IMPORT|KERNEL|bInterfaceClass|bDeviceClass|ID_USB_INTERFACES'; then
    fail "a rule gives by group, mode or class, names a node, or runs something"
fi
[[ "$(grep -vE '^[[:space:]]*(#|$)' "${RULES}" | grep -c 'TAG+="uaccess"')" == "${count}" ]] || fail "a rule without uaccess"
# A keyboard's interface is never named by class here, and the vendors whose keyboards' nodes the image takes back are only
# ever named by a product that is no keyboard: none of those is named, but Atmel's debuggers' vendor-only HID interfaces
if grep -E '^SUBSYSTEM=="hidraw"' "${RULES}" | grep -vE 'idVendor\}=="(0d28|03eb)"' | grep .; then
    fail "a hidraw rule for a vendor whose configuration interfaces are not known to be vendor-defined only"
fi
# It sorts before the files that take a keyboard's grant back, and before the seat's own (73-seat-late.rules), which turns the tag into one
name="$(basename "${RULES}")"
for later in 71-amethystora-keyboard-interfaces.rules 72-amethystora-keyboards-not-shared.rules 73-seat-late.rules; do
    [[ "${name}" < "${later}" ]] || fail "${name} does not sort before ${later}"
done
# What the system's own hardware database already gives to the person at the seat is not written again
for db in /usr/lib/udev/hwdb.d/70-software-radio.hwdb /usr/lib/udev/hwdb.d/70-analyzers.hwdb /usr/lib/udev/hwdb.d/70-maker-tools.hwdb; do
    [[ -r "${db}" ]] || continue
    while read -r known; do
        id="$(tr 'A-F' 'a-f' <<<"${known}" | sed -E 's/^usb:v([0-9a-f]{4})p([0-9a-f]{4}).*/\1:\2/')"
        for key in "${!SEEN[@]}"; do
            [[ "${key}" == usb:${id} ]] && fail "${id} is given by ${db} already"
        done
    done < <(grep -E '^usb:v[0-9A-Fa-f]{4}p[0-9A-Fa-f]{4}' "${db}")
done
if command -v udevadm >/dev/null && udevadm verify --help >/dev/null 2>&1; then
    udevadm verify "${RULES}" >/dev/null 2>&1 || fail "udevadm verify refuses the file"
fi
grep -q 'cmp -s "${etc}" "${LAB_DEVICES_RULES}"' "${WATCH}" || fail "the drift check does not know the file"
grep -qx 'LAB_DEVICES_RULES=/usr/share/amethystora/lab-devices/70-amethystora-lab-devices.rules' "${WATCH}" || fail "the watcher's copy of the path"

# --- The helper, against a stand-in root --------------------------------------------------------------------------------------------

export AMETHYSTORA_LABDEV_ROOT="${T}/root"
R="${AMETHYSTORA_LABDEV_ROOT}"
mkdir -p "${R}/usr/share/amethystora/lab-devices" "${R}/sys/bus/usb/devices"
cp "${RULES}" "${R}/usr/share/amethystora/lab-devices/"
TARGET="${R}/etc/udev/rules.d/70-amethystora-lab-devices.rules"
run() { python3 -I "${HELPER}" "$@"; }
usb() { # NAME VENDOR PRODUCT PRODUCT-NAME
    mkdir -p "${R}/sys/bus/usb/devices/$1"
    echo "$2" >"${R}/sys/bus/usb/devices/$1/idVendor"
    echo "$3" >"${R}/sys/bus/usb/devices/$1/idProduct"
    echo "$4" >"${R}/sys/bus/usb/devices/$1/product"
}

[[ "$(run status)" == off ]] || fail "it is not off as shipped"
[[ -z "$(run list)" ]] || fail "nothing is plugged in"
usb 1-1 0483 374b "STM32 STLink"
usb 1-2 0403 6001 "FT232R USB UART"
usb 1-3 046d c52b "USB Receiver"
usb 1-4 0bda 2838 "RTL2838UHIDIR"
usb 1-5 1d50 6108 "LimeSDR-USB"
LIST="$(run list)"
grep -qP '^0483:374b\tSTM32 STLink\tST-LINK debug probes' <<<"${LIST}" || fail "the probe is not listed: ${LIST}"
grep -qP '^0403:6001\tFT232R USB UART\t' <<<"${LIST}" || fail "the serial adapter is not listed: ${LIST}"
grep -qP '^1d50:6108\tLimeSDR-USB\t' <<<"${LIST}" || fail "the LimeSDR is not listed: ${LIST}"
grep -q 'c52b' <<<"${LIST}" && fail "a receiver is listed"
grep -q '2838' <<<"${LIST}" && fail "a radio the system already gives is listed"
[[ "$(wc -l <<<"${LIST}")" == 3 ]] || fail "listed once each: ${LIST}"
WHAT="$(run what)"
grep -qP '^ST-LINK debug probes.*\t0483:3744 ' <<<"${WHAT}" || fail "what: ${WHAT}"

run on
[[ -f "${TARGET}" ]] || fail "on copied nothing"
cmp -s "${TARGET}" "${RULES}" || fail "on did not copy the file byte for byte"
[[ "$(stat -c %a "${TARGET}")" == 644 ]] || fail "the file's mode"
[[ "$(run status)" == on ]] || fail "it is not on after on"
run on
cmp -s "${TARGET}" "${RULES}" || fail "on twice changed it"
# A file of that name that is not the image's is said so, and on puts the image's back
echo '# added by hand' >>"${TARGET}"
[[ "$(run status)" == changed ]] || fail "a changed file is not said"
run on
[[ "$(run status)" == on ]] || fail "on did not put the image's file back"
run off
[[ ! -e "${TARGET}" ]] || fail "off left the file"
[[ "$(run status)" == off ]] || fail "it is not off after off"
run off
# The image's file missing: on refuses, and writes nothing
mv "${R}/usr/share/amethystora/lab-devices/70-amethystora-lab-devices.rules" "${T}/gone"
if run on 2>/dev/null; then fail "on without the image's file"; fi
[[ ! -e "${TARGET}" ]] || fail "a refused on wrote something"
if python3 -I "${HELPER}" sideways 2>/dev/null; then fail "an unknown word"; fi

echo "test-lab-devices: the file's shape, its IDs, and on, off and list"
