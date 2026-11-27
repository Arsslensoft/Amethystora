#!/usr/bin/bash
# What a keyboard types stays root's, whichever maker built it (72-amethystora-keyboards-not-shared.rules): the helper
# that reads a hidraw node's report descriptor and a USB device's interface list, run against descriptors written out
# here, a boot keyboard, an NKRO keyboard, a vendor-only configuration interface, a game pad, a FIDO key, a keyboard
# that gives its usages four bytes, a descriptor that is empty, cut short or too long, and the order of the rule files.
#   bash test-hid-keyboards.sh [HELPER [RULES-DIR]]
set -euo pipefail
export LC_ALL=C

HELPER="${1:-/usr/libexec/amethystora-hid-vendor-only}"
RULES="${2:-/usr/lib/udev/rules.d}"
T="$(mktemp -d)"
trap 'rm -rf "${T}"' EXIT
fail() { echo "test-hid-keyboards: $*"; exit 1; }

python3 -I -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "${HELPER}"

python3 -I - "${HELPER}" "${T}" <<'EOF'
import importlib.machinery, importlib.util, os, subprocess, sys

helper, tmp = sys.argv[1], sys.argv[2]
loader = importlib.machinery.SourceFileLoader("hv", helper)
module = importlib.util.module_from_spec(importlib.util.spec_from_loader("hv", loader))
loader.exec_module(module)

D = {
    # QMK's raw HID: a vendor-defined page, one usage, a report each way
    "raw": "06 60 ff 09 61 a1 01 15 00 26 00 ff 75 08 95 20 09 62 81 32 c0",
    # the boot keyboard of the HID specification's appendix
    "boot": "05 01 09 06 a1 01 05 07 19 e0 29 e7 15 00 25 01 75 01 95 08 81 02 95 01 75 08 81 01 95 05 75 01 "
            "05 08 19 01 29 05 91 02 95 01 75 03 91 01 95 06 75 08 15 00 25 65 05 07 19 00 29 65 81 00 c0",
    # an NKRO keyboard: a modifier byte and a bitmap of 120 keys
    "nkro": "05 01 09 06 a1 01 05 07 19 e0 29 e7 15 00 25 01 75 01 95 08 81 02 05 07 19 00 29 77 15 00 25 01 "
            "75 01 95 78 81 02 c0",
    # a mouse, and a consumer control: no keys
    "mouse": "05 01 09 02 a1 01 09 01 a1 00 05 09 19 01 29 03 15 00 25 01 95 03 75 01 81 02 95 01 75 05 81 01 "
             "05 01 09 30 09 31 15 81 25 7f 75 08 95 02 81 06 c0 c0",
    "consumer": "05 0c 09 01 a1 01 15 00 26 01 03 75 10 95 01 81 00 c0",
    # a game pad: the generic desktop page's Game Pad, buttons on the button page, a vendor page for rumble
    "pad": "05 01 09 05 a1 01 05 09 19 01 29 10 15 00 25 01 75 01 95 10 81 02 05 01 09 30 09 31 15 81 25 7f "
           "75 08 95 02 81 02 06 00 ff 09 01 95 01 91 02 c0",
    # a FIDO key: usage page 0xF1D0, which is neither a keyboard nor a vendor-defined page
    "fido": "06 d0 f1 09 01 a1 01 09 20 15 00 26 ff 00 75 08 95 40 81 02 09 21 91 02 c0",
    # a keypad
    "keypad": "05 01 09 07 a1 01 05 07 19 e0 29 e7 15 00 25 01 75 01 95 08 81 02 c0",
    # a pad that uses the keyboard page for buttons of its own
    "pad-keys": "05 01 09 05 a1 01 05 07 19 e0 29 e7 15 00 25 01 75 01 95 08 81 02 c0",
    # usage page 0xFF00, then a 4-byte usage that is the generic desktop page's Keyboard
    "extended": "06 00 ff 0b 06 00 01 00 a1 01 15 00 25 01 75 01 95 08 81 02 c0",
    # usage page 0xFF00, a vendor usage, and a 4-byte usage on the keyboard page inside it
    "extended-page": "06 00 ff 09 61 a1 01 0b 04 00 07 00 15 00 25 01 75 01 95 08 81 02 c0",
    # a vendor collection whose keys are on a 4-byte Usage Page, 0x00010007, which the kernel takes as the keyboard page
    "wide-page": "06 00 ff 09 01 a1 01 07 07 00 01 00 19 e0 29 e7 15 00 25 01 75 01 95 08 81 02 c0",
}
data = {name: bytes.fromhex(value) for name, value in D.items()}


def answer(name):
    return module.vendor_only(data[name]), module.keyboard(data[name])


expected = {
    "raw": (True, False),
    "boot": (False, True),
    "nkro": (False, True),
    "mouse": (False, False),
    "consumer": (False, False),
    "pad": (False, False),
    "fido": (False, False),
    "keypad": (False, True),
    "pad-keys": (False, True),
    "extended": (False, True),
    "extended-page": (False, True),
    "wide-page": (False, True),
}
for name, want in expected.items():
    got = answer(name)
    assert got == want, (name, got, want, module.pages(data[name]))

# What is not a descriptor is a keyboard that is not vendor-only: empty, cut inside an item, a long item that runs
# past the end, nothing but a prefix
for name, blob in {"empty": b"", "cut": data["boot"][:-1] + b"\x81", "item": b"\x06", "long": b"\xfe\x05\x00", "long2": b"\xfe"}.items():
    only, typing = module.vendor_only(blob), module.keyboard(blob)
    assert (only, typing) == (False, True), (name, only, typing)
assert module.pages(data["boot"][:-1]) is not None
assert module.pages(b"\x06") is None and module.pages(b"") is None

# Both vendor-only and a keyboard is never said, and the old reading still holds
assert module.pages(data["raw"]) == [0xFF60]
assert module.pages(data["boot"]) is not None and 7 in module.pages(data["boot"])
assert module.pages(data["extended"]) == [0xFF00, 1], module.pages(data["extended"])
assert module.pages(data["extended-page"]) == [0xFF00, 7], module.pages(data["extended-page"])
assert module.pages(data["raw"] + data["boot"])[:2] == [0xFF60, 1]

# The read is bounded: 4096 bytes are read, one more byte is not a descriptor
limit = os.path.join(tmp, "limit")
for size, ok in ((0, True), (1, True), (4096, True), (4097, False), (1 << 20, False)):
    with open(limit, "wb") as handle:
        handle.write(b"\x00" * size)
    got = module.read_limited(limit)
    assert (got is not None) == ok, (size, got is not None)
    assert got is None or len(got) == size
assert module.descriptor("/nonexistent") is None
assert module.descriptor("/") is None  # nothing outside /sys/devices is read

# USB devices: a boot keyboard among HID interfaces only
for value, want in {
    ":030101:030000:": True,  # a keyboard with a configuration interface
    ":030101:": True,
    ":030101:030102:": True,
    ":030000:": False,  # a bootloader or a vendor-only device
    ":030201:": False,  # a boot mouse
    ":030101:010100:": False,  # a keyboard with a sound card
    ":030101:0b0000:": False,  # a keyboard with a smart card reader
    ":060101:": False,
    ":fe0101:": False,
    "": True,  # unreadable counts as one
    "030101": True,
    ":0301:": True,
    ":030101:ZZZZZZ:": True,
    ":03010:": True,
}.items():
    assert module.usb_keyboard(value) == want, (value, want)

# What the rules read is what the helper prints, and it never fails
def run(*args):
    done = subprocess.run([sys.executable, "-I", helper, *args], capture_output=True, text=True)
    assert done.returncode == 0, (args, done.returncode, done.stderr)
    return done.stdout.split()

safe = ["AMETHYSTORA_HID_VENDOR_ONLY=0", "AMETHYSTORA_HID_KEYBOARD=1"]
assert run() == safe and run("/nonexistent") == safe and run("a", "b") == safe and run("/sys/devices/none") == safe
assert run("usb", ":030101:030000:") == ["AMETHYSTORA_USB_KEYBOARD=1"]
assert run("usb", ":030101:0e0000:") == ["AMETHYSTORA_USB_KEYBOARD=0"]
assert run("usb", "") == ["AMETHYSTORA_USB_KEYBOARD=1"]
EOF

# The rules: the files that add the tag sort before the take-back, and the take-back before the grant
files="$(cd "${RULES}" && LC_ALL=C ls ./*.rules)"
back="./72-amethystora-keyboards-not-shared.rules"
grep -qxF "${back}" <<<"${files}" || fail "${back} is not there"
# (the grant is made at 73-seat-late.rules: a tag added after it, as 88-neutron_hifi_dac.rules and 92-viia.rules do, is
# never seen by it)
for tagger in $(cd "${RULES}" && grep -lE '^[^#]*TAG[+]="uaccess"' ./*.rules); do
    [[ "${tagger}" > "./73-seat-late.rules" || "${tagger}" < "${back}" ]] ||
        fail "${tagger} adds the uaccess tag after the rules that take it back"
done
[[ "./73-seat-late.rules" > "${back}" ]] || fail "73-seat-late.rules does not sort after the take-back"
grep -q 'TAG+="uaccess"' "${RULES}/70-uaccess.rules"
# Python runs isolated, as the files' own helper says
if grep -h 'IMPORT{program}' "${RULES}"/71-amethystora-keyboard-interfaces.rules "${RULES}/${back}" | grep -v '/usr/bin/python3 -I /usr/libexec/amethystora-hid-vendor-only'; then
    fail "a rule runs the helper without python3 -I"
fi
if command -v udevadm >/dev/null && udevadm verify --help >/dev/null 2>&1; then
    udevadm verify "${RULES}/${back}" "${RULES}/71-amethystora-keyboard-interfaces.rules" || fail "udevadm verify refuses the rules"
fi
echo "test-hid-keyboards: ok"
