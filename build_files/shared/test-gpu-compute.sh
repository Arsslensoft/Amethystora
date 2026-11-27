#!/usr/bin/bash
# Can a container use the graphics card (ame dev gpu): /usr/libexec/amethystora-gpu-compute against stand-ins for the machine (a /sys, a /dev, the
# helpers it asks, nvidia-smi, nvidia-ctk and podman), for 20-tests.sh. Each failure says the right sentence at the right step and names a command,
# nothing after a failed step is tried, nothing is fetched unless asked (and then it is the image by its digest), and it changes nothing.
#   bash test-gpu-compute.sh [HELPER [IMAGES]]

set -uo pipefail

HELPER="${1:-/usr/libexec/amethystora-gpu-compute}"
IMAGES="${2:-/usr/share/amethystora/gpu-compute/images.json}"
R="$(mktemp -d)"
trap 'rm -rf "${R}"' EXIT
chmod 0755 "${R}"
export AMETHYSTORA_GPU_ROOT="${R}/root" AMETHYSTORA_GPU_LIBEXEC="${R}/libexec" AMETHYSTORA_GPU_IMAGES="${IMAGES}"
SYS="${R}/root/sys/bus/pci/devices"
mkdir -p "${SYS}" "${R}/root/dev/dri" "${R}/libexec" "${R}/bin" "${R}/says" "${R}/root/usr/share/amethystora" "${R}/root/sys/bus/pci/drivers"/{nvidia,nouveau,amdgpu,i915}
echo '{"image-tag": "stable", "image-flavor": "main"}' >"${R}/root/usr/share/amethystora/image-info.json"
failed=0
fail() {
    echo "test-gpu-compute: $*" >&2
    failed=1
}

NEUTRAL="$(jq -r .neutral.image "${IMAGES}")"
AMD="$(jq -r .amd.image "${IMAGES}")"
jq -e '(.neutral.image, .amd.image | test("^[a-z0-9][a-z0-9./_-]*@sha256:[0-9a-f]{64}$")) and (.neutral.tag, .amd.tag | test("^[A-Za-z0-9._-]+$")) and (.neutral.size_mb < 3000) and (.amd.size_mb < 3000)' "${IMAGES}" >/dev/null ||
    fail "the images are not pinned by digest, or are over 3 GB"

# One stand-in under every name: it logs what it was asked, and answers from the files of says/
cat >"${R}/bin/stand-in" <<'EOF'
#!/usr/bin/bash
name="$(basename "$0")"
echo "${name} $*" >>"${CALLS}"
answer() {
    [[ -e "${SAYS}/$1.fail" ]] && { cat "${SAYS}/$1.fail" >&2; exit 1; }
    cat "${SAYS}/$1" 2>/dev/null
    exit 0
}
case "${name} $*" in
    "podman image exists "*) [[ -e "${SAYS}/image-present" ]]; exit ;;
    "podman pull "*) [[ -e "${SAYS}/pull.fail" ]] && { cat "${SAYS}/pull.fail" >&2; exit 1; }; touch "${SAYS}/image-present"; exit 0 ;;
    "podman run "*libcuda*) answer run-deep ;;
    "podman run "*rocminfo*) answer run-rocm ;;
    "podman run "*renderD*) answer run-intel ;;
    "podman run "*) answer run-nvidia ;;
    "nvidia-smi "*) answer nvidia-smi ;;
    "nvidia-ctk "*) answer nvidia-ctk ;;
    "amethystora-driver-status "*) answer driver-status ;;
    "amethystora-gpu-check "*) answer offer ;;
esac
exit 0
EOF
chmod +x "${R}/bin/stand-in"
for name in podman nvidia-smi nvidia-ctk; do
    ln -s stand-in "${R}/bin/${name}"
done
for name in amethystora-driver-status amethystora-gpu-check; do
    ln -s ../bin/stand-in "${R}/libexec/${name}"
done
export SAYS="${R}/says" CALLS="${R}/calls"
: >"${CALLS}"
export PATH="${R}/bin:${PATH}"

# A machine: one card with its class, maker, device and driver, and what the kernel made for it
card() { # ADDRESS CLASS VENDOR DEVICE DRIVER [RENDER]
    mkdir -p "${SYS}/$1"
    printf '%s\n' "$2" >"${SYS}/$1/class"
    printf '%s\n' "$3" >"${SYS}/$1/vendor"
    printf '%s\n' "$4" >"${SYS}/$1/device"
    [[ -z "${5:-}" ]] || ln -sfn "../../../../bus/pci/drivers/$5" "${SYS}/$1/driver"
    [[ -z "${6:-}" ]] || mkdir -p "${SYS}/$1/drm/$6"
}
reset() {
    rm -rf "${SYS:?}"/* "${SAYS:?}"/* "${R}/root/dev/kfd" "${R}/root/dev/dri"/* "${R}/root/run" "${R}/root/etc"
    mkdir -p "${R}/root/dev/dri"
    : >"${CALLS}"
}
says() { printf '%s\n' "$2" >"${SAYS}/$1"; }
# What it says and answers, for a run
go() {
    OUT="$("${HELPER}" "$@" 2>&1)"
    STATUS=$?
}
mentions() { grep -qF -- "$1" <<<"${OUT}" || fail "$2: no \"$1\" in: ${OUT}"; }
lacks() { grep -qF -- "$1" "${CALLS}" && fail "$2: ${1} was called: $(cat "${CALLS}")"; }
called() { grep -qF -- "$1" "${CALLS}" || fail "$2: ${1} was not called: $(cat "${CALLS}")"; }
status_is() { [[ "${STATUS}" == "$1" ]] || fail "$2: the answer was ${STATUS}, not $1: ${OUT}"; }

NV=0000:01:00.0
PCI_NVIDIA=(0x030000 0x10de 0x2684)
# An NVIDIA machine whose driver is loaded and the host sees: the way up to the container
nvidia_machine() {
    card "${NV}" "${PCI_NVIDIA[@]}" nvidia renderD128
    says nvidia-smi 'GPU 0: NVIDIA GeForce RTX 4090 (UUID: GPU-1)'
    says nvidia-ctk 'INFO[0000] Found 2 CDI devices
nvidia.com/gpu=0
nvidia.com/gpu=all'
}

# --- 1. The cards ------------------------------------------------------------------------------------------------------
reset
go
status_is 1 "no card"
mentions "No graphics card was found" "no card"
reset
card 0000:00:02.0 0x030000 0x1af4 0x1050 ''
go
status_is 1 "a virtual display"
mentions "nothing to compute on" "a virtual display"
lacks podman "a virtual display"

# --- 2. The driver -----------------------------------------------------------------------------------------------------
# NVIDIA's card on the image without the driver: nouveau drives it, and the image whose driver does is named
reset
card "${NV}" 0x030000 0x10de 0x2684 nouveau renderD128
says offer 'nvidia-card amethystora-nvidia-open'
go
status_is 1 "the wrong image"
mentions "amethystora-nvidia-open does" "the wrong image"
mentions "Fix: ame system rebase amethystora-nvidia-open stable" "the wrong image"
lacks nvidia-smi "the wrong image"
lacks podman "the wrong image"
# On the right image, the driver not loaded: what the driver check found, with its own fix
reset
card "${NV}" 0x030000 0x10de 0x2684 ''
says driver-status '{"checked": 1, "findings": [{"id": "nvidia:0000:01:00.0", "kind": "nvidia", "device": "x", "text": "NVIDIA'"'"'s driver did not load: Secure Boot is on, and the key it is signed with is not enrolled.", "fix": "ame security secure-boot", "manual": "m"}]}'
go
status_is 1 "a driver that did not load"
mentions "key it is signed with is not enrolled" "a driver that did not load"
mentions "Fix: ame security secure-boot" "a driver that did not load"
lacks nvidia-smi "a driver that did not load"
# No finding either: it still says so, and points to the driver check
reset
card "${NV}" 0x030000 0x10de 0x2684 ''
go
mentions "No driver took the card" "no driver, no finding"
mentions "Fix: ame system drivers" "no driver, no finding"

# --- 3. NVIDIA: the host, then the CDI description ---------------------------------------------------------------------
reset
nvidia_machine
rm -f "${SAYS}/nvidia-smi"
: >"${SAYS}/nvidia-smi.fail"
go
status_is 1 "nvidia-smi fails"
mentions "nvidia-smi does not see the card" "nvidia-smi fails"
lacks podman "nvidia-smi fails"
reset
nvidia_machine
: >"${SAYS}/nvidia-ctk"
go
status_is 1 "no CDI description"
mentions "CDI description podman needs" "no CDI description"
mentions "a fault of the image" "no CDI description"
mentions "Fix: sudo systemctl start nvidia-cdi-refresh.service" "no CDI description"
lacks podman "no CDI description"
# Without nvidia-ctk it looks for the file the refresh service writes, in /run/cdi (where /var/run/cdi leads) or /etc/cdi
rm -f "${R}/bin/nvidia-ctk"
# ...and none further down PATH: the NVIDIA images ship /usr/bin/nvidia-ctk, which lists nothing in a build. The stand-in's tools
# beside the stand-ins, and nothing else on PATH
for tool in basename cat touch; do
    ln -sf "$(command -v "${tool}")" "${R}/bin/${tool}"
done
reset
nvidia_machine
PATH="${R}/bin" go
mentions "CDI description podman needs" "no nvidia-ctk and no file"
mkdir -p "${R}/root/run/cdi"
echo 'cdiVersion: 0.5.0' >"${R}/root/run/cdi/nvidia.yaml"
PATH="${R}/bin" go
lacks "podman run" "the file only, no image yet"
mentions "The CDI description for podman is there" "the file in /run/cdi"
ln -s stand-in "${R}/bin/nvidia-ctk"

# --- 4. A container, and what is fetched ----------------------------------------------------------------------------------
reset
nvidia_machine
go
status_is 0 "an image that is not here"
mentions "python:3.14-slim, which is not here, and is about 44 MB" "the image and its size are said before the pull"
mentions "Fix: ame dev gpu --pull" "the way to ask"
mentions "container step has not run" "nothing failed, nothing proven"
lacks "podman pull" "no --pull"
lacks "podman run" "no image"
# --pull, with no terminal, is the consent: the image by its digest, then the container with the card passed through the CDI description
says run-nvidia 'GPU 0: NVIDIA GeForce RTX 4090 (UUID: GPU-1)'
go --pull
status_is 0 "--pull"
called "podman pull --quiet ${NEUTRAL}" "--pull fetches by digest"
called "podman run --rm --device nvidia.com/gpu=all --security-opt=label=disable ${NEUTRAL} nvidia-smi -L" "the container is given the card"
mentions "A container sees the same 1 card as the host" "a container that works"
mentions "A container can use the card." "a container that works"
lacks "libcuda" "no --deep"
# The same machine, the image there already: nothing is fetched
: >"${CALLS}"
go
lacks "podman pull" "an image that is here"
called "podman run" "an image that is here"
# A container that does not see the card
says run-nvidia 'no devices'
go
status_is 1 "a container that sees nothing"
mentions "does not see the card the way the host does" "a container that sees nothing"
rm -f "${SAYS}/run-nvidia"
echo "Error: setting up CDI devices: unresolvable CDI devices nvidia.com/gpu=all" >"${SAYS}/run-nvidia.fail"
go
status_is 1 "a container that fails"
mentions "unresolvable CDI devices" "a container that fails"
rm -f "${SAYS}/run-nvidia.fail"
# A pull that fails
rm -f "${SAYS}/image-present"
echo "Error: unable to copy from source: network is unreachable" >"${SAYS}/pull.fail"
go --pull
status_is 1 "a pull that fails"
mentions "network is unreachable" "a pull that fails"
rm -f "${SAYS}/pull.fail"

# The question a person is asked goes with a terminal, never into what a program reads: --json asks nothing and the flag is the consent
rm -f "${SAYS}/image-present"
says run-nvidia 'GPU 0: NVIDIA GeForce RTX 4090 (UUID: GPU-1)'
OUT="$(python3 - "${HELPER}" <<'PYEOF'
import os, pty, sys
pid, fd = pty.fork()
if pid == 0:
    os.execv(sys.argv[1], [sys.argv[1], "--pull", "--json"])
data = b""
try:
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        data += chunk
except OSError:
    pass
os.waitpid(pid, 0)
sys.stdout.write(data.decode())
PYEOF
)"
jq -e '.vendors | length == 1' <<<"${OUT}" >/dev/null 2>&1 || fail "--pull --json in a terminal printed more than JSON: ${OUT}"
grep -q 'Fetch ' <<<"${OUT}" && fail "--json asked a question"
called "podman pull --quiet ${NEUTRAL}" "--json takes --pull as the consent"

# --- 5. --deep -----------------------------------------------------------------------------------------------------------
reset
nvidia_machine
touch "${SAYS}/image-present"
says run-nvidia 'GPU 0: NVIDIA GeForce RTX 4090 (UUID: GPU-1)'
says run-deep OK
go --deep
status_is 0 "--deep"
mentions "A computation ran on the card" "--deep"
grep -q "podman run --rm --device nvidia.com/gpu=all --security-opt=label=disable ${NEUTRAL} python3 -c" "${CALLS}" || fail "--deep: no computation in the same image: $(cat "${CALLS}")"
says run-deep 'cuLaunchKernel failed (201)'
go --deep
status_is 1 "a computation that fails"
mentions "cuLaunchKernel failed (201)" "a computation that fails"
# --deep asks to fetch what it runs in, as --pull does
rm -f "${SAYS}/image-present" "${SAYS}/run-deep"
says run-deep OK
go --deep
called "podman pull --quiet ${NEUTRAL}" "--deep includes --pull"

# --- 6. AMD: /dev/kfd, the render node, ROCm ---------------------------------------------------------------------------------
reset
card 0000:03:00.0 0x030000 0x1002 0x744c amdgpu renderD128
go
status_is 1 "no /dev/kfd"
mentions "There is no /dev/kfd" "no /dev/kfd"
lacks podman "no /dev/kfd"
touch "${R}/root/dev/kfd" "${R}/root/dev/dri/renderD128"
touch "${SAYS}/image-present"
go
status_is 1 "no ROCm output"
mentions "ROCm in a container finds no GPU" "a container with no GPU"
called "podman run --rm --device /dev/kfd --device /dev/dri --security-opt=label=disable ${AMD} /opt/rocm/bin/rocminfo" "the container is given kfd and dri"
says run-rocm '  Name:                    AMD Ryzen 9
  Name:                    gfx1100
  Marketing Name:          AMD Radeon RX 7900 XTX'
go --deep
status_is 0 "ROCm sees the GPU"
mentions "ROCm in a container lists the GPU: gfx1100" "ROCm sees the GPU"
mentions "A computation test is not built for AMD" "--deep on AMD says what it is not"
# Not pulled yet: the size of ROCm's image is said first
rm -f "${SAYS}/image-present"
go
mentions "about 1216 MB" "the size of the AMD image"
lacks "podman pull" "the AMD image, no --pull"
# The account cannot open /dev/kfd (as another account: root opens everything)
if [[ "${EUID}" -eq 0 ]] && command -v setpriv >/dev/null; then
    chmod 0600 "${R}/root/dev/kfd"
    chmod -R a+rX "${R}"
    chmod 0600 "${R}/root/dev/kfd"
    OUT="$(setpriv --reuid=65534 --regid=65534 --clear-groups "${HELPER}" 2>&1)"
    STATUS=$?
    status_is 1 "a /dev/kfd the account cannot open"
    mentions "Your account cannot open /dev/kfd" "a /dev/kfd the account cannot open"
    mentions "rule gives every account it" "Fedora's rule is said"
fi
# A module the kernel refused that is not the card's driver is not the card's trouble (a Wi-Fi module), and one that is, is
reset
card "${NV}" 0x030000 0x10de 0x2684 ''
says driver-status '{"checked": 1, "findings": [{"id": "refused:iwlwifi", "kind": "refused", "device": "iwlwifi", "text": "The kernel refused to load it. Wi-Fi.", "fix": "ame security secure-boot", "manual": "m"}]}'
go
mentions "No driver took the card" "a refused Wi-Fi module is not the graphics driver's"
reset
card "${NV}" 0x030000 0x10de 0x2684 ''
says driver-status '{"checked": 1, "findings": [{"id": "refused:iwlwifi nvidia_drm", "kind": "refused", "device": "x", "text": "The kernel refused nvidia.", "fix": "ame security secure-boot", "manual": "m"}]}'
go
mentions "The kernel refused nvidia." "a refused graphics module is"
# amdgpu's compute rules out the old radeon driver
reset
card 0000:03:00.0 0x030000 0x1002 0x6798 radeon renderD128
go
status_is 1 "radeon"
mentions "driven by radeon, which cannot compute here" "radeon"

# --- 7. Intel: the render node -------------------------------------------------------------------------------------------------
reset
card 0000:00:02.0 0x030000 0x8086 0x46a6 i915
go
mentions "The kernel made no render node" "no render node"
reset
card 0000:00:02.0 0x030000 0x8086 0x46a6 i915 renderD128
touch "${R}/root/dev/dri/renderD128" "${SAYS}/image-present"
says run-intel /dev/dri/renderD128
go --deep
status_is 0 "Intel"
mentions "A container opens the render node: /dev/dri/renderD128" "Intel"
mentions "A computation test is not built for Intel" "--deep on Intel"
called "podman run --rm --device /dev/dri --security-opt=label=disable ${NEUTRAL} python3 -c" "Intel's container"
echo none >"${SAYS}/run-intel"
echo "" >"${SAYS}/run-intel.fail"
go
status_is 1 "Intel, no node opens in the container"
mentions "A container cannot open the render node" "Intel, no node opens in the container"

# --- 8. Two makers, and the answer for a program ----------------------------------------------------------------------------
reset
card "${NV}" 0x030000 0x10de 0x2684 nvidia renderD129
card 0000:00:02.0 0x030000 0x8086 0x46a6 i915 renderD128
touch "${R}/root/dev/dri/renderD128" "${SAYS}/image-present"
says nvidia-smi 'GPU 0: NVIDIA GeForce RTX 4090 (UUID: GPU-1)'
says run-intel /dev/dri/renderD128
go --json
status_is 1 "a card whose chain fails beside one whose chain works"
jq -e '.ok == true and .failed == true and (.vendors | map(.vendor) == ["nvidia", "intel"])
    and (.vendors[0].steps | map(.id) == ["cards", "driver", "host", "cdi"]) and .vendors[0].steps[3].state == "fail"
    and .vendors[0].steps[3].fix == "sudo systemctl start nvidia-cdi-refresh.service"
    and (.vendors[1].ok == true) and all(.vendors[].steps[].state; IN("ok", "fail", "skipped", "not-built"))
    and (.cards | length == 2)' <<<"${OUT}" >/dev/null || fail "the answer for a program: ${OUT}"

# --- It changes nothing, and refuses what it does not know -----------------------------------------------------------------------
grep -qE '^(sudo|rpm-ostree|dnf|flatpak|bootc|systemctl|pkexec) ' "${CALLS}" && fail "it ran something that changes the machine: $(grep -E '^(sudo|rpm-ostree|dnf|flatpak|bootc|systemctl|pkexec) ' "${CALLS}")"
BEFORE="$(find "${R}/root" -type f -printf '%p %s %T@\n' | sort | md5sum)"
go
go --json
[[ "$(find "${R}/root" -type f -printf '%p %s %T@\n' | sort | md5sum)" == "${BEFORE}" ]] || fail "it wrote something under the machine"
for argument in --nope "--deep --nope" bogus; do
    # shellcheck disable=SC2086
    "${HELPER}" ${argument} >/dev/null 2>&1 && fail "'${argument}' was taken"
done
if [[ "${EUID}" -eq 0 ]]; then
    env -u AMETHYSTORA_GPU_ROOT "${HELPER}" >/dev/null 2>&1 && fail "it ran as root"
fi

((failed == 0)) || exit 1
echo "test-gpu-compute: all passed"
