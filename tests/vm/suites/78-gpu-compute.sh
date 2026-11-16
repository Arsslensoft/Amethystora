#!/usr/bin/bash
# Whether a container can use the graphics card (ame dev gpu; amethystora-gpu-compute), in the test account's session. The lab's machine has
# a virtual display and no card to compute on, so what is checked is what does not depend on one: the answer, as a person and as a program
# reads it, for the machine as it is; that nothing is fetched, written or installed without --pull; that the images it would run are
# pinned by digest and small enough; and, on an NVIDIA image, that the toolkit's CDI refresh is enabled and skipped while the driver is
# not loaded, which is the part of the image this check relies on. The steps themselves are held by test-gpu-compute.sh at build.
# By hand, on real cards: an NVIDIA card on -nvidia-open, an AMD card, an Intel iGPU.
# vmlab-paths: @sf/usr/libexec/amethystora-gpu-compute @sf/usr/share/amethystora/gpu-compute/* @sf/*just/dev.just @sf/usr/libexec/amethystora-gpu-check @sf/usr/libexec/amethystora-driver-status
source "$(dirname "$0")/lib.sh"

same() { if [[ "$2" == "$3" ]]; then ok "$1"; else not_ok "$1" "expected: $3" "found: $2"; fi; }
INFO=/usr/share/amethystora/image-info.json
IMAGES=/usr/share/amethystora/gpu-compute/images.json

wait_for 300 has_session || { not_ok "the test account has a session"; finish; }

# --- The images it would run -----------------------------------------------------------------------------------------------
if jq -e '[.[] | .image] | all(test("^[a-z0-9][a-z0-9./_-]*@sha256:[0-9a-f]{64}$")) and ([.[] | .size_mb] | all(. < 3000))' "${IMAGES}" >/dev/null; then
    ok "the images are pinned by digest, each under 3 GB"
else
    not_ok "the images are pinned by digest, each under 3 GB" "$(cat "${IMAGES}")"
fi

# Podman itself takes the reference as written (a digest alone: it takes a tag beside one only in some commands): "not here" is 1, never an error
for key in neutral amd; do
    in_session podman image exists "$(jq -r ".${key}.image" "${IMAGES}")" >/dev/null 2>&1
    [[ $? -le 1 ]] && ok "podman reads the pinned reference of ${key}" || not_ok "podman reads the pinned reference of ${key}"
done

# --- The machine as it is -----------------------------------------------------------------------------------------------------
CARDS="$(for d in /sys/bus/pci/devices/*; do
    class="$(cat "${d}/class")"
    [[ "${class}" == 0x03* || "${class}" == 0x12* ]] && cat "${d}/vendor"
done | sort -u | tr '\n' ' ')"
BEFORE="$(user_bus podman images -q 2>/dev/null | sort | md5sum)"
OUT="$(in_session ame dev gpu 2>&1)"
STATUS=$?
JSON="$(in_session ame dev gpu --json 2>&1)"
if jq -e '(.ok | type) == "boolean" and (.cards | type) == "array" and (.vendors | type) == "array"' <<<"${JSON}" >/dev/null; then
    ok "the answer for a program is JSON: ${CARDS:-no cards}"
else
    not_ok "the answer for a program is JSON" "${JSON}"
fi
if [[ "${CARDS}" == *0x10de* || "${CARDS}" == *0x1002* || "${CARDS}" == *0x8086* ]]; then
    # A card of a maker it knows: it goes as far as the machine lets it, and no further than the first step that fails
    jq -e '[.vendors[].steps[] | select(.state == "fail") | .fix // ""] | all(. != null)' <<<"${JSON}" >/dev/null && ok "each failure has its sentence and a command" ||
        not_ok "each failure has its sentence and a command" "${JSON}"
else
    same "a virtual display has nothing to compute on, and it says so" "${STATUS}:$(grep -c 'nothing to compute on\|No graphics card' <<<"${OUT}")" "1:1"
fi
[[ "$(user_bus podman images -q 2>/dev/null | sort | md5sum)" == "${BEFORE}" ]] && ok "nothing was fetched without --pull" || not_ok "nothing was fetched without --pull"
in_session ame dev gpu --nope >/dev/null 2>&1 && not_ok "an option it does not know is refused" || ok "an option it does not know is refused"
# It runs as the account, never as root
if ame dev gpu >/dev/null 2>&1; then not_ok "it refuses to run as root"; else ok "it refuses to run as root"; fi

# --- The NVIDIA images: the CDI description is the image's job ------------------------------------------------------------
FLAVOR="$(jq -r '."image-flavor"' "${INFO}")"
if [[ "${FLAVOR}" == nvidia-* ]]; then
    for unit in nvidia-cdi-refresh.service nvidia-cdi-refresh.path; do
        same "${unit} is enabled" "$(systemctl is-enabled "${unit}" 2>&1)" enabled
    done
    same "the refresh is skipped where the driver is not loaded, not restarted until the machine is degraded" \
        "$(systemctl show -P ConditionResult nvidia-cdi-refresh.service)" "$([[ -d /sys/module/nvidia ]] && echo yes || echo no)"
    check "nvidia-ctk is there to list the description" command -v nvidia-ctk
else
    skip "not an NVIDIA image (flavor ${FLAVOR}): the CDI refresh is theirs"
fi
finish
