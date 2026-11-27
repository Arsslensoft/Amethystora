#!/usr/bin/bash
# amethystora-early-units against stand-ins for systemd-modules-load, systemd-remount-fs and findmnt: each known failure
# (a module refused for its key or by lockdown; the composefs root that cannot be remounted) no longer fails its unit, and
# says so; anything else still does, with the program's own status; what the program said reaches the unit's journal
# (stderr); and both units' drop-ins start it, falling back to systemd's program where it is not installed. Run by
# 20-tests.sh and the Integration workflow; HELPER names another copy.
set -euo pipefail

HELPER="${HELPER:-/usr/libexec/amethystora-early-units}"
UNITS="${UNITS:-/usr/lib/systemd/system}"
T="$(mktemp -d)"
trap 'rm -rf "${T}"' EXIT
mkdir -p "${T}/systemd" "${T}/bin"
export AMETHYSTORA_EARLY_SYSTEMD="${T}/systemd" PATH="${T}/bin:${PATH}"

fail() {
    echo "test-early-units: $*"
    exit 1
}

# Each stand-in prints SAYS (with \n for lines) to stderr and exits STATUS; findmnt says ROOT_FS
for program in systemd-modules-load systemd-remount-fs; do
    printf '#!/usr/bin/bash\n[[ "${SYSTEMD_LOG_TARGET:-}" == console ]] || { echo "not on the console target" >&2; exit 99; }\nprintf "%%b" "${SAYS:-}" >&2\nexit "${STATUS:-0}"\n' \
        >"${T}/systemd/${program}"
done
printf '#!/usr/bin/bash\necho "${ROOT_FS:-overlay}"\n' >"${T}/bin/findmnt"
chmod +x "${T}/systemd/"* "${T}/bin/findmnt"

# check WANT-STATUS MODE: the helper's status, and that what the program said is in its stderr
check() {
    local want="$1" got said
    shift
    set +e
    said="$("${HELPER}" "$@" 2>&1)"
    got=$?
    set -e
    [[ "${got}" == "${want}" ]] || fail "$* with STATUS=${STATUS:-0} ROOT_FS=${ROOT_FS:-overlay} exits ${got}, not ${want}: ${said}"
    [[ -z "${SAYS:-}" || "${said}" == *"$(printf '%b' "${SAYS%%\\n*}")"* ]] || fail "$* did not pass on what the program said: ${said}"
    LAST="${said}"
}

# Nothing failed: nothing changes
STATUS=0 SAYS='' check 0 modules-load
STATUS=0 SAYS='' check 0 remount-fs

# --- modules-load ---
export STATUS=1
SAYS="Failed to insert module 'v4l2loopback': Key was rejected by service\n" check 0 modules-load
grep -q 'refused for their key' <<<"${LAST}" || fail "a known refusal is not said: ${LAST}"
SAYS="Failed to insert module 'evdi': Required key not available\nFailed to insert module 'v4l2loopback': Operation not permitted\n" check 0 modules-load
# Any other failure, or one with a refusal beside it, still fails, with the program's status
SAYS="Failed to insert module 'xpad': No such file or directory\n" check 1 modules-load
SAYS="Failed to insert module 'v4l2loopback': Key was rejected by service\nFailed to insert module 'xpad': Invalid argument\n" check 1 modules-load
# A failure that names no module is not taken for a refusal
SAYS="Failed to open /etc/modules-load.d: Permission denied\n" check 1 modules-load
STATUS=3 SAYS='' check 3 modules-load

# --- remount-fs ---
SAYS="mount: /: fsconfig() failed: overlay: No changes allowed in reconfigure.\n/usr/bin/mount for / exited with exit status 32.\n" check 0 remount-fs
grep -q 'composefs root' <<<"${LAST}" || fail "the known root failure is not said: ${LAST}"
# Another mount point, beside the root or alone, still fails
SAYS="/usr/bin/mount for / exited with exit status 32.\n/usr/bin/mount for /dev/shm exited with exit status 32.\n" check 1 remount-fs
SAYS="/usr/bin/mount for /usr exited with exit status 1.\n" check 1 remount-fs
# The root on anything but composefs still fails: there it can be remounted
ROOT_FS=btrfs SAYS="/usr/bin/mount for / exited with exit status 32.\n" check 1 remount-fs
SAYS="Failed to parse /etc/fstab\n" check 1 remount-fs

# --- what else it takes ---
unset STATUS
STATUS=0 check 64 nothing-else

# --- the drop-ins ---
for unit in systemd-modules-load systemd-remount-fs; do
    dropin="${UNITS}/${unit}.service.d/50-amethystora-known-failures.conf"
    [[ -f "${dropin}" ]] || fail "${dropin} is not installed"
    mode="${unit#systemd-}"
    [[ "$(grep -c '^ExecStart=' "${dropin}")" == 2 ]] && grep -qx 'ExecStart=' "${dropin}" ||
        fail "${dropin} does not replace ExecStart once"
    grep -qF "exec /usr/libexec/amethystora-early-units ${mode};" "${dropin}" || fail "${dropin} does not start the helper's ${mode}"
    grep -qF "exec /usr/lib/systemd/${unit}'" "${dropin}" || fail "${dropin} has no fallback to systemd's ${unit}"
    # ...and no other drop-in that takes a failure for success, which would pass what the helper still fails
    if grep -lE '^SuccessExitStatus=' "${UNITS}/${unit}.service.d/"*.conf 2>/dev/null; then
        fail "a drop-in of ${unit} takes a failure for success: the helper is the one place that decides"
    fi
done

echo "test-early-units: ok"
