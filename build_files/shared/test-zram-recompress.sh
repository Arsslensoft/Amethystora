#!/usr/bin/bash
# amethystora-zram-recompress against stand-ins for /sys/block: a device with a second algorithm is repacked and then
# marked, a device with one algorithm, one of no size or a kernel without recompression is left alone, and a device that
# refuses is said by name without stopping the rest. Run by 20-tests.sh and the Integration workflow; HELPER names
# another copy.
set -euo pipefail

HELPER="${HELPER:-/usr/libexec/amethystora-zram-recompress}"
T="$(mktemp -d)"
trap 'chmod -R u+w "${T}" 2>/dev/null; rm -rf "${T}"' EXIT
export AMETHYSTORA_ZRAM_SYS="${T}/block"

fail() {
    echo "test-zram-recompress: $*"
    exit 1
}

# zram DEVICE DISKSIZE RECOMP_ALGORITHM [no-recompress]
zram() {
    local d="${AMETHYSTORA_ZRAM_SYS}/$1"
    mkdir -p "${d}"
    echo "$2" >"${d}/disksize"
    printf '%b' "$3" >"${d}/recomp_algorithm"
    [[ "${4:-}" == no-recompress ]] || : >"${d}/recompress"
    : >"${d}/idle"
}
zram zram0 8589934592 '#1: lzo lzo-rle lz4 lz4hc [zstd] \n'
zram zram1 8589934592 ''
zram zram2 0 '#1: lzo [zstd] \n'
zram zram3 8589934592 '#1: [zstd] \n' no-recompress
zram zram4 8589934592 '#1: lz4 [zstd] \n'
# A device that refuses (the kernel's EBUSY, here a file that cannot be written)
chmod a-w "${AMETHYSTORA_ZRAM_SYS}/zram4/recompress" "${AMETHYSTORA_ZRAM_SYS}/zram4/idle"

# Nothing to do on a machine with no zram at all
AMETHYSTORA_ZRAM_SYS="${T}/none" "${HELPER}" || fail "a machine with no zram device failed"

errors="$("${HELPER}" 2>&1 >/dev/null)" || fail "the run failed: ${errors}"
[[ "$(cat "${AMETHYSTORA_ZRAM_SYS}/zram0/recompress")" == type=idle ]] || fail "zram0 was not repacked"
[[ "$(cat "${AMETHYSTORA_ZRAM_SYS}/zram0/idle")" == all ]] || fail "zram0's pages were not marked"
for dev in zram1 zram2; do
    [[ ! -s "${AMETHYSTORA_ZRAM_SYS}/${dev}/recompress" && ! -s "${AMETHYSTORA_ZRAM_SYS}/${dev}/idle" ]] ||
        fail "${dev} was touched"
done
[[ ! -e "${AMETHYSTORA_ZRAM_SYS}/zram3/recompress" && ! -s "${AMETHYSTORA_ZRAM_SYS}/zram3/idle" ]] ||
    fail "zram3, on a kernel that cannot recompress, was touched"
if [[ "$(id -u)" != 0 ]]; then
    grep -qx 'zram4: could not recompress' <<<"${errors}" || fail "a device that refused was not named: ${errors}"
    grep -qx 'zram4: could not mark pages unused' <<<"${errors}" || fail "a device that refused to mark was not named: ${errors}"
fi

echo "test-zram-recompress: ok"
