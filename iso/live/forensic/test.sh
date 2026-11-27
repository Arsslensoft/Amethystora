#!/usr/bin/bash
# The forensic start's decisions against a stand-in for /sys/class/block (iso/live/build.sh runs it): which block devices
# it leaves alone and which it names as writable, what it says of a swap, a disk made writable and a volume group. What it
# does to a real device is the lab's (tests/vm/forensic-live.sh).
set -euo pipefail

HELPER="${1:-$(dirname "$0")/amethystora-forensic}"
root="$(mktemp -d)"
trap 'rm -rf "${root}"' EXIT
export AMETHYSTORA_FORENSIC_SYS="${root}/class" AMETHYSTORA_FORENSIC_STATE="${root}/state" AMETHYSTORA_FORENSIC_LIVEDEV="${root}/livedev"
export AMETHYSTORA_FORENSIC_SWAPS="${root}/swaps"
mkdir -p "${root}/class" "${root}/dev" "${root}/state" "${root}/bin"
printf 'Filename\tType\tSize\tUsed\tPriority\n' >"${root}/swaps"
: >"${root}/state/own-devices"

# A disk with partitions, as sysfs lays them out: /class/NAME is a link to the device, whose parent is the disk
disk() {
    mkdir -p "${root}/devices/$1"
    echo "$2" >"${root}/devices/$1/ro"
    echo "${3:-0}" >"${root}/devices/$1/removable"
    ln -sfn "../devices/$1" "${root}/class/$1"
}
part() {
    mkdir -p "${root}/devices/$1/$2"
    echo "$3" >"${root}/devices/$1/$2/ro"
    echo 1 >"${root}/devices/$1/$2/partition"
    ln -sfn "../devices/$1/$2" "${root}/class/$2"
}
# A loop or device-mapper device, with the major:minor it has
loop() {
    disk "$1" "$2"
    mkdir -p "${root}/devices/$1/loop"
    printf '%s\n' "$3" >"${root}/devices/$1/loop/backing_file"
    echo "$4" >"${root}/devices/$1/dev"
}
dm() {
    disk "$1" "$2"
    mkdir -p "${root}/devices/$1/dm"
    printf '%s\n' "$3" >"${root}/devices/$1/dm/name"
    echo "$4" >"${root}/devices/$1/dev"
}

# What udevadm, lvs and vgchange would say, as the helper asks them
cat >"${root}/bin/udevadm" <<'MOCK'
#!/usr/bin/bash
[[ -z "${MOCK_SERIAL:-}" ]] || echo "ID_SERIAL_SHORT=${MOCK_SERIAL}"
MOCK
cat >"${root}/bin/lvs" <<'MOCK'
#!/usr/bin/bash
cat "${MOCK_LVS}"
MOCK
cat >"${root}/bin/vgchange" <<'MOCK'
#!/usr/bin/bash
echo "vgchange $*" >>"${MOCK_LOG}"
MOCK
chmod +x "${root}/bin/"*
export PATH="${root}/bin:${PATH}" MOCK_LOG="${root}/log" MOCK_LVS="${root}/lvs"

failed=0
ok() { echo "ok - $1"; }
bad() { echo "not ok - $1"; failed=1; }
# What verify names, on one line
named() { "${HELPER}" verify 2>&1 | tr '\n' ' ' | sed 's/ $//' || true; }
expect() {
    local what="$1" want="$2" got
    got="$(named)"
    if [[ "${got}" == "${want}" ]]; then ok "${what}"; else bad "${what}: wanted '${want}', got '${got}'"; fi
}
run_lvm() { "${HELPER}" lvm-activate "$1" 2>&1 || true; }

disk sda 1
part sda sda1 1
# The live medium is what dmsquash-live links. A stick (removable) is left alone whole, as writable as it is
disk sdb 0 1
part sdb sdb1 0
: >"${root}/dev/sdb1"
ln -sfn "${root}/dev/sdb1" "${root}/livedev"
expect "everything is read-only but a removable live medium, which is left alone" ""
# ...a disk that is built in is not: the live system runs from memory and a read-only mount, so its partition goes read-only too
echo 0 >"${root}/devices/sdb/removable"
expect "the live medium on a built-in disk is not left alone" "sdb sdb1"
echo 1 >"${root}/devices/sdb/ro"
echo 1 >"${root}/devices/sdb/sdb1/ro"
expect "...and is read-only like any" ""
echo 1 >"${root}/devices/sdb/removable"
echo 0 >"${root}/devices/sdb/ro"
echo 0 >"${root}/devices/sdb/sdb1/ro"

disk sdc 0
part sdc sdc1 0
expect "a writable disk is named, with its partition" "sdc sdc1"
echo 1 >"${root}/devices/sdc/ro"
expect "the partition alone is named" "sdc1"
echo 1 >"${root}/devices/sdc/sdc1/ro"
expect "nothing is named once both are read-only" ""

# Memory is no disk. Only the loop and device-mapper devices that were there when the forensic start began are the live
# system's, by their numbers: a file that is gone, or a volume group called live, is not
disk zram0 0
loop loop0 0 /run/initramfs/live/LiveOS/squashfs.img 7:0
loop loop1 0 "/overlay (deleted)" 7:1
dm dm-0 0 live-rw 252:0
printf '7:0\n7:1\n252:0\n' >"${root}/state/own-devices"
loop loop2 0 /run/media/evidence/disk.img 7:2
loop loop3 0 "/run/media/x (deleted)" 7:3
loop loop4 0 "" 7:4
dm dm-5 0 live-home 252:5
dm dm-6 0 cryptevidence 252:6
expect "what the live system made is left alone, what a seized disk or an image made is not, an unattached loop is not looked at" "dm-5 dm-6 loop2 loop3"
for d in loop2 loop3 dm-5 dm-6; do echo 1 >"${root}/devices/${d}/ro"; done
expect "read-only, they are not named" ""

# A disk made writable on purpose is its own by name and by serial number: another disk of that name is not, and a disk that
# left takes its entry
disk sdd 0
export MOCK_SERIAL=SER1
echo "sdd SER1" >"${root}/state/writable"
expect "a disk made writable on purpose is not named" ""
export MOCK_SERIAL=SER2
expect "another disk with its name is" "sdd"
export MOCK_SERIAL=
expect "a disk with no serial number is" "sdd"
export MOCK_SERIAL=SER1
"${HELPER}" forget sdd
if [[ -s "${root}/state/writable" ]]; then bad "the entry went when the disk left"; else ok "the entry went when the disk left"; fi
expect "so the disk of that name is named again" "sdd"
echo 1 >"${root}/devices/sdd/ro"

# A swap on a disk that is not left alone is named, one in memory or a file is not
printf '/dev/sdc1\tpartition\t1024\t0\t-2\n' >>"${root}/swaps"
expect "a swap on a disk of the seized computer is named" "swap:sdc1"
printf 'Filename\tType\tSize\tUsed\tPriority\n/dev/zram0\tpartition\t1024\t0\t100\n/run/initramfs/live/LiveOS/swap.img\tfile\t1\t0\t-3\n' >"${root}/swaps"
expect "a swap in memory, or a file, is not" ""

# The volume group activated read-only: the list names it, a merge is refused, and what comes up writable goes down again
: >"${root}/log"
printf '  home  -wi-------\n' >"${root}/lvs"
out="$(run_lvm 'bad name')"
if [[ "${out}" == *"is not a volume group's name"* && ! -s "${root}/log" ]]; then ok "a name that is not a volume group's is refused"; else bad "a bad name: ${out}"; fi
printf '  home  Owi-------\n' >"${root}/lvs"
out="$(run_lvm vg1)"
if [[ "${out}" == *"waiting to be merged"* && ! -s "${root}/log" ]]; then ok "a snapshot waiting to be merged keeps the group from being activated"; else bad "a merge: ${out}"; fi
printf '  home  -wi-------\n' >"${root}/lvs"
run_lvm vg1 >/dev/null
if grep -qF 'vgchange -ay --config activation { read_only_volume_list = [ "vg1" ] } vg1' "${root}/log"; then
    ok "the group is activated with its own name in the read-only list"
else
    bad "the activation: $(cat "${root}/log")"
fi
: >"${root}/log"
printf '  home  -wi-a-----\n' >"${root}/lvs"
out="$(run_lvm vg1)"
if [[ "${out}" == *"came up writable"* ]] && grep -qF 'vgchange -an vg1' "${root}/log"; then ok "a volume that came up writable is deactivated again"; else bad "a writable volume: ${out}"; fi
: >"${root}/log"
printf '  home  -Ri-a-----\n  pool  twi-aot---\n' >"${root}/lvs"
out="$(run_lvm vg1)"
if [[ "${out}" == *"pool came up writable"* && "${out}" != *"home came"* ]]; then ok "one volume of the group writable is named, a read-only one is not"; else bad "a mixed group: ${out}"; fi
: >"${root}/log"
printf '  home  -Ri-a-----\n  pool  tRi-aot---\n' >"${root}/lvs"
out="$(run_lvm vg1)"
if [[ "${out}" == *"is active, read-only"* ]]; then ok "a group whose active volumes are all read-only stays active"; else bad "a read-only group: ${out}"; fi

# What the units, the rules and the entry are held to
if [[ " $("${HELPER}" args | tr '\n' ' ') " == *" noswap "* ]]; then ok "noswap is among the arguments"; else bad "noswap is among the arguments"; fi
if [[ "$("${HELPER}" overrides | tr '\n' ' ')" == "64-md-raid-assembly.rules 69-dm-lvm.rules 69-bcache.rules " ]]; then
    ok "the rule files made empty are the md assembly, LVM's and bcache's"
else
    bad "the rule files made empty"
fi
# shellcheck disable=SC2016
if "${HELPER}" rules | grep -qE '^ACTION=="remove", ENV\{DEVTYPE\}=="disk", RUN\+="/usr/bin/amethystora-forensic forget \$kernel"$'; then
    ok "a disk that leaves is forgotten by the rule"
else
    bad "the rule forgets nothing"
fi

if ((failed)); then exit 1; fi
echo "forensic start: the guard's decisions hold"
