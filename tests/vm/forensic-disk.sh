#!/usr/bin/bash
# forensic-disk.sh [DIR]: the disk the forensic start is tried against (forensic-live.sh), in the lab container: a GPT disk
# of 3 GiB with a file system or volume on each partition, one file with a known sentence in each, and its checksum in
# DIR/evidence.sha256. Runs once; a partition whose file system the lab's kernel cannot make is left out, said in
# DIR/evidence.manifest, which the test reads.
#
#   1 ext4, journal left unreplayed    2 XFS, log left unreplayed    3 btrfs    4 LVM (an ext4 volume, and an ext4 on a thin volume
#   of a thin pool, which writes its metadata when it is activated read-write)
#   5 LUKS2 (an ext4 inside; passphrase forensic-lab)    6 swap, with a sentence behind its header
#   7 and 8 the two halves of an MD RAID1 (an ext4 on it)
set -euo pipefail

DIR="${1:-/vm/forensic}"
RAW="${DIR}/evidence.raw"
PASSPHRASE=forensic-lab
SENTENCE="the evidence stays as it was"
mkdir -p "${DIR}"
dnf -y -q install --setopt=install_weak_deps=False e2fsprogs xfsprogs btrfs-progs lvm2 device-mapper-persistent-data cryptsetup mdadm gdisk util-linux xorriso >/dev/null

# No udev in here answers device-mapper, which would wait for it forever: libdevmapper makes the nodes
export DM_DISABLE_UDEV=1
rm -f "${RAW}" "${DIR}/evidence.manifest" "${DIR}/evidence.sha256"
truncate -s 3G "${RAW}"
loop="$(losetup -fP --show "${RAW}")"
mnt="$(mktemp -d)"
cleanup() {
    umount "${mnt}" 2>/dev/null || true
    mdadm --stop /dev/md/forensic 2>/dev/null || true
    vgchange -an forensic >/dev/null 2>&1 || true
    cryptsetup close forensic-luks 2>/dev/null || true
    losetup -d "${loop}" 2>/dev/null || true
    rmdir "${mnt}" 2>/dev/null || true
}
trap cleanup EXIT

sfdisk --quiet "${loop}" <<EOF
label: gpt
start=2048, size=128MiB, name="ext4"
size=320MiB, name="xfs"
size=256MiB, name="btrfs"
size=256MiB, name="lvm", type=E6D6D379-F507-44C2-A23C-238F2A3DF928
size=256MiB, name="luks"
size=64MiB, name="swap", type=0657FD6D-A4AB-43C4-84E5-0933C84B4F4F
size=64MiB, name="md1", type=A19D880F-05FC-4D3B-A006-743F0F84911E
size=64MiB, name="md2", type=A19D880F-05FC-4D3B-A006-743F0F84911E
EOF
for i in 1 2 3 4 5 6 7 8; do
    for _ in $(seq 50); do [[ -b "${loop}p${i}" ]] && break; sleep 0.2; done
done
manifest="${DIR}/evidence.manifest"
: >"${manifest}"

# The sentence in a file in the file system on DEVICE, which is then left as a crash would leave it where it can be
write_into() {
    local device="$1" options="${2:-}" fs="$3"
    mount ${options:+-o "${options}"} "${device}" "${mnt}"
    printf '%s\n' "${SENTENCE}" >"${mnt}/evidence.txt"
    mkdir -p "${mnt}/folder"
    head -c 200000 /dev/urandom >"${mnt}/folder/blob"
    sync
    # A crash with the log not yet applied: the journal is left to be replayed at the next mount. ext4 and XFS take the same
    # ioctl. What a mount that leaves the log alone (noload, norecovery) can read is only what was in place before it, so the
    # evidence is let go of cleanly first, and only a second, later write is the one the crash leaves in the log
    if [[ "${fs}" == ext4 || "${fs}" == xfs ]]; then
        umount "${mnt}"
        mount ${options:+-o "${options}"} "${device}" "${mnt}"
        printf '%s\n' "written after the evidence" >"${mnt}/after-the-evidence"
        sync
        xfs_io -x -c 'shutdown -f' "${mnt}" || true
    fi
    umount "${mnt}"
}
made() { echo "$1" >>"${manifest}"; }

if mkfs.ext4 -q -F -L evid-ext4 "${loop}p1" && write_into "${loop}p1" "" ext4; then
    made ext4
    dumpe2fs -h "${loop}p1" 2>/dev/null | grep -q needs_recovery && made ext4-dirty
fi
if mkfs.xfs -q -f -L evid-xfs "${loop}p2" && write_into "${loop}p2" "" xfs; then made xfs; fi
if mkfs.btrfs -q -f -L evid-btrfs "${loop}p3" && write_into "${loop}p3" "" btrfs; then made btrfs; fi
if pvcreate -q -ff -y "${loop}p4" && vgcreate -q forensic "${loop}p4" && lvcreate -q -y -n volume -L 128M forensic; then
    # device-mapper nodes made by libdevmapper are in /dev/mapper
    if mkfs.ext4 -q -F -L evid-lvm /dev/forensic/volume 2>/dev/null && write_into /dev/forensic/volume "" lvm; then made lvm; fi
    # A thin pool commits its metadata when it is activated read-write: that is what a plain vgchange -ay would do to the disk
    if lvcreate -q -y --type thin-pool -L 64M -n pool forensic && lvcreate -q -y -T forensic/pool -V 32M -n thin &&
        mkfs.ext4 -q -F -L evid-thin /dev/forensic/thin 2>/dev/null && write_into /dev/forensic/thin "" thin; then made thin; fi
    vgchange -an forensic >/dev/null
fi
if printf '%s' "${PASSPHRASE}" | cryptsetup luksFormat --type luks2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000 --batch-mode --key-file - "${loop}p5" &&
    printf '%s' "${PASSPHRASE}" | cryptsetup open --key-file - "${loop}p5" forensic-luks; then
    if mkfs.ext4 -q -F -L evid-luks /dev/mapper/forensic-luks && write_into /dev/mapper/forensic-luks "" luks; then made luks; fi
    cryptsetup close forensic-luks
fi
if mkswap -L evid-swap "${loop}p6" >/dev/null; then
    # A page of a past session behind the swap header, which swapping on and off would change
    printf '%s' "${SENTENCE}" | dd of="${loop}p6" bs=4096 seek=2 conv=notrunc status=none
    made swap
fi
if mdadm --create /dev/md/forensic --level=1 --raid-devices=2 --metadata=1.2 --run --force --assume-clean "${loop}p7" "${loop}p8" >/dev/null 2>&1; then
    if mkfs.ext4 -q -F -L evid-md /dev/md/forensic && write_into /dev/md/forensic "" md; then made md; fi
    mdadm --stop /dev/md/forensic >/dev/null
fi
sync
cat "${manifest}"
cleanup
trap - EXIT
sha256sum "${RAW}" | cut -d' ' -f1 >"${DIR}/evidence.sha256"
echo "evidence.raw: $(cat "${DIR}/evidence.sha256")"
