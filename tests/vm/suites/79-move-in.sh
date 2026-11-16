#!/usr/bin/bash
# Move in from Windows (amethystora-move-in, plans/everybody/PLAN-move-in.md), on the machine as a person would use it. The lab's first spare disk,
# SPARE-1 (8 GiB), is made into a Windows disk: a GPT partition of Microsoft's basic data type with an NTFS file system on it, holding Windows/System32,
# two accounts, folders and a OneDrive folder, and (where ntfs-3g is in the image) left not cleanly unmounted, as a disk Windows hibernated is.
#
#   1. The partition table alone: Control's Move in from Windows is unavailable before the disk is there and available after, and the offer
#      (`find --offer`) lists it without mounting anything.
#   2. The checksum of the whole disk, taken, and taken again at the end: nothing was written to it by any step below.
#   3. `ame system move-in` in a terminal as the account: the disk found, the two accounts offered to an administrator, the folders chosen,
#      a Downloads folder never offered, and a file already in the home kept with the Windows one beside it. The disk is unmounted at the end
#      (that it is mounted read-only, with no exec, is test-move-in.sh's, which sees the command: here the checksum shows nothing was written).
#   4. A second run copies nothing; a file edited since is not copied again; `look` and `find --json` say what the disk holds.
#   5. The first look's card (Coming from Windows?) in Control's window, once: its Not now puts it away, and a window opened again shows none.
#   6. The disk's checksum is what it was.
#
# Polkit's own question (an administrator's password for a disk inside the computer) is not asked here: the suite lets the account through for udisks
# alone while it runs, as 80-control.sh does for everything. Not here (by hand, `tests/real/checklist`): a BitLocker disk (cryptsetup cannot make
# one), a disk Windows really hibernated, and real OneDrive placeholders; the attribute the suite sets (offline) stands for them where the driver takes it.
# vmlab-paths: @sf/usr/libexec/amethystora-move-in @sf/*just/system.just @sf/usr/libexec/amethystora-control-list apps/control/src/welcome.rs
source "$(dirname "$0")/lib.sh"

HERE="$(dirname "$0")"
UID_TEST="$(id -u "${TEST_USER}")"
HOME_DIR="$(getent passwd "${TEST_USER}" | cut -d: -f6)"
HELPER=/usr/libexec/amethystora-move-in
POLKIT=/etc/polkit-1/rules.d/00-vmlab-move-in.rules
MNT=/run/vmlab-79-mnt
same() { if [[ "$2" == "$3" ]]; then ok "$1"; else not_ok "$1" "expected: $3" "found: $2"; fi; }
holds() { if "${@:2}"; then ok "$1"; else not_ok "$1"; fi; }
has() { [[ "$2" == *"$1"* ]]; }
lacks() { [[ "$2" != *"$1"* ]]; }
if ! wait_for 300 has_session; then
    not_ok "no session for ${TEST_USER}" "$(loginctl list-sessions --no-legend)"
    finish
fi
install -D -m 0644 "${HERE}/atspi.py" /run/vmlab-79/atspi.py
AS_TESTER=(runuser -u "${TEST_USER}" -- env "XDG_RUNTIME_DIR=/run/user/${UID_TEST}" "WAYLAND_DISPLAY=wayland-0"
    "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/${UID_TEST}/bus" bash -lc)
as_tester() { runuser -u "${TEST_USER}" -- "$@"; }
cleanup() {
    rm -f "${POLKIT}"
    umount -l "${MNT}" 2>/dev/null
    rm -rf "${MNT}"
}
trap cleanup EXIT

command -v mkfs.ntfs >/dev/null || { not_ok "mkfs.ntfs is not in the image (ntfsprogs, which udisks recommends), so no NTFS disk can be made here"; finish; }
DISK="$(readlink -f /dev/disk/by-id/ata-QEMU_HARDDISK_SPARE-1)"
if [[ ! -b "${DISK}" ]]; then
    not_ok "the lab's first spare disk is not there" "$(ls /dev/disk/by-id 2>&1 | head -n 10)"
    finish
fi

# The list the Control window reads, as the window runs it
entry() { as_tester systemd-run --user --pipe --wait --quiet --collect -- /usr/libexec/amethystora-control-list --json 2>/dev/null </dev/null |
    jq -c '.items[] | select(.id == "move-in")'; }
umount "${DISK}"* 2>/dev/null
wipefs -a "${DISK}" >/dev/null 2>&1
udevadm settle
before="$(entry)"
same "Control's Move in from Windows is unavailable with no Windows disk" "$(jq -r '.available' <<<"${before}")" false

# --- A Windows disk ---------------------------------------------------------------------------------------------------------------------
echo 'label: gpt
,,EBD0A0A2-B9E5-4433-87C0-68B6B72699C7' | sfdisk -q "${DISK}" || not_ok "the disk was not partitioned"
udevadm settle
PART="$(lsblk -ln -o PATH "${DISK}" | sed -n 2p)"
mkfs.ntfs -Q -F -L Windows "${PART}" >/dev/null 2>&1 || not_ok "the NTFS file system was not made"
mkdir -p "${MNT}"
# ntfs-3g where it is (it takes a file's Windows attributes as xattrs and leaves a volume it was killed on marked dirty), else the kernel's
DRIVER=ntfs3
command -v ntfs-3g >/dev/null && DRIVER=ntfs-3g
mount_rw() { if [[ "${DRIVER}" == ntfs-3g ]]; then ntfs-3g "${PART}" "${MNT}" -o rw,uid=0,gid=0 2>/dev/null; else mount -t ntfs3 "${PART}" "${MNT}"; fi; }
mount_rw || { not_ok "the disk was not mounted to fill it" "driver ${DRIVER}"; finish; }
SAM="${MNT}/Users/${TEST_USER}"
mkdir -p "${MNT}/Windows/System32" "${SAM}/Documents/letters" "${SAM}/Pictures" "${SAM}/Desktop" "${SAM}/Downloads" "${SAM}/OneDrive/Documents" \
    "${SAM}/AppData/Local/Google/Chrome/User Data/Default" "${MNT}/Users/Pat/Documents" "${MNT}/Users/Public"
: >"${SAM}/NTUSER.DAT"
: >"${MNT}/Users/Pat/NTUSER.DAT"
echo "the report, Windows' copy" >"${SAM}/Documents/report.docx"
echo "dear friend" >"${SAM}/Documents/letters/a.txt"
echo hidden >"${SAM}/Documents/desktop.ini"
echo "a picture" >"${SAM}/Pictures/p.jpg"
echo "on the desktop" >"${SAM}/Desktop/todo.txt"
echo "an installer" >"${SAM}/Downloads/setup.exe"
echo "CANARY-CHROME-PASSWORD" >"${SAM}/AppData/Local/Google/Chrome/User Data/Default/Login Data"
echo "Pat's own" >"${MNT}/Users/Pat/Documents/pat.txt"
echo "synced and here" >"${SAM}/OneDrive/Documents/synced.txt"
echo "only online" >"${SAM}/OneDrive/Documents/cloud-only.docx"
HOLDERS=0
if setfattr -n system.ntfs_attrib_be -v 0x00001000 "${SAM}/OneDrive/Documents/cloud-only.docx" 2>/dev/null; then
    HOLDERS=1
else
    skip "the driver (${DRIVER}) does not take a file's Windows attributes, so no OneDrive placeholder is made"
fi
sync
umount "${MNT}" || { not_ok "the disk would not unmount after it was filled"; finish; }
if [[ "${DRIVER}" == ntfs-3g ]]; then
    # Not cleanly unmounted: ntfs-3g marks the volume dirty while it is mounted, and being killed leaves it so
    mount_rw && {
        echo "written when Windows was cut off" >"${MNT}/Users/${TEST_USER}/Documents/last-minute.txt"
        pkill -9 -x ntfs-3g
        sleep 1
        umount -l "${MNT}" 2>/dev/null
        sleep 1
    }
fi
udevadm settle
SUM_BEFORE="$(sha256sum "${DISK}" | cut -d' ' -f1)"
echo "# the disk is filled (${DRIVER}); checksum ${SUM_BEFORE}"

# --- 1. The offer ------------------------------------------------------------------------------------------------------------------------
as_tester "${HELPER}" find --offer >/tmp/vmlab-79-offer.json 2>&1
holds "the offer finds the disk and mounts nothing" bash -c "jq -e --arg p '${PART}' '[.parts[].part] | index(\$p)' /tmp/vmlab-79-offer.json >/dev/null && ! findmnt -S '${PART}' >/dev/null"
after="$(entry)"
same "Control's Move in from Windows is available with one" "$(jq -r '.available' <<<"${after}")" true

# The account is let through for udisks alone while the suite runs (polkit would ask a person for an administrator's password)
cat >"${POLKIT}" <<EOF
polkit.addRule(function (action, subject) {
    if (subject.user == "${TEST_USER}" && action.id.indexOf("org.freedesktop.udisks2.") == 0) { return polkit.Result.YES; }
});
EOF
sleep 2

# --- 2. The whole thing, in a terminal -----------------------------------------------------------------------------------------------------
mkdir -p "${HOME_DIR}/Documents"
echo "mine, not Windows'" >"${HOME_DIR}/Documents/report.docx"
chown -R "${TEST_USER}:" "${HOME_DIR}/Documents"
as_tester rm -rf "${HOME_DIR}/.local/state/amethystora/move-in"
# One more terminal, at the same time, reads the mounts while the first one waits at its last question
STEPS=()
if id -nG "${TEST_USER}" | tr ' ' '\n' | grep -qx wheel; then
    # An administrator is offered every account: Pat's, then the account's own
    STEPS=("Whose files" $'2\r')
fi
SHOWN="$(in_terminal 300 "${STEPS[@]}" "Copy Documents" $'\r' "Copy Pictures" $'\r' "Copy Desktop" $'n\r' -- "${AS_TESTER[@]}" "ame system move-in" 2>&1)"
echo "${SHOWN}" | tail -n 25 | sed 's/^/# /'
if ((${#STEPS[@]})); then holds "the Windows accounts were offered to an administrator" has "Pat" "${SHOWN}"; fi
holds "Downloads was never offered" lacks "Downloads" "${SHOWN}"
holds "the copy was said" has "Copied" "${SHOWN}"
same "a file already here was never replaced" "$(cat "${HOME_DIR}/Documents/report.docx")" "mine, not Windows'"
same "the Windows file is beside it" "$(cat "${HOME_DIR}/Documents/report (from Windows).docx" 2>/dev/null)" "the report, Windows' copy"
same "a folder inside Documents came whole" "$(cat "${HOME_DIR}/Documents/letters/a.txt" 2>/dev/null)" "dear friend"
same "Pictures came" "$(cat "${HOME_DIR}/Pictures/p.jpg" 2>/dev/null)" "a picture"
holds "Desktop, which was answered no, did not" test ! -e "${HOME_DIR}/Desktop/todo.txt"
same "a OneDrive file that was downloaded came with Documents" "$(cat "${HOME_DIR}/Documents/synced.txt" 2>/dev/null)" "synced and here"
if ((HOLDERS)); then
    holds "a OneDrive placeholder was left" test ! -e "${HOME_DIR}/Documents/cloud-only.docx"
    holds "a OneDrive placeholder was counted" has "only in OneDrive" "${SHOWN}"
fi
holds "Downloads, AppData and the other account were not copied" bash -c "! find '${HOME_DIR}' -name setup.exe -o -name 'Login Data' -o -name pat.txt 2>/dev/null | grep -q ."
holds "no password was read into the home" bash -c "! grep -rqs CANARY-CHROME '${HOME_DIR}/Documents' '${HOME_DIR}/Pictures' '${HOME_DIR}/Desktop'"
holds "no half file was left" bash -c "! find '${HOME_DIR}' -name '*.amethystora-partial' | grep -q ."
holds "the disk was unmounted at the end" bash -c "! findmnt -S '${PART}' >/dev/null"
holds "what was copied is the account's own" test "$(stat -c %U "${HOME_DIR}/Documents/letters/a.txt")" = "${TEST_USER}"

# --- 3. Again, and in steps ------------------------------------------------------------------------------------------------------------------
echo "edited here" >"${HOME_DIR}/Documents/letters/a.txt"
AGAIN="$(in_terminal 300 -- "${AS_TESTER[@]}" "amethystora-move-in copy '${PART}' '${TEST_USER}' --json" 2>&1 | grep '^{' | tail -n 1)"
same "a second run copies nothing" "$(jq -r '.copied' <<<"${AGAIN}" 2>/dev/null)" 0
holds "what was edited here is not copied again" test "$(cat "${HOME_DIR}/Documents/letters/a.txt")" = "edited here"
holds "no second copy beside the first" test "$(find "${HOME_DIR}/Documents" -name 'report*' | wc -l)" = 2
FIND="$(as_tester "${HELPER}" find --json 2>&1)"
same "find lists the account of the disk" "$(jq -r --arg p "${PART}" '.parts[] | select(.part == $p) | .accounts | join(",")' <<<"${FIND}" 2>/dev/null)" "Pat,${TEST_USER}"
LOOK="$(as_tester "${HELPER}" look "${PART}" --json 2>&1)"
same "look says what each folder holds" "$(jq -r --arg u "${TEST_USER}" '.accounts[] | select(.name == $u) | .folders | map(.id) | sort | join(",")' <<<"${LOOK}" 2>/dev/null)" "desktop,documents,pictures"
same "a device nobody offered is refused" "$(as_tester "${HELPER}" look /dev/vda >/dev/null 2>&1; echo $?)" 1
holds "nothing is mounted after the steps" bash -c "! findmnt -S '${PART}' >/dev/null"

# --- 4. The first look's card ---------------------------------------------------------------------------------------------------------------------
atspi() { as_tester env "XDG_RUNTIME_DIR=/run/user/${UID_TEST}" "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/${UID_TEST}/bus" python3 /run/vmlab-79/atspi.py "$@"; }
as_tester rm -f "${HOME_DIR}/.local/state/amethystora/move-in-offered"
"${AS_TESTER[@]}" "systemd-run --user --collect --quiet --unit=vmlab-79-welcome -- amethystora-control welcome" 2>/dev/null
if wait_for 60 atspi amethystora-control has "COMING FROM WINDOWS"; then
    ok "the first look offers Move in from Windows"
    atspi amethystora-control click "Not now" >/dev/null 2>&1 || not_ok "Not now was not found"
    sleep 2
    if atspi amethystora-control has "COMING FROM WINDOWS" >/dev/null 2>&1; then not_ok "Not now left the card"; else ok "Not now puts the card away"; fi
else
    not_ok "the first look does not offer Move in from Windows" "$(atspi amethystora-control text 2>&1 | head -n 20)"
fi
systemctl --user -M "${TEST_USER}@" stop vmlab-79-welcome.service 2>/dev/null
sleep 2
"${AS_TESTER[@]}" "systemd-run --user --collect --quiet --unit=vmlab-79-welcome2 -- amethystora-control welcome" 2>/dev/null
sleep 8
if atspi amethystora-control has "Pick a look" >/dev/null 2>&1 && ! atspi amethystora-control has "COMING FROM WINDOWS" >/dev/null 2>&1; then
    ok "a window opened again offers it no more"
else
    not_ok "a second window still offers Move in from Windows, or did not open" "$(atspi amethystora-control text 2>&1 | head -n 20)"
fi
systemctl --user -M "${TEST_USER}@" stop vmlab-79-welcome2.service 2>/dev/null

# --- 5. The disk is what it was ------------------------------------------------------------------------------------------------------------------
udevadm settle
SUM_AFTER="$(sha256sum "${DISK}" | cut -d' ' -f1)"
same "the disk's checksum is unchanged by everything above" "${SUM_AFTER}" "${SUM_BEFORE}"
wipefs -a "${DISK}" >/dev/null 2>&1
finish
