#!/usr/bin/bash
# forensic-live.sh ISO [--control] | disk: the live ISO's forensic start (iso/live/forensic, manual: forensic-start.md) tried
# in the lab. `disk` makes the disk to try it against once (forensic-disk.sh: ext4, XFS, btrfs, LVM, LUKS, swap and an MD
# RAID1, with unreplayed logs); the ISO is the live ISO of a build (the one `build-iso.yml`'s live-iso job makes, or one made
# with the Titanoboa recipe of that job). The ISO's own kernel is started with the entry's arguments, the disk is
# checksummed before and after, and the session is used as a person would. With --control the first entry is tried
# instead and the checksum must differ. Not part of run.sh: the lab's other suites run in an installed image, this in the
# live system, and it needs the ISO. Needs the lab running (setup.sh) and KVM, as the lab does.
set -euo pipefail

export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")"
if ! command -v docker >/dev/null && command -v cygpath >/dev/null; then
    PATH="$(cygpath -u "${LOCALAPPDATA}")/Programs/DockerDesktop/resources/bin:${PATH}"
fi
LAB=/vm/forensic
docker exec amevm mkdir -p "${LAB}"
# The checkout's lab code, with LF endings: a run's copy in /opt can be older
for f in forensic-live.mjs forensic-disk.sh lab.mjs agent.py; do tr -d '\r' <"${f}" | docker exec -i amevm sh -c "cat >${LAB}/${f}"; done
case "${1:-}" in
disk)
    docker exec amevm bash "${LAB}/forensic-disk.sh" "${LAB}"
    ;;
*)
    iso="${1:?forensic-live.sh ISO [--control] | disk}"
    docker cp "${iso}" "amevm:${LAB}/live.iso"
    docker exec amevm sh -c "dnf -y -q install xorriso >/dev/null 2>&1 || true"
    [[ "${2:-}" == --control ]] && cp="--control" || cp=""
    # Each run starts from the disk as it was made: the checksum is of that file
    docker exec amevm sh -c "cd ${LAB} && node forensic-live.mjs ${LAB}/live.iso ${cp}"
    ;;
esac
