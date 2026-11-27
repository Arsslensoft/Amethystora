#!/usr/bin/bash
# iso.sh installer|live ISO [--digest sha256:...]: an ISO of a build installed in the lab as a person installs it, and the
# machine it made started under Secure Boot and looked at (iso.mjs says how). The installer ISO is the one
# build-iso.yml's ISO job makes (bootc-image-builder), the live ISO its live-iso job's (Titanoboa), from any image: the
# Lab (ISOs) workflow makes both from the commit's. --digest is the image's, which the installed machine must run. Not
# part of run.sh: the suites run in an image installed by make-disk.sh, this in what the ISOs install. Needs the lab
# running (setup.sh) and KVM, as the lab does; with VMLAB_VOLUME (a folder for /vm, as on GitHub) the ISO is moved there
# instead of copied into the container.
set -euo pipefail

export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")"
if ! command -v docker >/dev/null && command -v cygpath >/dev/null; then
    PATH="$(cygpath -u "${LOCALAPPDATA}")/Programs/DockerDesktop/resources/bin:${PATH}"
fi
kind="${1:?iso.sh installer|live ISO [--digest D]}"
iso="${2:?iso.sh installer|live ISO [--digest D]}"
shift 2
[[ "${kind}" == installer || "${kind}" == live ]] || { echo "iso.sh: installer or live, not ${kind}" >&2; exit 64; }
[[ -f "${iso}" ]] || { echo "iso.sh: no ISO ${iso}" >&2; exit 64; }

LAB=/vm/iso-lab
docker exec amevm mkdir -p "${LAB}"
# The checkout's lab code, with LF endings: a run's copy in /opt can be older
for f in iso.mjs webui.mjs lab.mjs agent.py; do tr -d '\r' <"${f}" | docker exec -i amevm sh -c "cat >${LAB}/${f}"; done
docker exec amevm sh -c "command -v xorriso >/dev/null || dnf -y -q install xorriso >/dev/null"
if [[ -n "${VMLAB_VOLUME:-}" ]]; then
    sudo mkdir -p "${VMLAB_VOLUME}/iso-lab"
    sudo mv "${iso}" "${VMLAB_VOLUME}/iso-lab/${kind}.iso"
else
    docker cp "${iso}" "amevm:${LAB}/${kind}.iso"
fi
status=0
docker exec amevm sh -c "cd ${LAB} && node iso.mjs ${kind} ${LAB}/${kind}.iso $*" || status=$?
# The screenshots and the console beside the results, for the run's files
docker exec amevm sh -c "cp -f /vm/vms/iso-${kind}.serial /vm/vms/iso-${kind}.log /vm/iso/${kind}/ 2>/dev/null; rm -f ${LAB}/${kind}.iso /vm/vms/iso-${kind}.qcow2" || true
exit "${status}"
