#!/usr/bin/bash
# ci-collect.sh: the end of a job of the Lab workflow (.github/workflows/lab.yml). Copies the run folders the lab wrote
# under VMLAB_VOLUME/runs (root's) to RUNNER_TEMP/runs, for the job's artifact, with each VM's serial console and
# QEMU's log, and adds each run's summary.md and the room left on the runner to the job's summary.
set -euo pipefail

vm="${VMLAB_VOLUME:-${RUNNER_TEMP}/vm}"
out="${RUNNER_TEMP}/runs"
mkdir -p "${out}"
if [[ -d "${vm}/runs" ]]; then
    sudo tar -C "${vm}/runs" --exclude='./last*' -cf - . | tar -xf - -C "${out}"
fi
if [[ -d "${vm}/vms" ]]; then
    mkdir -p "${out}/vms"
    sudo find "${vm}/vms" -maxdepth 1 -type f \( -name '*.serial' -o -name '*.log' \) -exec cp -t "${out}/vms" {} +
    sudo chown -R "$(id -u):$(id -g)" "${out}/vms"
fi
for summary in "${out}"/*/summary.md; do
    [[ -e "${summary}" ]] && cat "${summary}" >>"${GITHUB_STEP_SUMMARY}"
done
{
    echo '### Room left'
    echo '```'
    df -h / "${RUNNER_TEMP}"
    echo '```'
} >>"${GITHUB_STEP_SUMMARY}"
