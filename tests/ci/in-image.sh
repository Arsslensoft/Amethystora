#!/usr/bin/bash
# in-image.sh KIND [SHARD/OF]: tests/ci/run.sh inside the last published image, with this checkout's system_files laid
# over it, as the Unit and Integration workflows run it (and as anyone can on a machine with podman). The image is
# CI_IMAGE (default ghcr.io/arsslensoft/amethystora:latest), pulled once its signature checks out against cosign.pub
# when cosign is there; the checkout goes in at /ctx, the Node on PATH at /opt/node, and the results come back in
# RESULTS (default ./ci-results). What the change makes at build time (the apps, the schemas, the packages) is the
# published image's: a test of a helper that needs a new package or program waits for the image that has it.
set -euo pipefail

cd "$(dirname "$0")/../.."
IMAGE="${CI_IMAGE:-ghcr.io/arsslensoft/amethystora:latest}"
RESULTS="$(realpath -m "${RESULTS:-ci-results}")"
PODMAN="${PODMAN:-podman}"
mkdir -p "${RESULTS}"

digest="$(skopeo inspect --retry-times 3 --no-tags "docker://${IMAGE}" | jq -r .Digest)"
[[ "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "in-image.sh: no digest for ${IMAGE}" >&2; exit 1; }
if command -v cosign >/dev/null; then
    cosign verify --key cosign.pub "${IMAGE%:*}@${digest}" >/dev/null
    echo "in-image.sh: ${IMAGE%:*}@${digest}, signed"
else
    echo "::warning::cosign is not installed: ${IMAGE%:*}@${digest} is used unchecked"
fi
${PODMAN} pull --quiet --retry 3 "${IMAGE%:*}@${digest}" >/dev/null

node_dir=()
if command -v node >/dev/null; then
    node_dir=(--volume "$(dirname "$(dirname "$(realpath "$(command -v node)")")"):/opt/node:ro" --env NODE=/opt/node/bin/node)
elif [[ "$1" == unit ]]; then
    echo "in-image.sh: the unit tests need Node on PATH" >&2
    exit 1
fi

# Privileged and root, as a build's RUN is root with what a test of stand-ins asks of it (namespaces, mounts, other
# accounts); a container of its own each time, thrown away
exec ${PODMAN} run --rm --privileged --user root --tmpfs /tmp:exec --tmpfs /run:exec \
    --volume "${PWD}:/ctx" --volume "${RESULTS}:/results" "${node_dir[@]}" \
    --env CTX=/ctx --env RESULTS=/results --env TEST_TIMEOUT="${TEST_TIMEOUT:-1200}" \
    --entrypoint /usr/bin/bash "${IMAGE%:*}@${digest}" /ctx/tests/ci/run.sh --overlay "$@"
