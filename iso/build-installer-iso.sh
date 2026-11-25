#!/usr/bin/bash
# build-installer-iso.sh IMAGE ISO: the installer ISO of IMAGE (<repository>:<tag>, already in root's container storage
# under that name), as build-iso.yml publishes it and the Lab (ISOs) workflow installs it: bootc-image-builder with
# iso.toml, the installer's package list, the Amethystora product image and the licences. Run as root on an Ubuntu
# runner, from the checkout; it writes output/ and product/ beside it, and ISO. Every step's reason is below.
set -euo pipefail

IMAGE_REF="${1:?build-installer-iso.sh IMAGE ISO}"
ISO="${2:?build-installer-iso.sh IMAGE ISO}"
BUILDER=quay.io/centos-bootc/bootc-image-builder@sha256:2b52843ea2bfda73b0a08d97e76b734393b1d3a804681b9fabb26723bd3a2f0b
cd "$(dirname "$0")/.."
[[ "${IMAGE_REF}" =~ ^[a-z0-9./-]+:[a-z0-9._-]+$ ]] || { echo "build-installer-iso.sh: IMAGE is REPOSITORY:TAG, not ${IMAGE_REF}" >&2; exit 64; }
podman image exists "${IMAGE_REF}" || { echo "build-installer-iso.sh: ${IMAGE_REF} is not in root's container storage" >&2; exit 1; }

# --- The installer configuration --------------------------------------------------------------------------------------
config="$(mktemp)"
trap 'rm -f "${config}"' EXIT
sed "s|@IMAGE@|${IMAGE_REF%:*}|" iso/iso.toml >"${config}"
# The machine it installs takes updates signature-checked from the first one
grep -q -- "--enforce-container-sigpolicy" "${config}"
if grep -E "^[^#]*bootc switch" "${config}" | grep -v -- "--enforce-container-sigpolicy"; then
    echo "::error::iso.toml switches the installed machine without signature checking"
    exit 1
fi

# --- The ISO --------------------------------------------------------------------------------------------------------------
# bootc-image-builder chooses the installer's packages by the image's os-release ID and has no definition for
# amethystora, so Fedora's is written out under that name before it starts, with two packages added: generic-logos and
# generic-release. Fedora's trademark guidelines ask a system built from Fedora to leave fedora-logos and fedora-release
# out. The list names neither, so Fedora's would arrive as dependencies; asked for by name, the generic ones conflict
# with them and take their place. That needs the builder's container run by hand: its GitHub action cannot add to it.
# The storage configuration is the action's own fix, https://github.com/osbuild/bootc-image-builder/issues/446
#
# The builder is pinned to its build of June 2026, the last that reads its definitions from that folder. Its successor,
# which `latest` is due to become, has them compiled in, so moving to it means rewriting this step.
#
# It looks for the image's repositories in /etc/yum.repos.d alone, where Fedora 45 keeps none of its own
# (osbuild/image-builder#2704): iso/builder-repos.py has its solver read what the image's dnf reads, overrides included,
# so that the installer still comes from Fedora's repositories only.
#
# The builder will not start without the installed system's root filesystem type, which the image does not declare in
# /usr/lib/bootc/install. It only writes it into a kickstart of its own, and iso.toml brings one, so Anaconda still lays
# out the disk; btrfs is what it chooses.
#
# Ubuntu, from 25.10, confines /usr/bin/bwrap, in a container as well, with its bwrap-userns-restrict profile, which
# denies every capability to whatever bwrap starts. osbuild runs each stage under bwrap, so its stages could neither chown
# nor mount; the profile is unloaded before the builder starts.
if [[ -e /etc/apparmor.d/bwrap-userns-restrict ]]; then
    apparmor_parser -R /etc/apparmor.d/bwrap-userns-restrict || true
fi
podman pull "${BUILDER}"
rm -rf output
mkdir output
podman run --rm --privileged --security-opt label=type:unconfined_t \
    --volume /var/lib/containers/storage:/var/lib/containers/storage \
    --volume ./output:/output \
    --volume "${config}:/config.toml:ro" \
    --volume ./iso/builder-repos.py:/builder-repos.py:ro \
    --entrypoint /bin/bash "${BUILDER}" -c '
      set -euo pipefail
      python3 /builder-repos.py
      cd /usr/share/bootc-image-builder/defs
      for def in fedora-*.yaml; do
        { cat "${def}"; printf "    - generic-logos\n    - generic-release\n"; } > "amethystora-${def#fedora-}"
      done
      exec bootc-image-builder "$@"' bash \
    build --output /output --type anaconda-iso --rootfs btrfs --use-librepo=True \
    --chown "${SUDO_UID:-$(id -u)}:${SUDO_GID:-$(id -g)}" "${IMAGE_REF}"

# What the installer is made of, from the manifest the builder leaves beside the ISO, for the ISO to carry. This fails,
# before anything is uploaded, if Fedora's logo or release package is in the installer after all.
python3 iso/installer-packages.py output/manifest-anaconda-iso.json >INSTALLER-PACKAGES

# --- The installer's look and the licences ---------------------------------------------------------------------------------
# Anaconda is installed from Fedora's packages and looks like Fedora's until it finds a product.img in the images/
# directory of the install media, which it lays over its own root before it starts. iso/product is the Amethystora one,
# drawn by branding/generate.mjs.
#
# The web installer says what it installs by the installer's own os-release, generic-release's ("Generic"): the product
# image carries one that names the image as it names itself, and keeps the ID, ID_LIKE and VERSION_ID that Anaconda picks
# its profile and kickstart version by
rm -rf product
cp -a iso/product product
mkdir -p product/etc
# shellcheck disable=SC2016
podman run --rm --entrypoint /usr/bin/bash "${IMAGE_REF}" -c \
    '. /usr/lib/os-release && printf "NAME=\"%s\"\nVERSION=\"%s\"\nID=generic\nID_LIKE=fedora\nVERSION_ID=%s\nPRETTY_NAME=\"%s\"\n" \
      "${NAME//\"/}" "${VERSION_ID}" "${VERSION_ID}" "${PRETTY_NAME//\"/}"' >product/etc/os-release
grep -qx 'VERSION_ID=[0-9][0-9]*' product/etc/os-release
(cd product && find . -mindepth 1 | LC_ALL=C sort | cpio --quiet -o -H newc -R 0:0 | gzip -9) >product.img
mkdir -p "$(dirname "${ISO}")"
rm -f "${ISO}"
# replay keeps the boot records bootc-image-builder wrote: BIOS, UEFI and the hybrid MBR/GPT. LICENSE, NOTICE and the
# installer's package list go beside the installer: NOTICE names what the ISO redistributes and carries the written offer
# for its source, which has to reach whoever receives the ISO
xorriso -indev output/bootiso/install.iso -outdev "${ISO}" -boot_image any replay \
    -map product.img /images/product.img -map LICENSE /LICENSE -map NOTICE /NOTICE \
    -map INSTALLER-PACKAGES /INSTALLER-PACKAGES
# "Test this media" checks the image against the checksum implanted in it, which adding the file has invalidated
implantisomd5 --force "${ISO}"
[[ -n "${SUDO_UID:-}" ]] && chown "${SUDO_UID}:${SUDO_GID}" "${ISO}"
echo "build-installer-iso.sh: ${ISO}"
