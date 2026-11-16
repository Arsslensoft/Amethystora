#!/usr/bin/bash

echo "::group:: ===$(basename "$0")==="

set -eoux pipefail

IMPORTANT_PACKAGES_DX=(
    bpftool
    codium
    containerd.io
    docker-ce
    docker-buildx-plugin
    docker-compose-plugin
    flatpak-builder
    gdb
    libvirt
    ltrace
    perf
    qemu
    strace
    valgrind
    wireshark
)

for package in "${IMPORTANT_PACKAGES_DX[@]}"; do
    rpm -q "${package}" >/dev/null || { echo "Missing package: ${package}... Exiting"; exit 1 ; }
done

# genisoimage is Fedora's, not negativo17's CDDL mkisofs (00-dx.sh)
[[ "$(rpm -q --queryformat '%{VENDOR}' genisoimage)" == "Fedora Project" ]]
rpm -q mkisofs >/dev/null && false

# The development apps are installed on the first boot, beside the ones every image comes with
grep -q "^\[Flatpak Preinstall org.gnome.Builder\]$" /usr/share/flatpak/preinstall.d/amethystora-dx.preinstall

IMPORTANT_UNITS=(
    docker.socket
    podman.socket
)

for unit in "${IMPORTANT_UNITS[@]}"; do
    if ! systemctl is-enabled "$unit" 2>/dev/null | grep -q "^enabled$"; then
        echo "${unit} is not enabled"
        exit 1
    fi
done


# Passing a USB device to a virtual machine asks an administrator: the rule names the action spice-glib ships
grep -rqF 'action id="org.spice-space.lowlevelusbaccess"' /usr/share/polkit-1/actions
grep -qF 'org.spice-space.lowlevelusbaccess' /usr/share/polkit-1/rules.d/50-amethystora-spice-usb.rules
grep -qF 'polkit.Result.AUTH_ADMIN' /usr/share/polkit-1/rules.d/50-amethystora-spice-usb.rules

# qemu-bridge-helper (setuid root) is allowed no bridge, for any account
if grep -qE '^[[:space:]]*allow' /etc/qemu/bridge.conf; then
    echo "/etc/qemu/bridge.conf allows a bridge"
    exit 1
fi

# incus-workaround copies the right files and is enabled by nothing
grep -qF 'cp /usr/bin/incus-agent /usr/local/bin/overrides/incus-agent' /usr/lib/systemd/system/incus-workaround.service
grep -qF 'cp -R /usr/lib/incus /usr/local/lib/overrides/incus' /usr/lib/systemd/system/incus-workaround.service
if systemctl is-enabled incus-workaround.service 2>/dev/null | grep -q "^enabled$"; then
    echo "incus-workaround.service is enabled"
    exit 1
fi

# Every setuid, setgid and file-capability program of the image is named below. A package that brings another one
# is said in the build until somebody has looked at what it gives and added it here.
ALLOWED_PRIVILEGED=(
    # the base image's
    /usr/bin/fusermount
    /usr/bin/fusermount3
    /usr/bin/unix_chkpwd
    /usr/bin/pam_timestamp_check
    /usr/bin/pkexec
    /usr/bin/grub2-set-bootflag
    /usr/bin/umount
    /usr/bin/mount
    /usr/bin/mount.nfs
    /usr/bin/vmware-user-suid-wrapper
    /usr/bin/passwd
    /usr/bin/su
    /usr/bin/sudo
    /usr/bin/lockdev
    /usr/libexec/lxc/lxc-user-nic
    /usr/libexec/utempter/utempter
    /usr/lib/polkit-1/polkit-agent-helper-1
    /usr/bin/arping
    /usr/bin/clockdiff
    /usr/bin/mtr-packet
    /usr/bin/newuidmap
    /usr/bin/newgidmap
    /usr/bin/suexec
    /usr/libexec/sssd/krb5_child
    /usr/libexec/sssd/ldap_child
    /usr/libexec/sssd/selinux_child
    /usr/libexec/sssd/sssd_pam
    /usr/libexec/gstreamer-1.0/gst-ptp-helper
    /usr/libexec/gvfsd-nfs
    # dx's, read from Fedora 45's packages: spice-glib (setuid, with a polkit rule above), qemu-common (setuid,
    # with no bridge allowed above) and wireshark-cli (capabilities, runnable by the group wireshark only)
    /usr/libexec/spice-gtk-x86_64/spice-client-glib-usb-acl-helper
    /usr/libexec/qemu-bridge-helper
    /usr/bin/dumpcap
    # not read from a package: VSCodium's Electron sandbox and NVIDIA's module loader, which the first build
    # that has them shows
    /usr/share/codium/chrome-sandbox
    /usr/bin/nvidia-modprobe
)
command -v getcap >/dev/null
CAPS_FOUND=$(getcap -r /usr)
mapfile -t PRIVILEGED < <({ find /usr -type f \( -perm -4000 -o -perm -2000 \); awk '{print $1}' <<<"$CAPS_FOUND"; } | sort -u)
echo "Setuid, setgid and file-capability programs:"
printf '%s\n' "${PRIVILEGED[@]}"
UNEXPECTED=0
for program in "${PRIVILEGED[@]}"; do
    [[ -z "$program" ]] && continue
    if ! printf '%s\n' "${ALLOWED_PRIVILEGED[@]}" | grep -qxF -- "$program"; then
        echo "::warning::${program} is setuid, setgid or has file capabilities, and is not in the list of 01-tests-dx.sh"
        UNEXPECTED=1
    fi
done
# A warning until a dx build has shown the list whole (it was first written from Fedora's packages, without a dx
# image at hand): then this line becomes [[ "$UNEXPECTED" == 0 ]]
[[ "$UNEXPECTED" == 0 ]] || echo "::warning::01-tests-dx.sh: the list of privileged programs is not complete"

echo "::endgroup::"
