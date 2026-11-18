#!/usr/bin/bash
# Turns Amethystora into the live system of the live ISO (iso/live/Containerfile). The live session
# runs from the squashed image in memory; the system it installs is the published image itself, a copy
# of which this puts in the live system so that installing needs no network, and which the installed
# machine then follows from the registry.
#
# What it adds is Fedora's: the live boot (dracut-live), the live session (livesys-scripts), and the
# installer (anaconda-live with its web interface). Nothing from anywhere else, but the sealed images'
# own installer (amethystora-install-sealed), which downloads what it installs.

set -xeuo pipefail

: "${BASE_IMAGE:?the image the ISO installs}"
: "${BASE_DIGEST:?the digest of it that the workflow checked}"
LIVE=/src/live

mkdir -p "$(realpath /root)"

# --- The system to install ----------------------------------------------------------------------------

# Into the read-only image store that containers-common lists for root (additionalimagestores), where
# the installer's bootc install finds it by name. The storage settings are only for this pull. It is
# pulled by digest, the one the live system is built from, and only then given the name it installs by.
# podman 6 refuses to write into a store it also has as an additional one (ublue-os/titanoboa#151), and
# Fedora 45's containers-common lists it in a drop-in for root, which only a drop-in of the same name in
# /etc replaces: for the pull, each one is replaced by one without the store.
cat >/etc/containers/storage.conf <<'EOF'
[storage]
driver = "overlay"
runroot = "/run/containers/storage"
graphroot = "/usr/lib/containers/storage"
EOF
vendor=(/usr/share/containers/storage.rootful.conf.d/*.conf)
[[ -e "${vendor[0]}" ]] || vendor=()
mkdir -p /etc/containers/storage.rootful.conf.d
for conf in "${vendor[@]}"; do
    printf '[storage.options]\nadditionalimagestores = []\n' >"/etc/containers/storage.rootful.conf.d/${conf##*/}"
done
podman pull "${BASE_IMAGE%:*}@${BASE_DIGEST}"
podman tag "${BASE_IMAGE%:*}@${BASE_DIGEST}" "${BASE_IMAGE}"
for conf in "${vendor[@]}"; do rm "/etc/containers/storage.rootful.conf.d/${conf##*/}"; done
rmdir --ignore-fail-on-non-empty /etc/containers/storage.rootful.conf.d
rm -rf /run/containers/storage
# ...where the live session finds it, read-only, as the installer will: asked through a store of its own
# in /var/tmp, which is not kept, with the vendor's drop-ins
cat >/etc/containers/storage.conf <<'EOF'
[storage]
driver = "overlay"
runroot = "/var/tmp/store-run"
graphroot = "/var/tmp/store"
EOF
podman images --format '{{.Repository}}:{{.Tag}} {{.ReadOnly}}' | grep -qxF "${BASE_IMAGE} true"
rm -f /etc/containers/storage.conf

# --- The live boot and the installer ------------------------------------------------------------------

dnf -y install dracut-live livesys-scripts anaconda-live anaconda-webui \
    libblockdev-btrfs libblockdev-lvm libblockdev-dm grub2-efi-x64-cdboot \
    cryptsetup dosfstools efibootmgr mokutil

# An initramfs that can find the squashed system on the stick and lay a writable layer over it
kernel="$(find /usr/lib/modules -mindepth 1 -maxdepth 1 -printf '%f\n' | sort -V | tail -n 1)"
DRACUT_NO_XATTR=1 dracut --force --zstd --reproducible --no-hostonly \
    --add "dmsquash-live dmsquash-live-autooverlay" "/usr/lib/modules/${kernel}/initramfs.img" "${kernel}"

# Fedora's GNOME live session: logged in as liveuser, with the installer in the dash
sed -i 's/^livesys_session=.*/livesys_session=gnome/' /etc/sysconfig/livesys
systemctl enable livesys.service livesys-late.service

# The ISO boots through the image's own shim and GRUB, signed by Fedora, so Secure Boot can stay on
mkdir -p /boot/efi
cp -a /usr/lib/efi/*/*/EFI /boot/efi/
cp /boot/efi/EFI/fedora/grubx64.efi /boot/efi/EFI/BOOT/fbx64.efi

rm -f /etc/localtime
systemd-firstboot --timezone UTC

# The live session writes to memory, and what the installer unpacks goes through /var/tmp first
install -Dpm0644 "${LIVE}/var-tmp.mount" /usr/lib/systemd/system/var-tmp.mount
systemctl enable var-tmp.mount

# --- The installer's look and what it installs -------------------------------------------------------

# The same look as the installer ISO's (iso/product), laid over Anaconda as that ISO's product.img is
cp -a /src/product/. /
# ...and a profile for this os-release, whose ID is the image's own rather than the installer ISO's
install -Dpm0644 "${LIVE}/amethystora-live.conf" /etc/anaconda/profile.d/amethystora-live.conf
# What Anaconda installs, and where it points the installed machine
sed "s|@IMAGE@|${BASE_IMAGE}|g" "${LIVE}/installer.ks" >/usr/share/anaconda/interactive-defaults.ks
# ...which takes its updates signature-checked from the first one
grep -q -- "--enforce-container-sigpolicy" /usr/share/anaconda/interactive-defaults.ks
if grep "bootc switch" /usr/share/anaconda/interactive-defaults.ks | grep -v -- "--enforce-container-sigpolicy"; then
    echo "installer.ks switches the installed machine without signature checking" >&2
    exit 1
fi

# ...and relabels what Anaconda wrote with the policy's own user: started from its window it writes as the
# live account's, and installer.ks's label checks then failed the installation
grep -q -- 'restorecon -F -r /etc /var' /usr/share/anaconda/interactive-defaults.ks

# ...and keeps the image's firewall, without the ssh Anaconda adds by itself
grep -qx -- "firewall --use-system-defaults" /usr/share/anaconda/interactive-defaults.ks

# ...and gives the installed machine the boot splash and the keyboard chosen for its passphrase, which
# Anaconda's bootc path leaves out
grep -q -- 'set-kargs --sysroot=/mnt/sysimage --merge rhgb quiet .*vconsole.keymap=' /usr/share/anaconda/interactive-defaults.ks

# The sealed images (:stable-sealed), which Anaconda cannot install yet, have an installer of their own:
# a whole disk, the image downloaded from the registry, shim placed in front of systemd-boot. Amethystora's
# own images only: an image of one's own built on one (its template runs this too) has no sealed variant
if [[ "${BASE_IMAGE}" == ghcr.io/arsslensoft/* ]]; then
    install -Dpm0755 "${LIVE}/amethystora-install-sealed" /usr/bin/amethystora-install-sealed
    install -Dpm0644 "${LIVE}/amethystora-install-sealed.desktop" \
        /usr/share/applications/amethystora-install-sealed.desktop
fi

# Anaconda's welcome window for the live session names Fedora, as its desktop entries do: this is a
# system built on Fedora, not Fedora, and its trademark guidelines ask for its name to stay off it
# Each file changed here says so, as the GPL asks of a changed file (NOTICE names the changes too)
changed='Changed by Amethystora when its live ISO is built (iso/live/build.sh)'
{ grep -rlI --null 'Fedora' /usr/share/anaconda/gnome /usr/share/applications/liveinst.desktop 2>/dev/null || true; } |
    while IFS= read -r -d '' file; do
        sed -i 's/\bFedora\b/Amethystora/g' "${file}"
        # The welcome window is a GJS script since Fedora 45, where a line that starts with # is a syntax error:
        # it never opened, and the live session started without the installer's offer
        if [[ "$(head -n1 "${file}")" == '#!'*gjs* ]]; then
            echo "// ${changed}" >>"${file}"
        elif [[ ${file} == *.desktop || "$(head -c2 "${file}")" == '#!' ]]; then
            echo "# ${changed}" >>"${file}"
        fi
    done
# ...which the session opens at its start (livesys copies it into the live account's autostart), and which still reads
# as the language it is written in
welcome=/usr/share/anaconda/gnome/fedora-welcome
[[ -x ${welcome} && -e /usr/share/anaconda/gnome/org.fedoraproject.welcome-screen.desktop ]] ||
    { echo "the live session has no welcome window that offers the installer" >&2; exit 1; }
if [[ "$(head -n1 "${welcome}")" == '#!'*gjs* ]] && tail -n +2 "${welcome}" | grep -nE '^#'; then
    echo "${welcome}: a # comment in a GJS script, which would keep it from opening" >&2
    exit 1
fi
# The installer's offer is what a live session opens on: not the Manual's welcome page, Pick a look or the greeting
# of a new account, which would open over it and are for the installed system's first login (the live account's
# home is made from /etc/skel at every start)
rm -f /usr/share/amethystora/user-setup.hooks.d/17-welcome.sh /usr/share/amethystora/user-setup.hooks.d/25-first-look.sh
install -d /etc/skel/.local/state/amethystora
echo '{}' >/etc/skel/.local/state/amethystora/first-look.json

# liveinst takes a release package whose release starts with 0. for a pre-release, and Fedora's
# generic-release is one (44-0.2): the web installer would show a "Pre-release" badge on a stable image
sed -i -E 's/(ANACONDA_ISFINAL=)"?false"?/\1"true"/' /usr/bin/liveinst
echo "# ${changed}" >>/usr/bin/liveinst
if grep -nE 'ANACONDA_ISFINAL="?false' /usr/bin/liveinst; then
    echo "liveinst still calls the live system a pre-release" >&2
    exit 1
fi
# ...and its last page, on every release, asks for feedback on Fedora's forum, with a QR code for it
webui=/usr/share/cockpit/anaconda-webui
zcat "${webui}/index.js.gz" | grep -c 'className:"feedback-section"' >/dev/null
{ zcat "${webui}/index.css.gz"; echo "/* ${changed} */"; echo '.feedback-section { display: none !important; }'; } |
    gzip -9n >"${webui}/index.css.gz.new"
mv "${webui}/index.css.gz.new" "${webui}/index.css.gz"

# --- The live session --------------------------------------------------------------------------------

# Nothing that would download, scan or set up a machine for good runs in a session that ends at
# shutdown: the apps come with the first boot of the installed system
systemctl disable uupd.timer flatpak-preinstall.service fwupd-refresh.timer amethystora-gpu-check.timer \
    amethystora-signed-updates.service amethystora-clamav-scan.timer amethystora-lynis-audit.timer \
    amethystora-security-watch.timer clamav-freshclam.service clamd@scan.service rpm-ostree-countme.service \
    brew-setup.service
systemctl --global disable amethystora-pkg-upgrade.timer amethystora-update-alert.service \
    amethystora-security-alert.service
# ...and bootupd, which finds no boot disk to update in a session started from a stick, and fails
systemctl mask bootloader-update.service

# An installation takes long enough for GNOME to lock the screen and suspend the machine, and livesys
# no longer stops either. Waking a live system from a USB stick can lose the stick, and the session
# with the installer in it (issue #6), so the live session never locks or suspends by itself. It
# still blanks: that ends nothing. Sorted after the image's own zz0 and zz1, which set none of these.
cat >/usr/share/glib-2.0/schemas/zz9-amethystora-live.gschema.override <<'EOF'
[org.gnome.desktop.screensaver]
lock-enabled=false

[org.gnome.desktop.lockdown]
disable-lock-screen=true

[org.gnome.settings-daemon.plugins.power]
sleep-inactive-ac-type='nothing'
sleep-inactive-battery-type='nothing'
EOF
glib-compile-schemas /usr/share/glib-2.0/schemas

# The forensic start (the third boot menu entry, manual: forensic-start.md): units that do nothing unless the kernel's
# command line has amethystora.forensic=1. They are in this live system alone: the system it installs is the published
# image, pulled above, which has none of this
install -Dpm0755 "${LIVE}/forensic/amethystora-forensic" /usr/bin/amethystora-forensic
for unit in amethystora-forensic amethystora-forensic-session; do
    install -Dpm0644 "${LIVE}/forensic/${unit}.service" "/usr/lib/systemd/system/${unit}.service"
done
install -Dpm0644 "${LIVE}/forensic/amethystora-forensic-pill.service" /usr/lib/systemd/user/amethystora-forensic-pill.service
systemctl enable amethystora-forensic.service amethystora-forensic-session.service
systemctl --global enable amethystora-forensic-pill.service
for tool in blockdev dconf logger udevadm findmnt swapon; do command -v "${tool}" >/dev/null; done
bash -n /usr/bin/amethystora-forensic
bash "${LIVE}/forensic/test.sh" /usr/bin/amethystora-forensic
# ...and the rule files it makes empty are there under those names in this live system (a package that renames one would leave
# arrays, volumes or caches put together by udev)
for rule in $(/usr/bin/amethystora-forensic overrides); do
    [[ -e "/usr/lib/udev/rules.d/${rule}" ]] || { echo "the forensic start empties ${rule}, which this system does not have" >&2; exit 1; }
done
# ...whose rule udev can read and whose units systemd can load
forensic_rules="$(mktemp)"
/usr/bin/amethystora-forensic rules >"${forensic_rules}"
udevadm verify "${forensic_rules}"
rm -f "${forensic_rules}"
systemd-analyze verify /usr/lib/systemd/system/amethystora-forensic.service /usr/lib/systemd/system/amethystora-forensic-session.service
for unit in amethystora-forensic amethystora-forensic-session; do
    grep -qx 'ConditionKernelCommandLine=amethystora.forensic=1' "/usr/lib/systemd/system/${unit}.service"
done
grep -qx 'ConditionKernelCommandLine=amethystora.forensic=1' /usr/lib/systemd/user/amethystora-forensic-pill.service
# ...and a boot entry for it that has every argument the helper says it needs, besides the live system's own
forensic_entry="$(grep -B1 -A2 -F 'name: "Start without touching the disks' "${LIVE}/iso.yaml")"
[[ -n "${forensic_entry}" ]] || { echo "iso/live/iso.yaml: no forensic boot entry" >&2; exit 1; }
forensic_linux="$(grep -E '^ +linux: ' <<<"${forensic_entry}")"
for arg in $(/usr/bin/amethystora-forensic args) rd.live.image root=live:CDLABEL=Amethystora-Live; do
    grep -qE " ${arg}( |\")" <<<"${forensic_linux}" || { echo "iso/live/iso.yaml: the forensic boot entry lacks ${arg}" >&2; exit 1; }
done
# ...and no other entry has any of it: the first two start the disks as they always were
if grep -E '^ +linux: ' "${LIVE}/iso.yaml" | grep -vF 'amethystora.forensic=1' | grep -qE ' (fstab=0|noresume|systemd\.swap=0)'; then
    echo "iso/live/iso.yaml: a boot entry other than the forensic one has its arguments" >&2
    exit 1
fi

# What Titanoboa makes the ISO from (the container-native ISO contract): its label and boot menu, every
# entry of which carries the image's kernel arguments from kargs.d, which a live boot does not read
install -Dpm0644 "${LIVE}/iso.yaml" /usr/lib/bootc-image-builder/iso.yaml
for karg in $(sed -n 's/^kargs = \[\(.*\)\]$/\1/p' /usr/lib/bootc/kargs.d/12-amethystora-console.toml | tr -d '",'); do
    if grep -E '^ +linux: ' "${LIVE}/iso.yaml" | grep -vqF " ${karg}"; then
        echo "iso/live/iso.yaml: a boot entry lacks ${karg}" >&2
        exit 1
    fi
done

dnf clean all
