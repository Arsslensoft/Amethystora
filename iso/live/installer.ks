# What the installer in the live session installs: the image the live system carries a copy of
# (iso/live/build.sh puts it in the read-only image store), so that installing needs no network.
# build.sh replaces @IMAGE@ with the image the ISO was built from. Through bootc install, not ostreecontainer
# (ostree container image deploy): it unpacks without syncing the disk after each layer. Anaconda has the
# command from Fedora 43. The installer ISO (iso/iso.toml) cannot take it: its builder
# writes an ostreecontainer line of its own, and the two commands refuse each other.
bootc --source-imgref=containers-storage:@IMAGE@ --target-imgref=@IMAGE@

# Left alone, Anaconda runs `firewall-offline-cmd --enabled --service=ssh`, which adds ssh to the image's
# default zone on every machine. The firewall is the image's: build.sh fails without this line. iso/iso.toml's
# installer has Anaconda's Network module off, so it has no such step, and no such command to give.
firewall --use-system-defaults

# Then the installed machine follows that image in the registry rather than the copy, signature-checked
# from its first update, as one installed from the installer ISO does (iso/iso.toml). build.sh fails on
# a switch without the flag. The marker tells the first boot that this is a new installation, which gets
# the hourly snapshots of the home folders (system-setup.hooks.d/26-snapshots-new-installation.sh).
# Anaconda goes by the script's last exit status only, hence set -e. On the NVIDIA images, with Secure
# Boot on, the driver's key is queued for the MOK manager, for the reason iso/iso.toml gives.
# After the bootc command, Anaconda (45) gives the deployment it chroots into neither the physical root at
# /sysroot, where bootc finds the deployment to change ("No such file or directory"), nor SELinux's file
# system, without which the relabel it ends with sees SELinux off and changes nothing: the files it
# rewrote (/etc/shadow, the journal's folder) keep their folder's label, and rpm-ostreed cannot start.
# So this runs outside, in the live system, binds both for the switch and relabels /etc and /var itself
# (never /usr, whose files are the ostree repository's).
%post --nochroot --erroronfail --interpreter=/usr/bin/bash
set -euo pipefail
deploy=(/mnt/sysimage/ostree/deploy/*/deploy/*.0)
[ "${#deploy[@]}" -eq 1 ] && [ -d "${deploy[0]}" ]
deploy="${deploy[0]}"
mount --bind /mnt/sysimage "${deploy}/sysroot"
mount --bind /sys/fs/selinux "${deploy}/sys/fs/selinux"
trap 'umount "${deploy}/sys/fs/selinux" "${deploy}/sysroot"' EXIT
chroot "${deploy}" bootc switch --mutate-in-place --enforce-container-sigpolicy --transport registry @IMAGE@
grep -q "^container-image-reference=ostree-image-signed:" "${deploy}.origin"
# Anaconda's bootc path hands bootc only the kernel arguments it collected before the image was on the disk:
# not "rhgb quiet", which it adds only when the target's packages have Plymouth, nor the console's keymap,
# which its ostree path (the installer ISO's) adds so that an encrypted disk's passphrase is typed on the
# keyboard chosen. Without them the machine starts in text with every message on the screen, and asks for the
# passphrase on a US keyboard. So they are added here as that path adds them, from the keymap Anaconda wrote.
# bootc leaves /boot read-only when it is done with it, and so it is left again.
keymap="$(sed -n 's/^KEYMAP="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' "${deploy}/etc/vconsole.conf" 2>/dev/null || :)"
if mountpoint -q /mnt/sysimage/boot; then mount -o remount,rw /mnt/sysimage/boot; fi
ostree admin instutil set-kargs --sysroot=/mnt/sysimage --merge rhgb quiet ${keymap:+"vconsole.keymap=${keymap}"}
if mountpoint -q /mnt/sysimage/boot; then mount -o remount,ro /mnt/sysimage/boot; fi
mkdir -p "${deploy}/var/lib/amethystora" && touch "${deploy}/var/lib/amethystora/new-installation"
# /var/log first, which Anaconda makes only after this, to copy its logs into: made then, it would take
# /var's label, and journald could not keep the journal in it
mkdir -p "${deploy}/var/log"
# -F: started from the installer's window, Anaconda runs in the live account's session, and what it writes
# is unconfined_u's. Without it restorecon leaves the user part alone, and the checks below failed every
# installation made from the window ("Installation failed"), which an unattended one in the lab never showed
chroot "${deploy}" restorecon -F -r /etc /var
[ "$(chroot "${deploy}" stat -c %C /etc/shadow)" = system_u:object_r:shadow_t:s0 ]
[ "$(chroot "${deploy}" stat -c %C /var/log)" = system_u:object_r:var_log_t:s0 ]
if [ -e "${deploy}/usr/lib/bootc/kargs.d/00-nvidia.toml" ] && mokutil --sb-state 2>/dev/null | grep -qi enabled; then
    mokutil --timeout -1 || :
    { echo amethystora; echo amethystora; } | mokutil --import "${deploy}"/usr/share/amethystora/secure-boot/*.der || :
fi
%end
