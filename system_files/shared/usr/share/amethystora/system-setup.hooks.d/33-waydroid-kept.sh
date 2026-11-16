#!/usr/bin/env bash

source /usr/lib/amethystora/setup-services/libsetup.sh

version-script waydroid-kept system 1 || exit 0

set -x

# The image now ships Waydroid's container service masked, as it does usbguard's bus service, so that nothing starts
# it for an account that never turned Android apps on, and `ame apps android` unmasks it. A machine that had Android
# apps on before that update gets the mask with the update: taken off once, where Android was set up and its service
# was enabled, so that it goes on starting as its owner left it.
[[ -f /var/lib/waydroid/waydroid.cfg ]] || exit 0
compgen -G '/etc/systemd/system/*.wants/waydroid-container.service' >/dev/null || exit 0
[[ "$(systemctl is-enabled waydroid-container.service 2>/dev/null)" == masked ]] || exit 0
systemctl unmask waydroid-container.service
systemctl start --no-block waydroid-container.service
