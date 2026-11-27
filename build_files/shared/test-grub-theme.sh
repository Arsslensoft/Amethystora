#!/usr/bin/bash
# amethystora-grub-theme against a stand-in /boot/grub2: the theme's block is written into user.cfg, what else the
# file holds (grub2-setpassword's hash) stays, and the file keeps the mode it had. Run by 20-tests.sh as root.
set -euo pipefail

SCRIPT="${1:-/usr/bin/amethystora-grub-theme}"
[[ ${EUID} -eq 0 ]] || { echo "test-grub-theme: skipped, it needs root"; exit 0; }
T="$(mktemp -d)"
trap 'rm -rf "${T}"' EXIT
mkdir -p "${T}/bin" "${T}/src" "${T}/boot/grub2"
printf '#!/bin/sh\nexit 0\n' >"${T}/bin/grub2-script-check"
chmod +x "${T}/bin/grub2-script-check"
echo font >"${T}/src/font16.pf2"
echo theme >"${T}/src/theme.txt"
echo 'source ${prefix}/user.cfg' >"${T}/boot/grub2/grub.cfg"
sed -e "s|^SOURCE=.*|SOURCE=${T}/src|" -e "s|^BOOT_GRUB=.*|BOOT_GRUB=${T}/boot/grub2|" "${SCRIPT}" >"${T}/theme"
export PATH="${T}/bin:${PATH}" AMETHYSTORA_BOOT_RW=1
CFG="${T}/boot/grub2/user.cfg"
fail() { echo "test-grub-theme: $*" >&2; exit 1; }

# A password hash set by grub2-setpassword: 0600, and still so after the theme is written over it
echo 'GRUB2_PASSWORD=grub.pbkdf2.sha512.10000.AAAA.BBBB' >"${CFG}"
chmod 0600 "${CFG}"
bash "${T}/theme" install >/dev/null
[[ "$(stat -c %a "${CFG}")" == 600 ]] || fail "user.cfg is $(stat -c %a "${CFG}"), not 0600"
grep -qx 'GRUB2_PASSWORD=grub.pbkdf2.sha512.10000.AAAA.BBBB' "${CFG}" || fail "the password line is gone"
grep -qx '### BEGIN amethystora boot menu' "${CFG}" || fail "the theme's block is not there"
echo changed >"${T}/src/theme.txt"
bash "${T}/theme" refresh >/dev/null
[[ "$(stat -c %a "${CFG}")" == 600 ]] || fail "after a refresh user.cfg is $(stat -c %a "${CFG}"), not 0600"
[[ "$(grep -c '^### BEGIN amethystora boot menu$' "${CFG}")" == 1 ]] || fail "the block is there twice"

# With no file before, the theme's own is readable by all, as it always was
rm -f "${CFG}"
bash "${T}/theme" install >/dev/null
[[ "$(stat -c %a "${CFG}")" == 644 ]] || fail "a new user.cfg is $(stat -c %a "${CFG}"), not 0644"

echo "test-grub-theme: every check passed"
