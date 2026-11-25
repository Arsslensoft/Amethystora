#!/usr/bin/bash
# Whether tailscaled runs (amethystora-tailscale, `ame system tailscale`) against a stand-in root and stand-ins for
# systemctl and tailscale: nobody's choice follows an earlier login, `on` and `off` are kept and win over it, `status`
# says the choice or, with none, what the boot decided, and nothing else is accepted. Run by 20-tests.sh and the
# Integration workflow; HELPER names another copy.
set -euo pipefail

HELPER="${HELPER:-/usr/libexec/amethystora-tailscale}"
T="$(mktemp -d)"
trap 'rm -rf "${T}"' EXIT
export AMETHYSTORA_TAILSCALE_ROOT="${T}/root" LOG="${T}/log" PATH="${T}/bin:${PATH}"
STATE="${T}/root/var/lib/tailscale/tailscaled.state"
CHOICE="${T}/root/var/lib/amethystora/tailscale"
mkdir -p "${T}/bin" "${STATE%/*}"
: >"${LOG}"

fail() {
    echo "test-tailscale: $*"
    exit 1
}

# What it runs is written down, and `systemctl is-active` answers what ACTIVE says
cat >"${T}/bin/systemctl" <<'EOF'
#!/usr/bin/bash
echo "systemctl $*" >>"${LOG}"
[[ "$1" != is-active ]] || [[ "${ACTIVE:-no}" == yes ]]
EOF
cat >"${T}/bin/tailscale" <<'EOF'
#!/usr/bin/bash
echo "tailscale $*" >>"${LOG}"
EOF
chmod +x "${T}/bin/systemctl" "${T}/bin/tailscale"

# Nobody chose, and the machine never joined a tailnet: it does not run
! "${HELPER}" wanted || fail "wanted on a machine that never joined a tailnet"
# A state with no profile in it is not a joined machine
echo '{"_machinekey":"x"}' >"${STATE}"
! "${HELPER}" wanted || fail "wanted with a state that has no profile"
# One that joined before keeps it
echo '{"profile-abcd":"x"}' >"${STATE}"
"${HELPER}" wanted || fail "not wanted on a machine that had joined a tailnet"
[[ ! -e "${CHOICE}" ]] || fail "wanted wrote a choice"

# Status without a choice says what the boot decided, through systemd alone
[[ "$(ACTIVE=yes "${HELPER}" status)" == on ]] || fail "status of a running tailscaled is not on"
[[ "$(ACTIVE=no "${HELPER}" status)" == off ]] || fail "status of a stopped tailscaled is not off"

# Off is kept, wins over the joined state, stops it and says how to turn it on again
out="$("${HELPER}" off)"
[[ "$(cat "${CHOICE}")" == off ]] || fail "off kept no choice"
grep -qx 'systemctl stop tailscaled.service' "${LOG}" || fail "off did not stop tailscaled: $(cat "${LOG}")"
grep -qF 'ame system tailscale on' <<<"${out}" || fail "off does not say how to turn it on: ${out}"
! "${HELPER}" wanted || fail "wanted after off"
[[ "$(ACTIVE=yes "${HELPER}" status)" == off ]] || fail "status after off follows the unit, not the choice"
grep -q 'tailscale up' "${LOG}" && fail "off joined a tailnet"

# On is kept, starts it first and passes its arguments to tailscale up, each as it was given
: >"${LOG}"
rm -f "${STATE}"
"${HELPER}" on --ssh "--hostname=a b" >/dev/null
[[ "$(cat "${CHOICE}")" == on ]] || fail "on kept no choice"
[[ "$(cat "${LOG}")" == $'systemctl start tailscaled.service\ntailscale up --ssh --hostname=a b' ]] ||
    fail "on ran: $(cat "${LOG}")"
"${HELPER}" wanted || fail "not wanted after on, on a machine that never joined"
[[ "$(ACTIVE=no "${HELPER}" status)" == on ]] || fail "status after on follows the unit, not the choice"

# Anything else is the usage, and changes nothing
: >"${LOG}"
set +e
usage="$("${HELPER}" restart 2>&1)"
status=$?
set -e
[[ "${status}" == 64 ]] || fail "an unknown command exits ${status}"
grep -qF 'amethystora-tailscale wanted' <<<"${usage}" || fail "the usage does not name the commands: ${usage}"
[[ ! -s "${LOG}" && "$(cat "${CHOICE}")" == on ]] || fail "an unknown command changed something"

echo "test-tailscale: ok"
