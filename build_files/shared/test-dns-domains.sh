#!/usr/bin/bash
# Encrypted DNS and a network's search domains (amethystora-dns domains), against stand-ins for nmcli and resolvectl: a domain a
# network hands out is a routing domain too and would take every name under it back from the encrypted resolver, so each connected
# Wi-Fi and wired network keeps only the domains that only a network can have (.local, .lan, .home.arpa...), the ones routed on
# purpose ("~") and the ones its connection lists itself (its DNS search domains); a VPN's or Tailscale's are never touched, and
# nothing is set where there is nothing to take off.
#
# The watcher (amethystora-dns domains-watch) is run too, with stand-ins for the signals it listens to: systemd-resolved's change of a
# link's domains is acted on at once, and a lease that changes without a line from `nmcli monitor` is taken off again.
#
#   test-dns-domains.sh   HELPER names another copy
set -euo pipefail

HELPER="${HELPER:-/usr/libexec/amethystora-dns}"
T="$(mktemp -d)"
watcher=""
cleanup() {
    [[ -z "${watcher}" ]] || kill -- "-${watcher}" 2>/dev/null || true
    rm -rf "${T}"
}
trap cleanup EXIT
fail() { echo "test-dns-domains: $*" >&2; exit 1; }

export PATH="${T}/bin:${PATH}" LOG="${T}/log" STATUS="${T}/status" DEVICES="${T}/devices" OWN="${T}/own"
mkdir -p "${T}/bin"
: >"${LOG}"
# nmcli: the devices (DEVICE:TYPE:STATE:CON-UUID) and a connection's own DNS search domains, which comes as two lines, IPv4's and IPv6's
cat >"${T}/bin/nmcli" <<'EOS'
#!/usr/bin/bash
case "$*" in
    "-t -f DEVICE,TYPE,STATE,CON-UUID device") cat "${DEVICES}" ;;
    "-g ipv4.dns-search,ipv6.dns-search connection show "*) sed -n "s/^$5 //p" "${OWN}"; echo ;;
    monitor) exec sleep 600 ;;
    *) exit 1 ;;
esac
EOS
# resolvectl: `domain -- LINK` prints that link's line of the status, `domain -- LINK DOMAIN...` is only logged
cat >"${T}/bin/resolvectl" <<'EOS'
#!/usr/bin/bash
[[ "$1 $2" == "domain --" ]] || exit 1
if [[ $# -eq 3 ]]; then grep "^Link [0-9]* ($3):" "${STATUS}" || true; else shift 2; echo "domain $*" >>"${LOG}"; fi
EOS
chmod +x "${T}/bin/nmcli" "${T}/bin/resolvectl"
cat >"${DEVICES}" <<'EOF'
lo:loopback:connected (externally):
wlan0:wifi:connected:aaaa
eth0:ethernet:connected:bbbb
tun0:tun:connected (externally):
enp3s0:ethernet:connected:cccc
tailscale0:tun:connected (externally):
docker0:bridge:connected (externally):
wlan1:wifi:disconnected:
EOF
# wlan0's connection lists corp.example.com itself, in the case it was typed
printf 'aaaa Corp.Example.com\n' >"${OWN}"
cat >"${STATUS}" <<'EOF'
Link 2 (wlan0): com example.org lan Home.Arpa ~corp.example.com ~. printer.LAN corp.example.com -evil.lan
Link 3 (eth0): internal local
Link 4 (tun0): evil.com
Link 5 (enp3s0): notlocal lan.example.com xlan COM local.com
Link 6 (tailscale0): tail1234.ts.net
Link 7 (docker0): corp.test
Link 8 (wlan1): com
EOF

"${HELPER}" domains
# wlan0 keeps what only a network has, what is routed on purpose and what its connection lists, in the order it had them, with no
# case changed (the stand-in refuses a call without `--`, which stops a domain starting with a dash from being an option)
grep -qx 'domain wlan0 lan Home.Arpa ~corp.example.com ~. printer.LAN corp.example.com -evil.lan' "${LOG}" || fail "wlan0: $(cat "${LOG}")"
# A network with nothing of its own left has its list cleared with an empty string; a name that only ends like a private one is not one
grep -qx 'domain enp3s0 ' "${LOG}" || fail "enp3s0 kept a domain a network can claim for a public name: $(cat "${LOG}")"
# Nothing to take off, or not a Wi-Fi or wired network that is connected: nothing set (a VPN's and Tailscale's domains stay)
grep -qE '^domain (eth0|tun0|tailscale0|docker0|wlan1|lo)( |$)' "${LOG}" && fail "a link that was not to be touched was set: $(cat "${LOG}")"
[[ "$(wc -l <"${LOG}")" == 2 ]] || fail "expected two calls: $(cat "${LOG}")"

# Once taken off, a second pass finds nothing to do
cat >"${STATUS}" <<'EOF'
Link 2 (wlan0): lan Home.Arpa ~corp.example.com ~. printer.LAN corp.example.com -evil.lan
Link 5 (enp3s0):
EOF
: >"${LOG}"
"${HELPER}" domains
[[ ! -s "${LOG}" ]] || fail "a second pass set something: $(cat "${LOG}")"
# A network that is still connecting has its domains handed to resolved already
cat >"${DEVICES}" <<'EOF'
wlan2:wifi:connecting (getting IP configuration):dddd
EOF
printf 'Link 9 (wlan2): com lan\n' >"${STATUS}"
: >"${LOG}"
"${HELPER}" domains
grep -qx 'domain wlan2 lan' "${LOG}" || fail "a network still connecting kept its domains: $(cat "${LOG}")"

# The watcher, on a copy that looks for its switch in the temporary folder
sed "s|^RESOLVED_DROP_IN=.*|RESOLVED_DROP_IN=${T}/dropin|" "${HELPER}" >"${T}/helper"
chmod +x "${T}/helper"
: >"${T}/dropin"
export EV_RESOLVED="${T}/ev-resolved" EV_NM="${T}/ev-nm"
: >"${EV_RESOLVED}"
: >"${EV_NM}"
# gdbus monitor: what resolved and NetworkManager say, a line each, from files the test writes to
cat >"${T}/bin/gdbus" <<'EOS'
#!/usr/bin/bash
case "$*" in
    "monitor --system --dest org.freedesktop.resolve1") exec tail -n0 -F -s 0.05 "${EV_RESOLVED}" ;;
    "monitor --system --dest org.freedesktop.NetworkManager") exec tail -n0 -F -s 0.05 "${EV_NM}" ;;
    *) exit 1 ;;
esac
EOS
chmod +x "${T}/bin/gdbus"
waits() {
    local tries="$1"
    shift
    while ((tries-- > 0)); do
        "$@" && return 0
        sleep 0.05
    done
    return 1
}
: >"${LOG}"
setsid "${T}/helper" domains-watch 2>"${T}/watch.err" &
watcher=$!
waits 100 grep -qx 'domain wlan2 lan' "${LOG}" || fail "the watcher did not look first: $(cat "${LOG}" "${T}/watch.err")"
sleep 0.5

# A lease changes: NetworkManager hands resolved the domains again and nmcli monitor prints nothing. resolved says it, and the
# domains are taken off again straight away, well before the second that nmcli's events wait
: >"${LOG}"
echo "/org/freedesktop/resolve1/link/_39: org.freedesktop.DBus.Properties.PropertiesChanged ('org.freedesktop.resolve1.Link', {'Domains': <[(0, 'com', false), (0, 'lan', false)]>}, @as [])" >>"${EV_RESOLVED}"
waits 10 grep -qx 'domain wlan2 lan' "${LOG}" || fail "a change of a link's domains in resolved was not acted on at once: $(cat "${LOG}" "${T}/watch.err")"

# What NetworkManager says about something else wakes nothing; a new IP configuration is followed by a pass a second later
sleep 0.5
: >"${LOG}"
echo "/org/freedesktop/NetworkManager/AccessPoint/3: org.freedesktop.DBus.Properties.PropertiesChanged ('org.freedesktop.NetworkManager.AccessPoint', {'Strength': <byte 0x42>}, @as [])" >>"${EV_NM}"
sleep 1.6
[[ ! -s "${LOG}" ]] || fail "an access point's signal strength set something: $(cat "${LOG}")"
echo "/org/freedesktop/NetworkManager/IP4Config/7: org.freedesktop.DBus.Properties.PropertiesChanged ('org.freedesktop.NetworkManager.IP4Config', {'Searches': <['com']>}, @as [])" >>"${EV_NM}"
waits 80 grep -qx 'domain wlan2 lan' "${LOG}" || fail "a new IP configuration was not followed by a pass: $(cat "${LOG}" "${T}/watch.err")"
kill -0 "${watcher}" 2>/dev/null || fail "the watcher ended: $(cat "${T}/watch.err")"
echo "test-dns-domains: ok"
