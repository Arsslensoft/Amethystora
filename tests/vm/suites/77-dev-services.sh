#!/usr/bin/bash
# Services in one line (ame dev service, ame dev ports; amethystora-dev-services), in the test account's session, on any image:
# - a mail catcher and a cache made, started from their quadlets, and reached from the machine on the loopback address, with the cache's
#   password from the file only the account reads, and a wrong one refused;
# - `ame dev ports` naming each port as the service that holds it, and ss finding the ports on the loopback address and nowhere else;
# - the security watcher not saying a loopback port of the account's own container;
# - stopped, the ports close; removed with no terminal, the data stays; removed in one, DELETE deletes it and anything else does not.
# The images come from Docker Hub by their digests: where the lab cannot reach it, the suite says so and ends there.
# vmlab-paths: @sf/usr/libexec/amethystora-dev-services @sf/usr/share/amethystora/dev-services/* @sf/*just/dev.just
source "$(dirname "$0")/lib.sh"

same() { if [[ "$2" == "$3" ]]; then ok "$1"; else not_ok "$1" "expected: $3" "found: $2"; fi; }
UID_TEST="$(id -u "${TEST_USER}")"
HOME_DIR="/var/home/${TEST_USER}"
QUADLETS="${HOME_DIR}/.config/containers/systemd"
SECRETS="${HOME_DIR}/.config/amethystora/dev-services"
STATUS=/var/lib/amethystora/security/status.json
HISTORY=/var/log/amethystora-security-events.jsonl
STARTED="$(mktemp)"

wait_for 300 has_session || { not_ok "the test account has a session"; finish; }

# --- Made, and what it made ----------------------------------------------------------------------------------------------
check "ame dev service add mailpit labmail" in_session ame dev service add mailpit labmail
check "ame dev service add redis labcache" in_session ame dev service add redis labcache
[[ -s "${QUADLETS}/amethystora-dev-labmail.container" ]] && ok "a quadlet of the account's own" || not_ok "a quadlet of the account's own"
same "its ports are on the loopback address only" \
    "$(grep -c '^PublishPort=127\.0\.0\.1:' "${QUADLETS}/amethystora-dev-labmail.container")/$(grep -c '^PublishPort=' "${QUADLETS}/amethystora-dev-labmail.container")" 2/2
if grep -q '^\[Install\]' "${QUADLETS}/amethystora-dev-labmail.container"; then not_ok "it does not start at login unless asked"; else ok "it does not start at login unless asked"; fi
same "the cache's password file is the account's alone" "$(stat -c '%a %U' "${SECRETS}/labcache.env")" "600 ${TEST_USER}"
same "its folder too" "$(stat -c '%a' "${SECRETS}")" 700
if [[ "$(user_bus systemctl --user show -P LoadState amethystora-dev-labmail.service)" == loaded ]]; then
    ok "podman made a unit of the quadlet"
else
    not_ok "podman made a unit of the quadlet" "$(user_bus systemctl --user status amethystora-dev-labmail.service 2>&1 | head -n 8)"
fi
if jq -e 'length == 2 and all(.[]; .state != "active")' <<<"$(in_session ame dev service list --json)" >/dev/null; then
    ok "listed, and nothing running yet"
else
    not_ok "listed, and nothing running yet"
fi

# --- Started, and reached --------------------------------------------------------------------------------------------------
in_session ame dev service start labmail >"${STARTED}" 2>&1
if ! wait_for 240 bash -c 'exec 3<>/dev/tcp/127.0.0.1/1025 && [[ "$(head -c 3 <&3)" == 220 ]]'; then
    LOG="$(user_bus journalctl --user -u amethystora-dev-labmail.service --no-pager -n 20 2>&1)"
    if grep -qiE 'pull|resolve|lookup|network|registry|unable to copy' <<<"${LOG}"; then
        skip "the lab cannot pull the images from Docker Hub: $(tail -n 1 <<<"${LOG}")"
    else
        not_ok "the mail catcher answers on 127.0.0.1:1025" "$(cat "${STARTED}")" "${LOG}"
    fi
    finish
fi
ok "the mail catcher answers on 127.0.0.1:1025 with its greeting"
in_session ame dev service start labcache >/dev/null 2>&1
PASSWORD="$(sed -n 's/^DEV_PASSWORD=//p' "${SECRETS}/labcache.env")"
# What the cache answers to a first line and a PING, over the loopback address
cache() {
    (
        exec 3<>/dev/tcp/127.0.0.1/6379
        printf '%s\r\nPING\r\n' "$1" >&3
        timeout 3 head -n 2 <&3 | tr -d '\r' | tr '\n' ' '
    )
}
wait_for 120 bash -c 'exec 3<>/dev/tcp/127.0.0.1/6379'
same "the cache takes its password" "$(cache "AUTH ${PASSWORD}")" "+OK +PONG "
[[ "$(cache "AUTH wrong")" == -WRONGPASS* ]] && ok "and refuses a wrong one" || not_ok "and refuses a wrong one" "$(cache "AUTH wrong")"
[[ "$(cache "PING")" == -NOAUTH* ]] && ok "and a client with none" || not_ok "and a client with none" "$(cache "PING")"

# --- Which program holds each port --------------------------------------------------------------------------------------------
PORTS="$(in_session ame dev ports --json)"
if jq -e '(.[] | select(.port == 1025) | .container.service == "labmail" and .scope == "loopback")
    and (.[] | select(.port == 8025) | .container.service == "labmail")
    and (.[] | select(.port == 6379) | .container.service == "labcache")' <<<"${PORTS}" >/dev/null; then
    ok "ame dev ports names each as its service"
else
    not_ok "ame dev ports names each as its service" "${PORTS}"
fi
in_session ame dev ports | grep -q 'the service labmail' && ok "and says it in words" || not_ok "and says it in words"
# ss sees every socket: the ports are on the loopback address, and on no other
LISTENING="$(ss -Htln)"
grep -qE '127\.0\.0\.1:(1025|8025|6379) ' <<<"${LISTENING}" && ok "the ports are on the loopback address" || not_ok "the ports are on the loopback address" "${LISTENING}"
if grep -qE '(\*|0\.0\.0\.0|\[::\]):(1025|8025|6379) ' <<<"${LISTENING}"; then not_ok "no port is on every address" "${LISTENING}"; else ok "no port is on every address"; fi
FROM="$(grep -c . "${HISTORY}" 2>/dev/null || echo 0)"
systemctl start amethystora-security-watch.service
if [[ -e "${HISTORY}" ]] && tail -n +"$((FROM + 1))" "${HISTORY}" |
    jq -e 'select(.key == "listeners" and (.text | test("(:|port )(1025|8025|6379)")))' >/dev/null 2>&1; then
    not_ok "the watcher says nothing of the loopback ports"
else
    ok "the watcher says nothing of the loopback ports"
fi
if jq -e '[.listeners[]? | select(.port == 1025 or .port == 8025 or .port == 6379)] | length == 0' "${STATUS}" >/dev/null; then
    ok "and its list of listeners has none"
else
    not_ok "and its list of listeners has none"
fi

# --- Stopped, and removed ----------------------------------------------------------------------------------------------------
check "ame dev service stop labmail" in_session ame dev service stop labmail
wait_for 60 bash -c '! (exec 3<>/dev/tcp/127.0.0.1/1025) 2>/dev/null' && ok "its port closes" || not_ok "its port closes"
# No terminal: the data stays, and with it the password
in_session ame dev service remove labmail </dev/null >/dev/null 2>&1
[[ ! -e "${QUADLETS}/amethystora-dev-labmail.container" ]] && ok "removed: the quadlet is gone" || not_ok "removed: the quadlet is gone"
in_session podman volume exists amethystora-dev-labmail && ok "and with no terminal its data stays" || not_ok "and with no terminal its data stays"
[[ -e "${SECRETS}/labmail.env" ]] && ok "with the password the data holds" || not_ok "with the password the data holds"
# A terminal: anything but DELETE keeps it, DELETE deletes it
check "made again" in_session ame dev service add mailpit labmail
UNDER=(runuser -u "${TEST_USER}" -- env XDG_RUNTIME_DIR="/run/user/${UID_TEST}" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${UID_TEST}/bus")
in_terminal 60 'Type DELETE' $'no\n' -- "${UNDER[@]}" ame dev service remove labmail >/dev/null 2>&1
in_session podman volume exists amethystora-dev-labmail && ok "a terminal's answer that is not DELETE keeps the data" || not_ok "a terminal's answer that is not DELETE keeps the data"
check "made again, once more" in_session ame dev service add mailpit labmail
in_terminal 60 'Type DELETE' $'DELETE\n' -- "${UNDER[@]}" ame dev service remove labmail >/dev/null 2>&1
if in_session podman volume exists amethystora-dev-labmail; then not_ok "DELETE deletes the data"; else ok "DELETE deletes the data"; fi
[[ ! -e "${SECRETS}/labmail.env" ]] && ok "and the password with it" || not_ok "and the password with it"
# What the lab made, taken away
in_session ame dev service stop labcache >/dev/null 2>&1
in_terminal 60 'Type DELETE' $'DELETE\n' -- "${UNDER[@]}" ame dev service remove labcache >/dev/null 2>&1
[[ ! -e "${QUADLETS}/amethystora-dev-labcache.container" ]] && ok "the lab's cache is taken away" || not_ok "the lab's cache is taken away"
rm -f "${STARTED}"
finish
