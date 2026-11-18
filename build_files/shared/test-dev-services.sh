#!/usr/bin/bash
# Services in one line (ame dev service, ame dev ports): /usr/libexec/amethystora-dev-services against stand-ins for podman, systemctl and ss,
# for 20-tests.sh. The quadlet it writes, a port on the loopback address only, a password in a file nobody else reads, a service made twice
# or on a taken port refused, the data removed only after DELETE is typed in a terminal, and `ports` naming what holds each port.
#   bash test-dev-services.sh [HELPER [TEMPLATES]]

set -uo pipefail

HELPER="${1:-/usr/libexec/amethystora-dev-services}"
TEMPLATES="${2:-/usr/share/amethystora/dev-services}"
ROOT="$(mktemp -d)"
trap 'rm -rf "${ROOT}"' EXIT
export HOME="${ROOT}/home"
export AMETHYSTORA_DEV_TEMPLATES="${TEMPLATES}"
# Not root's, and no /proc of the real machine: the stand-in /proc is also what lets the helper run as root, as the build does
export AMETHYSTORA_DEV_PROC="${ROOT}/proc"
mkdir -p "${HOME}" "${ROOT}/bin" "${ROOT}/says" "${ROOT}/proc"
QUADLETS="${HOME}/.config/containers/systemd"
SECRETS="${HOME}/.config/amethystora/dev-services"
failed=0
fail() {
    echo "test-dev-services: $*" >&2
    failed=1
}

# One stand-in under every name, which logs what it was asked and answers from the files of says/
cat >"${ROOT}/bin/stand-in" <<'EOF'
#!/usr/bin/bash
name="$(basename "$0")"
echo "${name} $*" >>"${CALLS}"
case "${name} $*" in
    "podman image exists "*) [[ -e "${SAYS}/image-present" ]]; exit ;;
    "podman volume exists "*) [[ -e "${SAYS}/volume-unknown" ]] && exit 125; [[ -e "${SAYS}/volume-present" ]]; exit ;;
    "podman ps --format "*) cat "${SAYS}/ps.json" 2>/dev/null || echo '[]'; exit 0 ;;
    "systemctl --user is-active "*) cat "${SAYS}/active" 2>/dev/null || echo inactive; [[ -e "${SAYS}/active" ]]; exit ;;
    "ss -Htln") cat "${SAYS}/ss" 2>/dev/null; exit 0 ;;
    "ss -Htlnp") cat "${SAYS}/ssp" 2>/dev/null; exit 0 ;;
esac
exit 0
EOF
chmod +x "${ROOT}/bin/stand-in"
for name in podman systemctl ss; do
    ln -s stand-in "${ROOT}/bin/${name}"
done
export SAYS="${ROOT}/says" CALLS="${ROOT}/calls"
: >"${CALLS}"
export PATH="${ROOT}/bin:${PATH}"

reset() {
    rm -rf "${HOME}/.config" "${SAYS:?}"/*
    : >"${CALLS}"
}
quadlet() { cat "${QUADLETS}/amethystora-dev-$1.container" 2>/dev/null; }
has() { grep -qxF -- "$2" <<<"$1"; }
mode() { stat -c %a "$1" 2>/dev/null; }

# --- Every shipped template, as the helper reads it ---------------------------------------------------------------------
shipped=0
for file in "${TEMPLATES}"/*.json; do
    shipped=$((shipped + 1))
    jq -e '(.name == "'"$(basename "${file}" .json)"'") and (.image | test("^[a-z0-9][a-z0-9./_-]*@sha256:[0-9a-f]{64}$")) and (.tag | test("^[A-Za-z0-9._-]+$"))
        and (.ports | length > 0) and (.volume | startswith("/")) and (.size_mb | type == "number")' "${file}" >/dev/null ||
        fail "${file} is not a template the helper takes: an image pinned by digest, a port, a volume and a size"
done
((shipped >= 4)) || fail "the templates are PostgreSQL, MariaDB, Valkey and the mail catcher: ${shipped}"
"${HELPER}" add | grep -q postgres || fail "add with no name does not list the services"

# --- add: the quadlet and the secrets ------------------------------------------------------------------------------------
for template in postgres mariadb valkey mailpit; do
    reset
    "${HELPER}" add "${template}" >/dev/null || fail "add ${template} failed"
    Q="$(quadlet "${template}")"
    image="$(jq -r .image "${TEMPLATES}/${template}.json")"
    has "${Q}" "Image=${image}" || fail "${template}: the quadlet does not name the image by its digest"
    has "${Q}" "Label=amethystora.dev.service=${template}" || fail "${template}: the quadlet has no label"
    has "${Q}" "ContainerName=amethystora-dev-${template}" || fail "${template}: the container's name"
    grep -q '^Volume=amethystora-dev-'"${template}"':/' <<<"${Q}" || fail "${template}: no named volume"
    # Every published port is on the loopback address, and nothing is started at login unless asked
    published="$(grep -c '^PublishPort=' <<<"${Q}")"
    local_only="$(grep -c '^PublishPort=127\.0\.0\.1:[0-9]*:[0-9]*$' <<<"${Q}")"
    [[ "${published}" == "$(jq '.ports | length' "${TEMPLATES}/${template}.json")" && "${published}" == "${local_only}" ]] ||
        fail "${template}: a port is not on the loopback address only: ${Q}"
    grep -q '0\.0\.0\.0' <<<"${Q}" && fail "${template}: the quadlet names every address"
    grep -q '^\[Install\]' <<<"${Q}" && fail "${template}: it starts at login without being asked"
    [[ "$(mode "${SECRETS}")" == 700 ]] || fail "${template}: the secrets folder is $(mode "${SECRETS}")"
    [[ "$(mode "${QUADLETS}/amethystora-dev-${template}.container")" == 644 ]] || fail "${template}: the quadlet is not an ordinary file"
    # A service with a password has it in a file only the account reads, and nowhere in the quadlet or on a command line
    if [[ -e "${SECRETS}/${template}.env" ]]; then
        [[ "$(mode "${SECRETS}/${template}.env")" == 600 ]] || fail "${template}: its env file is $(mode "${SECRETS}/${template}.env")"
    fi
    if grep -q '^DEV_PASSWORD=' "${SECRETS}/${template}.env" 2>/dev/null; then
        password="$(sed -n 's/^DEV_PASSWORD=//p' "${SECRETS}/${template}.env")"
        [[ "${password}" =~ ^[0-9a-f]{32}$ ]] || fail "${template}: its password is not made: ${password}"
        grep -q "${password}" <<<"${Q}" && fail "${template}: the password is in the quadlet"
        grep -q "${password}" "${CALLS}" && fail "${template}: the password went to a program's arguments"
    fi
    grep -q '^systemctl --user daemon-reload' "${CALLS}" || fail "${template}: the units were not reloaded"
done

# PostgreSQL's variables are filled; Valkey's password is in a configuration file of its own, mounted read-only, never in the arguments
reset
"${HELPER}" add postgres >/dev/null
grep -qE '^POSTGRES_PASSWORD=[0-9a-f]{32}$' "${SECRETS}/postgres.env" || fail "postgres: POSTGRES_PASSWORD is not made"
grep -q '^EnvironmentFile='"${SECRETS}"'/postgres.env$' <<<"$(quadlet postgres)" || fail "postgres: the quadlet does not read its env file"
reset
"${HELPER}" add redis cache --at-login >/dev/null || fail "add redis cache --at-login failed"
Q="$(quadlet cache)"
has "${Q}" "Label=amethystora.dev.template=valkey" || fail "redis is not Valkey: ${Q}"
has "${Q}" "WantedBy=default.target" || fail "--at-login did not start it at login"
has "${Q}" "Volume=${SECRETS}/cache.valkey.conf:/etc/valkey/valkey.conf:ro,Z" || fail "valkey's configuration is not mounted read-only: ${Q}"
has "${Q}" "Entrypoint=valkey-server" || fail "valkey is not started with its own configuration"
[[ "$(mode "${SECRETS}/cache.valkey.conf")" == 600 ]] || fail "valkey's configuration is $(mode "${SECRETS}/cache.valkey.conf")"
grep -qE '^requirepass [0-9a-f]{32}$' "${SECRETS}/cache.valkey.conf" || fail "valkey has no password"

# --- add: refusals and ports --------------------------------------------------------------------------------------------
reset
"${HELPER}" add postgres >/dev/null
"${HELPER}" add postgres 2>/dev/null && fail "a service made twice"
"${HELPER}" add nonsense 2>/dev/null && fail "a service no template makes"
for bad in ../x Upper -x 'a b' ''; do
    "${HELPER}" add postgres "${bad}" 2>/dev/null && fail "a service called '${bad}'"
done
[[ "$(ls "${QUADLETS}")" == amethystora-dev-postgres.container ]] || fail "a refused service left a file: $(ls "${QUADLETS}")"
# 5432 is taken by the first one, though nothing listens yet: the next is on 5433
"${HELPER}" add postgres second >/dev/null || fail "a second PostgreSQL failed"
grep -q '^PublishPort=127.0.0.1:5433:5432$' <<<"$(quadlet second)" || fail "the second PostgreSQL is not on the next port: $(quadlet second)"
# Something listens on 5434: skipped too; --port says exactly, and is held to the unprivileged range and to what is free
echo 'LISTEN 0 4096 127.0.0.1:5434 0.0.0.0:*' >"${SAYS}/ss"
"${HELPER}" add postgres third >/dev/null || fail "a third PostgreSQL failed"
grep -q '^PublishPort=127.0.0.1:5435:5432$' <<<"$(quadlet third)" || fail "a port something listens on was taken: $(quadlet third)"
"${HELPER}" add postgres fourth --port 5434 2>/dev/null && fail "--port on a port something listens on"
"${HELPER}" add postgres fourth --port 80 2>/dev/null && fail "--port below 1024"
"${HELPER}" add postgres fourth --port 5440 >/dev/null || fail "--port 5440 failed"
grep -q '^PublishPort=127.0.0.1:5440:5432$' <<<"$(quadlet fourth)" || fail "--port was not taken"

# --- start, stop, list ---------------------------------------------------------------------------------------------------
reset
"${HELPER}" add postgres >/dev/null
: >"${CALLS}"
OUT="$("${HELPER}" start postgres)" || fail "start failed"
grep -q 'postgres:18-alpine, about 120 MB' <<<"${OUT}" || fail "the first start does not say what it pulls: ${OUT}"
grep -q '^systemctl --user start amethystora-dev-postgres.service$' "${CALLS}" || fail "start did not start the unit"
grep -q "${SECRETS}/postgres.env" <<<"${OUT}" || fail "start does not point to the password's file"
grep -q "$(sed -n 's/^DEV_PASSWORD=//p' "${SECRETS}/postgres.env")" <<<"${OUT}" && fail "start printed the password"
touch "${SAYS}/image-present"
OUT="$("${HELPER}" start postgres)"
grep -q 'MB' <<<"${OUT}" && fail "an image that is here is said to be pulled: ${OUT}"
"${HELPER}" start nothing 2>/dev/null && fail "start of a service that is not there"
"${HELPER}" start '../postgres' 2>/dev/null && fail "start of a path"
"${HELPER}" stop postgres >/dev/null || fail "stop failed"
grep -q '^systemctl --user stop amethystora-dev-postgres.service$' "${CALLS}" || fail "stop did not stop the unit"
echo active >"${SAYS}/active"
LIST="$("${HELPER}" list --json)"
jq -e 'length == 1 and .[0].name == "postgres" and .[0].state == "active" and .[0].at_login == false
    and .[0].ports == [{"address": "127.0.0.1", "port": 5432}] and .[0].env == "'"${SECRETS}"'/postgres.env" and (.[0] | tostring | test("DEV_PASSWORD|POSTGRES_PASSWORD") | not)' \
    <<<"${LIST}" >/dev/null || fail "list --json: ${LIST}"
"${HELPER}" list | grep -q "${SECRETS}/postgres.env" || fail "list does not point to the password's file"

# A file in the folder that this program did not make is not a service of it
cat >"${QUADLETS}/amethystora-dev-stranger.container" <<'EOF'
[Container]
Image=docker.io/library/alpine
EOF
jq -e 'length == 1' <<<"$("${HELPER}" list --json)" >/dev/null || fail "list shows a quadlet that is not this program's"
"${HELPER}" remove stranger 2>/dev/null && fail "remove of a quadlet that is not this program's"
[[ -e "${QUADLETS}/amethystora-dev-stranger.container" ]] || fail "remove touched a file that is not this program's"
rm -f "${QUADLETS}/amethystora-dev-stranger.container"

# --- remove: the data goes only after DELETE, typed in a terminal ---------------------------------------------------------
# What the person types in a terminal, through a pseudo-terminal of its own ('' is no terminal at all)
terminal_run() {
    python3 - "$1" "${HELPER}" remove "$2" <<'EOF'
import os, pty, sys
answer, argv = sys.argv[1], sys.argv[2:]
pid, fd = pty.fork()
if pid == 0:
    os.execv(argv[0], argv)
os.read(fd, 4096)
try:
    os.write(fd, (answer + "\n").encode())
    while os.read(fd, 4096):
        pass
except OSError:
    pass
_, status = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(status))
EOF
}
reset
"${HELPER}" add postgres >/dev/null
touch "${SAYS}/volume-present"
"${HELPER}" remove postgres >/dev/null </dev/null || fail "remove with no terminal failed"
[[ -e "${QUADLETS}/amethystora-dev-postgres.container" ]] && fail "remove left the quadlet"
grep -q '^podman volume rm' "${CALLS}" && fail "remove with no terminal deleted the data"
[[ -e "${SECRETS}/postgres.env" ]] || fail "remove with no terminal lost the password the data still holds"
# Made again, it takes that password back
before="$(sed -n 's/^DEV_PASSWORD=//p' "${SECRETS}/postgres.env")"
"${HELPER}" add postgres >/dev/null
[[ "$(sed -n 's/^DEV_PASSWORD=//p' "${SECRETS}/postgres.env")" == "${before}" ]] || fail "a service made again does not take the password back"
: >"${CALLS}"
terminal_run no postgres || fail "remove, answered no, failed"
grep -q '^podman volume rm' "${CALLS}" && fail "remove deleted the data when the answer was not DELETE"
[[ -e "${SECRETS}/postgres.env" ]] || fail "remove, answered no, lost the password"
"${HELPER}" add postgres >/dev/null
terminal_run DELETE postgres || fail "remove, answered DELETE, failed"
grep -q '^podman volume rm -f amethystora-dev-postgres$' "${CALLS}" || fail "remove did not delete the data after DELETE"
[[ -e "${SECRETS}/postgres.env" ]] && fail "the password stayed after the data went"
# podman that cannot say whether the volume is there (it failed, or timed out) is not "no volume": the password stays, and it says so
reset
"${HELPER}" add postgres >/dev/null
touch "${SAYS}/volume-unknown"
OUT="$("${HELPER}" remove postgres </dev/null)" || fail "remove with podman not answering failed"
[[ -e "${SECRETS}/postgres.env" ]] || fail "remove deleted the password when podman could not say whether the data is there"
grep -q 'could not say' <<<"${OUT}" || fail "remove does not say that podman could not answer: ${OUT}"
grep -q '^podman volume rm' "${CALLS}" && fail "remove deleted a volume it could not see"
# The data of one template is not another's: a kept volume of PostgreSQL's is refused by MariaDB under the same name, and says why
reset
"${HELPER}" add postgres db >/dev/null
grep -qx 'DEV_TEMPLATE=postgres' "${SECRETS}/db.env" || fail "the env file does not record the template"
touch "${SAYS}/volume-present"
"${HELPER}" remove db >/dev/null </dev/null
OUT="$("${HELPER}" add mariadb db 2>&1)" && fail "MariaDB was made over PostgreSQL's kept data"
grep -q 'holds the data of a postgres service' <<<"${OUT}" || fail "the refusal does not say why: ${OUT}"
[[ -e "${QUADLETS}/amethystora-dev-db.container" ]] && fail "a refused service left a quadlet"
"${HELPER}" add postgres db >/dev/null || fail "PostgreSQL could not take its own data back"
"${HELPER}" remove db >/dev/null </dev/null
rm -f "${SAYS}/volume-present"
"${HELPER}" add mariadb db >/dev/null || fail "MariaDB refused where there is no volume"
touch "${SAYS}/volume-unknown"
"${HELPER}" remove db >/dev/null </dev/null
"${HELPER}" add mariadb db >/dev/null || fail "a volume podman cannot see refused a service"
# A service that never ran has no data to ask about, and nothing to keep a password for
reset
"${HELPER}" add redis >/dev/null
"${HELPER}" remove redis >/dev/null </dev/null || fail "remove of a service that never ran failed"
[[ -z "$(ls -A "${SECRETS}" 2>/dev/null)" ]] || fail "remove left what a service that never ran made: $(ls -A "${SECRETS}")"

# --- ports ---------------------------------------------------------------------------------------------------------------
reset
mkdir -p "${ROOT}/proc/700" "${ROOT}/proc/701" "${HOME}/code/shop"
ln -s "${HOME}/code/shop" "${ROOT}/proc/700/cwd"
ln -s "${HOME}" "${ROOT}/proc/701/cwd"
cat >"${SAYS}/ssp" <<'EOF'
LISTEN 0 4096 127.0.0.1:3000 0.0.0.0:* users:(("node",pid=700,fd=18))
LISTEN 0 4096 [::1]:3000 [::]:* users:(("node",pid=700,fd=19))
LISTEN 0 4096 127.0.0.1:5432 0.0.0.0:* users:(("pasta",pid=702,fd=8))
LISTEN 0 4096 0.0.0.0:8080 0.0.0.0:* users:(("python3",pid=701,fd=3))
LISTEN 0 4096 *:22 *:*
LISTEN 0 4096 127.0.0.1:9000 0.0.0.0:* users:(("pasta",pid=703,fd=8))
EOF
cat >"${SAYS}/ps.json" <<'EOF'
[{"Names": ["amethystora-dev-postgres"], "Labels": {"amethystora.dev.service": "postgres", "amethystora.dev.template": "postgres"},
  "Ports": [{"host_ip": "127.0.0.1", "container_port": 5432, "host_port": 5432, "range": 1, "protocol": "tcp"}]},
 {"Names": ["tool\u001b[31m"], "Labels": {"org.example.thing": "yes"}, "Ports": [{"host_ip": "127.0.0.1", "container_port": 80, "host_port": 9000, "range": 1, "protocol": "tcp"}]}]
EOF
PORTS="$("${HELPER}" ports --json)" || fail "ports failed"
jq -e 'length == 5
    and (.[] | select(.port == 3000) | .program == "node" and .folder == "~/code/shop" and .scope == "loopback" and .container == null)
    and ([.[] | select(.port == 3000)] | length == 1)
    and (.[] | select(.port == 5432) | .container.service == "postgres" and .container.name == "amethystora-dev-postgres" and .folder == null)
    and (.[] | select(.port == 8080) | .scope == "every-address" and .folder == null and .program == "python3")
    and (.[] | select(.port == 22) | .other_account == true and .scope == "every-address" and .program == null)
    and (.[] | select(.port == 9000) | .container.service == null and .container.labels["org.example.thing"] == "yes")' <<<"${PORTS}" >/dev/null ||
    fail "ports --json: ${PORTS}"
TEXT="$("${HELPER}" ports)"
grep -qE '^5432 +127.0.0.1 +container amethystora-dev-postgres, the service postgres' <<<"${TEXT}" || fail "ports names the service: ${TEXT}"
grep -qE '^3000 +127.0.0.1 +node +~/code/shop$' <<<"${TEXT}" || fail "ports names the project folder: ${TEXT}"
grep -qE '^22 +every address +another account, or the system$' <<<"${TEXT}" || fail "ports says another account: ${TEXT}"
grep -q $'\033' <<<"${TEXT}" && fail "a container's name reached the terminal with a control character"
# podman not answering is no reason to say nothing. Not the image's own podman further down PATH either: run as the build's
# root, it made its database in /var/lib/containers/storage, which the rechunker moves into the read-only store the live
# ISO pulls into, and podman refused that pull. The stand-in's tools beside the stand-ins, and nothing else on PATH
rm -f "${ROOT}/bin/podman"
for tool in basename cat; do
    ln -sf "$(command -v "${tool}")" "${ROOT}/bin/${tool}"
done
PATH="${ROOT}/bin" "${HELPER}" ports --json | jq -e 'length == 5' >/dev/null || fail "ports with no podman"
ln -s stand-in "${ROOT}/bin/podman"

# --- the rest ------------------------------------------------------------------------------------------------------------
for argument in "bogus" "start" "start a b" "ports --nope" "list --nope"; do
    # shellcheck disable=SC2086
    "${HELPER}" ${argument} 2>/dev/null && fail "'${argument}' was taken"
done
if [[ "${EUID}" -eq 0 ]]; then
    env -u AMETHYSTORA_DEV_PROC "${HELPER}" list >/dev/null 2>&1 && fail "it ran as root"
fi

((failed == 0)) || exit 1
echo "test-dev-services: all passed"
