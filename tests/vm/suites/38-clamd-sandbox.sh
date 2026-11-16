#!/usr/bin/bash
# clamd runs confined (clamd@.service.d/10-amethystora.conf: no network, no homes, a read-only system, no new
# privileges, a system-call filter) and still finds a file by every way the image scans: the weekly scan's and the
# Security app's clamdscan --fdpass, the quarantine's rescan, a package file's standard input, and the reload.
# The signatures are one the suite writes itself for the test string, beside whatever freshclam has fetched, and
# are taken away at the end. A scan that finds nothing with the sandbox on is the failure this suite is for.
# vmlab-paths: @sf/usr/lib/systemd/system/clamd@* @sf/usr/libexec/amethystora-clamav-scan @sf/usr/libexec/amethystora-quarantine
source "$(dirname "$0")/lib.sh"

HOME_DIR="/var/home/${TEST_USER}"
DB=/var/lib/clamav/amethystora-vmlab.ndb
EICAR='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
SIGNATURE=Amethystora.VmLab.Eicar.UNOFFICIAL
FILES=("${HOME_DIR}/Downloads/vmlab-eicar" /tmp/vmlab-eicar /var/tmp/vmlab-eicar)

if ! wait_for 300 has_session; then
    skip "no session for ${TEST_USER} (10-account.sh)"
    finish
fi

cleanup() {
    rm -f "${DB}" "${FILES[@]}" "${HOME_DIR}/Downloads/vmlab-clean"
    systemctl stop clamd@scan.service 2>/dev/null
}
trap cleanup EXIT

if [[ "$(/usr/libexec/amethystora-security-config VIRUS_SCAN)" == off ]]; then
    skip "VIRUS_SCAN is off on this machine (38-off-is-off.sh covers it)"
    finish
fi

# clamd reads a signature for the test string and runs only while something scans: stopped, then started by its socket
install -d -o clamupdate -g clamupdate -m 0755 /var/lib/clamav
printf '%s:0:*:%s\n' "${SIGNATURE%.UNOFFICIAL}" "$(printf '%s' 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE' | od -An -tx1 | tr -d ' \n')" >"${DB}"
chown clamupdate: "${DB}"
install -d -o "${TEST_USER}" -g "$(id -gn "${TEST_USER}")" -m 0700 "${HOME_DIR}/Downloads"
for file in "${FILES[@]}"; do printf '%s' "${EICAR}" >"${file}"; done
chown "${TEST_USER}:" "${FILES[0]}"
chmod 0600 "${FILES[0]}"
printf 'nothing here\n' >"${HOME_DIR}/Downloads/vmlab-clean"
chown "${TEST_USER}:" "${HOME_DIR}/Downloads/vmlab-clean"
systemctl stop clamd@scan.service

# Started by its socket, the first call waits for the signatures to load
found() { grep -q ": ${SIGNATURE} FOUND$" <<<"$1"; }
out="$(timeout 300 clamdscan --fdpass --no-summary "${FILES[1]}" 2>&1)"
found "${out}" && ok "clamd, started by its socket under its sandbox, finds the test file" ||
    not_ok "clamd under its sandbox did not find the test file" "${out}" "$(journalctl -b -u clamd@scan.service --no-pager -o cat | tail -n 12)"

# The sandbox is the one the drop-in says, on the process that scanned
pid="$(systemctl show -P MainPID clamd@scan.service)"
status="$(cat "/proc/${pid}/status" 2>/dev/null)"
[[ "$(awk '$1 == "NoNewPrivs:" { print $2 }' <<<"${status}")" == 1 && "$(awk '$1 == "Seccomp:" { print $2 }' <<<"${status}")" == 2 ]] &&
    ok "clamd runs with no new privileges and a system-call filter" || not_ok "clamd's process has no sandbox" "${status}"
[[ "$(awk '$1 == "CapBnd:" { print $2 }' <<<"${status}")" == 00000000000000c0 ]] &&
    ok "clamd's capability set is the drop to its user and no more" || not_ok "clamd's capability bounding set is not CAP_SETUID and CAP_SETGID" "$(grep Cap <<<"${status}")"
[[ -z "$(ls -A "/proc/${pid}/root${HOME_DIR%/*}" 2>/dev/null)" ]] && ok "clamd sees no home folder" || not_ok "clamd sees $(ls -A "/proc/${pid}/root${HOME_DIR%/*}")"
[[ "$(nsenter -t "${pid}" -n awk -F: 'NR > 2 { gsub(/ /, "", $1); print $1 }' /proc/net/dev | tr '\n' ' ')" == "lo " ]] &&
    ok "clamd has no network but its own loopback" || not_ok "clamd's network namespace has more than lo"
nsenter -t "${pid}" -m sh -c 'touch /usr/vmlab-write /var/lib/clamav/vmlab-write' 2>/dev/null &&
    not_ok "clamd could write in /usr or its signature folder" || ok "clamd can write nowhere in the system"

# Every way the image hands clamd a file
out="$(timeout 300 clamdscan --fdpass --multiscan --infected "${HOME_DIR}" /tmp /var/tmp 2>&1)"
for file in "${FILES[@]}"; do
    grep -qF "${file}: ${SIGNATURE} FOUND" <<<"${out}" && ok "the weekly scan's call finds ${file}" ||
        not_ok "the weekly scan's call did not find ${file}" "${out}"
done
grep -q "vmlab-clean" <<<"${out}" && not_ok "the weekly scan's call reported the clean file" "${out}" || ok "the weekly scan's call leaves the clean file out"
if [[ "$(/usr/libexec/amethystora-security-config ON_DETECTION)" == report ]]; then
    out="$(/usr/libexec/amethystora-quarantine act "${FILES[0]}" "${HOME_DIR}/Downloads/vmlab-clean" 2>&1)"
    grep -q "^reported	${SIGNATURE}	${FILES[0]}$" <<<"${out}" && ok "the quarantine's rescan finds the file in a home" || not_ok "the quarantine's rescan did not" "${out}"
    grep -q "^clean	-	${HOME_DIR}/Downloads/vmlab-clean$" <<<"${out}" && ok "the quarantine's rescan finds the clean file clean" || not_ok "the quarantine's rescan said of the clean file" "${out}"
else
    skip "ON_DETECTION is not report here: the quarantine's rescan would act on the test file"
fi
out="$(timeout 300 clamdscan --no-summary - <"${FILES[0]}" 2>&1)"
found "${out}" && ok "a file on standard input (a package file, a Windows program) is found" || not_ok "a file on standard input was not found" "${out}"
out="$(setpriv --reuid="${TEST_USER}" --regid="$(id -g "${TEST_USER}")" --groups=virusgroup timeout 300 clamdscan --fdpass --multiscan --no-summary "${HOME_DIR}/Downloads" 2>&1)"
found "${out}" && ok "an account in the socket's group scans its own folder (the Security app's call)" || not_ok "the Security app's call found nothing" "${out}"
timeout 60 clamdscan --reload >/dev/null 2>&1
out="$(timeout 300 clamdscan --fdpass --no-summary "${FILES[2]}" 2>&1)"
found "${out}" && ok "clamd finds the test file again after a reload" || not_ok "clamd found nothing after a reload" "${out}"

# The weekly scan itself, when this machine has real signatures to pass its age check
if [[ "$(/usr/libexec/amethystora-security-config ON_DETECTION)" == report ]] && /usr/libexec/amethystora-clamav-signature-age >/dev/null; then
    systemctl start amethystora-clamav-scan.service
    grep -qF "${FILES[1]}: ${SIGNATURE}" /var/log/amethystora-clamav-findings.log 2>/dev/null &&
        ok "the weekly scan's unit reports the test file" || not_ok "the weekly scan's unit did not report the test file" "$(cat /var/log/amethystora-clamav-findings.log 2>&1)"
    rm -f /var/log/amethystora-clamav-findings.log
else
    skip "the weekly unit is not started: it needs current signatures and ON_DETECTION=report here"
fi

# Nothing was refused: the unit ran from start to now, with no system call killed and no restart
[[ "$(systemctl show -P NRestarts clamd@scan.service)" == 0 && "$(systemctl show -P Result clamd@scan.service)" == success ]] &&
    ok "clamd did not restart or fail" || not_ok "clamd restarted or failed" "$(systemctl status clamd@scan.service --no-pager 2>&1 | tail -n 12)"
journalctl -b -u clamd@scan.service --no-pager -o cat | grep -qiE 'SIGSYS|Bad system call|Read-only file system' &&
    not_ok "clamd's journal names a refusal" "$(journalctl -b -u clamd@scan.service --no-pager -o cat | grep -iE 'SIGSYS|Bad system call|Read-only file system' | head -n 5)" ||
    ok "clamd's journal names no refusal"
journalctl -b -k --no-pager 2>/dev/null | grep -E 'audit: type=1326' | grep -q 'comm="clamd"' &&
    not_ok "the kernel logged a system call clamd's filter refused" || ok "the kernel logged no refused system call of clamd"
check "systemd-analyze security scores clamd below 5" sh -c 'systemd-analyze security --threshold=5 --no-pager clamd@scan.service'
finish
