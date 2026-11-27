#!/usr/bin/bash
# pin_repo_key (copr-helpers.sh) against repository files of each shape a vendor's server could serve: it must pass
# the good one and fail the rest, by what dnf itself reads from the file. Needs root, dnf5, gpg, jq and curl, and
# writes only under /etc/yum.repos.d and /etc/pki/rpm-gpg, which it takes away again.
set -euo pipefail

# shellcheck source=build_files/shared/copr-helpers.sh
source "$(dirname "$0")/copr-helpers.sh"

fail() {
    echo "test-repo-pin: $*" >&2
    exit 1
}

tmp="$(mktemp -d)"
files=()
cleanup() {
    rm -rf "${tmp}" "${files[@]}"
}
trap cleanup EXIT

# The key the "server" serves, as a file: pin_repo_key takes any address curl reads
mkdir -m700 "${tmp}/gnupg"
gpg --homedir "${tmp}/gnupg" --batch --pinentry-mode loopback --passphrase '' --quick-gen-key 'pin test' default default never 2>&1 | tail -n 3
gpg --homedir "${tmp}/gnupg" --armor --export >"${tmp}/key.asc"
fpr="$(key_fingerprints "${tmp}/key.asc")"

section() { # id, then the lines of the section
    printf '[%s]\nname=%s\nbaseurl=https://example.invalid/%s\nenabled=0\n' "$1" "$1" "$1"
    shift
    printf '%s\n' "$@"
}

# check NAME pass|fail FINGERPRINT: the repository file in "${tmp}/repo" is run through pin_repo_key
check() {
    local name="$1" want="$2" print="$3" file="/etc/yum.repos.d/pintest-${1}.repo" rc=0
    files+=("${file}" "/etc/pki/rpm-gpg/pintest-${name}.gpg")
    cp "${tmp}/repo" "${file}"
    (pin_repo_key "${file}" "${print}") >"${tmp}/out" 2>&1 || rc=$?
    if [[ "${want}" == pass && ${rc} != 0 ]] || [[ "${want}" == fail && ${rc} == 0 ]]; then
        cat "${tmp}/out" >&2
        fail "${name}: expected ${want}, pin_repo_key returned ${rc}"
    fi
}

key="gpgkey=file://${tmp}/key.asc"

{ section pintest-a gpgcheck=1 "${key}"; section pintest-b gpgcheck=1 repo_gpgcheck=1 "${key}"; } >"${tmp}/repo"
check good pass "${fpr}"

# The pinned fingerprint is not the served key's
check wrong-key fail 0000000000000000000000000000000000000000

# A value that goes on over the next line is a second key to dnf, which the single-line rewrite leaves behind
section pintest-c gpgcheck=1 "${key}" '  https://example.invalid/other-key' >"${tmp}/repo"
check continued-key fail "${fpr}"

# A section the caller did not expect, with no key of its own
{ section pintest-d gpgcheck=1 "${key}"; section pintest-e gpgcheck=1; } >"${tmp}/repo"
check extra-section fail "${fpr}"

# A file that turns the check off, in either spelling dnf takes
section pintest-f gpgcheck=0 "${key}" >"${tmp}/repo"
check gpgcheck-off fail "${fpr}"
section pintest-g gpgcheck=1 pkg_gpgcheck=0 "${key}" >"${tmp}/repo"
check pkg-gpgcheck-off fail "${fpr}"

echo "test-repo-pin: ok"
