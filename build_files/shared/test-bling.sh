#!/usr/bin/bash
# The terminal's extras (bling.sh for bash and zsh, bling.fish for fish) against a stand-in for Homebrew's folder: an account
# that does not own the folder runs nothing from it and gets no alias for its tools; the account that owns it gets both.
#   bash test-bling.sh [BLING-DIR]
# Needs root, to hand the stand-in folder to another account. A shell that is not installed is skipped.

set -uo pipefail

DIR="${1:-/usr/share/amethystora/bling}"
ROOT="$(realpath "$(mktemp -d)")"
trap 'rm -rf "${ROOT}"' EXIT
PREFIX="${ROOT}/linuxbrew"
export MARKER="${ROOT}/marker"
failed=0
fail() {
    echo "test-bling: $*" >&2
    failed=1
}
[[ ${EUID} -eq 0 ]] || { echo "test-bling: needs root" >&2; exit 1; }

mkdir -p "${PREFIX}/bin"
for tool in direnv eza ug bat zoxide mise; do
    printf '#!/usr/bin/bash\necho "%s" >>"${MARKER}"\n' "${tool}" >"${PREFIX}/bin/${tool}"
done
chmod -R a+rx "${PREFIX}"
# The files name Homebrew's folder, which this stand-in replaces
for file in bling.sh bling.fish; do
    sed "s#/home/linuxbrew/.linuxbrew#${PREFIX}#g" "${DIR}/${file}" >"${ROOT}/${file}"
done
export PATH="${PREFIX}/bin:${PATH}"

# The command that sources the file in the shell, and the aliases the shell then has
run() {
    : >"${MARKER}"
    case "$1" in
        bash) bash -c ". ${ROOT}/bling.sh; alias" 2>&1 ;;
        zsh) zsh -c ". ${ROOT}/bling.sh; alias" 2>&1 ;;
        fish) BLING_USE_ABBR=0 fish -i -c "source ${ROOT}/bling.fish; alias" 2>&1 ;;
    esac
}

for shell in bash zsh fish; do
    command -v "${shell}" >/dev/null || { echo "test-bling: no ${shell}, skipped"; continue; }
    chown -R 65000:65000 "${PREFIX}"
    out="$(run "${shell}")"
    [[ -z "$(cat "${MARKER}")" ]] || fail "${shell}: another account ran $(tr '\n' ' ' <"${MARKER}")from Homebrew's folder"
    grep -Eq "(^| )(ls|cat|grep)[= ]" <<<"${out}" && fail "${shell}: another account got an alias for a tool in Homebrew's folder"
    chown -R 0:0 "${PREFIX}"
    out="$(run "${shell}")"
    [[ -n "$(cat "${MARKER}")" ]] || fail "${shell}: the owner of Homebrew's folder got none of its tools"
    grep -Eq "(^| )ls[= ]" <<<"${out}" || fail "${shell}: the owner got no alias for eza"
done
exit "${failed}"
