#!/usr/bin/bash
# The tests of tests/ci/tests.txt, for the Unit and Integration workflows.
#
#   run.sh --listed                       every test file of build_files/shared is in tests.txt, and every test there exists
#                                         (on the checkout, anywhere: no image needed)
#   run.sh [--overlay] KIND [SHARD/OF]    run KIND's tests, the SHARD-th of every OF (1/4, 2/4...), each on its own with
#                                         a time limit, after laying the checkout's system_files over / (--overlay, as
#                                         build.sh does). Inside the image (in-image.sh); CTX is the checkout. Writes
#                                         RESULTS/results.tsv and RESULTS/summary.md, prints each test's output, and
#                                         exits 1 when one failed
set -uo pipefail

CTX="${CTX:-$(cd "$(dirname "$0")/../.." && pwd)}"
LIST="${CTX}/tests/ci/tests.txt"
RESULTS="${RESULTS:-/results}"
LIMIT="${TEST_TIMEOUT:-1200}"

# KIND<TAB>COMMAND lines, comments and blank lines left out
entries() { grep -vE '^(#|[[:space:]]*$)' "${LIST}" | tr -d '\r'; }

if [[ "${1:-}" == --listed ]]; then
    failed=0
    named="$(entries | grep -oE '(test|check)-[a-z0-9-]+\.(sh|mjs|js)' | sort -u)"
    while read -r file; do
        grep -qxF "${file}" <<<"${named}" && continue
        echo "::error file=build_files/shared/${file}::${file} is in no line of tests/ci/tests.txt, so CI never runs it"
        failed=1
    done < <(cd "${CTX}/build_files/shared" && ls test-*.sh test-*.mjs test-*.js 2>/dev/null)
    while read -r file; do
        [[ -f "${CTX}/build_files/shared/${file}" ]] && continue
        echo "::error file=tests/ci/tests.txt::tests.txt names ${file}, which is not in build_files/shared"
        failed=1
    done <<<"${named}"
    bad="$(entries | grep -vE $'^(unit|integration|lint|helper)\t')"
    if [[ -n "${bad}" ]]; then
        echo "::error file=tests/ci/tests.txt::lines of no known kind: ${bad}"
        failed=1
    fi
    [[ "${failed}" == 0 ]] && echo "Every test of build_files/shared is run by CI ($(wc -l <<<"${named}") in tests.txt)"
    exit "${failed}"
fi

overlay=0
if [[ "${1:-}" == --overlay ]]; then
    overlay=1
    shift
fi
KIND="${1:?run.sh [--overlay] KIND [SHARD/OF] | --listed}"
SHARD="${2:-1/1}"
[[ "${SHARD}" =~ ^([0-9]+)/([0-9]+)$ && "${BASH_REMATCH[1]}" -ge 1 && "${BASH_REMATCH[1]}" -le "${BASH_REMATCH[2]}" ]] ||
    { echo "run.sh: the shard is N/OF, not ${SHARD}" >&2; exit 64; }
part="${BASH_REMATCH[1]}" of="${BASH_REMATCH[2]}"

# The image as this checkout would build it, as far as files go: what build.sh copies (rsync -rK: no links, into the
# image's own linked folders). What the build makes from them (schemas, catalogs, renames) is the published image's
if [[ "${overlay}" == 1 ]]; then
    if command -v rsync >/dev/null; then
        rsync -rK "${CTX}/system_files/shared/" / || { echo "run.sh: system_files could not be laid over /" >&2; exit 1; }
    else
        (cd "${CTX}/system_files/shared" && find . -type f -print0 | cpio --quiet -0 -pdmu /) ||
            { echo "run.sh: system_files could not be laid over /" >&2; exit 1; }
    fi
fi

export CTX
export NODE="${NODE:-node}"
export UI=/usr/share/gnome-shell/extensions/amethystora-ui@arsslensoft.github.io
mkdir -p "${RESULTS}"
: >"${RESULTS}/results.tsv"

mapfile -t mine < <(entries | awk -F'\t' -v kind="${KIND}" -v part="${part}" -v of="${of}" \
    '$1 == kind { n++; if ((n - 1) % of == part - 1) print $2 }')
if [[ "${#mine[@]}" == 0 ]]; then
    echo "run.sh: no ${KIND} test in shard ${SHARD}" >&2
    exit 1
fi

failed=0
for command in "${mine[@]}"; do
    name="$(grep -oE '(test|check)-[a-z0-9-]+\.(sh|mjs|js)' <<<"${command}" | head -1)"
    log="${RESULTS}/${name}.log"
    start="${SECONDS}"
    # As 20-tests.sh runs them: root, from /, its own HOME, no terminal and no TERM (starship, for one, draws nothing under TERM=dumb)
    (cd / && env -u TERM HOME=/root LANG=C.UTF-8 timeout --kill-after=30 "${LIMIT}" bash -c "${command}") \
        </dev/null >"${log}" 2>&1
    status=$?
    took=$((SECONDS - start))
    if [[ "${status}" == 0 ]]; then
        result=pass
    elif [[ "${status}" == 124 || "${status}" == 137 ]]; then
        result=timeout
    else
        result=fail
    fi
    printf '%s\t%s\t%s\t%s\n' "${name}" "${result}" "${took}" "${status}" >>"${RESULTS}/results.tsv"
    echo "::group::${result} - ${name} (${took} s)"
    cat "${log}"
    echo "::endgroup::"
    if [[ "${result}" != pass ]]; then
        failed=1
        echo "::error title=${name}::${result} after ${took} s (exit ${status}): $(tail -n 3 "${log}" | tr '\n' ' ' | cut -c1-300)"
    fi
done

{
    echo "### ${KIND} tests, shard ${SHARD}"
    echo
    echo "| Test | Result | Seconds |"
    echo "| --- | --- | ---: |"
    awk -F'\t' '{ printf "| `%s` | %s | %s |\n", $1, ($2 == "pass" ? "pass" : "**" $2 "**"), $3 }' "${RESULTS}/results.tsv"
    echo
    echo "$(grep -c $'\tpass\t' "${RESULTS}/results.tsv") of ${#mine[@]} passed."
} >"${RESULTS}/summary.md"
exit "${failed}"
