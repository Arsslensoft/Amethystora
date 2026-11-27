#!/usr/bin/bash
# Firefox's bookmarks for the desktop's search (amethystora-bookmarks): a places.sqlite is read as bookmarks only when
# moz_bookmarks and moz_places are tables in it, and the copy is gone when the answer is printed.
#
#   test-bookmarks.sh   HELPER names another copy
set -euo pipefail

HELPER="${HELPER:-/usr/libexec/amethystora-bookmarks}"
T="$(mktemp -d)"
trap 'rm -rf "${T}"' EXIT
fail() { echo "test-bookmarks: $*" >&2; exit 1; }

mkdir -p "${T}/home/.mozilla/firefox/p.default" "${T}/run"
chmod 700 "${T}/run"
printf '[Profile0]\nName=default\nIsRelative=1\nPath=p.default\nDefault=1\n' >"${T}/home/.mozilla/firefox/profiles.ini"
PLACES="${T}/home/.mozilla/firefox/p.default/places.sqlite"
bookmarks() { HOME="${T}/home" XDG_RUNTIME_DIR="${T}/run" python3 -I "${HELPER}" list; }

python3 -I - "${PLACES}" <<'PY'
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
db.execute('CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT)')
db.execute('CREATE TABLE moz_bookmarks (id INTEGER PRIMARY KEY, type INTEGER, fk INTEGER, parent INTEGER, title TEXT, lastModified INTEGER)')
db.execute("INSERT INTO moz_places VALUES (1, 'https://example.org/')")
db.execute("INSERT INTO moz_bookmarks VALUES (1, 1, 1, 0, 'Example', 1)")
db.commit()
db.close()
PY
[[ "$(bookmarks | jq -r '.[0].url')" == "https://example.org/" ]] || fail "a bookmark is not found"
[[ -z "$(ls -A "${T}/run")" ]] || fail "the copy is left in the runtime folder"

# The same names as views over another table: nothing is read
rm -f "${PLACES}"
python3 -I - "${PLACES}" <<'PY'
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
db.execute('CREATE TABLE other (id INTEGER, type INTEGER, fk INTEGER, parent INTEGER, title TEXT, lastModified INTEGER, url TEXT)')
db.execute("INSERT INTO other VALUES (1, 1, 1, 0, 'Planted', 1, 'https://example.net/')")
db.execute('CREATE VIEW moz_bookmarks AS SELECT id, type, fk, parent, title, lastModified FROM other')
db.execute('CREATE VIEW moz_places AS SELECT id, url FROM other')
db.commit()
db.close()
PY
[[ "$(bookmarks)" == "[]" ]] || fail "views named like the tables were read"
