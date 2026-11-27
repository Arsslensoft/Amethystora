// Makes system_files/shared/usr/share/amethystora/anticheat-list.json from the games.json of the community list of games
// and the state of their anti-cheat on Linux: what `amethystora-will-it-run` answers from, and `windows-programs.json`'s
// `game` ids are checked against. Not part of the image build: run by hand to move to a newer commit, after which the commit
// and the checksums in usr/share/licenses/areweanticheatyet/SOURCE move with it.
//
//   node build_files/shared/trim-anticheat-list.mjs GAMES.json OUT.json COMMIT UPDATED-DATE LICENSE
//
// A row is [id, name, state, [anti-cheats], date], the state one of the list's five (supported, running, planned, broken,
// denied) in lower case and the date the day the entry last changed (YYYY-MM-DD, or "" where the list gives none). Rows
// keep the list's order. Text is the list's, which anybody may have written: control characters are taken out here, and
// the helper that shows it cleans it again.
import fs from 'node:fs';

const STATES = ['supported', 'running', 'planned', 'broken', 'denied'];
// Controls, the C1 ones and the marks that turn text around
// eslint-disable-next-line no-control-regex
const UNSAFE = /[\u0000-\u001f\u007f-\u009f\u061c\u200e-\u200f\u2028-\u202e\u2066-\u2069]/gu;
const clean = (text, max) => String(text ?? '').replace(UNSAFE, ' ').replace(/\s+/gu, ' ').trim().slice(0, max);

const [games, out, commit, updated, licence] = process.argv.slice(2);
if (!games || !out || !/^[0-9a-f]{40}$/u.test(commit ?? '') || !/^\d{4}-\d{2}-\d{2}$/u.test(updated ?? '') || !licence) {
    console.error('usage: trim-anticheat-list.mjs GAMES.json OUT.json COMMIT(40 hex) UPDATED-DATE(YYYY-MM-DD) LICENSE');
    process.exit(64);
}
const rows = [];
const seen = new Set();
for (const game of JSON.parse(fs.readFileSync(games, 'utf8'))) {
    const id = clean(game.slug, 100);
    const name = clean(game.name, 120);
    const state = String(game.status ?? '').toLowerCase();
    if (!id || !name || !STATES.includes(state) || seen.has(id))
        continue;
    seen.add(id);
    const anticheats = [...new Set((Array.isArray(game.anticheats) ? game.anticheats : []).map(item => clean(item, 60)).filter(Boolean))];
    const date = /^(\d{4}-\d{2}-\d{2})/u.exec(String(game.dateChanged ?? ''))?.[1] ?? '';
    rows.push([id, name, state, anticheats, date]);
}
const text = fs.readFileSync(licence, 'utf8').replace(/\r\n/gu, '\n').trim();
if (!text.startsWith('MIT License'))
    throw new Error('the licence is not the MIT License the list has been under');
fs.writeFileSync(out, JSON.stringify({source: 'https://github.com/AreWeAntiCheatYet/AreWeAntiCheatYet', commit, updated, license: text, entries: rows}) + '\n');
console.log(`${rows.length} rows`);
