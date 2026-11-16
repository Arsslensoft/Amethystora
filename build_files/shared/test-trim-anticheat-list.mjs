// The script that trims the community list of games and their anti-cheat (build_files/shared/trim-anticheat-list.mjs), run on
// a made-up games.json: what is kept, what is dropped, the state and the date as the helper reads them, text that tries to act,
// and the arguments it refuses. Run by 20-tests.sh under node:
//   node build_files/shared/test-trim-anticheat-list.mjs
// A failure throws.

import {execFileSync, spawnSync} from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const SCRIPT = path.join(path.dirname(fileURLToPath(import.meta.url)), 'trim-anticheat-list.mjs');
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'trim-anticheat-'));
const COMMIT = 'a'.repeat(40);
const failures = [];
let count = 0;

function expect(what, got, wanted) {
    count++;
    const a = JSON.stringify(got), b = JSON.stringify(wanted);
    if (a !== b)
        failures.push(`${what}: expected ${b}, got ${a}`);
}

const ESC = String.fromCharCode(27);
const BEL = String.fromCharCode(7);
const NEL = String.fromCharCode(0x85);
const LINE_SEPARATOR = String.fromCharCode(0x2028);
const RTL_OVERRIDE = String.fromCharCode(0x202e);

const game = (slug, name, status, anticheats, dateChanged, extra = {}) => ({
    url: 'https://example.org', name, logo: '', native: false, status, reference: '', anticheats, notes: [['a note', 'https://example.org']],
    updates: [{name: 'x', date: 'Jan 1, 2020', reference: 'https://example.org'}], storeIds: {steam: '1'}, slug, dateChanged, ...extra,
});
const games = [
    game('one', 'One', 'Supported', ['Guard A'], '2024-01-19T04:40:56.000Z'),
    game('two', 'Two', 'Running', ['Guard A', 'Guard B', 'Guard A'], '2024-11-04T00:18:17.181Z'),
    game('three', 'Three', 'Planned', [], '2025-12-17T01:02:03Z'),
    game('four', 'Four', 'Broken', ['Guard C'], '2026-08-21T11:22:52.0000000-04:00'),
    game('five', 'Five', 'Denied', ['Guard C'], 'yesterday'),
    // Not a state of the list, no name, no id, a repeated id
    game('six', 'Six', 'Maybe', ['Guard A'], '2024-01-01T00:00:00Z'),
    game('seven', '  ', 'Supported', [], '2024-01-01T00:00:00Z'),
    game('', 'Eight', 'Supported', [], '2024-01-01T00:00:00Z'),
    game('one', 'One again', 'Denied', [], '2024-01-01T00:00:00Z'),
    // Text that tries to act, and an id that is odd but a name
    game('nine', `Nine${ESC}[31m red${BEL}${NEL}after${LINE_SEPARATOR}break${RTL_OVERRIDE}`, 'Supported', [`Guard${ESC}[2J\nFORGED`], '2024-01-01T00:00:00Z'),
    game('s%26box', 's&box', 'Supported', ['VAC'], '2026-01-01T00:00:00.000Z'),
];
const input = path.join(work, 'games.json');
const licence = path.join(work, 'LICENSE');
const out = path.join(work, 'out.json');
fs.writeFileSync(input, JSON.stringify(games));
fs.writeFileSync(licence, 'MIT License\r\n\r\nCopyright (c) Somebody\r\n');

const run = (...args) => spawnSync(process.execPath, [SCRIPT, ...args], {encoding: 'utf8'});

try {
    execFileSync(process.execPath, [SCRIPT, input, out, COMMIT, '2026-10-24', licence]);
    const list = JSON.parse(fs.readFileSync(out, 'utf8'));
    expect('header', [list.source, list.commit, list.updated], ['https://github.com/AreWeAntiCheatYet/AreWeAntiCheatYet', COMMIT, '2026-10-24']);
    expect('licence, as the repository wrote it, with the line ends of a file', list.license, 'MIT License\n\nCopyright (c) Somebody');
    expect('the ids kept, in the list\'s order', list.entries.map(row => row[0]), ['one', 'two', 'three', 'four', 'five', 'nine', 's%26box']);
    expect('a row', list.entries[0], ['one', 'One', 'supported', ['Guard A'], '2024-01-19']);
    expect('an anti-cheat named twice is named once', list.entries[1][3], ['Guard A', 'Guard B']);
    expect('a game with no anti-cheat named', list.entries[2][3], []);
    expect('the day of a date with an offset is the date written', list.entries[3][4], '2026-08-21');
    expect('a date that is no date is nothing', list.entries[4][4], '');
    expect('only the five states', [...new Set(list.entries.map(row => row[2]))].sort(), ['broken', 'denied', 'planned', 'running', 'supported']);
    expect('five fields a row, and nothing else of the list kept', list.entries.every(row => row.length === 5), true);
    expect('the notes, links and store numbers are not kept', /example\.org|steam|a note/u.test(fs.readFileSync(out, 'utf8')), false);
    const nine = list.entries.find(row => row[0] === 'nine');
    const controls = new RegExp(`[${String.fromCharCode(0)}-${String.fromCharCode(31)}${String.fromCharCode(127)}-${String.fromCharCode(159)}${LINE_SEPARATOR}${RTL_OVERRIDE}]`, 'u');
    expect('no control character, line break or turned text in a name or an anti-cheat', controls.test(nine[1]) || controls.test(nine[3][0]), false);
    expect('the forged line is one anti-cheat', nine[3].length, 1);
    expect('an odd id is kept as it is', list.entries.find(row => row[0] === 's%26box')[1], 's&box');
} finally {
    // Arguments it refuses
    expect('no arguments', run().status, 64);
    expect('a short commit', run(input, out, 'abc', '2026-10-24', licence).status, 64);
    expect('a bad date', run(input, out, COMMIT, '24 October', licence).status, 64);
    fs.writeFileSync(licence, 'Some other licence\n');
    expect('a licence that is not the MIT License', run(input, out, COMMIT, '2026-10-24', licence).status === 0, false);
    fs.rmSync(work, {recursive: true, force: true});
}

const say = globalThis.print ?? console.log;
if (failures.length) {
    for (const failure of failures)
        say(`FAIL ${failure}`);
    throw new Error(`${failures.length} of ${count} checks failed`);
}
say(`test-trim-anticheat-list: ${count} checks ok`);
