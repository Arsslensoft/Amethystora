// What the tiling keeps in ~/.local/state/amethystora/tiling.json (modules/tiling/state.js): a record is used only when
// its schema is installed, has the key, and the key holds the type the record is for; any other is dropped when the
// file is read. GNOME Shell's modules are not run here: state.js is loaded with stand-ins for GLib and Gio.
//   node build_files/shared/test-tiling-state.mjs
// A failure throws, which makes node exit with an error.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {pathToFileURL} from 'node:url';

const fail = what => { throw new Error(`test-tiling-state: ${what}`); };
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tiling-state-'));
const source = fs.readFileSync(new URL('../../system_files/shared/usr/share/gnome-shell/extensions/amethystora-ui@arsslensoft.github.io/modules/tiling/state.js', import.meta.url), 'utf8');

// Two installed schemas: one with a fixed path, one relocatable
const schemas = {
    'org.test.fixed': {path: '/org/test/', keys: {'edge-tiling': 'b', 'accels': 'as', 'count': 'i'}},
    'org.test.relocatable': {path: null, keys: {'edge-tiling': 'b'}},
};
globalThis.stand_ins = {
    Gio: {SettingsSchemaSource: {get_default: () => ({lookup: id => {
        const schema = schemas[id];
        return schema && {
            get_path: () => schema.path,
            has_key: key => key in schema.keys,
            get_key: key => ({get_value_type: () => ({dup_string: () => schema.keys[key]})}),
        };
    }})}},
    GLib: {
        get_user_state_dir: () => dir,
        build_filenamev: parts => parts.join('/'),
        file_get_contents: file => [true, fs.readFileSync(file)],
        file_set_contents: (file, text) => fs.writeFileSync(file, text),
        mkdir_with_parents: folder => fs.mkdirSync(folder, {recursive: true}),
    },
};
const patched = source
    .replace("import Gio from 'gi://Gio';", 'const Gio = globalThis.stand_ins.Gio;')
    .replace("import GLib from 'gi://GLib';", 'const GLib = globalThis.stand_ins.GLib;');
const file = path.join(dir, 'state-under-test.mjs');
fs.writeFileSync(file, patched);
const {State} = await import(pathToFileURL(file).href);

const taken = (schema, key, extra = {}) => ({schema, key, removed: [{accelerator: '<Super>a', index: 0}], wrote: ['<Super>b'], ...extra});
const forced = (schema, key, extra = {}) => ({schema, key, was: true, wrote: false, ...extra});
const load = data => {
    fs.mkdirSync(path.join(dir, 'amethystora'), {recursive: true});
    fs.writeFileSync(path.join(dir, 'amethystora', 'tiling.json'), JSON.stringify(data));
    fs.rmSync(path.join(dir, 'amethystora', 'tiling.json.bak'), {force: true});
    return new State();
};

const state = load({
    taken: [
        taken('org.test.fixed', 'accels'),
        taken('org.test.fixed', 'edge-tiling'),
        taken('org.test.fixed', 'count'),
        taken('org.test.fixed', 'no-such-key'),
        taken('org.test.not-installed', 'accels'),
        taken('org.test.relocatable', 'accels'),
    ],
    forced: [
        forced('org.test.fixed', 'edge-tiling'),
        forced('org.test.fixed', 'accels'),
        forced('org.test.fixed', 'no-such-key'),
        forced('org.test.not-installed', 'edge-tiling'),
        forced('org.test.relocatable', 'edge-tiling'),
    ],
});
if (JSON.stringify(state.get('taken')?.map(r => `${r.schema} ${r.key}`)) !== JSON.stringify(['org.test.fixed accels']))
    fail(`taken kept ${JSON.stringify(state.get('taken'))}`);
if (JSON.stringify(state.get('forced')?.map(r => `${r.schema} ${r.key}`)) !== JSON.stringify(['org.test.fixed edge-tiling']))
    fail(`forced kept ${JSON.stringify(state.get('forced'))}`);
if (load({taken: [taken('org.test.not-installed', 'accels')]}).get('taken') !== undefined)
    fail('a file of nothing usable should leave no taken records');

(globalThis.print ?? console.log)('test-tiling-state: ok');
