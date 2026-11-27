// Will a game run? (the key `game`): after `game:` (or `games:`) and a name, what a community list of games and their
// anti-cheat says of it, from `amethystora-will-it-run`, which answers from the copy of the list in the image and reads no
// network. The name goes to the helper on its standard input, never on a command line; one short process for each pause in
// what is typed, stopped when the search moves on, nothing kept between searches and nothing logged. The helper cleans the
// list's text, and says what the list says and never that a game will run: an exact name or id answers, a name that only
// resembles one is shown as the closest entry and never as the answer. Enter opens the manual at that section.

import Gio from 'gi://Gio';
import St from 'gi://St';

import {gettext as _} from 'resource:///org/gnome/shell/extensions/extension.js';

import {output, pause} from './run.js';

const HELPER = '/usr/libexec/amethystora-will-it-run';
const QUIET = 250;
const ASK = /^\s*games?\s*:\s*(.+)$/iu;
const ROW = 'game:answer';

// What each state of the list is told as: the helper's own sentences, so that the two say the same in a language
function said(state) {
    switch (state) {
    case 'supported': return _('The list says it runs on Linux: its maker turned the anti-cheat on there, or the anti-cheat works under Wine and Proton as it is.');
    case 'running': return _('The list says it runs on Linux without harm to online play, but may need some tinkering first.');
    case 'planned': return _('The list says its maker plans to support Linux, and has not yet.');
    case 'broken': return _('The list says it does not run online on Linux, because of its anti-cheat.');
    case 'denied': return _('The list says its maker has said it will not turn its anti-cheat on for Linux.');
    default: return _('The list does not say.');
    }
}

export class GamesProvider {
    constructor() {
        this.id = 'amethystora-games';
        this.isRemoteProvider = false;
        this.canLaunchSearch = false;
        this._answer = null;
        this._previous = null;
    }

    destroy() {
        this._gone = true;
        this._answer = null;
        this._previous = null;
    }

    async getInitialResultSet(terms, cancellable) {
        this._previous = this._answer;
        this._answer = null;
        const asked = ASK.exec(terms.join(' '));
        const name = asked ? asked[1].trim().slice(0, 100) : '';
        if (name.length < 2 || !await pause(QUIET, cancellable) || this._gone)
            return [];
        const printed = await output([HELPER, '--json', '--stdin'], cancellable, name);
        if (cancellable?.is_cancelled() || printed === null || this._gone)
            return [];
        let answer;
        try {
            answer = JSON.parse(printed);
        } catch {
            return [];
        }
        if (typeof answer?.match !== 'string')
            return [];
        this._answer = answer;
        return [ROW];
    }

    getSubsearchResultSet(previous, terms, cancellable) {
        return this.getInitialResultSet(terms, cancellable);
    }

    getResultMetas(ids) {
        return Promise.resolve(ids.map(id => {
            const answer = this._answer ?? this._previous;
            const icon = size => new St.Icon({icon_name: 'input-gaming-symbolic', icon_size: size});
            if (id !== ROW || !answer)
                return {id, name: id};
            if (answer.match === 'exact') {
                const parts = [said(answer.state)];
                if (Array.isArray(answer.anticheats) && answer.anticheats.length)
                    parts.push(_('Anti-cheat: %s').format(answer.anticheats.join(', ')));
                if (typeof answer.date === 'string')
                    parts.push(_('The list changed this entry on %s.').format(answer.date));
                return {id, name: String(answer.name), description: parts.join(' · '), createIcon: icon, hint: _('Enter opens the manual')};
            }
            const description = answer.match === 'closest' && answer.closest
                ? _('The closest entry in the list is %s, which is not an answer. Ask for it by its name.').format(String(answer.closest.name))
                : _('It has no entry named %s.').format(String(answer.query ?? ''));
            return {id, name: _('The list does not say.'), description, createIcon: icon, hint: _('Enter opens the manual')};
        }));
    }

    filterResults(ids, max) {
        return ids.slice(0, Math.min(max, 1));
    }

    activateResult() {
        try {
            Gio.Subprocess.new(['amethystora-manual', 'games#will-it-run'], Gio.SubprocessFlags.NONE);
        } catch (e) {
            console.warn(`Amethystora UI: the search could not open the manual: ${e.message}`);
        }
    }
}
