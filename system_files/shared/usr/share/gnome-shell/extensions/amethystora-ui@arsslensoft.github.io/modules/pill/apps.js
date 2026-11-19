// The apps a computer comes with, as they arrive. flatpak-preinstall.service installs them from Flathub on the first boot
// that has a network, as root and in the background, and told nobody: the pill showed only the Flatpak pulls going by
// (moving.js). Here: how many of the image's list are in, with the ring; that they wait for the internet while the service
// waits to try again; and, once the install was seen, that they are ready. While it says so, moving.js leaves the Flatpak
// pulls out of what it says (they are this) and still stays awake for them.
//
// What it reads, when it starts (with the shell, and at every unlock): the lists in preinstall.d (appslist.js) and whether
// each app's deploy is there, under /var/lib/flatpak, all of it asynchronously. On a computer that has them all, nothing
// else. Only while some are missing and the service may still run does it follow the unit (the system manager's signals,
// subscribed for that while, subscribe.js) and the entries of /var/lib/flatpak (the .changed mark Flatpak touches as each
// app is deployed, and the app folder), never polling.

import Clutter from 'gi://Clutter';
import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import St from 'gi://St';

import {gettext as _, ngettext} from 'resource:///org/gnome/shell/extensions/extension.js';
import * as Main from 'resource:///org/gnome/shell/ui/main.js';

import {appsOf, settled, viewOf} from './appslist.js';
import {buttonRow, cardButton, retire} from './clock.js';
import {subscribeUnits} from './subscribe.js';

Gio._promisify(Gio.File.prototype, 'enumerate_children_async');
Gio._promisify(Gio.FileEnumerator.prototype, 'next_files_async');
Gio._promisify(Gio.File.prototype, 'load_contents_async');
Gio._promisify(Gio.File.prototype, 'query_info_async');

// flatpak preinstall's own folders, the image's first: a file of the same name in /etc stands in for it
const LISTS = ['/usr/share/flatpak/preinstall.d', '/etc/flatpak/preinstall.d'];
const SUFFIX = '.preinstall';
const FLATPAK = '/var/lib/flatpak';
const UNIT = 'flatpak-preinstall.service';
const SYSTEMD = 'org.freedesktop.systemd1';
const ICON = 'system-software-install-symbolic';
// "Ready" stays this long, then the pill is the clock again
const READY_SECONDS = 10;
// Several deploys in a second are counted once
const COALESCE_MS = 1000;

// The install was shown during this shell's run, so that "ready" is said after an unlock too (a lock stops the module)
let said = false;

const cancelled = e => e?.matches?.(Gio.IOErrorEnum, Gio.IOErrorEnum.CANCELLED);

// The type of what is at a path, links followed, or null when nothing is
async function typeOf(path, cancellable) {
    try {
        const info = await Gio.File.new_for_path(path).query_info_async('standard::type', Gio.FileQueryInfoFlags.NONE,
            GLib.PRIORITY_LOW, cancellable);
        return info.get_file_type();
    } catch (e) {
        if (cancelled(e))
            throw e;
        return null;
    }
}

// The lists' files by name, /etc's standing in for /usr's
async function lists(cancellable) {
    const files = new Map();
    for (const folder of LISTS) {
        let enumerator;
        try {
            enumerator = await Gio.File.new_for_path(folder).enumerate_children_async('standard::name,standard::type',
                Gio.FileQueryInfoFlags.NONE, GLib.PRIORITY_LOW, cancellable);
        } catch (e) {
            if (cancelled(e))
                throw e;
            continue;
        }
        for (;;) {
            const infos = await enumerator.next_files_async(32, GLib.PRIORITY_LOW, cancellable);
            if (infos.length === 0)
                break;
            for (const info of infos) {
                const name = info.get_name();
                if (name.endsWith(SUFFIX) && info.get_file_type() === Gio.FileType.REGULAR)
                    files.set(name, `${folder}/${name}`);
            }
        }
    }
    return [...files.values()];
}

// The apps of every list, each once
async function listed(cancellable) {
    const apps = new Set();
    for (const path of await lists(cancellable)) {
        try {
            const [bytes] = await Gio.File.new_for_path(path).load_contents_async(cancellable);
            for (const id of appsOf(new TextDecoder().decode(bytes)))
                apps.add(id);
        } catch (e) {
            if (cancelled(e))
                throw e;
        }
    }
    return [...apps];
}

export class FirstApps {
    // awake: whether the computer stays awake for what moves (moving.js); changed: told when covers changes
    constructor(activities, {awake, changed} = {}) {
        this.id = 'apps';
        this.plate = '';
        this._activities = activities;
        this._awake = awake;
        this._changed = changed;
        this._view = null;
        this._apps = [];
        this._done = 0;
        this._total = 0;
    }

    enable() {
        this._cancellable = new Gio.Cancellable();
        this._start(this._cancellable).catch(e => {
            if (!cancelled(e))
                console.warn(`Amethystora UI: the pill could not read the apps the computer comes with: ${e.message}`);
        });
    }

    disable() {
        this._cancellable?.cancel();
        this._cancellable = null;
        this._stopFollowing();
        if (this._readyId)
            GLib.source_remove(this._readyId);
        this._readyId = 0;
        this._setView(null);
    }

    // Whether the Flatpak pulls going by are this install's, for moving.js to leave them out of what it says
    get covers() {
        return this._view === 'installing' || this._view === 'waiting';
    }

    // For the suites
    state() {
        return {view: this._view, done: this._done, total: this._total, following: !!this._following};
    }

    async _start(cancellable) {
        this._apps = await listed(cancellable);
        await this._count(cancellable);
        if (this._cancellable === cancellable && !this._settledNow())
            this._follow();
    }

    // Deployed: Flatpak's link to the active commit of the app's current branch is there
    async _count(cancellable) {
        const found = await Promise.all(this._apps.map(id => typeOf(`${FLATPAK}/app/${id}/current/active`, cancellable)));
        if (this._cancellable !== cancellable)
            return;
        this._total = this._apps.length;
        this._done = found.filter(type => type !== null).length;
    }

    get _sub() {
        return this._proxy?.get_cached_property('SubState')?.unpack() ?? '';
    }

    get _fileState() {
        return this._proxy?.get_cached_property('UnitFileState')?.unpack() ?? '';
    }

    // With nothing missing, or nothing left to happen, nothing is followed: true when so. The unit is known only once
    // followed: before that, only "all in" settles it
    _settledNow() {
        const state = {sub: this._sub, fileState: this._fileState, done: this._done, total: this._total, said};
        this._setView(viewOf(state));
        const over = this._done >= this._total || (!!this._proxy && settled(state));
        if (over)
            this._stopFollowing();
        return over;
    }

    // --- Following the unit and the installation ------------------------------------------------------------------

    _follow() {
        this._following = true;
        this._unsubscribe = subscribeUnits('system');
        const cancellable = this._cancellable;
        Gio.DBus.system.call(SYSTEMD, '/org/freedesktop/systemd1', `${SYSTEMD}.Manager`, 'LoadUnit',
            new GLib.Variant('(s)', [UNIT]), new GLib.VariantType('(o)'), Gio.DBusCallFlags.NO_AUTO_START, 2000, cancellable,
            (connection, result) => {
                let path;
                try {
                    [path] = connection.call_finish(result).deepUnpack();
                } catch (e) {
                    // No such unit, or no manager to ask: nothing will tell when it changes
                    if (!cancelled(e) && this._cancellable === cancellable)
                        this._stopFollowing();
                    return;
                }
                Gio.DBusProxy.new(Gio.DBus.system,
                    Gio.DBusProxyFlags.DO_NOT_AUTO_START | Gio.DBusProxyFlags.GET_INVALIDATED_PROPERTIES, null,
                    SYSTEMD, path, `${SYSTEMD}.Unit`, cancellable, (source, done) => {
                        let proxy;
                        try {
                            proxy = Gio.DBusProxy.new_finish(done);
                        } catch {
                            return;
                        }
                        if (this._cancellable !== cancellable || !this._following)
                            return;
                        this._proxy = proxy;
                        proxy.connectObject('g-properties-changed', () => this._recountSoon(), this);
                        this._recount();
                    });
            });
        // "Wait for the internet" or "try again soon", as the network goes
        Gio.NetworkMonitor.get_default().connectObject('notify::connectivity', () => this._recountSoon(), this);
        this._watch(FLATPAK, '_flatpakMonitor', file => {
            // The app folder comes with the first app
            if (file.get_basename() === 'app')
                this._watch(`${FLATPAK}/app`, '_appsMonitor', () => this._recountSoon());
            this._recountSoon();
        });
        this._watch(`${FLATPAK}/app`, '_appsMonitor', () => this._recountSoon());
    }

    // A monitor on a folder that is there: one on a missing path would make GLib look for it every few seconds
    async _watch(path, name, changed) {
        const cancellable = this._cancellable;
        if (this[name] || !cancellable)
            return;
        try {
            if (await typeOf(path, cancellable) !== Gio.FileType.DIRECTORY)
                return;
        } catch {
            return;
        }
        if (this[name] || !this._following || this._cancellable !== cancellable)
            return;
        try {
            this[name] = Gio.File.new_for_path(path).monitor_directory(Gio.FileMonitorFlags.NONE, cancellable);
        } catch (e) {
            console.warn(`Amethystora UI: the pill cannot watch ${path}: ${e.message}`);
            return;
        }
        this[name].connect('changed', (monitor, file) => changed(file));
    }

    _stopFollowing() {
        this._following = false;
        Gio.NetworkMonitor.get_default().disconnectObject(this);
        this._proxy?.disconnectObject(this);
        this._proxy = null;
        for (const name of ['_flatpakMonitor', '_appsMonitor']) {
            this[name]?.cancel();
            this[name] = null;
        }
        if (this._soon)
            GLib.source_remove(this._soon);
        this._soon = 0;
        this._unsubscribe?.();
        this._unsubscribe = null;
    }

    _recountSoon() {
        this._soon ||= GLib.timeout_add(GLib.PRIORITY_DEFAULT, COALESCE_MS, () => {
            this._soon = 0;
            this._recount();
            return GLib.SOURCE_REMOVE;
        });
    }

    // One count at a time; one asked for meanwhile runs after it
    async _recount() {
        const cancellable = this._cancellable;
        if (!cancellable || !this._following)
            return;
        if (this._counting) {
            this._again = true;
            return;
        }
        this._counting = true;
        try {
            await this._count(cancellable);
        } catch (e) {
            if (!cancelled(e))
                console.warn(`Amethystora UI: the pill could not count the apps: ${e.message}`);
        } finally {
            this._counting = false;
        }
        if (this._cancellable !== cancellable || !this._following)
            return;
        this._settledNow();
        if (this._again) {
            this._again = false;
            this._recountSoon();
        }
    }

    // --- In the pill and the card ---------------------------------------------------------------------------------

    _setView(view) {
        const before = this._view;
        this._view = view;
        if (view === 'installing' || view === 'waiting')
            said = true;
        if (view === 'ready' && !this._readyId) {
            this._readyId = GLib.timeout_add_seconds(GLib.PRIORITY_DEFAULT, READY_SECONDS, () => {
                this._readyId = 0;
                said = false;
                this._setView(null);
                return GLib.SOURCE_REMOVE;
            });
        }
        if (!view) {
            if (this._activities.get('apps') === this)
                this._activities.set('apps', null);
            retire(this._content);
            this._content = null;
            this._label = null;
        } else {
            this.pill();
            this._label.text = this.text;
            this._activities.set('apps', this);
            this._activities.update('apps');
            this._card?.update?.();
        }
        if ((before === 'installing' || before === 'waiting') !== this.covers)
            this._changed?.();
    }

    _online() {
        return Gio.NetworkMonitor.get_default().connectivity === Gio.NetworkConnectivity.FULL;
    }

    get text() {
        switch (this._view) {
        case 'installing':
            return ngettext('Installing your apps · %d of %d', 'Installing your apps · %d of %d', this._total).format(this._done, this._total);
        case 'waiting':
            return this._online() ? _('Your apps try again soon') : _('Your apps wait for the internet');
        case 'ready':
            return _('Your apps are ready');
        }
        return '';
    }

    get accessible() {
        return this.text;
    }

    get short() {
        return this._view === 'ready' ? '' : `${this._done}/${this._total}`;
    }

    get row() {
        return {icon: ICON, text: this.text};
    }

    // The ring: how many are in, while they come
    get progress() {
        return this._view === 'installing' && this._total > 0 ? this._done / this._total : null;
    }

    pill() {
        if (!this._content) {
            this._content = new St.BoxLayout({style_class: 'amethystora-pill-content amethystora-pill-apps'});
            this._content.add_child(new St.Icon({
                icon_name: ICON,
                fallback_icon_name: 'folder-download-symbolic',
                icon_size: 16,
                y_align: Clutter.ActorAlign.CENTER,
            }));
            this._label = new St.Label({y_align: Clutter.ActorAlign.CENTER});
            this._content.add_child(this._label);
        }
        return this._content;
    }

    card(api) {
        const body = new St.BoxLayout({style_class: 'amethystora-pill-card-body', orientation: Clutter.Orientation.VERTICAL});
        const title = new St.Label({style_class: 'amethystora-pill-card-label'});
        const text = new St.Label({style_class: 'amethystora-pill-card-text'});
        text.clutter_text.line_wrap = true;
        const note = new St.Label({style_class: 'amethystora-pill-card-text'});
        note.clutter_text.line_wrap = true;
        body.add_child(title);
        body.add_child(text);
        body.add_child(note);
        body.add_child(buttonRow([cardButton(_('Show the apps'), () => {
            api.close();
            Main.overview.showApps();
        })]));
        body.update = () => {
            const [done, total] = [this._done, this._total];
            switch (this._view) {
            case 'installing':
                title.text = _('Installing your apps');
                // The extractor (check-translations.js) reads a call and its words from one line
                text.text = ngettext('The apps Amethystora comes with are on their way from Flathub: %d of %d is in. Each shows in the app grid as it arrives, and you can use the computer meanwhile.', 'The apps Amethystora comes with are on their way from Flathub: %d of %d are in. Each shows in the app grid as it arrives, and you can use the computer meanwhile.', done).format(done, total);
                break;
            case 'waiting':
                title.text = this._online() ? _('Your apps try again soon') : _('Waiting for the internet');
                text.text = this._online()
                    ? _('The last try did not finish. It starts again by itself, less often each time: there is nothing to do.')
                    : _('The apps Amethystora comes with install from Flathub as soon as the computer is online. Connect to a network in the top bar\'s menu.');
                break;
            case 'ready':
                title.text = _('Your apps are ready');
                text.text = _('Everything Amethystora comes with is installed.');
                break;
            }
            note.text = _('The screen can go dark. The computer stays awake until they are in, then sleeps as usual.');
            note.visible = this._view === 'installing' && !!this._awake?.();
        };
        body.update();
        this._card = body;
        body.connect('destroy', () => {
            if (this._card === body)
                this._card = null;
        });
        return body;
    }
}
