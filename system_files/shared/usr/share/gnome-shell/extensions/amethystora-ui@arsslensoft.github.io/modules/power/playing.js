// While you play (key `while-playing` of org.gnome.shell.extensions.amethystora-ui.power, ame desktop while-playing,
// Control's Games card): GameMode's daemon counts the games that asked it for its mode, and while that count is above
// zero the desktop keeps out of the way. Banners wait, as Present holds them (the pill's hold, with a reason of its own;
// calls, alarms and urgent ones pass). The power mode goes to performance through power-profiles-daemon's own hold, on
// mains only, never on the battery. And the account's timed backup and containers' upgrade wait, through
// /usr/libexec/amethystora-metered, which counts six hours at most from the start of the mark, so that a game that never
// unregisters cannot stop them for good. The system update and the whole-machine scan are never held (root must not take
// a file an account writes as a reason to delay them), and a run the person starts still runs.
//
// All of it is given back when the count returns to zero, GameMode leaves the bus, the key goes off, the screen locks
// (a lock stops the extension, and nothing is kept at module scope on purpose: the unlock reads the count again), the
// shell stops, or the person presses Let them run in the pill's card. The profile hold ends with the shell's connection
// anyway, and the mark names the shell's process, which /usr/libexec/amethystora-metered checks is still gnome-shell.
//
// With the key off nothing is watched. With it on, only GameMode's bus name is (never started from here); UPower's
// OnBattery and the profile's ProfileReleased are followed only while a game counts. No timer. Whatever claims the name
// on the account's own bus can make this hold banners and the account's own backup for six hours: that is the account's
// to do, and bounded.

import Clutter from 'gi://Clutter';
import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import St from 'gi://St';

import {gettext as _} from 'resource:///org/gnome/shell/extensions/extension.js';

import {buttonRow, cardButton, retire} from '../pill/clock.js';
import {lines, makeQueue, plan} from './playingdata.js';

const GAMEMODE = 'com.feralinteractive.GameMode';
const GAMEMODE_PATH = '/com/feralinteractive/GameMode';
const UPOWER = 'org.freedesktop.UPower';
const UPOWER_PATH = '/org/freedesktop/UPower';
const PROFILES = 'org.freedesktop.UPower.PowerProfiles';
const PROFILES_PATH = '/org/freedesktop/UPower/PowerProfiles';
const APP_ID = 'org.amethystora.UI';
const METERED = '/usr/libexec/amethystora-metered';
const MARK = GLib.build_filenamev([GLib.get_user_runtime_dir(), 'amethystora', 'playing']);
// What a timer found held while the mark was there: the end of the game starts it (amethystora-metered playing off ended)
const WAITED = GLib.build_filenamev([GLib.get_user_runtime_dir(), 'amethystora', 'playing-waited']);
const ICON = 'input-gaming-symbolic';

// The helper's runs one at a time, across a lock too (a new instance starts at the unlock): `on` and `off` are two processes,
// and an `off` that finished before the `on` before it would leave the mark behind
const queued = makeQueue();

function label(text, style) {
    const actor = new St.Label({style_class: style, text});
    actor.clutter_text.use_markup = false;
    actor.clutter_text.line_wrap = true;
    return actor;
}

// The pill's activity: "Playing", with a card that says what is held and offers Let them run
class Mark {
    constructor(owner) {
        this.id = 'playing';
        this.plate = '';
        this._owner = owner;
    }

    get text() {
        return _('Playing');
    }

    get accessible() {
        return _('Playing: banners and background work are waiting');
    }

    get row() {
        return {icon: ICON, text: this.text};
    }

    pill() {
        if (!this._content) {
            const content = new St.BoxLayout({style_class: 'amethystora-pill-content amethystora-pill-playing'});
            content.add_child(new St.Icon({icon_name: ICON, icon_size: 14, y_align: Clutter.ActorAlign.CENTER}));
            content.add_child(new St.Label({text: this.text, y_align: Clutter.ActorAlign.CENTER}));
            this._content = content;
            content.connect('destroy', () => {
                if (this._content === content)
                    this._content = null;
            });
        }
        return this._content;
    }

    card(api) {
        const owner = this._owner;
        const body = new St.BoxLayout({style_class: 'amethystora-pill-card-body amethystora-pill-news-card',
            orientation: Clutter.Orientation.VERTICAL});
        body.add_child(label(_('Playing'), 'amethystora-pill-news-title'));
        const words = {
            banners: _('Banners wait. Calls, alarms and urgent ones still come through.'),
            performance: _('The power mode is on performance while you are plugged in.'),
            battery: _('The power mode is left alone on the battery.'),
            waits: _('Your timed backup and the containers’ upgrade wait, for six hours at most. The system update does not, and one you start yourself still runs.'),
        };
        for (const id of lines(owner.held()))
            body.add_child(label(words[id], 'amethystora-pill-card-text'));
        body.add_child(buttonRow([cardButton(_('Let them run'), () => {
            api.close();
            owner.letRun();
        }, {primary: true})]));
        return body;
    }

    destroy() {
        retire(this._content);
        this._content = null;
    }
}

export class Playing {
    constructor(ext) {
        this._ext = ext;
        this._count = 0;
        this._letRun = false;
        this._declined = false;
        this._onBattery = null;
        this._generation = 0;
        this._signals = [];
        this._mains = [];
        this._marking = false;
        this._marked = false;
        this._cookie = 0;
        this._asking = null;
        this._tried = false;
        this._released = 0;
        this._mark = null;
        this._byKey = false;
    }

    enable() {
        this._cancellable = new Gio.Cancellable();
        // Never started from here: only watched. Told at once when GameMode is not on the bus, which also takes away a mark
        // that a shell that died left behind.
        this._watch = Gio.bus_watch_name(Gio.BusType.SESSION, GAMEMODE, Gio.BusNameWatcherFlags.NONE,
            () => this._appeared(), () => this._vanished());
    }

    disable() {
        if (this._watch)
            Gio.bus_unwatch_name(this._watch);
        this._watch = 0;
        this._unlisten();
        this._cancellable?.cancel();
        this._cancellable = null;
        this._generation++;
        // The lock, the key and the shell's end all give everything back; the unlock reads the count again
        this._count = 0;
        this._letRun = false;
        this._declined = false;
        // The key turned off in the middle of a game is an end like the game's own: what waited is started. A lock, and the
        // shell's end, are not.
        this._apply(this._byKey);
        this._mark?.destroy();
        this._mark = null;
    }

    // The power module says so just before it stops this part because its key went off
    keyOff() {
        this._byKey = true;
    }

    get _pill() {
        return this._ext.modules?.get('pill') ?? null;
    }

    // --- GameMode ---------------------------------------------------------------------------------------------------

    _appeared() {
        this._unlisten();
        const session = Gio.DBus.session;
        const listen = (interface_, member, arg0 = null) => this._signals.push(session.signal_subscribe(GAMEMODE, interface_,
            member, GAMEMODE_PATH, arg0, Gio.DBusSignalFlags.NONE, () => this._read()));
        listen(GAMEMODE, 'GameRegistered');
        listen(GAMEMODE, 'GameUnregistered');
        listen('org.freedesktop.DBus.Properties', 'PropertiesChanged', GAMEMODE);
        this._read();
    }

    _vanished() {
        this._unlisten();
        this._generation++;
        this._counted(0);
    }

    _unlisten() {
        for (const id of this._signals)
            Gio.DBus.session.signal_unsubscribe(id);
        this._signals = [];
    }

    // The count is read, never counted from the signals: a signal only says to look
    _read() {
        const generation = ++this._generation;
        Gio.DBus.session.call(GAMEMODE, GAMEMODE_PATH, 'org.freedesktop.DBus.Properties', 'Get',
            new GLib.Variant('(ss)', [GAMEMODE, 'ClientCount']), new GLib.VariantType('(v)'),
            Gio.DBusCallFlags.NO_AUTO_START, 2000, this._cancellable, (connection, result) => {
                if (generation !== this._generation)
                    return;
                try {
                    const [value] = connection.call_finish(result).deepUnpack();
                    this._counted(value.unpack());
                } catch (e) {
                    if (!e.matches?.(Gio.IOErrorEnum, Gio.IOErrorEnum.CANCELLED))
                        console.debug(`Amethystora UI: GameMode's client count could not be read: ${e.message}`);
                }
            });
    }

    _counted(count) {
        this._count = Number.isInteger(count) && count > 0 ? count : 0;
        // Back to zero: the next game starts afresh, and what the person gave back or changed by hand is forgotten
        if (this._count === 0) {
            this._letRun = false;
            this._declined = false;
        }
        this._apply(true);
    }

    // --- What it holds ----------------------------------------------------------------------------------------------

    // Every part follows what is wanted; each is idempotent, so that any change may call it. `ended` says that the game is
    // over (or the person said Let them run), not that the part stopped for a lock or the key: only then is what a timer
    // found held started.
    _apply(ended = false) {
        const wanted = plan({count: this._count, onBattery: this._onBattery, letRun: this._letRun, declined: this._declined});
        this._followMains(wanted.playing);
        this._syncPill(wanted.banners);
        this._syncMark(wanted.waits, ended);
        this._syncProfile(wanted.performance);
        this._pill?.playingChanged?.();
    }

    _syncPill(on) {
        const pill = this._pill;
        if (on) {
            this._mark ??= new Mark(this);
            pill?.setPlaying(this._mark);
        } else {
            pill?.setPlaying(null);
            this._mark?.destroy();
            this._mark = null;
        }
    }

    // The account's timed backup and containers' upgrade: the mark /usr/libexec/amethystora-metered reads
    _syncMark(on, ended) {
        if (on && !this._marking) {
            this._marking = true;
            this._run('on', ok => {
                this._marked = ok && this._marking;
                this._pill?.playingChanged?.();
            });
        } else if (!on && (this._marking || GLib.file_test(MARK, GLib.FileTest.EXISTS) ||
            (ended && GLib.file_test(WAITED, GLib.FileTest.IS_DIR)))) {
            this._marking = false;
            this._marked = false;
            this._run(ended ? 'off ended' : 'off', () => {});
        }
    }

    _run(word, done) {
        queued(() => new Promise(resolve => {
            try {
                const process = Gio.Subprocess.new([METERED, 'playing', ...word.split(' ')],
                    Gio.SubprocessFlags.STDOUT_SILENCE | Gio.SubprocessFlags.STDERR_SILENCE);
                process.wait_check_async(null, (p, result) => {
                    let ok = false;
                    try {
                        p.wait_check_finish(result);
                        ok = true;
                    } catch {
                        // Said below by what the caller does with a false
                    }
                    done(ok);
                    resolve();
                });
            } catch (e) {
                console.warn(`Amethystora UI: ${METERED} did not start: ${e.message}`);
                done(false);
                resolve();
            }
        }));
    }

    // Power-profiles-daemon's own hold, which ends if the shell's connection does: performance, on mains
    _syncProfile(on) {
        if (on && !this._cookie && !this._asking && !this._tried) {
            // Once for each time it is wanted: a machine that refuses is not asked at every change
            this._tried = true;
            const asking = {};
            this._asking = asking;
            Gio.DBus.system.call(PROFILES, PROFILES_PATH, PROFILES, 'HoldProfile',
                new GLib.Variant('(sss)', ['performance', _('Playing a game'), APP_ID]), new GLib.VariantType('(u)'),
                Gio.DBusCallFlags.NO_AUTO_START, -1, null, (connection, result) => {
                    let cookie = 0;
                    try {
                        [cookie] = connection.call_finish(result).deepUnpack();
                    } catch (e) {
                        // A machine with no performance mode, or no daemon: nothing is said to be held
                        console.debug(`Amethystora UI: the performance mode could not be held: ${e.message}`);
                    }
                    if (this._asking !== asking) {
                        // Over before the answer came: the hold made now is given back
                        if (cookie)
                            this._release(cookie);
                        return;
                    }
                    this._asking = null;
                    this._cookie = cookie;
                    if (cookie)
                        this._followRelease();
                    this._pill?.playingChanged?.();
                });
        } else if (!on) {
            this._tried = false;
            this._asking = null;
            if (this._cookie) {
                const cookie = this._cookie;
                this._cookie = 0;
                this._release(cookie);
            }
            this._unfollowRelease();
        }
    }

    _release(cookie) {
        Gio.DBus.system.call(PROFILES, PROFILES_PATH, PROFILES, 'ReleaseProfile', new GLib.Variant('(u)', [cookie]),
            null, Gio.DBusCallFlags.NO_AUTO_START, -1, null, (connection, result) => {
                try {
                    connection.call_finish(result);
                } catch {
                    // Somebody chose a mode by hand, which ends every hold: nothing left to give back
                }
            });
    }

    // The person chose a power mode by hand: the hold is over, and it is not taken again for this game
    _followRelease() {
        if (this._released)
            return;
        this._released = Gio.DBus.system.signal_subscribe(PROFILES, PROFILES, 'ProfileReleased', PROFILES_PATH, null,
            Gio.DBusSignalFlags.NONE, (c, s, p, i, name, parameters) => {
                const [cookie] = parameters.deepUnpack();
                if (!this._cookie || cookie !== this._cookie)
                    return;
                this._cookie = 0;
                this._declined = true;
                this._apply();
            });
    }

    _unfollowRelease() {
        if (this._released)
            Gio.DBus.system.signal_unsubscribe(this._released);
        this._released = 0;
    }

    // UPower's OnBattery, only while a game counts: plugged in takes the performance mode, unplugged gives it back
    _followMains(on) {
        if (on && this._mains.length === 0) {
            this._mains.push(Gio.DBus.system.signal_subscribe(UPOWER, 'org.freedesktop.DBus.Properties', 'PropertiesChanged',
                UPOWER_PATH, UPOWER, Gio.DBusSignalFlags.NONE, (c, s, p, i, name, parameters) => {
                    const [, changed] = parameters.recursiveUnpack();
                    if (typeof changed?.OnBattery === 'boolean') {
                        this._onBattery = changed.OnBattery;
                        this._apply();
                    }
                }));
            Gio.DBus.system.call(UPOWER, UPOWER_PATH, 'org.freedesktop.DBus.Properties', 'Get',
                new GLib.Variant('(ss)', [UPOWER, 'OnBattery']), new GLib.VariantType('(v)'), Gio.DBusCallFlags.NO_AUTO_START,
                2000, this._cancellable, (connection, result) => {
                    try {
                        const [value] = connection.call_finish(result).deepUnpack();
                        if (this._mains.length > 0) {
                            this._onBattery = value.unpack();
                            this._apply();
                        }
                    } catch {
                        // UPower cannot be asked: it is not known to be on mains, so the performance mode is left alone
                    }
                });
        } else if (!on && this._mains.length > 0) {
            for (const id of this._mains)
                Gio.DBus.system.signal_unsubscribe(id);
            this._mains = [];
            this._onBattery = null;
        }
    }

    // --- The pill's card --------------------------------------------------------------------------------------------

    // What is held now, for the card's lines
    held() {
        return {banners: !!this._mark, performance: this._cookie !== 0, waits: this._marked, onBattery: this._onBattery === true};
    }

    // Let them run: all of it back before the game ends, until the count has been to zero
    letRun() {
        this._letRun = true;
        this._apply(true);
    }

    // --- For the suites and the harness -----------------------------------------------------------------------------

    state() {
        return {
            count: this._count,
            playing: !!this._mark,
            banners: this._pill?.hold?.reason === 'playing',
            performance: this._cookie !== 0,
            cookie: this._cookie,
            marked: this._marked,
            onBattery: this._onBattery,
            letRun: this._letRun,
            declined: this._declined,
            watching: this._signals.length,
            following: this._mains.length,
        };
    }
}
