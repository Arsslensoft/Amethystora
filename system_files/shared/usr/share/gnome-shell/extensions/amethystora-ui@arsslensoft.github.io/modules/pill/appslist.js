// The apps the image's preinstall lists name, as flatpak-preinstall.service reads them, and what the pill says of their
// install (pill/apps.js). Free of GNOME Shell's imports, so that it runs under node (test-pill-logic.mjs).

// [Flatpak Preinstall <id>], the id as Flatpak allows it
const GROUP = /^\[Flatpak Preinstall ([A-Za-z_][\w-]*(?:\.[A-Za-z_][\w-]*)+)\]$/;

// The apps one list names: its groups, less the runtimes (a GTK 3 theme) and any it says not to install
export function appsOf(text) {
    const apps = new Map();
    let id = null;
    for (const raw of String(text).split('\n')) {
        const line = raw.trim();
        if (line === '' || line.startsWith('#'))
            continue;
        if (line.startsWith('[')) {
            id = GROUP.exec(line)?.[1] ?? null;
            if (id && !apps.has(id))
                apps.set(id, true);
            continue;
        }
        const at = line.indexOf('=');
        if (!id || at < 0)
            continue;
        const [key, value] = [line.slice(0, at).trim(), line.slice(at + 1).trim()];
        if ((key === 'IsRuntime' && value === 'true') || (key === 'Install' && value === 'false'))
            apps.set(id, false);
    }
    return [...apps].filter(([, app]) => app).map(([name]) => name);
}

// The unit's states (systemd's SubState) in which `flatpak preinstall` runs, and the one in which it waits to try again
const RUNNING = new Set(['start-pre', 'start', 'start-post', 'running']);
const RETRY = 'auto-restart';

// What the pill says, from the unit's SubState and how many of the apps are in: 'installing', 'waiting', 'ready' or
// null. Ready is said only after the install was seen (said), never at a login on a computer that has them all.
export function viewOf({sub, done, total, said}) {
    if (!(total > 0))
        return null;
    if (done >= total)
        return said ? 'ready' : null;
    if (RUNNING.has(sub))
        return 'installing';
    return sub === RETRY ? 'waiting' : null;
}

// Whether there is nothing more to follow this boot: every app in, the unit done (an app its user uninstalled stays out
// for good), or a unit that will not start (the live ISO's, disabled; an image's own, masked)
export function settled({sub, fileState, done, total}) {
    if (!(total > 0) || done >= total || sub === 'exited')
        return true;
    return sub === 'dead' && fileState !== '' && !String(fileState).startsWith('enabled');
}
