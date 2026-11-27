// A systemd manager tells a unit's changes only to a connection that subscribed, and a subscription is the connection's,
// not the caller's. Everyone in the shell who follows a unit takes one here and gives it back, so that the last to leave
// undoes it and none takes it from another. The account's own manager by default; the system's for a system unit, which
// anyone may follow.

import Gio from 'gi://Gio';

const SYSTEMD = 'org.freedesktop.systemd1';

const holders = {session: 0, system: 0};

function manager(bus, method) {
    Gio.DBus[bus].call(SYSTEMD, '/org/freedesktop/systemd1', `${SYSTEMD}.Manager`, method, null, null,
        Gio.DBusCallFlags.NO_AUTO_START, 2000, null, (connection, result) => {
            try {
                connection.call_finish(result);
            } catch {
                // Already subscribed by somebody else, or no manager to ask: nothing is lost
            }
        });
}

// Subscribes if nobody has; returns the function that gives it back. bus: 'session' or 'system'
export function subscribeUnits(bus = 'session') {
    if (holders[bus]++ === 0)
        manager(bus, 'Subscribe');
    let released = false;
    return () => {
        if (released)
            return;
        released = true;
        if (--holders[bus] === 0)
            manager(bus, 'Unsubscribe');
    };
}

// For the checks
export function subscribers(bus = 'session') {
    return holders[bus];
}
