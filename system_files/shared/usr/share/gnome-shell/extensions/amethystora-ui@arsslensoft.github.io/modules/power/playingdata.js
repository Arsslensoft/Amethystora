// While you play: what to hold and what to say, as sums with nothing of the shell in them, so that
// build_files/shared/test-pill-logic.mjs runs them under node. power/playing.js does the holding.

// The account's own timed backup and containers' upgrade wait this long at most (s), whatever GameMode still says:
// /usr/libexec/amethystora-metered counts it from the mark's own time, so that a game that never unregisters cannot
// stop them for good
export const CAP_SECONDS = 6 * 3600;

// What GameMode's client count means for each thing held. `letRun` is the person's Let them run: all of it is back
// until the count has gone to zero once.
export function plan({count, onBattery, letRun = false, declined = false}) {
    const playing = Number.isInteger(count) && count > 0 && !letRun;
    return {
        playing,
        banners: playing,
        waits: playing,
        // The performance mode only on mains, never on the battery, and not again once the person changed the mode by hand
        performance: playing && onBattery === false && !declined,
    };
}

// The ids of the lines the card shows, from what is held now ({banners, performance, waits}) and whether the machine is
// on its battery: only what is true is said
export function lines({banners, performance, waits, onBattery}) {
    const list = [];
    if (banners)
        list.push('banners');
    if (performance)
        list.push('performance');
    else if (onBattery)
        list.push('battery');
    if (waits)
        list.push('waits');
    return list;
}

// Whether a mark that started at `since` (seconds) still holds the account's runs at `now`
export function underCap(since, now) {
    return Number.isFinite(since) && Number.isFinite(now) && now - since < CAP_SECONDS;
}

// A queue that runs one job at a time, in the order they came, whatever each takes and even when one fails: the helper's `on`
// and `off` are two processes, and `off` finishing before the `on` that came first would leave a mark with nobody to take it
// away. `job` returns a promise (or a value); the answer is that job's own.
export function makeQueue() {
    let tail = Promise.resolve();
    return job => {
        const run = tail.then(job);
        tail = run.catch(() => {});
        return run;
    };
}
