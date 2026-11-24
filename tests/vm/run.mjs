#!/usr/bin/env node
// A test run, in the lab container: builds the image from the commit tests/vm/run.sh sent, installs it onto a
// disk, boots it, and runs the suites in tests/vm/suites in it. Everything it did is in /vm/runs/<when>/
// (/vm/runs/last): run.log, one log per stage and per suite, a screenshot after each suite, the guest's
// journal, results.json, and summary.md, which it prints last.
//
//   node run.mjs [all | build | disk | test | plan | ready] [--keep] [--image IMAGE] [--tag TAG] [--suites NN,NN...]
//                [--skip NN,NN...]
//                [--parallel N [--reuse]] [--memory MB] [--json]
//   node run.mjs report DIR [--expect NAME,...]
//
// all (the default) does the three in turn and stops at the first that fails; the others do one, from what
// the last run left. --keep leaves the VMs running afterwards, for a closer look over MCP. The exit status is
// 0 only when everything that ran passed. VMLAB_NAME (default test) names the run's image tag, disks and VMs,
// so that two sessions' runs do not take each other's. --image builds amethystora-dx, or either with -nvidia-open or
// -nvidia-lts, instead of amethystora; --tag builds that stream (beta, which can be on the next Fedora) instead of
// latest; --suites runs only the suites with those numbers or names (11, 11-dock-screens), and --skip leaves those out
// (the Lab workflow's run of every suite leaves out the long ones, which Lab (long suites) runs a runner each).
//
// --parallel N runs the suites in N VMs at once. VM NAME starts on the disk, runs the suites shards.json calls prep
// (the boot, the first-run setup, the sign-in), waits for the first boot's Flatpaks and powers itself off: that is
// the ready state, which VMs NAME-p1...NAME-pN start from (lab.mjs's vm_start from: an overlay on its overlay,
// nothing copied). The other suites are spread over the N lanes by their minutes in shards.json, longest first onto
// the lane with the least; a suite it does not name counts default_minutes. A lane runs its suites in name order,
// those that come last after the rest, then its installer suites on NAME-installer-pK, a fresh overlay of the
// installer disk; the screens suites are one unit, on NAME-screens, also from the ready state. plan prints the
// lanes and runs nothing. --memory gives every VM but the screens one that much memory (default 4096). --reuse
// starts from the ready state an earlier run made on the same disk, when there is one, instead of making it again.
//
// For the Lab workflow (.github/workflows/lab.yml), which runs each lane on a runner of its own: plan --json prints the
// lanes for its matrix, planned as if the ready state were made before any of them starts; ready makes only the ready
// state, which its build job hands to the lanes; and report DIR [--expect NAME,...] puts every results.json under DIR
// (a folder per job) into one table, counting a suite of --expect that has none as not run.
//
// A suite is a bash script run as root in the guest, beside lib.sh: one "ok - ...", "not ok - ..." or
// "skip - ..." line per check, and exit status 0 only when it passed. Exit status 100 asks for a reboot:
// the suite runs again after it, with SUITE_PHASE one higher. A suite whose second line is
// "# vmlab-vm: installer" runs on a machine of its own installed as the installer lays a disk out, encrypted, and
// "# vmlab-vm: screens" on the first machine's disk with four screens. A suite that leaves its machine of no use to
// the suites after it (90 switches the image and starts over) says "# vmlab-order: last" in its first lines, and runs
// after every other suite of that machine; the others run in the order of their names.
// Exit status 101 runs the next phase in the same boot, for what takes longer than a phase may (30 minutes),
// and with /var/lib/vmlab-tests/usb.json left (usb_next in lib.sh) USB devices plugged in or out first, and with
// /var/lib/vmlab-tests/screen-next left (screen_next) the screen as QEMU shows it in /var/lib/vmlab-tests/screen.png.
// A phase that leaves /var/lib/vmlab-tests/next-boot.json gets a power cycle instead of a reboot, with what it
// asks for (next_boot in lib.sh): spare disks absent or faulty, other credentials, the passphrase typed; or
// with {"itself": true} no restart from here at all, only a wait for the one the phase left to happen, a soft
// reboot included, which keeps the boot id and counts in systemd's SoftRebootsCount.
import { execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { MARGIN_MB, agent, building, call, decode, headroom, qmp, refusal, screendump, serialWrite } from './lab.mjs';

// A path on Windows too, where plan runs as well (with VMLAB_DIR somewhere writable)
const HERE = path.dirname(fileURLToPath(import.meta.url));
const SRC = path.resolve(HERE, '../..');
const SUITES = `${HERE}/suites`;
const NAME = process.env.VMLAB_NAME || 'test';
if (!/^[a-z0-9][a-z0-9-]{0,20}$/.test(NAME)) throw new Error(`VMLAB_NAME must be lowercase letters, digits and - (got ${NAME})`);
const option = (flag) => (process.argv.includes(flag) ? process.argv[process.argv.indexOf(flag) + 1] : undefined);
const BUILD = option('--image') || 'amethystora';
if (!/^amethystora(-dx)?(-nvidia-(open|lts))?$/.test(BUILD)) throw new Error(`run.mjs: no image ${BUILD}`);
const TAG = option('--tag') || 'latest';
if (!/^(latest|beta|stable)$/.test(TAG)) throw new Error(`run.mjs: no stream ${TAG}`);
const ONLY = option('--suites')?.split(',');
const SKIP = option('--skip')?.split(',').filter(Boolean);
// A suite by its number (every suite of it) or by its whole name, with or without .sh
const named = (list, f) => list.some((o) => o === f.slice(0, 2) || o === f || `${o}.sh` === f);
const only = (f) => (!ONLY || named(ONLY, f)) && !(SKIP && named(SKIP, f));
const BUILT = `localhost/${BUILD}:${TAG}`;
// What `just build` tags, kept under the run's own name at once, which the disks are made from
const IMAGE = `localhost/amethystora-run:${NAME}`;
const GUEST_DIR = '/run/amethystora-tests';
const NEXT_BOOT = '/var/lib/vmlab-tests/next-boot.json';
const USB = '/var/lib/vmlab-tests/usb.json';
const SCREEN = '/var/lib/vmlab-tests/screen-next';
const SCREEN_PNG = '/var/lib/vmlab-tests/screen.png';
// The USB devices a phase can have plugged in, on the VM's xHCI controller: sticks with serials of their own, on
// drives that read as zeros, and a keyboard and nothing else. Each has a port of its own (the tablet has 1):
// without one, QEMU puts a hub of its own in front of the second, which USB protection blocks as the new
// device it is.
const USB_DEVICES = {
  stick: { driver: 'usb-storage', serial: 'VMLAB-STICK-1', port: '2' },
  keyboard: { driver: 'usb-kbd', port: '3' },
  stick2: { driver: 'usb-storage', serial: 'VMLAB-STICK-2', port: '4' },
  // An FTDI serial adapter (0403:6001, ttyUSB0 in the guest), its other end nowhere (78-lab-devices.sh)
  // It is a full-speed device, which the controller takes on its first four ports only (5 to 8 are USB 3), so it has the
  // second stick's port: no suite plugs both
  serial: { driver: 'usb-serial', chardev: true, port: '4' },
};
// The lab's disk passphrase, and the PIN a suite enrols the TPM with, both handed to systemd-cryptsetup as
// credentials so that nobody has to type them (next_boot can have one typed instead). The PIN goes under both of
// its names: systemd-cryptsetup first tries every LUKS2 token through libcryptsetup, asking "Please enter LUKS2
// token PIN:" (cryptsetup.luks2-pin), before its own TPM2 path (cryptsetup.tpm2-pin)
const PASSPHRASE = 'amethystora-lab-passphrase';
const TPM_PIN = '246813579';
// Two machines: the one `bootc install to-disk` makes, with blank disks for the pools of disks (50-raid.sh): four
// alike, then a larger one, and one larger than the system's data for its mirror, unplugged until a suite asks
// for it (next_boot), so that the others see five; and one installed as the installer lays a disk out, encrypted,
// with two disks for a pool and two larger than its own for the mirror
const MACHINES = {
  default: { vm: NAME, disk: NAME, make: [], spares: [8, 8, 8, 8, 10, 24], absent: [6], credentials: {} },
  installer: {
    vm: `${NAME}-installer`, disk: `${NAME}-installer`, make: ['40G', `--installer=${PASSPHRASE}`], spares: [8, 8, 48, 48],
    credentials: { 'cryptsetup.passphrase': PASSPHRASE, 'cryptsetup.tpm2-pin': TPM_PIN, 'cryptsetup.luks2-pin': TPM_PIN },
  },
  // The first one's disk again, on a machine with four screens side by side: a workspace on each (tiling/screens.js)
  screens: { vm: `${NAME}-screens`, disk: NAME, make: [], spares: [], absent: [], credentials: {}, screens: 4 },
};
const MAX_PHASES = 16;
const stage = process.argv[2] && !process.argv[2].startsWith('--') ? process.argv[2] : 'all';
const keep = process.argv.includes('--keep');
const PARALLEL = option('--parallel') === undefined ? 0 : Number(option('--parallel'));
if (!Number.isInteger(PARALLEL) || PARALLEL < 0 || PARALLEL > 12) throw new Error('run.mjs: --parallel is 1 to 12');
if (stage === 'plan' && !PARALLEL) throw new Error('run.mjs: plan needs --parallel N');
const JSON_PLAN = process.argv.includes('--json');
const REUSE = process.argv.includes('--reuse');
const MEMORY = option('--memory') === undefined ? undefined : Number(option('--memory'));
if (MEMORY !== undefined && !(Number.isInteger(MEMORY) && MEMORY >= 2048)) throw new Error('run.mjs: --memory is MB, 2048 or more');
if (MEMORY) for (const m of [MACHINES.default, MACHINES.installer]) m.memory = MEMORY;
// The machine a function was given, by its kind or as itself (a lane's)
const machineOf = (machine) => (typeof machine === 'string' ? MACHINES[machine] : machine);
// How a suite's lines start in the log: with the VM's name when several run at once
const lane = (m) => (m.lane ? `[${m.vm}] ` : '   ');

// A plan and a report write nothing: no run folder, and /vm/runs/last left to the run it names
const RUN = ['plan', 'report'].includes(stage) ? '' : `/vm/runs/${new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)}${NAME === 'test' ? '' : `-${NAME}`}`;
if (RUN) {
  fs.mkdirSync(RUN, { recursive: true });
  const LAST = NAME === 'test' ? '/vm/runs/last' : `/vm/runs/last-${NAME}`;
  fs.rmSync(LAST, { force: true });
  fs.symlinkSync(RUN, LAST);
}

const say = (line) => {
  console.log(line);
  if (RUN) fs.appendFileSync(`${RUN}/run.log`, `${line}\n`);
};
const minutes = (began) => `${((Date.now() - began) / 60000).toFixed(1)} min`;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const git = (...args) => execFileSync('git', ['-C', SRC, ...args], { encoding: 'utf8' }).trim();
const stages = [];

// A command, with its output in NAME.log and the end of it said when it fails
function step(name, command, args) {
  return new Promise((resolve) => {
    const began = Date.now();
    say(`== ${name}: ${[command, ...args].join(' ')}`);
    const log = fs.openSync(`${RUN}/${name}.log`, 'w');
    const child = spawn(command, args, { cwd: SRC, stdio: ['ignore', log, log] });
    child.on('close', (code) => {
      const passed = code === 0;
      stages.push({ stage: name, passed, time: minutes(began) });
      if (passed) {
        say(`== ${name}: passed in ${minutes(began)}`);
      } else {
        // Only the log's last 256 KiB: a build's set -x log runs to hundreds of MB, past a string's length
        const fd = fs.openSync(`${RUN}/${name}.log`, 'r');
        const size = fs.fstatSync(fd).size;
        const end = Buffer.alloc(Math.min(size, 256 * 1024));
        fs.readSync(fd, end, 0, end.length, size - end.length);
        fs.closeSync(fd);
        const tail = end.toString('utf8').trimEnd().split('\n').slice(-80).join('\n');
        say(`== ${name}: FAILED (exit ${code}) after ${minutes(began)}. The end of ${RUN}/${name}.log:\n${tail}`);
      }
      resolve(passed);
    });
  });
}

async function build() {
  // Git submodules, if the repository has any again: a bundle carries none of them
  if (!(await step('submodules', 'git', ['-C', SRC, 'submodule', 'update', '--init', '--recursive']))) return false;
  const flavor = BUILD.match(/-(nvidia-(open|lts))$/)?.[1] || 'main';
  if (!(await step('build', 'just', ['build', BUILD.replace(/-nvidia-(open|lts)$/, ''), TAG, flavor]))) return false;
  if (!(await step('tag', 'podman', ['tag', BUILT, IMAGE]))) return false;
  // What earlier builds left, no longer tagged
  await step('prune', 'podman', ['image', 'prune', '-f']);
  return true;
}

// A machine's suites that are there to run, in the order they run: by name, those that come last after the rest
const suiteHead = (f) => fs.readFileSync(`${SUITES}/${f}`, 'utf8').split('\n').slice(0, 3).join('\n');
const comesLast = (f) => /^# vmlab-order: last$/m.test(suiteHead(f));
const suitesOf = (machine) => {
  const names = fs.readdirSync(SUITES)
    .filter((f) => /^\d\d-.+\.sh$/.test(f) && only(f)).sort()
    .filter((f) => (suiteHead(f).match(/^# vmlab-vm: (installer|screens)$/m)?.[1] ?? 'default') === machine);
  return [...names.filter((f) => !comesLast(f)), ...names.filter(comesLast)];
};

async function disk() {
  const made = new Set();
  for (const [kind, m] of Object.entries(MACHINES)) {
    // A machine on another's disk has it made once
    if (!suitesOf(kind).length || made.has(m.disk)) continue;
    if (!(await step(`disk-${kind}`, 'bash', [`${HERE}/make-disk.sh`, IMAGE, m.disk, ...m.make]))) return false;
    made.add(m.disk);
  }
  return true;
}

// The guest's boot id, or nothing while it does not answer
async function bootId(vm) {
  try {
    const answer = await agent(vm, { op: 'read', path: '/proc/sys/kernel/random/boot_id' }, 5);
    return decode(answer.data).trim();
  } catch {
    return '';
  }
}

// How many soft reboots systemd made since the kernel started, which a soft reboot counts and its boot id does
// not show
const softReboots = (vm) => guest(vm, 'systemctl show -P SoftRebootsCount', 10);

async function guest(vm, command, seconds = 20) {
  try {
    return decode((await agent(vm, { op: 'exec', command, timeout: seconds }, seconds)).stdout).trim();
  } catch {
    return '';
  }
}
const sessionExpected = async (vm) => (await guest(vm, 'grep -s "^AutomaticLogin=tester" /etc/gdm/custom.conf')) !== '';
async function session(vm, seconds) {
  for (const until = Date.now() + seconds * 1000; Date.now() < until; await sleep(10000)) {
    if ((await guest(vm, 'loginctl show-user tester -p State --value')) === 'active') return true;
  }
  return false;
}

// START once a VM of SIZE MB may start (lab.mjs's refusal: no build in the lab, its memory free), waiting up to WAIT
// ms for the memory, else an error. One start at a time, the check and the start together, so that the VM one start
// made counts in the next one's sum
const DEFAULT_MB = 4096;
let starting = Promise.resolve();
function admitted(vm, size, startVm, wait = 900000) {
  const turn = starting.then(async () => {
    for (const until = Date.now() + wait; ; await sleep(20000)) {
      const why = refusal(size);
      if (!why) return startVm();
      if (building() || Date.now() > until) throw new Error(`${vm} not started: ${why}`);
    }
  });
  starting = turn.catch(() => {});
  return turn;
}

// A VM of this run started, as a machine is, or with what a suite asked for its next start
async function start(machine, request = {}, fresh = false) {
  const m = machineOf(machine);
  const credentials = { ...m.credentials, ...(request.credentials || {}) };
  if (request.type_passphrase) delete credentials['cryptsetup.passphrase'];
  // A credential asked for as null is left out: {"cryptsetup.passphrase": null} has the TPM open the disk alone
  for (const [key, value] of Object.entries(credentials)) if (value === null) delete credentials[key];
  await admitted(m.vm, m.memory || DEFAULT_MB, () => call('vm_start', { name: m.vm, disk: m.disk, from: m.from, memory_mb: m.memory, fresh,
    spares_gb: m.spares, absent: request.absent || m.absent || [], system_absent: Boolean(request.system_absent), faulty: request.faulty || {},
    credentials, screens: m.screens || 1 }));
  if (request.menu_last) await chooseLastEntry(m.vm);
  if (request.menu_edit) await editEntry(m.vm);
  if (request.type_passphrase) await typePassphrase(m.vm);
}

// The serial console's text, once the boot menu shows on it, before its countdown ends
async function bootMenu(vm) {
  const serial = `/vm/vms/${vm}.serial`;
  const read = () => (fs.existsSync(serial) ? fs.readFileSync(serial, 'latin1') : '');
  const began = Date.now();
  while (!read().includes('will be executed automatically')) {
    if (Date.now() - began > 300000) throw new Error('no boot menu on the serial console within 5 minutes');
    await sleep(300);
  }
  return read;
}

// The default entry opened for editing, as a person would, with e. With a boot menu password GRUB asks for a
// user first, and refuses an empty one ("Press any key to continue"); without one, its editor opens, which
// Escape leaves. Either way the menu is back, and Enter starts the default entry. What GRUB did goes to the
// next phase as VMLAB_MENU_EDIT: asked, editor or nothing.
const menuEdits = new Map();
async function editEntry(vm) {
  const read = await bootMenu(vm);
  const before = read().length;
  await call('vm_keys', { name: vm, keys: ['e'] });
  await sleep(4000);
  const shown = read().slice(before);
  const asked = shown.includes('Enter username:');
  menuEdits.set(vm, asked ? 'asked' : /Ctrl-x|ESC to discard/.test(shown) ? 'editor' : 'nothing');
  await call('vm_keys', { name: vm, keys: ['esc'] });
  await sleep(2000);
  if (asked) {
    await call('vm_keys', { name: vm, keys: ['ret'] });
    await sleep(2000);
  }
  await call('vm_keys', { name: vm, keys: ['ret'] });
}

// The boot menu's last entry chosen, as a person would, with End and Enter, once the menu shows on the serial
// console (GRUB writes there through the firmware) and before its countdown ends: on a system over several
// disks that is "Start with a disk missing" (custom.cfg, after every other entry)
async function chooseLastEntry(vm) {
  await bootMenu(vm);
  await call('vm_keys', { name: vm, keys: ['end', 'ret'] });
}

// The passphrase typed at the prompt, as a person would, once it shows on the serial console: the installer's
// disk starts without Plymouth, with console=ttyS0 last, so systemd asks there. How many times it was asked
// goes to the suite as VMLAB_PROMPTS.
const prompts = new Map();
async function typePassphrase(vm) {
  const serial = `/vm/vms/${vm}.serial`;
  const asked = () => (fs.existsSync(serial) ? fs.readFileSync(serial, 'latin1') : '').match(/[Pp]lease enter passphrase/g)?.length || 0;
  const began = Date.now();
  while (asked() === 0) {
    if (Date.now() - began > 600000) throw new Error('no passphrase prompt on the serial console within 10 minutes');
    await sleep(3000);
  }
  await sleep(2000);
  await serialWrite(vm, `${PASSPHRASE}\r`);
  // Long enough for a second prompt to show if there is one, which is then answered too
  await sleep(45000);
  if (asked() > 1) await serialWrite(vm, `${PASSPHRASE}\r`);
  prompts.set(vm, asked());
}

// Until flatpak-preinstall has ended, an hour at most, said in the log when it had not. A start taken with the first
// boot's Flatpaks half in installs the rest while GNOME starts, and the account's shell then registers so slowly that
// GDM puts its greeter in front: the boot after suite 30's first phase came up with no session in 4 runs of 2026-11.
// The Flatpaks are asked about in short calls: the guest's helper answers one caller at a time
async function flatpaksIn(m, retries = false) {
  // Installing; one waiting to try again (no network: a suite's own doing) installs nothing meanwhile, and only the
  // ready state waits for it, so as not to be kept with apps missing
  const running = retries ? /^(running|start|start-pre|start-post|auto-restart|auto-restart-queued)$/ : /^(running|start|start-pre|start-post)$/;
  const now = await guest(m.vm, 'systemctl show -P SubState flatpak-preinstall.service', 20);
  if (now && !running.test(now)) return;
  const began = Date.now();
  for (const until = Date.now() + 3600000; Date.now() < until; await sleep(15000)) {
    // Its sub-state: it stays active (exited) once done. No answer is no answer, not the end
    const state = await guest(m.vm, 'systemctl show -P SubState flatpak-preinstall.service', 20);
    if (state && !running.test(state)) break;
  }
  say(`${lane(m)}flatpak-preinstall ${await guest(m.vm, 'systemctl show -P ActiveState,SubState flatpak-preinstall.service | paste -sd/', 20)} after ${minutes(began)}; ` +
    `${await guest(m.vm, 'flatpak list --app --columns=application | wc -l', 30)} apps`);
}

async function reboot(machine) {
  const m = machineOf(machine);
  const { vm } = m;
  await flatpaksIn(m);
  // A power cycle, when the phase asked for one
  let request = null;
  try {
    const answer = await agent(vm, { op: 'read', path: NEXT_BOOT }, 10);
    if (answer.rc === 0) request = JSON.parse(decode(answer.data));
  } catch {
    // None asked for
  }
  const before = await bootId(vm);
  const softBefore = await softReboots(vm);
  if (request?.itself) {
    // The phase left something to restart the machine once it ended, as a person would
    await agent(vm, { op: 'exec', command: `rm -f ${NEXT_BOOT}` }, 10);
    say(`${lane(m)}the machine restarts itself`);
  } else if (request?.powers_off) {
    // ...or to power it off: started again once QEMU has ended, as a person presses the power button
    await agent(vm, { op: 'exec', command: `rm -f ${NEXT_BOOT}` }, 10);
    say(`${lane(m)}the machine powers itself off`);
    // USB devices the phase asked to have pulled out (usb_next) go now: the power off is what pulling one does (77-pull-key.sh)
    await usb(vm);
    const off = new RegExp(`^${vm}: stopped`, 'm');
    for (const began = Date.now(); !off.test((await call('vm_list')).content[0].text); await sleep(5000)) {
      if (Date.now() - began > 900000) throw new Error('the VM did not power itself off within 15 minutes');
    }
    await start(machine);
  } else if (request) {
    await agent(vm, { op: 'exec', command: `rm -f ${NEXT_BOOT}` }, 10);
    say(`${lane(m)}power cycle: ${JSON.stringify(request)}`);
    await call('vm_stop', { name: vm });
    await start(machine, request);
  } else {
    await agent(vm, { op: 'exec', command: '(sleep 2; systemctl reboot) >/dev/null 2>&1 &' }, 30);
  }
  // A restart that has not come back within 6 minutes (seen on a loaded lab, never alone) is kept as evidence, the
  // screen and the serial console's tail, then powered off and on once; only a second miss stops the lane
  for (let tries = 0; ; tries++) {
    const began = Date.now();
    let back = false;
    while (Date.now() - began < 360000) {
      await sleep(5000);
      const now = await bootId(vm);
      if (now && (now !== before || (await softReboots(vm)) !== softBefore)) {
        back = true;
        break;
      }
    }
    if (back) break;
    if (tries === 1) throw new Error('the VM did not come back after a reboot, nor after a power cycle');
    say(`${lane(m)}the restart did not come back within 6 minutes: powering the VM off and on again`);
    try {
      fs.writeFileSync(`${RUN}/lost-reboot-${vm}.png`, await screendump(vm));
    } catch {
      // No screen to take
    }
    try {
      fs.copyFileSync(`/vm/vms/${vm}.serial`, `${RUN}/lost-reboot-${vm}.serial`);
    } catch {
      // No console kept
    }
    await call('vm_stop', { name: vm, force: true });
    await start(machine, request ?? {});
  }
  await call('vm_wait', { name: vm, timeout_s: 900 });
  // Once the test account signs in by itself, a boot that brings it no session stalled: now and then PID 1
  // waits on the console for the answer to its size query, which plymouthd, holding the console, never
  // gives (12-amethystora-console.toml skips the query). Powered off and on again, said in the log, twice at
  // most; then the suite cannot run, rather than skip everything as passed.
  for (let tries = 0; await sessionExpected(vm) && !(await session(vm, 240)); tries++) {
    if (tries === 2) throw new Error('the test account got no session after three boots');
    say(`${lane(m)}no session after this boot: powering the VM off and on again`);
    // What PID 1 and plymouthd wait on, which the power cycle loses: the evidence for the stall. The journal is
    // written to disk first (journald keeps it in memory for minutes), so that the next boot's `journalctl -b -1`
    // still has the whole boot; and what GDM, logind and AccountsService said, which is where a session goes missing
    fs.writeFileSync(`${RUN}/stalled-boot-${m.lane ? `${vm}-` : ''}${tries + 1}.txt`, await guest(vm, 'journalctl --sync; ' +
      'cat /proc/1/stack; ' +
      'for p in $(pidof plymouthd); do echo "plymouthd $p $(grep ^State /proc/$p/status)"; cat /proc/$p/stack; done; ' +
      'journalctl -b -o short-monotonic --no-pager _PID=1 | grep -v " audit" | tail -n 15; echo "== sessions"; ' +
      'loginctl list-sessions --no-legend; loginctl show-user tester 2>&1 | grep -E "^(State|Sessions|Display)="; ' +
      'echo "== GDM, logind, AccountsService"; journalctl -b -o short-monotonic --no-pager -u gdm -u systemd-logind ' +
      '-u accounts-daemon | grep -v " audit" | tail -n 40; echo "== the sessions and shells"; journalctl -b -o short-monotonic ' +
      '--no-pager _COMM=gdm-session-wor _COMM=gnome-shell _COMM=gnome-session-s | tail -n 40; ' +
      'echo "== failed and still starting"; systemctl list-units --no-legend --state=failed --state=activating', 60));
    await call('vm_stop', { name: vm, force: true });
    await start(machine, request ? { ...request, type_passphrase: false } : {});
    await call('vm_wait', { name: vm, timeout_s: 900 });
  }
}

// What the VM's screen shows, as QEMU scans it out, handed to the next phase as a PNG, where a phase that ended with 101
// asked (screen_next): for a suite that has to see the real screen, not the shell's idea of it
async function screenNext(vm) {
  const answer = await agent(vm, { op: 'exec', command: `test -e ${SCREEN} && rm -f ${SCREEN}` }, 10).catch(() => null);
  if (answer?.rc !== 0) return;
  const png = await screendump(vm);
  await agent(vm, { op: 'write', path: SCREEN_PNG, data: png.toString('base64'), mode: '0644' }, 30);
  say(`   screen: handed to the next phase`);
}

// USB devices plugged out, then in, as a phase that ended with 101 asked (usb_next), before the next one
let drives = 0;
let chardevs = 0;
async function usb(vm) {
  let request = null;
  try {
    const answer = await agent(vm, { op: 'read', path: USB }, 10);
    if (answer.rc === 0) request = JSON.parse(decode(answer.data));
  } catch {
    // None asked for
  }
  if (!request) return;
  await agent(vm, { op: 'exec', command: `rm -f ${USB}` }, 10);
  for (const name of request.unplug || []) await qmp(vm, 'device_del', { id: `vmlab-${name}` }).catch(() => {});
  if (request.unplug?.length) await sleep(5000);
  for (const name of request.plug || []) {
    const device = USB_DEVICES[name];
    if (!device) throw new Error(`usb_next: no device ${name}`);
    const args = { driver: device.driver, id: `vmlab-${name}`, port: device.port };
    if (device.serial) {
      const node = `vmlab-drive-${++drives}`;
      await qmp(vm, 'blockdev-add', { driver: 'null-co', 'node-name': node, size: 64 * 1024 * 1024, 'read-zeroes': true });
      Object.assign(args, { drive: node, serial: device.serial });
    }
    if (device.chardev) {
      const id = `vmlab-chardev-${++chardevs}`;
      // A ring buffer: QEMU attaches a usb-serial only once its other end is open, which a null one never is
      await qmp(vm, 'chardev-add', { id, backend: { type: 'ringbuf', data: { size: 65536 } } });
      args.chardev = id;
    }
    await qmp(vm, 'device_add', args);
  }
  say(`   usb (${vm}): ${JSON.stringify(request)}`);
}

// The suites and lib.sh into the guest's /run, which a reboot empties
async function install(vm) {
  await agent(vm, { op: 'exec', command: `mkdir -p ${GUEST_DIR}` });
  for (const name of fs.readdirSync(SUITES)) {
    const data = fs.readFileSync(`${SUITES}/${name}`).toString('base64');
    const answer = await agent(vm, { op: 'write', path: `${GUEST_DIR}/${name}`, data, mode: '0755' });
    if (answer.rc !== 0) throw new Error(`could not write ${name} into the VM: ${answer.error}`);
  }
  // The suites' fixtures (72's hostile plugin), beside them as fixtures/
  for (const file of fixtureFiles()) {
    const target = `${GUEST_DIR}/fixtures/${file}`;
    await agent(vm, { op: 'exec', command: `mkdir -p ${path.dirname(target)}` });
    const answer = await agent(vm, { op: 'write', path: target, data: fs.readFileSync(`${FIXTURES}/${file}`).toString('base64'), mode: '0755' });
    if (answer.rc !== 0) throw new Error(`could not write fixtures/${file} into the VM: ${answer.error}`);
  }
}

// Every file under tests/vm/fixtures, by its path there
const FIXTURES = `${HERE}/fixtures`;
const fixtureFiles = (dir = '') => (fs.existsSync(`${FIXTURES}/${dir}`) ? fs.readdirSync(`${FIXTURES}/${dir}`, { withFileTypes: true })
  .flatMap((e) => (e.isDirectory() ? fixtureFiles(path.join(dir, e.name)) : [path.join(dir, e.name)])) : []);

// The live captions' speech model (suite 67), when the lab keeps a copy: handed to the guest once, in pieces the agent
// takes, so that a run neither downloads 39 MiB each time nor fails offline
const CAPTIONS_ZIP = '/vm/cache/vosk-model-small-en-us-0.15.zip';
const captionsGiven = new Set();
async function giveCaptionsModel(vm) {
  if (captionsGiven.has(vm) || !fs.existsSync(CAPTIONS_ZIP)) return;
  const data = fs.readFileSync(CAPTIONS_ZIP);
  const piece = 3 << 20;
  for (let at = 0, n = 0; at < data.length; at += piece, n++) {
    const path = `/var/tmp/vmlab-captions.zip.${String(n).padStart(3, '0')}`;
    const answer = await agent(vm, { op: 'write', path, data: data.subarray(at, at + piece).toString('base64'), mode: '0644' });
    if (answer.rc !== 0) throw new Error(`could not write ${path} into the VM: ${answer.error}`);
  }
  await agent(vm, { op: 'exec', command: 'cat /var/tmp/vmlab-captions.zip.* >/var/tmp/vmlab-captions.zip && rm -f /var/tmp/vmlab-captions.zip.*' });
  captionsGiven.add(vm);
}

// tests/vm/known-failures: a line "SUITE :: the start of a check's words", for a check that fails on every machine the lab runs
// on (a pointer or a drawing that depends on the hardware) until a person has looked at it on one. Reported, never silent
const KNOWN = fs.existsSync(`${HERE}/known-failures`)
  ? fs.readFileSync(`${HERE}/known-failures`, 'utf8').split('\n').map((l) => l.replace(/\r$/, '')).filter((l) => l.trim() && !l.startsWith('#'))
    .map((l) => l.split(' :: ')).filter((p) => p.length === 2).map(([s, t]) => [s.trim(), t.trim()])
  : [];
const isKnown = (suiteName, line) => KNOWN.some(([s, t]) => suiteName === s && line.replace(/^not ok - /, '').startsWith(t));

async function suite(machine, name) {
  const m = machineOf(machine);
  const { vm } = m;
  const began = Date.now();
  let output = '';
  let rc = 0;
  if (name.startsWith('67-')) await giveCaptionsModel(vm);
  for (let phase = 1; ; phase++) {
    await install(vm);
    const env = `SUITE_PHASE=${phase} VMLAB_PASSPHRASE=${PASSPHRASE} VMLAB_TPM_PIN=${TPM_PIN} VMLAB_PROMPTS=${prompts.get(vm) ?? ''}` +
      ` VMLAB_MENU_EDIT=${menuEdits.get(vm) ?? ''} VMLAB_RECORD_ONLY=${process.env.VMLAB_RECORD_ONLY ?? ''}`;
    prompts.delete(vm);
    menuEdits.delete(vm);
    const answer = await agent(vm, { op: 'exec', command: `${env} bash ${GUEST_DIR}/${name}`, timeout: 1800 }, 1800);
    output += decode(answer.stdout);
    const stderr = decode(answer.stderr);
    fs.appendFileSync(`${RUN}/${name}.log`, `--- phase ${phase}, exit ${answer.rc}${answer.error ? ` (${answer.error})` : ''}\n${decode(answer.stdout)}${stderr ? `--- stderr\n${stderr}` : ''}`);
    rc = answer.rc;
    if ((rc !== 100 && rc !== 101) || phase >= MAX_PHASES) break;
    // 101: the next phase in the same boot, for what takes longer than one phase may, or after USB devices
    if (rc === 101) {
      await usb(vm);
      await screenNext(vm);
      continue;
    }
    say(`${lane(m)}${name}: rebooting for phase ${phase + 1}`);
    await reboot(machine);
  }
  try {
    fs.writeFileSync(`${RUN}/${name}.png`, await screendump(vm));
  } catch {
    // No screen to take
  }
  const lines = output.split('\n');
  const failures = [];
  const known = [];
  lines.forEach((line, i) => {
    if (!line.startsWith('not ok')) return;
    // A failure with the indented lines that explain it
    const detail = [];
    for (let j = i + 1; j < lines.length && lines[j].startsWith('  '); j++) detail.push(lines[j]);
    // One that tests/vm/known-failures names is reported and does not fail the suite
    (isKnown(name, line) ? known : failures).push([line, ...detail].join('\n'));
  });
  const result = {
    suite: name,
    // A suite ends with status 1 when a check failed: it passes when every check that failed is a known one
    passed: (rc === 0 && failures.length === 0) || (rc === 1 && failures.length === 0 && known.length > 0),
    known,
    exit: rc,
    ok: lines.filter((l) => l.startsWith('ok')).length,
    skipped: lines.filter((l) => l.startsWith('skip')).length,
    failures,
    time: minutes(began),
    vm,
  };
  say(`${lane(m)}${name}: ${result.passed ? 'passed' : 'FAILED'} (${result.ok} ok, ${failures.length} not ok, ${result.skipped} skipped, exit ${rc}, ${result.time})`);
  return result;
}

const couldNot = (name, m, why) => ({ suite: name, passed: false, exit: -1, ok: 0, skipped: 0, failures: [`not ok - the suite could not run: ${why}`], time: '-', vm: m.vm });

// One machine started fresh and NAMES run on it in turn, then its journal kept as JOURNAL.log. With ready, the
// machine powers itself off afterwards and is left as it is, for VMs to start from (--parallel).
async function onMachine(m, names, results, journal, ready = false) {
  const { vm } = m;
  say(`== test: ${IMAGE} on ${m.from ? `VM ${m.from}` : `disk ${m.disk}`}, VM ${vm}: ${names.join(' ')}`);
  try {
    await call('vm_stop', { name: vm, force: true });
  } catch {
    // Not running
  }
  try {
    await start(m, {}, true);
    say(`${lane(m)}${(await call('vm_wait', { name: vm, timeout_s: 900 })).content[0].text}`);
  } catch (error) {
    say(`${lane(m)}${vm} did not start: ${error.message}`);
    for (const name of names) results.push(couldNot(name, m, `${vm} did not start: ${error.message}`));
    return false;
  }
  for (const name of names) {
    try {
      results.push(await suite(m, name));
    } catch (error) {
      results.push(couldNot(name, m, error.message));
      say(`${lane(m)}${name}: could not run: ${error.message}`);
    }
  }
  try {
    const answer = await agent(vm, { op: 'exec', command: 'journalctl -b -p warning --no-pager -o short-monotonic; echo; systemctl --failed --no-pager', timeout: 120 }, 120);
    fs.writeFileSync(`${RUN}/${journal}.log`, decode(answer.stdout));
  } catch {
    // The guest no longer answers: the suites' logs say why
  }
  if (ready) return readyState(m);
  // A lane's VM is stopped even with --keep, which then only keeps it: the next one in the lane needs its memory
  if (!keep || m.lane) await call('vm_stop', { name: vm }).catch(() => {});
  return true;
}

async function test() {
  if (PARALLEL) return testParallel();
  const began = Date.now();
  const results = [];
  for (const machine of Object.keys(MACHINES)) {
    const names = suitesOf(machine);
    if (names.length) await onMachine(MACHINES[machine], names, results, `journal${machine === 'default' ? '' : `-${machine}`}`);
  }
  fs.writeFileSync(`${RUN}/results.json`, `${JSON.stringify(results, null, 2)}\n`);
  const passed = results.every((r) => r.passed);
  stages.push({ stage: 'test', passed, time: minutes(began), results });
  return passed;
}

// --- Several VMs at once (--parallel) -------------------------------------------------------------------------

const SHARDS = JSON.parse(fs.readFileSync(`${HERE}/shards.json`, 'utf8'));
const kindOf = (f) => suiteHead(f).match(/^# vmlab-vm: (installer|screens)$/m)?.[1] ?? 'default';
const cost = (f) => SHARDS.minutes[f] ?? SHARDS.default_minutes;
const inOrder = (names) => [...names].sort().filter((f) => !comesLast(f)).concat([...names].sort().filter(comesLast));

// The suites the ready state is made with, in the order they run
const prepSuites = () => fs.readdirSync(SUITES).filter((f) => SHARDS.prep.includes(f) && kindOf(f) === 'default').sort();

// The lanes: the prep suites first, on VM NAME, then every other suite, as units (one suite, or every screens suite
// together), longest first onto the lane that would end soonest. The installer's suites need no ready state, so
// they are placed first and run while the prep VM gets it ready; nothing else starts before the prep has ended.
// With prepElsewhere (the Lab workflow) the ready state is made before every lane, so that no lane waits for it.
function planLanes(n, prepElsewhere = false) {
  const all = fs.readdirSync(SUITES).filter((f) => /^\d\d-.+\.sh$/.test(f)).sort();
  const wanted = only;
  const units = all.filter((f) => wanted(f) && kindOf(f) !== 'screens' && !SHARDS.prep.includes(f))
    .map((f) => ({ kind: kindOf(f), suites: [f], minutes: cost(f) }));
  const screens = all.filter((f) => wanted(f) && kindOf(f) === 'screens');
  if (screens.length) units.push({ kind: 'screens', suites: screens, minutes: screens.reduce((t, f) => t + cost(f), 0) });
  const needsReady = units.some((u) => u.kind !== 'installer') || all.some((f) => wanted(f) && SHARDS.prep.includes(f));
  const prep = needsReady ? prepSuites() : [];
  const prepMinutes = needsReady && !prepElsewhere && !(REUSE && reusable()) ? SHARDS.prep_minutes : 0;
  const lanes = Array.from({ length: n }, (_, i) => ({ lane: i + 1, minutes: i === 0 ? prepMinutes : 0, kinds: new Set(), units: [] }));
  const place = (list) => {
    for (const u of list.sort((a, b) => b.minutes - a.minutes || a.suites[0].localeCompare(b.suites[0]))) {
      const end = (l) => l.minutes + u.minutes + (l.kinds.has(u.kind) ? 0 : SHARDS.boot_minutes);
      const best = lanes.reduce((a, b) => (end(b) < end(a) ? b : a));
      best.minutes = end(best);
      best.kinds.add(u.kind);
      best.units.push(u);
    }
  };
  place(units.filter((u) => u.kind === 'installer'));
  if (needsReady) for (const l of lanes) l.minutes = Math.max(l.minutes, prepMinutes);
  place(units.filter((u) => u.kind !== 'installer'));
  return {
    prep,
    prepMinutes,
    lanes: lanes.map((l) => {
      const of = (kind) => inOrder(l.units.filter((u) => u.kind === kind).flatMap((u) => u.suites));
      return { lane: l.lane, minutes: Math.round(l.minutes), installer: of('installer'), default: of('default'), screens: of('screens') };
    }),
  };
}

function printPlan(p) {
  say(`Plan for --parallel ${PARALLEL}, by the minutes in shards.json:`);
  if (p.prep.length) say(`  prep (${NAME}, about ${p.prepMinutes} min with the first boot's Flatpaks): ${p.prep.join(' ')}`);
  for (const l of p.lanes) {
    const parts = [['installer', l.installer], ['', l.default], ['screens', l.screens]].filter(([, s]) => s.length)
      .map(([what, s]) => `${what ? `${what}: ` : ''}${s.join(' ')}`);
    say(`  lane ${l.lane} (about ${l.minutes} min): ${parts.join(' | ') || '(nothing)'}`);
  }
}

// The Lab workflow's plan: whether its build job makes the ready state, the lanes that have suites (the matrix of its
// lane jobs: which disks each needs, and its suites, which it runs with test --parallel 1 --reuse --suites), and every
// suite it runs, for the report
function planJson(p) {
  const lanes = p.lanes.map((l) => ({ lane: l.lane, minutes: l.minutes, suites: [...l.installer, ...l.default, ...l.screens].join(','),
    installer: l.installer.length > 0, ready: l.default.length + l.screens.length > 0 })).filter((l) => l.suites);
  const suites = [...p.prep, ...lanes.flatMap((l) => l.suites.split(','))];
  return { ready: p.prep.length > 0, installer: lanes.some((l) => l.installer), lanes, suites: suites.join(',') };
}

// The prep VM, its suites run, kept as the ready state: once the first boot's Flatpaks are in (taken half done,
// every start installs them again, and the account's shell then starts so slowly that GDM locks the session), and
// powered off from inside (the power button has GNOME lock the session, and a start from it came up locked). The
// Flatpaks are asked about in short calls: the guest's helper answers one caller at a time.
async function readyState(m) {
  say(`${lane(m)}waiting for the first boot's Flatpaks (flatpak-preinstall) before keeping the ready state`);
  await flatpaksIn(m, true);
  await agent(m.vm, { op: 'exec', command: '(sleep 1; systemctl poweroff) >/dev/null 2>&1 &' }, 30).catch(() => {});
  const off = new RegExp(`^${m.vm}: stopped`, 'm');
  for (const until = Date.now() + 300000; !off.test((await call('vm_list')).content[0].text); await sleep(2000)) {
    if (Date.now() > until) {
      await call('vm_stop', { name: m.vm, force: true });
      break;
    }
  }
  // Marked with the disk it was made on, for --reuse
  fs.writeFileSync(READY, diskDigest());
  say(`${lane(m)}ready state kept: VM ${m.vm}, stopped`);
  return true;
}
const READY = `/vm/vms/${NAME}.ready`;
const diskDigest = () => (fs.existsSync(`/vm/disks/${NAME}.digest`) ? fs.readFileSync(`/vm/disks/${NAME}.digest`, 'utf8').trim() : '?');
const reusable = () => fs.existsSync(READY) && fs.readFileSync(READY, 'utf8') === diskDigest() && fs.existsSync(`/vm/vms/${NAME}.qcow2`);

async function testParallel() {
  const began = Date.now();
  const plan = planLanes(PARALLEL);
  printPlan(plan);
  // N VMs have to fit before the first starts (each start is checked again, start() and admitted())
  const size = MACHINES.default.memory || DEFAULT_MB;
  const refuse = building() ? `an image is being built in the lab (${building()})` :
    headroom() < PARALLEL * size ? `--parallel ${PARALLEL} wants ${PARALLEL * size} MB for its VMs, and ${Math.max(headroom(), 0)} MB ` +
      `are free beyond a ${MARGIN_MB} MB margin: ${Math.max(Math.floor(headroom() / size), 0)} VM(s) of ${size} MB fit now` : '';
  if (refuse) {
    say(`== test: not started: ${refuse}`);
    stages.push({ stage: 'test', passed: false, time: minutes(began), results: [] });
    return false;
  }
  // VMs an earlier run left running on the ready state, which a new one would be made under
  for (let k = 1; k <= 12; k++) {
    for (const vm of [`${NAME}-p${k}`, `${NAME}-installer-p${k}`]) await call('vm_stop', { name: vm, force: true }).catch(() => {});
  }
  await call('vm_stop', { name: MACHINES.screens.vm, force: true }).catch(() => {});
  const results = [];
  const vms = [];
  const prepMachine = { ...MACHINES.default, lane: 0 };
  let prepared = Promise.resolve(true);
  const laneTimes = [];
  const runLane = async (l) => {
    const t = Date.now();
    // Lane 1 makes the ready state first, which the others wait for once their installer suites are done
    if (l.lane === 1 && plan.prep.length && REUSE && reusable()) {
      say(`== test: the ready state of an earlier run, VM ${NAME} (--reuse): no prep suites`);
    } else if (l.lane === 1 && plan.prep.length) {
      fs.rmSync(READY, { force: true });
      prepared = onMachine(prepMachine, plan.prep, results, 'journal-prep', true)
        .then((started) => started && results.find((r) => r.suite === SHARDS.prep.at(-1))?.passed !== false);
      await prepared;
    }
    if (l.installer.length) {
      const m = { ...MACHINES.installer, vm: `${NAME}-installer-p${l.lane}`, lane: l.lane };
      vms.push(m.vm);
      await onMachine(m, l.installer, results, `journal-installer-p${l.lane}`);
    }
    const ready = await prepared;
    for (const [kind, names] of [['default', l.default], ['screens', l.screens]]) {
      if (!names.length) continue;
      const m = kind === 'default' ? { ...MACHINES.default, vm: `${NAME}-p${l.lane}`, from: NAME, lane: l.lane }
        : { ...MACHINES.screens, from: NAME, lane: l.lane };
      vms.push(m.vm);
      if (!ready) {
        for (const name of names) results.push(couldNot(name, m, `the ready state was not made (${SHARDS.prep.at(-1)})`));
        continue;
      }
      await onMachine(m, names, results, `journal-${m.vm.slice(NAME.length + 1)}`);
    }
    laneTimes.push({ lane: l.lane, time: minutes(t), suites: [...l.installer, ...l.default, ...l.screens].length });
    say(`== lane ${l.lane}: done in ${minutes(t)}`);
  };
  // Lane 1 first: it sets prepared before its first await, which the others then wait on
  await Promise.all(plan.lanes.map(runLane));
  if (!keep) {
    for (const vm of vms) {
      await call('vm_stop', { name: vm, force: true }).catch(() => {});
      await call('vm_delete', { name: vm }).catch(() => {});
    }
  }
  // In the order a run on one VM has them
  const order = Object.keys(MACHINES).flatMap((k) => suitesOf(k));
  const rank = (r) => (order.includes(r.suite) ? order.indexOf(r.suite) : -1);
  results.sort((a, b) => rank(a) - rank(b));
  fs.writeFileSync(`${RUN}/results.json`, `${JSON.stringify(results, null, 2)}\n`);
  const passed = results.every((r) => r.passed);
  stages.push({ stage: 'test', passed, time: minutes(began), results, lanes: laneTimes.sort((a, b) => a.lane - b.lane) });
  return passed;
}

// The ready state alone, as --parallel makes it, for VMs on other machines to start from (the Lab workflow's build
// job): the prep suites on VM NAME, the first boot's Flatpaks in, powered off. Kept only when every prep suite passed.
async function ready() {
  const began = Date.now();
  const results = [];
  fs.rmSync(READY, { force: true });
  const made = await onMachine({ ...MACHINES.default, lane: 0 }, prepSuites(), results, 'journal-prep', true);
  fs.writeFileSync(`${RUN}/results.json`, `${JSON.stringify(results, null, 2)}\n`);
  const passed = made && results.every((r) => r.passed);
  if (!passed) fs.rmSync(READY, { force: true });
  stages.push({ stage: 'ready', passed, time: minutes(began), results });
  return passed;
}

// The suites' results as a table, with the VM each ran on when vm, then every failure with its reasons
function table(results, vm) {
  const head = ['Suite', 'Result', 'ok', 'not ok', 'skipped', 'Time', ...(vm ? ['VM'] : [])];
  const lines = ['', `| ${head.join(' | ')} |`, `|${' --- |'.repeat(head.length)}`];
  for (const r of results) {
    lines.push(`| ${[r.suite, r.passed ? (r.known?.length ? `passed (${r.known.length} known)` : 'passed') : '**failed**', r.ok, r.failures.length, r.skipped, r.time, ...(vm ? [r.vm] : [])].join(' | ')} |`);
  }
  for (const r of results.filter((x) => x.known?.length)) {
    lines.push('', `## ${r.suite}: known failures (tests/vm/known-failures)`, '', '```', ...r.known, '```');
  }
  for (const r of results.filter((x) => !x.passed)) {
    lines.push('', `## ${r.suite} (exit ${r.exit})`, '', '```', ...(r.failures.length ? r.failures : ['(no "not ok" line: see its log)']), '```');
  }
  return lines;
}

// The Lab workflow's results, one folder per job under DIR, as one table: the job's folder names the VM. True only when
// there are results and every suite passed, a suite of --expect without one counting as failed
function report(dir) {
  const results = [];
  const walk = (folder, job) => {
    for (const entry of fs.readdirSync(folder, { withFileTypes: true })) {
      const where = path.join(folder, entry.name);
      if (entry.isDirectory()) walk(where, job ?? entry.name);
      else if (entry.name === 'results.json') results.push(...JSON.parse(fs.readFileSync(where, 'utf8')).map((r) => ({ ...r, vm: `${job}: ${r.vm}` })));
    }
  };
  if (fs.existsSync(dir)) walk(dir);
  for (const name of (option('--expect') || '').split(',').filter((s) => s && !results.some((r) => r.suite === s))) {
    results.push(couldNot(name, { vm: '-' }, 'no result: its job did not finish'));
  }
  results.sort((a, b) => a.suite.localeCompare(b.suite));
  const failed = results.filter((r) => !r.passed).length;
  console.log([`# Lab: ${results.length - failed} of ${results.length} suites passed`, ...table(results, true)].join('\n'));
  return results.length > 0 && failed === 0;
}

function summary() {
  const lines = [`# Test run ${path.basename(RUN)}`, '', `Commit: ${git('log', '-1', '--format=%h %s')}`, ''];
  for (const s of stages) {
    if (s.stage === 'prune' || s.stage === 'tag') continue;
    lines.push(`- ${s.stage}: ${s.passed ? 'passed' : '**FAILED**'} (${s.time})`);
  }
  const tested = stages.find((s) => s.results);
  if (tested) {
    for (const l of tested.lanes || []) lines.push(`- lane ${l.lane}: ${l.time}, ${l.suites} suites`);
    lines.push(...table(tested.results, Boolean(tested.lanes)));
  }
  lines.push('', `Files: ${RUN}`);
  const text = `${lines.join('\n')}\n`;
  fs.writeFileSync(`${RUN}/summary.md`, text);
  console.log(`\n${text}`);
}

if (stage === 'plan') {
  if (JSON_PLAN) console.log(JSON.stringify(planJson(planLanes(PARALLEL, true))));
  else printPlan(planLanes(PARALLEL));
  process.exit(0);
}
if (stage === 'report') process.exit(report(process.argv[3] || '.') ? 0 : 1);
// The lab's own files from the commit under test, so that the MCP server is the one this run used
for (const name of ['agent.py', 'lab.mjs', 'make-disk.sh', 'server.mjs']) {
  fs.copyFileSync(`${HERE}/${name}`, `/opt/amethystora-vm/${name}`);
}
say(`Test run of ${git('log', '-1', '--format=%h %s')}: ${stage}${NAME === 'test' ? '' : ` (${NAME})`}`);
let ok = true;
if (stage === 'all' || stage === 'build') ok = await build();
if (ok && (stage === 'all' || stage === 'disk')) ok = await disk();
if (ok && (stage === 'all' || stage === 'test')) ok = await test();
if (stage === 'ready') ok = await ready();
summary();
process.exit(ok ? 0 : 1);
