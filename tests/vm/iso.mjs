// The lab's half of iso.sh: an ISO of a build installed as a person installs it, and the machine it made started and
// looked at. Everything runs in the lab container, beside the other VMs, with the lab's helper reaching each system as a
// systemd credential (lab.mjs), the installer's and the live session's too.
//
//   node iso.mjs installer ISO [--digest sha256:...]   the installer ISO (<image>-non-uefi.iso, bootc-image-builder's)
//   node iso.mjs live ISO [--digest sha256:...]        the live ISO (<image>.iso, Titanoboa's)
//
// 1. The ISO is started by the firmware, Secure Boot on with Microsoft's keys, from its own boot menu's first entry: its
//    shim, GRUB, kernel and system start, and are looked at (the installer's, or the live session).
// 2. It installs onto a blank 40 GiB disk with only the answers a person gives Anaconda (the disk, all of it,
//    encrypted, and the keyboard and language): the installer ISO with its own kernel started with its entry's arguments
//    and a kickstart of those answers that runs the ISO's own kickstart, the live ISO from the live session, with
//    Anaconda on the kickstart its installer uses (interactive-defaults.ks) and the same answers.
// 3. The disk alone is started under Secure Boot, the passphrase handed to systemd-cryptsetup as a credential, and
//    looked at: the signed origin, the layout, SELinux, the firewall, the first boot's setup, GNOME Initial Setup; then
//    once more after a restart.
//
// Writes TAP-style lines (ok, not ok with indented lines saying why, skip) to stdout and DIR/results.tap, a screenshot
// after each step, and exits 0 only when every line is ok. --digest is the image the ISO was built from, which the
// installed machine must run.
import { execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';

import { agent, credentials, decode, screendump } from './lab.mjs';

const ROOT = process.env.VMLAB_DIR || '/vm';
const VMS = `${ROOT}/vms`;
const OVMF = '/usr/share/edk2/ovmf';
const PASSPHRASE = 'amethystora-lab-passphrase';
// What the installed machine follows: @IMAGE@:stable in iso.toml, BASE_IMAGE in installer.ks
const FOLLOWS = process.env.ISO_IMAGE_REF || 'ghcr.io/arsslensoft/amethystora:stable';
const option = (flag) => (process.argv.includes(flag) ? process.argv[process.argv.indexOf(flag) + 1] : undefined);
const [kind, iso] = process.argv.slice(2);
const DIGEST = option('--digest');
if (!['installer', 'live'].includes(kind) || !iso || !fs.existsSync(iso)) throw new Error('iso.mjs installer|live ISO [--digest D]');
if (DIGEST && !/^sha256:[0-9a-f]{64}$/.test(DIGEST)) throw new Error(`iso.mjs: no digest ${DIGEST}`);
const NAME = `iso-${kind}`;
const DIR = `${ROOT}/iso/${kind}`;
const file = (ext) => `${VMS}/${NAME}.${ext}`;
const DISK = file('qcow2');
const VARS = file('vars.json');
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const began = Date.now();
fs.rmSync(DIR, { recursive: true, force: true });
fs.mkdirSync(DIR, { recursive: true });
fs.mkdirSync(VMS, { recursive: true });
const tap = fs.openSync(`${DIR}/results.tap`, 'w');
const out = (line) => {
  console.log(line);
  fs.writeSync(tap, `${line}\n`);
};
const note = (line) => out(`# [${((Date.now() - began) / 60000).toFixed(1).padStart(5)} min] ${line}`);
let failed = 0;
const say = (ok, what, why = '') => {
  out(`${ok ? 'ok' : 'not ok'} - ${what}`);
  if (!ok) {
    failed++;
    if (String(why).trim()) out(`  ${String(why).trim().split('\n').slice(-40).join('\n  ')}`);
  }
  return ok;
};
const skip = (what) => out(`skip - ${what}`);

// --- What the ISO carries ----------------------------------------------------------------------------------------------
const work = `${DIR}/iso`;
fs.mkdirSync(work, { recursive: true });
const extract = (inside, to) => {
  try {
    execFileSync('xorriso', ['-osirrox', 'on', '-indev', iso, '-extract', inside, to], { stdio: 'ignore' });
    return fs.existsSync(to);
  } catch {
    return false;
  }
};
// The first boot menu entry that starts a system (bootc-image-builder's EFI menu, or Titanoboa's)
let entry = null;
for (const cfg of ['/EFI/BOOT/grub.cfg', '/boot/grub2/grub.cfg']) {
  const local = `${work}/${cfg.replaceAll('/', '_')}`;
  if (!extract(cfg, local)) continue;
  const lines = fs.readFileSync(local, 'utf8').split('\n');
  for (let i = 0; i < lines.length && !entry; i++) {
    if (!/^\s*menuentry /.test(lines[i])) continue;
    const linux = lines.slice(i + 1).find((l) => /^\s*linux(efi)?\s/.test(l));
    const initrd = lines.slice(i + 1).find((l) => /^\s*initrd(efi)?\s/.test(l));
    if (!linux || !initrd || /check|basic graphics|without touching|rescue/i.test(lines[i])) continue;
    const [, kernel, ...args] = linux.trim().split(/\s+/);
    entry = { name: lines[i].trim(), kernel, initrd: initrd.trim().split(/\s+/)[1], args };
  }
  if (entry) break;
}
if (!say(entry !== null, 'the ISO has a boot menu entry that starts the system', 'no menuentry with a linux and an initrd line')) process.exit(1);
note(`boot entry: ${entry.name}: ${entry.kernel} ${entry.args.join(' ')}`);

// --- The machine ---------------------------------------------------------------------------------------------------------
const alive = () => {
  try {
    return !/^\d+ \(.*\) Z/.test(fs.readFileSync(`/proc/${Number(fs.readFileSync(file('pid'), 'utf8'))}/stat`, 'utf8'));
  } catch {
    return false;
  }
};
function stop() {
  if (!alive()) return;
  try {
    process.kill(Number(fs.readFileSync(file('pid'), 'utf8')));
  } catch {
    // Gone already
  }
}
// QEMU as the lab starts it (lab.mjs's vm_start): UEFI with its variables in QEMU, Secure Boot by those variables
async function start({ cdrom = false, kernel, extra = [], creds = {}, memory = 8192 }) {
  stop();
  for (const ext of ['pid', 'agent', 'qmp', 'console']) fs.rmSync(file(ext), { force: true });
  const args = ['-name', NAME, '-enable-kvm', '-machine', 'q35,smm=off', '-cpu', 'host', '-smp', '4', '-m', String(memory),
    '-global', 'ICH9-LPC.disable_s3=1', '-bios', `${OVMF}/OVMF.qemuvars.fd`, '-device', `uefi-vars-x64,jsonfile=${VARS}`,
    '-drive', `file=${DISK},if=none,id=disk,format=qcow2,discard=unmap`, '-device', 'virtio-blk-pci,drive=disk,bootindex=1',
    ...(cdrom ? ['-drive', `file=${iso},media=cdrom,if=none,id=cd,readonly=on,format=raw`, '-device', 'ide-cd,drive=cd,bus=ide.0,bootindex=0'] : []),
    ...(kernel ? ['-kernel', kernel.kernel, '-initrd', kernel.initrd, '-append', kernel.append] : []),
    ...extra,
    '-netdev', 'user,id=n0', '-device', 'virtio-net-pci,netdev=n0',
    '-device', 'virtio-serial-pci', '-chardev', `socket,id=lab,path=${file('agent')},server=on,wait=off`,
    '-device', 'virtserialport,chardev=lab,name=org.amethystora.vmtest',
    '-device', 'VGA,id=vga1,xres=1280,yres=800', '-device', 'qemu-xhci', '-device', 'usb-tablet', '-display', 'none',
    '-chardev', `socket,id=con,path=${file('console')},server=on,wait=off,logfile=${file('serial')},logappend=on`, '-serial', 'chardev:con',
    '-qmp', `unix:${file('qmp')},server=on,wait=off`, '-pidfile', file('pid'), ...credentials(creds)];
  const log = fs.openSync(file('log'), 'a');
  const qemu = spawn('qemu-system-x86_64', args, { detached: true, stdio: ['ignore', log, log] });
  qemu.unref();
  for (let i = 0; i < 50 && !alive(); i++) await sleep(200);
  if (!alive()) throw new Error(`QEMU did not start: ${fs.readFileSync(file('log'), 'utf8').trim().split('\n').slice(-10).join('\n')}`);
}
const sh = async (command, timeout = 120) => {
  const a = await agent(NAME, { op: 'exec', command, timeout }, timeout);
  return { rc: a.rc, out: decode(a.stdout), err: `${decode(a.stderr)}${a.error || ''}` };
};
const yes = async (command, timeout) => (await sh(command, timeout)).rc === 0;
const value = async (command, timeout) => (await sh(command, timeout)).out.trim();
async function write(target, text) {
  const a = await agent(NAME, { op: 'write', path: target, data: Buffer.from(text).toString('base64'), mode: '0644' });
  if (a.rc !== 0) throw new Error(`writing ${target}: ${a.error}`);
}
// Until the helper answers: the firmware, the boot menu's timeout and, under nested virtualization, a slow first start
async function answers(minutes) {
  for (const until = Date.now() + minutes * 60000; Date.now() < until; await sleep(5000)) {
    if (!alive()) return 'stopped';
    try {
      await agent(NAME, { op: 'ping' }, 5);
      return 'answers';
    } catch {
      // Not yet
    }
  }
  return 'silent';
}
async function shot(step) {
  try {
    fs.writeFileSync(`${DIR}/${step}.png`, await screendump(NAME));
  } catch {
    // No screen to take
  }
}
const serialTail = () => {
  try {
    return fs.readFileSync(file('serial'), 'utf8').replace(/\x1b\[[0-9;?]*[A-Za-z]/g, '').split('\n').slice(-40).join('\n');
  } catch {
    return '(no serial console)';
  }
};
async function poweroff(minutes = 3) {
  await sh('systemctl poweroff', 20).catch(() => {});
  for (let i = 0; i < minutes * 60 && alive(); i++) await sleep(1000);
  stop();
}

// The answers a person gives: the disk, all of it, encrypted, and the language and keyboard. Each is left out when the
// ISO's own kickstart says it already
const ANSWERS = ['lang en_US.UTF-8', 'keyboard us', 'zerombr', 'clearpart --all --initlabel --disklabel=gpt',
  `autopart --type=btrfs --encrypted --luks-version=luks2 --passphrase=${PASSPHRASE}`];
const answered = (own, extra) => [...ANSWERS, ...extra].filter((line) => !new RegExp(`^\\s*${line.split(' ')[0]}\\b`, 'm').test(own));

// --- The installed machine ----------------------------------------------------------------------------------------------
async function installed(step) {
  const s = await answers(20);
  await shot(`${step}-booted`);
  if (!say(s === 'answers', `${step}: the installed disk starts under Secure Boot and answers`, `${s}\n${serialTail()}`)) return false;
  const state = await value('systemctl is-system-running --wait', 900);
  say(state === 'running', `${step}: the start ends with every unit started (${state})`,
    await value('systemctl --failed --no-pager --plain; journalctl -b -p err --no-pager -n 40'));
  say(await yes('mokutil --sb-state 2>&1 | grep -q "SecureBoot enabled"'), `${step}: Secure Boot is on`, await value('mokutil --sb-state 2>&1'));
  const origin = await value("grep -h '^container-image-reference=' /ostree/deploy/*/deploy/*.origin");
  say(origin.split('\n').every((l) => l === `container-image-reference=ostree-image-signed:docker://${FOLLOWS}`) && origin !== '',
    `${step}: it follows ${FOLLOWS}, signature-checked`, origin);
  if (DIGEST) {
    const booted = await value("bootc status --format=json | jq -r '.status.booted.image.imageDigest // empty'", 60);
    say(booted === DIGEST, `${step}: it runs the image the ISO was built from`, `booted ${booted || '(none)'}\nbuilt  ${DIGEST}`);
  }
  say(await yes('[ "$(findmnt -no FSTYPE /sysroot)" = btrfs ] && lsblk -nro TYPE,FSTYPE | grep -qx "crypt btrfs"'),
    `${step}: the system is btrfs on an encrypted partition`, await value('lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINTS'));
  say(await yes('dev="$(lsblk -nrpo NAME,FSTYPE | awk \'$2 == "crypto_LUKS" { print $1; exit }\')" && cryptsetup luksDump "$dev" | grep -Eq "^Version:\\s+2$"'),
    `${step}: the encryption is LUKS2`);
  say(await value('getenforce') === 'Enforcing', `${step}: SELinux enforces`);
  say(await value('stat -c %C /etc/shadow') === 'system_u:object_r:shadow_t:s0' && await value('stat -c %C /var/log') === 'system_u:object_r:var_log_t:s0',
    `${step}: what the installation wrote has its SELinux labels`, await value('stat -c "%n %C" /etc/shadow /var/log'));
  const zone = await value('firewall-cmd --get-default-zone');
  say(zone === 'amethystora', `${step}: the firewall's default zone is the image's`, zone);
  say(await yes(`! firewall-cmd --zone=${zone || 'amethystora'} --query-service=ssh`), `${step}: the installation opened no SSH port`);
  say(await yes('! rpm -q fedora-logos fedora-release >/dev/null 2>&1 && rpm -q generic-release >/dev/null'), `${step}: no Fedora logo or release package`,
    await value('rpm -q fedora-logos fedora-release generic-release 2>&1'));
  say(await value('systemctl get-default') === 'graphical.target', `${step}: it starts to the desktop`, await value('systemctl get-default'));
  if (kind === 'live') {
    say(await yes('grep -qw rhgb /proc/cmdline && grep -qw quiet /proc/cmdline && grep -q "vconsole.keymap=" /proc/cmdline'),
      `${step}: the splash and the keyboard's layout are in the kernel's arguments`, await value('cat /proc/cmdline'));
  } else {
    skip(`${step}: the kernel arguments of the installer ISO's ostree path are the image's to catch up (hook 32)`);
  }
  return true;
}

// --- 1, 2: the ISO ----------------------------------------------------------------------------------------------------------
try {
  fs.rmSync(DISK, { force: true });
  fs.rmSync(file('serial'), { force: true });
  execFileSync('qemu-img', ['create', '-q', '-f', 'qcow2', DISK, '40G']);
  fs.copyFileSync(`${OVMF}/vars.secboot.json`, VARS);

  note('1. the ISO, from its boot menu, Secure Boot on');
  await start({ cdrom: true });
  const first = await answers(25);
  await shot('1-iso');
  // The live session is where the installation starts from, so without it nothing more can be tried; the installer's
  // system is looked at when it answers, and the installation below needs none of it
  if (!say(first === 'answers', `the ${kind} ISO starts under Secure Boot from its own boot menu`, `${first}\n${serialTail()}`) && kind === 'live') {
    throw new Error('stop');
  }
  if (first === 'answers') {
    say(await yes('mokutil --sb-state 2>&1 | grep -q "SecureBoot enabled"'), 'Secure Boot is on in the started ISO', await value('mokutil --sb-state 2>&1'));
    say(await yes('! rpm -q fedora-logos >/dev/null 2>&1'), 'the started system carries no Fedora logo package');
  }

  if (kind === 'installer') {
    if (first === 'answers') {
      say(await yes('grep -q Amethystora /etc/os-release'), 'the installer names Amethystora (its product image)', await value('cat /etc/os-release'));
      say(await yes('findmnt /run/install/repo >/dev/null'), 'the installer found the ISO it carries the image on');
    }
    await poweroff(1);

    // Its own kernel, with its entry's arguments, and a kickstart of the answers that runs the ISO's own one
    note('2. installing: the entry\'s kernel and arguments, the answers as a kickstart');
    const ksArg = entry.args.find((a) => a.startsWith('inst.ks='));
    const own = ksArg && ksArg.match(/^inst\.ks=hd:[^:]+:(\/.+)$/);
    if (!say(Boolean(own), 'the boot entry runs a kickstart of the ISO\'s own', entry.args.join(' '))) throw new Error('stop');
    const ownKs = `${work}/own.ks`;
    if (!say(extract(own[1], ownKs), `the ISO carries ${own[1]}`)) throw new Error('stop');
    const ownText = fs.readFileSync(ownKs, 'utf8');
    // poweroff last, after the ISO's own kickstart, so that a reboot of its own cannot start the installation again
    const ks = ['# The answers a person gives (tests/vm/iso.mjs), then the ISO\'s own kickstart', 'cmdline', ...answered(ownText, []), '',
      ownText, '', 'poweroff', ''].join('\n');
    fs.mkdirSync(`${work}/answers`, { recursive: true });
    fs.writeFileSync(`${work}/answers/lab.ks`, ks);
    execFileSync('xorriso', ['-as', 'mkisofs', '-quiet', '-V', 'LABKS', '-o', `${work}/answers.iso`, `${work}/answers`], { stdio: 'ignore' });
    for (const [inside, local] of [[entry.kernel, `${work}/vmlinuz`], [entry.initrd, `${work}/initrd.img`]]) {
      if (!extract(inside, local)) throw new Error(`the ISO has no ${inside}`);
    }
    const append = [...entry.args.filter((a) => !a.startsWith('inst.ks=') && a !== 'quiet'), 'inst.ks=hd:LABEL=LABKS:/lab.ks', 'console=tty0', 'console=ttyS0,115200'].join(' ');
    // The installer starts under UEFI with Secure Boot off: the firmware checks no kernel it is handed directly. What
    // it writes onto the disk is started under Secure Boot below
    fs.copyFileSync(`${OVMF}/vars.blank.json`, VARS);
    await start({
      cdrom: true, kernel: { kernel: `${work}/vmlinuz`, initrd: `${work}/initrd.img`, append },
      extra: ['-no-reboot', '-drive', `file=${work}/answers.iso,media=cdrom,if=none,id=ks,readonly=on,format=raw`, '-device', 'ide-cd,drive=ks,bus=ide.1'],
    });
    for (const until = Date.now() + 75 * 60000; alive() && Date.now() < until;) await sleep(10000);
    await shot('2-install');
    const done = !alive();
    stop();
    if (!say(done, 'Anaconda installs with the answers alone, and powers the machine off', `still running after 75 minutes\n${serialTail()}`)) throw new Error('stop');
    fs.copyFileSync(`${OVMF}/vars.secboot.json`, VARS);
  } else {
    // The live session, as it starts from the ISO
    const session = await value('for i in $(seq 120); do pgrep -u liveuser -x gnome-shell >/dev/null && break; sleep 5; done; pgrep -u liveuser -x gnome-shell', 660);
    say(session !== '', 'the live session starts, signed in as the live account', await value('loginctl list-sessions --no-legend; systemctl --failed --no-pager --plain'));
    say(await yes('test -e /usr/share/applications/liveinst.desktop || ls /usr/share/applications/*anaconda*.desktop >/dev/null 2>&1'),
      'the installer has its launcher in the live session');
    const store = await value('podman images --format "{{.Repository}}:{{.Tag}} {{.ReadOnly}}"', 120);
    say(store.split('\n').includes(`${FOLLOWS} true`), 'the image to install is in the live system, read-only', store);
    if (DIGEST) {
      const copy = await value(`podman image inspect --format '{{.Digest}}' ${FOLLOWS}`, 120);
      say(copy === DIGEST, 'the copy it installs is the image the ISO was built from', `copy  ${copy}\nbuilt ${DIGEST}`);
    }
    await shot('1-live-session');

    note('2. installing from the live session: Anaconda on its own kickstart and the answers');
    const ownText = await value('cat /usr/share/anaconda/interactive-defaults.ks');
    if (!say(/^bootc /m.test(ownText), 'the live installer\'s kickstart installs the image it carries (bootc)', ownText.slice(0, 400))) throw new Error('stop');
    // xconfig: a run without a window would otherwise make the installed machine start to a text console
    const ks = ['# The answers a person gives (tests/vm/iso.mjs), then the live installer\'s own kickstart', 'cmdline',
      ...answered(ownText, ['xconfig --startxonboot']), '', ownText].join('\n');
    await sh('mkdir -p /run/lab');
    await write('/run/lab/lab.ks', ks);
    const begin = await sh(`systemd-run --unit=lab-install --property=StandardOutput=file:/run/lab/anaconda.out --property=StandardError=inherit \
      /usr/bin/script -qefc '/usr/sbin/anaconda --liveinst --cmdline --kickstart=/run/lab/lab.ks' /dev/null`, 60);
    if (!say(begin.rc === 0, 'Anaconda starts on the kickstart', begin.err)) throw new Error('stop');
    let state = '';
    for (const until = Date.now() + 75 * 60000; Date.now() < until; await sleep(15000)) {
      state = await value('systemctl show -p ActiveState --value lab-install', 30).catch(() => 'no answer');
      if (!['active', 'activating', 'deactivating'].includes(state)) break;
    }
    const result = await value('systemctl show -p Result,ExecMainStatus lab-install');
    await shot('2-install');
    if (!say(/Result=success/.test(result) && /ExecMainStatus=0/.test(result), 'Anaconda installs from the live session with the answers alone', `${state}\n${result}\n` +
      await value('tail -n 30 /run/lab/anaconda.out; tail -n 30 /tmp/anaconda.log; tail -n 20 /tmp/storage.log 2>/dev/null', 60))) throw new Error('stop');
    await poweroff();
  }

  // --- 3: the installed machine, twice ---------------------------------------------------------------------------------
  note('3. the installed disk, Secure Boot on, the passphrase as a credential');
  await start({ creds: { 'cryptsetup.passphrase': PASSPHRASE } });
  if (await installed('first start')) {
    const setup = await value('for i in $(seq 60); do [ ! -e /var/lib/amethystora/new-installation ] && break; sleep 5; done; ls /var/lib/amethystora/new-installation 2>&1', 330);
    say(/No such file/.test(setup), 'the first boot took the new installation\'s marker', setup);
    say(await yes('systemctl is-enabled --quiet amethystora-home-snapshot.timer'), 'a new installation has the hourly snapshots of the home folders on');
    const initial = await value('for i in $(seq 60); do pgrep -f gnome-initial-setup >/dev/null && break; sleep 5; done; pgrep -fa gnome-initial-setup | head -3', 330);
    await shot('3-first-start');
    say(initial !== '', 'GNOME Initial Setup starts, to make the first account', await value('systemctl status gdm --no-pager -n 20'));
    note('restarting once');
    await sh('systemctl reboot', 20).catch(() => {});
    for (let i = 0; i < 120 && (await answers(0.05)) === 'answers'; i++) await sleep(1000);
    await installed('after a restart');
    await shot('3-restarted');
    await poweroff();
  }
} catch (error) {
  if (error.message !== 'stop') say(false, 'the test ran to its end', error.stack || error.message);
} finally {
  stop();
}
note(`${failed ? `${failed} not ok` : 'every line ok'}`);
fs.closeSync(tap);
process.exit(failed ? 1 : 0);
