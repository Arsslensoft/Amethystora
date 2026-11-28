// The lab's half of iso.sh: an ISO of a build installed as a person installs it, and the machine it made started and
// looked at. Everything runs in the lab container, beside the other VMs, with the lab's helper reaching each system as a
// systemd credential (lab.mjs), the installer's and the live session's too.
//
//   node iso.mjs installer ISO [--digest sha256:...] [--files SHA]   the installer ISO (<image>-non-uefi.iso, bootc-image-builder's)
//   node iso.mjs live ISO [--digest sha256:...] [--files SHA]        the live ISO (<image>.iso, Titanoboa's)
//
// 1. The ISO is started by the firmware, Secure Boot on with Microsoft's keys, from its own boot menu's first entry: its
//    shim, GRUB, kernel and system start, and are looked at (the installer's, or the live session).
// 2. It installs onto a blank 40 GiB disk, in the system step 1 started, through Anaconda's web interface, page by page,
//    as a person clicks through it (webui.mjs, a headless Chromium in the lab): the language, the keyboard, the disk,
//    all of it, encrypted, the review, the installation, and Reboot. The live session starts the installer from its
//    launcher first, as a click on it does.
// 3. The disk alone is started under Secure Boot, the passphrase handed to systemd-cryptsetup as a credential, and
//    looked at: the signed origin, the layout, SELinux, the firewall, the first boot's setup, GNOME Initial Setup; then
//    once more after a restart.
//
// Writes TAP-style lines (ok, not ok with indented lines saying why, skip) to stdout and DIR/results.tap, a screenshot
// after each step, and exits 0 only when every line is ok. --digest is the image the live ISO copies, --files the checksum
// of the image's helpers and recipes (sha256sum of FILES_OF, then of that), which the installed machine must match; the
// installed machine must run.
import { execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';

import { agent, credentials, decode, screendump } from './lab.mjs';
import { browser } from './webui.mjs';

const ROOT = process.env.VMLAB_DIR || '/vm';
const VMS = `${ROOT}/vms`;
const OVMF = '/usr/share/edk2/ovmf';
const PASSPHRASE = 'amethystora-lab-passphrase';
// What the installed machine follows: @IMAGE@:stable in iso.toml, BASE_IMAGE in installer.ks
const FOLLOWS = process.env.ISO_IMAGE_REF || 'ghcr.io/arsslensoft/amethystora:stable';
const option = (flag) => (process.argv.includes(flag) ? process.argv[process.argv.indexOf(flag) + 1] : undefined);
const [kind, iso] = process.argv.slice(2);
const DIGEST = option('--digest');
// --files: the checksum of the image's helpers and recipes, made by FILES_OF in the image (lab-iso.yml)
const FILES = option('--files');
const FILES_OF = '/usr/libexec/amethystora-* /usr/share/amethystora/just/*.just';
if (FILES && !/^[0-9a-f]{64}$/.test(FILES)) throw new Error(`iso.mjs: no checksum ${FILES}`);
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
async function start({ cdrom = false, kernel, extra = [], creds = {}, memory = 8192, forward }) {
  stop();
  for (const ext of ['pid', 'agent', 'qmp', 'console']) fs.rmSync(file(ext), { force: true });
  const args = ['-name', NAME, '-enable-kvm', '-machine', 'q35,smm=off', '-cpu', 'host', '-smp', '4', '-m', String(memory),
    '-global', 'ICH9-LPC.disable_s3=1', '-bios', `${OVMF}/OVMF.qemuvars.fd`, '-device', `uefi-vars-x64,jsonfile=${VARS}`,
    // A kernel handed over directly takes boot index 0 (QEMU's linuxboot), so the disks then have none
    '-drive', `file=${DISK},if=none,id=disk,format=qcow2,discard=unmap`, '-device', `virtio-blk-pci,drive=disk${kernel ? '' : ',bootindex=1'}`,
    ...(cdrom ? ['-drive', `file=${iso},media=cdrom,if=none,id=cd,readonly=on,format=raw`,
      '-device', `ide-cd,drive=cd,bus=ide.0${kernel ? '' : ',bootindex=0'}`] : []),
    ...(kernel ? ['-kernel', kernel.kernel, '-initrd', kernel.initrd, '-append', kernel.append] : []),
    ...extra,
    '-netdev', `user,id=n0${forward ? `,hostfwd=tcp:127.0.0.1:${forward}-:${forward}` : ''}`, '-device', 'virtio-net-pci,netdev=n0',
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
// Until the helper answers from the system itself: the firmware, the boot menu's timeout and, under nested
// virtualization, a slow first start. It starts in the initramfs already (systemd hands it the credential there), where
// nothing of the system is to be seen yet, so an answer from the initramfs is waited past; with initramfs, it is enough
async function answers(minutes, initramfs = false) {
  for (const until = Date.now() + minutes * 60000; Date.now() < until; await sleep(5000)) {
    if (!alive()) return 'stopped';
    try {
      await agent(NAME, { op: 'ping' }, 5);
      if (initramfs || (await sh('test ! -e /etc/initrd-release', 10)).rc === 0) return 'answers';
    } catch {
      // Not yet, or switching from the initramfs to the system
    }
  }
  return 'silent';
}
// Secure Boot as the firmware says it, which needs no mokutil (the installer's system has none): the SecureBoot variable's
// last byte
const SECURE_BOOT = 'test "$(od -An -t u1 /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c 2>/dev/null | awk \'{ print $NF }\')" = 1';
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

// --- The installed machine ----------------------------------------------------------------------------------------------
async function installed(step) {
  const s = await answers(20);
  await shot(`${step}-booted`);
  if (!say(s === 'answers', `${step}: the installed disk starts under Secure Boot and answers`, `${s}\n${serialTail()}`)) return false;
  const state = await value('systemctl is-system-running --wait', 900);
  say(state === 'running', `${step}: the start ends with every unit started (${state})`,
    await value('systemctl --failed --no-pager --plain; journalctl -b -p err --no-pager -n 40'));
  say(await yes(SECURE_BOOT), `${step}: Secure Boot is on`);
  const origin = await value("grep -h '^container-image-reference=' /ostree/deploy/*/deploy/*.origin");
  say(origin.split('\n').every((l) => l === `container-image-reference=ostree-image-signed:docker://${FOLLOWS}`) && origin !== '',
    `${step}: it follows ${FOLLOWS}, signature-checked`, origin);
  // Not by digest: bootc-image-builder repacks the image onto the ISO, so the installed manifest is a new one. The image's
  // own helpers and recipes, which nearly every change touches, tell this build from a published one
  if (FILES) {
    const installed = await value(`export LC_ALL=C; sha256sum ${FILES_OF} | sha256sum | cut -d' ' -f1`, 60);
    say(installed === FILES, `${step}: it runs the image the ISO was built from`, `installed ${installed}\nbuilt     ${FILES}`);
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
  const lang = await value('. /etc/locale.conf 2>/dev/null; echo "${LANG:-}"');
  say(lang === `${LANGUAGE}.UTF-8`, `${step}: the language chosen in the installer is the system's (${LANGUAGE}.UTF-8)`, await value('cat /etc/locale.conf 2>&1'));
  const keymap = await value('. /etc/vconsole.conf 2>/dev/null; echo "${KEYMAP:-}"');
  say(keymap === KEYBOARD, `${step}: the keyboard layout chosen in the installer is the console's (${KEYBOARD})`, await value('cat /etc/vconsole.conf 2>&1'));
  if (kind === 'live') {
    say(await yes(`grep -qw rhgb /proc/cmdline && grep -qw quiet /proc/cmdline && grep -qw "vconsole.keymap=${KEYBOARD}" /proc/cmdline`),
      `${step}: the splash and the keyboard's layout are in the kernel's arguments`, await value('cat /proc/cmdline'));
  } else {
    skip(`${step}: the kernel arguments of the installer ISO's ostree path are the image's to catch up (hook 32)`);
  }
  return true;
}

// --- 2: the web interface, as a person goes through it ----------------------------------------------------------------------
// The installer ISO's system starts Anaconda's web interface by itself; the live session starts it from the installer's
// launcher, as its dash and its welcome window do. cockpit-ws serves it on the loopback alone, to the installer's own
// window. A forwarder started there through the lab's helper opens it on WEBUI_PORT (in the live system's firewall too, for
// as long as the session lasts), which QEMU forwards to the lab, where a headless Chromium (webui.mjs) clicks through every
// page. A language and a keyboard other than the defaults are chosen, so that the installed system can show they were taken.
// The pages the ISO hides must not appear; the others are passed with Next as they come. Reboot ends QEMU, which runs with
// -no-reboot, and the disk is then started alone (step 3).
const WEBUI_PORT = 9919;
const LANGUAGE = 'en_GB';
const KEYBOARD = 'gb';
// iso/product/etc/anaconda/conf.d/99-amethystora.conf, iso/live/amethystora-live.conf
const HIDDEN = kind === 'installer' ? ['network', 'date-time', 'accounts'] : ['accounts'];
const PASSED = ['network', 'date-time', 'installation-source', 'software-selection'];
// Two hours from the live ISO: the copy it installs is read from the squashed system on a virtual DVD
const INSTALL_MINUTES = kind === 'live' ? 120 : 75;
const LAUNCHER = 'ls /usr/share/applications/liveinst.desktop /usr/share/applications/*anaconda*.desktop 2>/dev/null | head -n 1';
const FORWARDER = `import socket, sys, threading

def pipe(src, dst):
    try:
        while data := src.recv(65536):
            dst.sendall(data)
    except OSError:
        pass
    try:
        dst.shutdown(socket.SHUT_WR)
    except OSError:
        pass

server = socket.create_server(("0.0.0.0", int(sys.argv[1])))
while True:
    client, _ = server.accept()
    try:
        upstream = socket.create_connection(("127.0.0.1", int(sys.argv[2])))
    except OSError:
        client.close()
        continue
    for a, b in ((client, upstream), (upstream, client)):
        threading.Thread(target=pipe, args=(a, b), daemon=True).start()
`;
const onPage = (id) => `location.hash === '#/anaconda-screen-${id}'`;
const installerLog = async () => (await value('echo "--- anaconda.log"; grep -vE " DBG " /tmp/anaconda.log 2>/dev/null | tail -n 25 | cut -c1-300', 30).catch(() => '(the installer does not answer)'));

async function webInstall() {
  if (kind === 'live') {
    // In the live account's session, in a scope of its own so that it outlives the helper's command: its launcher's entry,
    // which runs liveinst, which asks polkit to run Anaconda as root, as a click on it does
    const a = await agent(NAME, { op: 'exec', user: 'liveuser', session: true, timeout: 60,
      command: `d="$(${LAUNCHER})" && systemd-run --user --scope --unit=lab-liveinst gio launch "$d"` }, 60);
    if (!say(a.rc === 0, 'the installer starts from its launcher in the live session', `${decode(a.stderr)}${a.error || ''}`)) return false;
  }
  // The web interface starts after Anaconda's modules, slower under nested virtualization
  // Its port by ss, or, in a system without ss, the ports cockpit-ws takes (80, 9090 before) once it runs
  const port = await value('for i in $(seq 120); do p="$(ss -Hltnp 2>/dev/null | awk \'/cockpit-ws/ { n = split($4, a, ":"); print a[n]; exit }\')"; ' +
    'if [ -z "$p" ] && ! command -v ss >/dev/null && pgrep -f cockpit-ws >/dev/null; then for q in 80 9090; do (echo >/dev/tcp/127.0.0.1/$q) 2>/dev/null && { p=$q; break; }; done; fi; ' +
    '[ -n "$p" ] && { echo "$p"; exit; }; sleep 5; done', 660);
  if (!say(/^\d+$/.test(port), 'the installer serves its web interface (cockpit-ws)',
    await value('ps -eo args | grep -E "[c]ockpit|[a]naconda|[l]iveinst|[f]irefox" | cut -c1-200 | head; ss -Hltnp 2>/dev/null | head; ' +
      'journalctl -b --no-pager -n 15 -t polkitd -t pkexec -t liveinst 2>/dev/null', 30))) return false;
  note(`the web interface: cockpit-ws on the installer's port ${port}`);
  await sh('mkdir -p /run/lab');
  await write('/run/lab/forward.py', FORWARDER);
  // The live system's firewall, which the installation does not carry over, is opened to the forwarder until it shuts down
  const forwarding = await sh(`systemd-run --unit=lab-webui-forward /usr/bin/python3 /run/lab/forward.py ${WEBUI_PORT} ${port} && ` +
    `if firewall-cmd --state >/dev/null 2>&1; then firewall-cmd -q --add-port=${WEBUI_PORT}/tcp; fi`, 30);
  if (!say(forwarding.rc === 0, 'the web interface is forwarded to the lab', forwarding.err)) return false;

  const b = await browser(`${DIR}/browser`);
  let shots = 0;
  const step = async (what, act) => {
    const name = `2-${String(++shots).padStart(2, '0')}`;
    try {
      await act();
      await b.shot(`${DIR}/${name}.png`);
      return say(true, what);
    } catch (error) {
      await b.shot(`${DIR}/${name}-failed.png`);
      await shot(`${name}-screen`);
      const where = await b.evaluate('`${location.href}\\n${document.body.innerText.slice(0, 1200)}`').catch(() => '(no page)');
      return say(false, what, `${error.message}\n--- the page\n${where}\n${await installerLog()}`);
    }
  };
  const exists = async (selector) => b.evaluate(`Boolean(${b.q(selector)})`);
  const checked = async (selector) => b.evaluate(`Boolean(${b.q(selector)}?.matches(':checked'))`);
  const next = async () => b.click('#installation-next-btn', 'Next');
  const optionOf = (prefix, id) => `[id^="${prefix}-option-"][id$="-${id}"]`;
  // Next, and Next again past the pages a person passes as they come, to target: any other page is an error. A hidden page
  // passed on the way is caught at the review
  const nextTo = async (target) => {
    for (let from = await b.evaluate('location.hash'); ;) {
      await next();
      const at = await b.until(`location.hash !== ${JSON.stringify(from)} && location.hash`, `the page after ${from}`, 180);
      if (at === `#/anaconda-screen-${target}`) return;
      const page = at.replace('#/anaconda-screen-', '');
      if (!PASSED.includes(page)) throw new Error(`Next led to ${at}, not to the ${target} page`);
      await b.until(b.usable('#installation-next-btn'), `Next on the ${page} page`, 180);
      await b.shot(`${DIR}/2-passed-${page}.png`);
      note(`the ${page} page, passed with Next as it comes`);
      from = at;
    }
  };
  try {
    // The installer opened on the review, with no way past it, when its Localization module was off (iso/iso.toml)
    const ok = await step('the web interface opens on its first page, the language', async () => {
      await b.goto(`http://127.0.0.1:${WEBUI_PORT}/cockpit/@localhost/anaconda-webui/index.html`);
      await b.until(`${b.usable('#installation-next-btn')} && location.hash.startsWith('#/anaconda-screen-')`, 'a page of the installer, with its Next button', 600);
      await b.evaluate("window.labPages = [location.hash]; addEventListener('hashchange', () => labPages.push(location.hash)); true");
      await new Promise((resolve) => setTimeout(resolve, 5000));
      const at = await b.evaluate('location.hash');
      if (at !== '#/anaconda-screen-language') throw new Error(`it opened on ${at}, not on the language page`);
    })
      && await step(`the language page lists the languages, and ${LANGUAGE} is chosen`, async () => {
        const count = await b.evaluate('document.querySelectorAll(\'[id^="anaconda-screen-language-option-"]\').length');
        if (!count) throw new Error('the page lists no language');
        const option = optionOf('anaconda-screen-language', LANGUAGE);
        if (!(await exists(option))) await b.type('.anaconda-screen-language-language-search input', 'United Kingdom', 'the language search');
        await b.click(option, `the language ${LANGUAGE}`);
        await b.until(`[...document.querySelectorAll(${JSON.stringify(option)})].some((e) => e.matches('.pf-m-selected') || e.querySelector('.pf-m-selected'))`, `${LANGUAGE} shown as chosen`, 30);
      })
      && await step(`the keyboard layout ${KEYBOARD} is chosen`, async () => {
        await b.click('#anaconda-screen-language-change-system-keyboard-layout-modal-open-button', 'the button that changes the keyboard layout');
        await b.until(b.usable('#anaconda-screen-language-change-system-keyboard-layout-modal'), 'the keyboard layout dialog', 30);
        const option = optionOf('anaconda-screen-language-keyboard', KEYBOARD);
        if (!(await exists(option))) await b.type('.anaconda-screen-language-keyboard-search input', 'English (UK)', 'the keyboard layout search');
        await b.click(option, `the keyboard layout ${KEYBOARD}`);
        await b.click('#anaconda-screen-language-change-system-keyboard-layout-modal-save-button', 'Save');
        await b.until("/\\bgb\\b|\\bUK\\b|United Kingdom/i.test(document.querySelector('#anaconda-screen-language-selected-keyboards')?.textContent || '')",
          `${KEYBOARD} shown as the layout`, 30);
      })
      && await step('Next leads to the installation method, the disk, past any page the ISO shows on the way', async () => {
        await nextTo('method');
      })
      && await step('the whole of the disk vda is chosen, to be erased', async () => {
        if (!(await exists('#anaconda-screen-method-target-disk-vda'))) {
          await b.click('#anaconda-screen-method-change-destination-button', 'the button that changes the disk');
          const box = '#anaconda-screen-method-disk-selection-menu-item-vda input[type=checkbox]';
          await b.until(`Boolean(${b.q(box)})`, 'the disk vda in the list', 60);
          if (!(await checked(box))) await b.click(box, 'the disk vda in the list');
          await b.clickButton('#anaconda-screen-method-change-destination-modal', 'Select');
          await b.until(`Boolean(${b.q('#anaconda-screen-method-target-disk-vda')})`, 'vda as the disk', 60);
        }
        const erase = '#anaconda-screen-method-scenario-erase-all';
        if (!(await checked(erase))) await b.click(erase, 'Use entire disk');
        await b.until(`Boolean(${b.q(erase)}?.matches(':checked'))`, 'Use entire disk chosen', 30);
      })
      && await step('Next leads to the storage configuration, where the disk is encrypted with a passphrase given twice', async () => {
        await nextTo('storage-configuration');
        if (!(await checked('#disk-encryption-encrypt-devices'))) await b.click('#disk-encryption-encrypt-devices', 'Encrypt my data');
        await b.type('#disk-encryption-password-field', PASSPHRASE, 'the passphrase');
        await b.type('#disk-encryption-password-confirm-field', PASSPHRASE, 'the passphrase again');
        await b.until(b.usable('#installation-next-btn'), 'Next, the passphrase accepted', 60);
      })
      && await step(`Next leads to the review, which shows ${LANGUAGE} and the disk vda, with no page the ISO hides on the way`, async () => {
        await nextTo('review');
        const language = await b.evaluate("document.querySelector('#anaconda-screen-review-target-system-language')?.textContent || ''");
        if (!/United Kingdom/.test(language)) throw new Error(`the review's language is ${JSON.stringify(language)}`);
        const review = await b.evaluate("(document.querySelector('[class*=\"wizard__main\"]') || document.body).innerText");
        if (!/\bvda\b/.test(review)) throw new Error('the review does not name the disk vda');
        const shown = (await b.evaluate('labPages')).filter((h) => HIDDEN.some((page) => h === `#/anaconda-screen-${page}`));
        if (shown.length) throw new Error(`it showed ${shown.join(', ')}`);
      })
      && await step('the erasure confirmed, the installation starts', async () => {
        await b.click('#anaconda-screen-review-next-confirmation-checkbox', 'the box that confirms erasing the disk');
        await next();
        await b.until(`${onPage('progress')} || Boolean(document.querySelector('[class*="progress-stepper"]'))`, 'the progress page', 120);
      })
      && await step('Anaconda installs, and says it has', async () => {
        const end = await b.until("document.querySelector('.anaconda-screen-progress-status-success') ? 'success' : " +
          "(document.querySelector('.anaconda-screen-progress-status-danger, #critical-error-bz-report-modal, #anaconda-screen-progress-installation-error-dialog') ? 'failed' : '')",
        'the end of the installation', INSTALL_MINUTES * 60);
        if (end !== 'success') throw new Error('the installation failed');
      })
      && await step('Reboot ends the installer', async () => {
        await b.clickButton('.anaconda-screen-progress-status-success', 'Reboot');
        for (let i = 0; i < 300 && alive(); i++) await sleep(1000);
        if (alive()) throw new Error('the machine still runs five minutes after Reboot');
      });
    return ok;
  } finally {
    await b.close();
  }
}

// --- 1, 2: the ISO ----------------------------------------------------------------------------------------------------------
try {
  fs.rmSync(DISK, { force: true });
  fs.rmSync(file('serial'), { force: true });
  execFileSync('qemu-img', ['create', '-q', '-f', 'qcow2', DISK, '40G']);
  fs.copyFileSync(`${OVMF}/vars.secboot.json`, VARS);

  note('1. the ISO, from its boot menu, Secure Boot on');
  // -no-reboot: the installer's Reboot, at the end of the installation, ends QEMU, and the disk is started alone
  await start({ cdrom: true, extra: ['-no-reboot'], forward: WEBUI_PORT });
  const first = await answers(25);
  await shot('1-iso');
  // The installation is driven from the system the ISO started (the installer's, or the live session), so without it
  // nothing more can be tried
  if (!say(first === 'answers', `the ${kind} ISO starts under Secure Boot from its own boot menu`, `${first}\n${serialTail()}`)) throw new Error('stop');
  say(await yes(SECURE_BOOT), 'Secure Boot is on in the started ISO');
  say(await yes('! rpm -q fedora-logos >/dev/null 2>&1'), 'the started system carries no Fedora logo package');

  if (kind === 'installer') {
    say(await yes('grep -q Amethystora /etc/os-release'), 'the installer names Amethystora (its product image)', await value('cat /etc/os-release'));
    say(await yes('findmnt /run/install/repo >/dev/null'), 'the installer found the ISO it carries the image on');
    // The ISO's own kickstart, which the web interface takes as given: the image to install and the switch to the signed one
    say(entry.args.some((a) => /^inst\.ks=hd:[^:]+:\/.+$/.test(a)), 'the boot entry runs a kickstart of the ISO\'s own', entry.args.join(' '));
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

    // The kickstart the web interface takes as given: the image to install and the switch to the signed one
    const ownText = await value('cat /usr/share/anaconda/interactive-defaults.ks');
    say(/^bootc /m.test(ownText), 'the live installer\'s kickstart installs the image it carries (bootc)', ownText.slice(0, 400));
  }
  note('2. installing through the web interface, page by page');
  if (!(await webInstall())) throw new Error('stop');
  stop();

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
    for (let i = 0; i < 120 && (await answers(0.05, true)) === 'answers'; i++) await sleep(1000);
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
