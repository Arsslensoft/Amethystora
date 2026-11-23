// The lab's half of forensic-live.sh: the live ISO's forensic start tried against the disk forensic-disk.sh made. The ISO's
// own kernel and initramfs are started by QEMU with the arguments of its boot menu entry, as that entry would start them
// (the entry's name and arguments are read from the ISO's own grub.cfg), with the disk beside the ISO as a SATA disk. The
// session is used as a person would, and the disk's checksum, before and after, is the test: it must be the same.
//
//   node forensic-live.mjs ISO [--control]
//
// --control starts the first entry ("Try or install") instead and mounts one partition read-write: the checksum must then
// differ, which shows the test would see a write. Writes TAP-style lines, and exits 0 only when every line is ok.
import { execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';

import { agent, credentials, decode } from './lab.mjs';

const DIR = process.env.FORENSIC_DIR || '/vm/forensic';
const NAME = 'forensic';
const VMS = `${process.env.VMLAB_DIR || '/vm'}/vms`;
const ENTRY = 'Start without touching the disks';
const [iso, flag] = process.argv.slice(2);
const control = flag === '--control';
if (!iso || !fs.existsSync(iso)) throw new Error('forensic-live.mjs: ISO');
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
let failed = 0;
const say = (ok, what, why = '') => {
  console.log(`${ok ? 'ok' : 'not ok'} - ${what}`);
  if (!ok) {
    failed++;
    if (why) console.log(`  ${why.trim().split('\n').join('\n  ')}`);
  }
};
const skip = (what) => console.log(`skip - ${what}`);

// --- What the ISO carries ------------------------------------------------------------------------------------------
const work = `${DIR}/boot`;
fs.rmSync(work, { recursive: true, force: true });
fs.mkdirSync(work, { recursive: true });
execFileSync('xorriso', ['-osirrox', 'on', '-indev', iso, '-extract', '/images/pxeboot/vmlinuz', `${work}/vmlinuz`,
  '-extract', '/images/pxeboot/initrd.img', `${work}/initrd.img`, '-extract', '/boot/grub2/grub.cfg', `${work}/grub.cfg`], { stdio: 'ignore' });
const grub = fs.readFileSync(`${work}/grub.cfg`, 'utf8');
// The kernel's arguments of the entry whose name starts with WANT: the linux line after its menuentry, less the kernel's path
const entry = (want) => {
  const lines = grub.split('\n');
  const at = lines.findIndex((l) => l.startsWith(`menuentry '${want}`));
  if (at < 0) return null;
  const linux = lines.slice(at + 1).find((l) => /^\s*linux\s/.test(l));
  return linux ? linux.trim().split(/\s+/).slice(2).join(' ') : null;
};
const forensic = entry(ENTRY);
const normal = entry('Try or install Amethystora');
say(forensic !== null, 'the ISO has the boot entry "Start without touching the disks"');
say(normal !== null && !/amethystora\.forensic/.test(normal), 'the first entry does not carry its arguments');
if (forensic === null || normal === null) process.exit(1);
const append = control ? normal : forensic;

// --- The machine ---------------------------------------------------------------------------------------------------
const file = (ext) => `${VMS}/${NAME}.${ext}`;
fs.mkdirSync(VMS, { recursive: true });
for (const ext of ['pid', 'agent', 'qmp', 'serial', 'log']) fs.rmSync(file(ext), { force: true });
// The control writes, so it works on a copy (sparse: little of the disk is anything but zeros), taken away at the end
const disk = control ? `${DIR}/evidence-control.raw` : `${DIR}/evidence.raw`;
if (control) execFileSync('cp', ['--sparse=always', `${DIR}/evidence.raw`, disk]);
const manifest = fs.readFileSync(`${DIR}/evidence.manifest`, 'utf8').split('\n').filter(Boolean);
const before = fs.readFileSync(`${DIR}/evidence.sha256`, 'utf8').trim();
const args = ['-name', NAME, '-enable-kvm', '-machine', 'q35,smm=off', '-cpu', 'host', '-smp', '4', '-m', '4096',
  '-kernel', `${work}/vmlinuz`, '-initrd', `${work}/initrd.img`, '-append', append,
  '-drive', `file=${iso},media=cdrom,if=none,id=live,readonly=on,format=raw`, '-device', 'ide-cd,drive=live,bus=ide.0',
  // The evidence is a plain SATA disk and the VM's only other disk: every write it takes is in the file
  '-drive', `file=${disk},if=none,id=evidence,format=raw,cache=none`, '-device', 'ide-hd,drive=evidence,bus=ide.1,serial=EVIDENCE-1',
  '-netdev', 'user,id=n0', '-device', 'virtio-net-pci,netdev=n0',
  '-device', 'virtio-serial-pci', '-chardev', `socket,id=lab,path=${file('agent')},server=on,wait=off`,
  '-device', 'virtserialport,chardev=lab,name=org.amethystora.vmtest',
  '-device', 'VGA,id=vga1,xres=1280,yres=800', '-device', 'qemu-xhci', '-device', 'usb-tablet', '-display', 'none',
  '-chardev', `socket,id=con,path=${file('console')},server=on,wait=off,logfile=${file('serial')},logappend=off`, '-serial', 'chardev:con',
  '-qmp', `unix:${file('qmp')},server=on,wait=off`, '-pidfile', file('pid'), ...credentials()];
const log = fs.openSync(file('log'), 'w');
const qemu = spawn('qemu-system-x86_64', args, { detached: true, stdio: ['ignore', log, log] });
let ended = '';
qemu.on('exit', (code, signal) => { ended = `exit ${code ?? ''}${signal ? ` signal ${signal}` : ''}`; });
qemu.unref();
const alive = () => {
  try {
    return !/^\d+ \(.*\) Z/.test(fs.readFileSync(`/proc/${Number(fs.readFileSync(file('pid'), 'utf8'))}/stat`, 'utf8'));
  } catch {
    return false;
  }
};
const sh = async (command, timeout = 120, extra = {}) => {
  const a = await agent(NAME, { op: 'exec', command, timeout, ...extra }, timeout);
  return { rc: a.rc, out: decode(a.stdout), err: `${decode(a.stderr)}${a.error || ''}` };
};
const out = async (command, timeout) => (await sh(command, timeout)).out.trim();

try {
  // QEMU writes its pid file once it has started: until then it is not "stopped" (the helper's socket is not there yet
  // either, so the first ping fails at once)
  for (let i = 0; i < 50 && !alive() && !ended; i++) await sleep(200);
  // The first start is slow under nested virtualization
  for (let waited = 0; ; waited += 5) {
    try {
      await agent(NAME, { op: 'ping' }, 5);
      break;
    } catch {
      if (!alive()) throw new Error(`QEMU stopped (${ended || 'no pid file'}): ${fs.readFileSync(file('log'), 'utf8')}`);
      if (waited > 1200) throw new Error('the live system did not answer within 20 minutes');
      await sleep(5000);
    }
  }
  await sh('systemctl is-system-running --wait', 600);

  if (control) {
    // What the test would see if the disk were as writable as a normal live start leaves it: a file written, which changes the disk
    const r = await sh('mkdir -p /mnt/c && mount /dev/disk/by-label/evid-ext4 /mnt/c && echo changed >/mnt/c/changed && umount /mnt/c', 60);
    say(r.rc === 0, 'control: the normal start lets a partition be mounted and written', r.err);
  } else {
    // The evidence disk's name in the guest, by its serial: the live medium is sr0
    const dev = await out("lsblk -dno NAME,SERIAL | awk '$2==\"EVIDENCE-1\" {print $1}'");
    say(/^sd[a-z]$/.test(dev), 'the evidence disk is there', dev);
    const ro = `test "$(cat /sys/class/block/${dev}/ro)" = 1 && for p in /sys/class/block/${dev}[0-9]*; do test "$(cat $p/ro)" = 1 || exit 1; done`;

    // --- What the entry starts ---
    const status = await sh('amethystora-forensic status', 60);
    say(status.rc === 0, 'amethystora-forensic status is satisfied', status.out);
    say((await sh('grep -qw amethystora.forensic=1 /proc/cmdline')).rc === 0, 'the kernel was started with amethystora.forensic=1');
    say((await sh('systemctl -q is-active amethystora-forensic.service amethystora-forensic-session.service')).rc === 0, 'both units ran');
    say((await sh(ro)).rc === 0, 'the evidence disk and every partition of it are read-only');
    say((await sh('test -z "$(swapon --noheadings --show=NAME)"')).rc === 0, 'no swap');
    say((await sh('! ls /dev/zram* 2>/dev/null | grep -q .')).rc === 0, 'no zram device');
    say((await sh('! grep -q "^md" /proc/mdstat')).rc === 0, 'no MD array assembled');
    say((await sh('test -z "$(dmsetup ls 2>/dev/null | grep -v "^live-" | grep -v "No devices")"')).rc === 0, "no device-mapper device but the live system's own");
    say((await sh('test -z "$(lvs --noheadings 2>/dev/null)"')).rc === 0, 'no logical volume known active');
    say((await sh(`! findmnt -rn -o SOURCE | grep -q "^/dev/${dev}"`)).rc === 0, 'nothing of the evidence disk is mounted');
    say((await sh('! test -x /usr/bin/liveinst')).rc === 0, 'the installer cannot be started');
    say((await sh('! ls /usr/share/applications/liveinst.desktop /usr/share/applications/anaconda.desktop 2>/dev/null | grep -q .')).rc === 0, 'the installer has no launcher');
    for (const unit of ['fstrim.timer', 'smartd.service', 'amethystora-raid-check.timer', 'amethystora-disk-health.timer', 'lvm2-pvscan@.service']) {
      say((await out(`systemctl is-enabled ${unit} 2>&1`)).startsWith('masked'), `${unit} is masked`);
    }
    say((await out('runuser -u liveuser -- env DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus gsettings get org.gnome.desktop.media-handling automount')) === 'false',
      "GNOME's automount is off");
    say((await sh(`udevadm info -q property -n /dev/${dev}1 | grep -qx UDISKS_IGNORE=1`)).rc === 0, 'udisks is told to ignore the disk');
    say((await sh(`! udisksctl dump 2>/dev/null | grep -q "block_devices/${dev}"`)).rc === 0, 'udisks shows nothing of the disk');
    // The top bar's words: the pill file of the live account, within five minutes of the session
    let pill = '';
    for (let i = 0; i < 60 && !pill.includes('Disks read-only'); i++) {
      pill = await out('cat /run/user/1000/amethystora/pill/*.json 2>/dev/null');
      if (!pill.includes('Disks read-only')) await sleep(5000);
    }
    say(pill.includes('Disks read-only'), '"Disks read-only" is in the top bar (the live pill)', pill);

    // --- A write that is tried ---
    say((await sh(`dd if=/dev/zero of=/dev/${dev}1 bs=512 count=1 conv=notrunc 2>&1`)).rc !== 0, 'a write to the disk is refused');
    say((await sh('mkdir -p /mnt/w && ! mount -o rw,noload /dev/disk/by-label/evid-ext4 /mnt/w 2>/dev/null')).rc === 0, 'a read-write mount is refused');
    say((await sh('mkdir -p /mnt/w && { mount /dev/disk/by-label/evid-ext4 /mnt/w 2>&1 && ! touch /mnt/w/x 2>/dev/null; r=$?; umount /mnt/w 2>/dev/null; exit $r; } || true')).rc === 0,
      'a plain mount of a dirty file system is refused, or read-only, and nothing can be written in it');

    // --- The manual's mounts, one file system after another ---
    const mounts = {
      ext4: ['/dev/disk/by-label/evid-ext4', 'ro,noload'],
      xfs: ['/dev/disk/by-label/evid-xfs', 'ro,norecovery,nouuid'],
      btrfs: ['/dev/disk/by-label/evid-btrfs', 'ro,rescue=nologreplay'],
    };
    const sentence = 'the evidence stays as it was';
    for (const [fs_, [device, options]] of Object.entries(mounts)) {
      if (!manifest.includes(fs_)) { skip(`${fs_}: the lab could not make it`); continue; }
      const r = await sh(`mkdir -p /mnt/${fs_} && mount -o ${options} ${device} /mnt/${fs_} && cat /mnt/${fs_}/evidence.txt; umount /mnt/${fs_}`, 60);
      say(r.out.includes(sentence), `${fs_} mounted with ${options} and read`, r.err);
    }
    if (manifest.includes('luks')) {
      const r = await sh(`luks="$(blkid -t TYPE=crypto_LUKS -o device | head -1)"; printf forensic-lab | cryptsetup open --readonly --key-file - "$luks" forensic-luks &&
        mkdir -p /mnt/luks && mount -o ro,noload /dev/mapper/forensic-luks /mnt/luks && cat /mnt/luks/evidence.txt; umount /mnt/luks; cryptsetup close forensic-luks`, 90);
      say(r.out.includes(sentence), 'LUKS opened read-only by hand, its ext4 mounted ro,noload and read', r.err);
    } else skip('luks: the lab could not make it');
    if (manifest.includes('lvm')) {
      // Read-only for real: every active volume has permission r or R (the helper puts the group back if one is not), a thin pool included
      const r = await sh('amethystora-forensic lvm-activate forensic 2>&1; lvs --noheadings -a -o lv_name,lv_attr forensic; mkdir -p /mnt/lvm && mount -o ro,noload /dev/forensic/volume /mnt/lvm && cat /mnt/lvm/evidence.txt; umount /mnt/lvm', 90);
      say(r.out.includes(sentence), 'the volume group activated read-only by the helper, its ext4 mounted ro,noload and read', r.out + r.err);
      say(!/^\s*\S+\s+\S[w]\S{2}a/m.test(r.out), 'no volume of it is active read-write', r.out);
      if (manifest.includes('thin')) {
        const t = await sh('mkdir -p /mnt/thin && mount -o ro,noload /dev/forensic/thin /mnt/thin && cat /mnt/thin/evidence.txt; umount /mnt/thin', 60);
        say(t.out.includes(sentence), 'the thin volume of its thin pool mounted ro,noload and read', t.out + t.err);
      } else skip('thin: the lab could not make it');
      await sh('vgchange -an forensic >/dev/null 2>&1');
    } else skip('lvm: the lab could not make it');
    // What udev would have put together by itself is switched off by name, and the live system's swap is not on a disk
    say((await sh('for r in 64-md-raid-assembly 69-dm-lvm 69-bcache; do test "$(readlink /run/udev/rules.d/$r.rules)" = /dev/null || exit 1; done')).rc === 0,
      'the rule files that assemble, activate and register are made empty');
    say((await sh('grep -qw noswap /proc/cmdline && test -z "$(swapon --noheadings --show=NAME)"')).rc === 0, 'noswap, and none on');
    say((await sh('amethystora-forensic writable /dev/sr0 2>&1')).rc !== 0, 'the disc the system started from cannot be made writable');
    if (manifest.includes('md')) {
      const r = await sh(`mdadm --assemble --readonly /dev/md/forensic /dev/${dev}7 /dev/${dev}8 >/dev/null 2>&1; mkdir -p /mnt/md && mount -o ro,noload /dev/md/forensic /mnt/md && cat /mnt/md/evidence.txt; umount /mnt/md; mdadm --stop /dev/md/forensic >/dev/null 2>&1`, 90);
      say(r.out.includes(sentence), 'the RAID1 assembled read-only by hand, mounted ro,noload and read', r.err);
    } else skip('md: the lab could not make it');
    say((await sh(`! findmnt -rn -o SOURCE | grep -q "^/dev/${dev}"`)).rc === 0, 'nothing of the disk is left mounted');
    // The one drive the findings go to: made writable on purpose, and the check says so; then put back as it was
    say((await sh(`amethystora-forensic writable /dev/${dev} 2>&1 && test "$(cat /sys/class/block/${dev}/ro)" = 0 && amethystora-forensic verify`)).rc === 0,
      'amethystora-forensic writable makes a disk writable on purpose, and the check accepts it');
    await sh(`blockdev --setro /dev/${dev}; for p in /sys/class/block/${dev}[0-9]*; do blockdev --setro /dev/$(basename $p); done`);
  }

  // --- The end of it ---
  await sh('sync; systemctl poweroff', 30).catch(() => {});
  for (let i = 0; i < 120 && alive(); i++) await sleep(1000);
  if (alive()) execFileSync('kill', [String(Number(fs.readFileSync(file('pid'), 'utf8')))]);
} finally {
  if (alive()) {
    try {
      process.kill(Number(fs.readFileSync(file('pid'), 'utf8')));
    } catch {
      // Gone already
    }
  }
}

const after = execFileSync('sha256sum', [disk]).toString().split(' ')[0];
if (control) say(after !== before, 'control: the disk changed, so the checksum would show a write', `${before}\n${after}`);
else say(after === before, 'the disk is byte for byte what it was before the session', `before ${before}\nafter  ${after}`);
if (control) fs.rmSync(disk, { force: true });
process.exit(failed ? 1 : 0);
