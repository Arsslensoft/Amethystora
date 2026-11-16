# Start without touching the disks

When a computer has to be looked at and not changed, start it from the live stick with **Start without touching the
disks**. The disks are read-only for the whole session, nothing of them is mounted, swapped to or put together by
itself, and the desktop tells you so.

It is a setting of the software, not a hardware write blocker: read [what it is not](#what-it-is-not) first.

## Start it

[Write the live ISO to a stick](installing.md#write-it-to-a-usb-stick) and start the computer from it. In the boot
menu choose **Start without touching the disks (software read-only, not a hardware write blocker)**, the third entry.
It is on the live ISO only: the installer ISO and an installed system do not have it. The network works as in any
live start, so unplug the cable and keep Wi-Fi off if the computer must not reach one.

## What it does

- **Every disk is read-only as it appears**, whole disks and partitions, before anything else of the system can see
  it. A disk plugged in later is the same. The stick or disc the system started from, and memory, are left as they are:
  a live system on a disk that is built into the computer is not, since it is one of the disks. It runs from memory
  and from a read-only mount, so it works all the same.
- **Nothing is swapped to, resumed, assembled or opened by itself.** No swap, no compressed memory, no hibernation image
  resumed, no LVM volume, RAID array, bcache or encrypted volume put together, no file system mounted, no check or
  repair run. The read-only setting does not stop a driver of the kernel that writes on its own (swap, bcache, a RAID or
  LVM target), so these are not started at all, and what you start yourself is started read-only.
- **The desktop does not see the disks.** Files shows no drive for them and nothing starts when one is plugged in.
  You open what you need yourself, below.
- **What touches a disk by itself is off for this start:** TRIM, SMART's self-tests, RAID and disk-health checks, the
  hourly snapshots and the integrity check.
- **The installer is not offered.** It would erase a disk.
- **The top bar says "Disks read-only"** while every disk is, and **"A disk is writable"** if one is not.

`amethystora-forensic status` in a terminal says what is in force and whether each disk is read-only.

## What it is not

A software setting, not a hardware write blocker. The setting keeps programs from writing to a disk and file systems
from being mounted read-write. It does not stop a driver of the kernel that submits its own writes, and a disk's own
firmware can still write. A kernel fault can still write. So can a command run as root that makes a device writable again, one that talks to the disk directly (SCSI
generic, ATA pass-through, NVMe admin commands), and a bridge between a disk and the computer that does something of
its own. When a procedure, a court or a client needs a hardware write blocker, use
one, and use this start in addition to it.

The first entry of the boot menu starts the disks as they always are. Check which entry is running: the top bar says
"Disks read-only" in this one only.

## Look at the disks

```bash
lsblk -f                 # what is on each disk: nothing is mounted
```

A disk that is read-only keeps the kernel from writing to it, so a mount that has to write fails with an error. A file
system that was not closed cleanly has a journal or log to replay, and replaying writes: the plain mount can fail for
that. Ask for the replay to be skipped with these options. What was in the journal is then not in what you see, and the
file system may look inconsistent.

| File system | Mount it with |
| --- | --- |
| ext4 | `sudo mount -o ro,noload /dev/sdX1 /mnt` |
| XFS | `sudo mount -o ro,norecovery,nouuid /dev/sdX1 /mnt` (`nouuid` only if another with the same ID is mounted) |
| btrfs | `sudo mount -o ro,rescue=nologreplay /dev/sdX1 /mnt` |
| Others | `sudo mount -o ro /dev/sdX1 /mnt` |

`noload`, `norecovery` and `rescue=nologreplay` are the kernel's own words for not replaying the journal, the log and
the tree log. XFS and btrfs mount only read-only with them. btrfs replays its log even in a read-only mount unless
told not to.

### Encrypted, LVM and RAID

These are never opened for you. Open them read-only, and mount what is inside as above. A plain `vgchange -ay` is not
that: it loads every volume read-write, and a thin pool, a RAID volume or a snapshot to be merged then writes to the
disks under it by itself, past the read-only setting.

```bash
sudo cryptsetup open --readonly /dev/sdX2 evidence    # then mount /dev/mapper/evidence
sudo vgs                                              # the volume groups there are
sudo amethystora-forensic lvm-activate VOLUMEGROUP    # then mount /dev/VOLUMEGROUP/NAME
sudo mdadm --assemble --readonly /dev/md/evidence /dev/sdX3 /dev/sdX4
```

`lvm-activate` activates the group with every volume read-only, so that the disks under them are opened without write
access, and puts it back at once if one comes up writable. It refuses a group with a snapshot waiting to be merged, which
activating its origin would start. `mdadm --readonly` starts no resynchronising either. Check with
`amethystora-forensic status`.

### A drive for what you find

Write findings to another drive, not to the evidence. Plug it in, then make that one writable on purpose:

```bash
sudo amethystora-forensic writable /dev/sdY
```

It stays writable while it is the same disk, known by its serial number, and until it is unplugged. A drive with no
serial number is refused, since it could not be told from another of its make plugged in later under the same name. The
stick the system started from cannot be chosen. Every other disk stays as it was.

## After

Shut down and take the stick out. Nothing of the session is kept: its files were in memory.
