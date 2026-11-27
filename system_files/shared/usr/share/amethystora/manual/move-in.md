# Move in from Windows

Your Documents, Pictures, Music, Videos and Desktop, from the Windows disk of this computer, or from one you plug in,
into the same folders here. The disk is only read. Nothing is written to it, and nothing on it is run.

If Windows is still on this computer, the first look offers it once, when it finds that disk. You can start it any
time: Control's **System** page, **Move in from Windows**, or in a terminal:

```bash
ame system move-in
```

A disk inside this computer asks for an administrator's password to be opened; a USB disk you plugged in asks for none.

## What you choose

It lists the Windows accounts on the disk, then each of the five folders with how much is in it, and you answer yes or no
for each. Only an administrator sees every account. Anyone else sees the one named like them.

- **Documents, Pictures, Music, Videos and Desktop** go to the same folders here, in your own language's names.
- **Downloads is left out.** It is big, and mostly programs for Windows.
- **Nothing else is read.** Not your browser's data, passwords, e-mail or Windows' settings. Firefox has its own import
  for bookmarks, in its own settings. Programs are never copied: see [Windows programs](windows-programs.md).

## The disk is only read

It is mounted read-only, with nothing allowed to run from it, and put away again at the end. Windows' own boot, and
everything else on the disk, are left as they were. A disk Windows did not shut down fully (hibernated, or with Fast
Startup on) can still be read, but it may be missing what Windows kept in memory: shut Windows down properly first if
a recent file is not there.

If Files already opened the disk so that it can be written to, finding and looking leave it as it is and say so. Copying
says so first and asks: it unmounts the disk, mounts it read-only for the copy, and mounts it again as it was at the end.
If something is using it, it is left alone and nothing is copied.

## A BitLocker disk

Most Windows 11 disks are encrypted. The terminal asks for the **48-digit recovery key**, which is on the Microsoft
account page of whoever set the computer up, or on a printout. Nothing shows as you type. The key goes to the disk
service once, the disk is opened read-only, and the key is kept nowhere: not in a file, not in a Vault, not on a command
line. Without the key the disk stays locked.

## A file you already have

A file is never replaced. If one with the same name is already here, the Windows one is copied beside it:
`report.docx` stays, and `report (from Windows).docx` comes next to it. If you copy again and it is the same file,
nothing is made twice.

It stays out of the way, at low priority, and keeps a gigabyte free: if what you chose does not fit, it says so and
copies nothing.

## OneDrive

With Windows' backup to OneDrive on, your folders live in `OneDrive` on the disk, and a file you never opened on that
computer is only a label with no content. Those files are not on the disk, so they are left and counted: "N files are
only in OneDrive". They are still in your OneDrive, on the web. Files that Windows did download are copied as usual.

## Another account

NTFS permissions are not enforced here, so every account's folder on a mounted Windows disk can be read. Copying
another account's files is for an administrator, and it says so first and asks. Go on only if its owner agreed.
Showing anyone else only the account named like them is a courtesy, not protection: a person can change their own name in
Settings, and a disk you plug in can be read in Files anyway.

## Stopping, and carrying on

Press `Ctrl+C` at any time. A file appears under its name only when whole, so nothing half copied is left. Run it again
and it carries on with what is missing, from a short record of what it copied
(`~/.local/state/amethystora/move-in`, names and sizes of files, which you can delete). A copy you have since edited,
moved or deleted is not made again.

While it copies, the pill at the top shows how far it is, and no file name.

## In steps

For a script, each part is a command, with `--json`. `PART` is a disk from `find`, as `/dev/sda3`:

```bash
amethystora-move-in find --json                    # the disks with Windows on them, and their accounts
amethystora-move-in look /dev/sda3 --json          # one disk's folders, with sizes
amethystora-move-in copy /dev/sda3 Sam --yes       # copy; --folders documents,music for some only
```

[The agent](ai-agent.md) cannot start any of it: it opens a disk and a person's files. For the disk of another kind
of computer, or another Amethystora computer, see [Moving in](moving.md).
