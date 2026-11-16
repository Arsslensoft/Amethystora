# Moving a person's files in from a Windows disk

Written for AI agents: what to tell a person who wants their Documents, Pictures, Music, Videos and Desktop from Windows,
and what the agent does not do.

## The agent does not run it

`ame system move-in` (`/usr/libexec/amethystora-move-in`) opens a disk and copies a person's files, and may ask for the
disk's BitLocker recovery key. It is the person's alone: the tools and the root helper refuse it in every spelling
(`move-in`, `find`, `look` and `copy` too). Tell the person the command, or that Control's **System** page has **Move in
from Windows**, and that the first look offers it once when a Windows disk is found. Never ask for the recovery key
and never ask the person to type it into the conversation.

## What it does

- It finds NTFS and BitLocker volumes that hold `Windows` and `Users`, mounts one **read-only** (`ro,noexec,nosuid,nodev`)
  through udisks, and puts it away at the end. It never writes to the disk or runs anything from it. An administrator's
  password opens a disk inside the computer; a USB disk at the seat asks for none.
- A BitLocker volume is unlocked read-only with the 48-digit recovery key, typed in the terminal and kept nowhere.
  Without it the disk stays locked: there is no other way in, and no way round it.
- It copies five folders of one Windows account into the same folders here: Documents, Pictures, Music, Videos and
  Desktop. Downloads, `AppData` (browser data), the registry, password stores and e-mail are never read.
- A file already here is never replaced: the copy goes beside it as `NAME (from Windows).EXT`. A second run copies only
  what is missing, from `~/.local/state/amethystora/move-in/*.jsonl` (names and sizes). `Ctrl+C` stops it, and nothing
  half written is left.
- Files that are only in OneDrive (never downloaded on that computer) are not on the disk. They are counted and left.
- An administrator sees every Windows account and may copy one that is not their own, after being told. Anyone else
  sees only the account named like them: a courtesy, not protection (a person can rename themselves in Settings).
- A disk Files mounted read-write is not touched by finding or looking. Copying says so, asks, mounts it read-only for the
  copy and mounts it again as it was; a busy mount is left alone and nothing is copied. A BitLocker volume that is already
  unlocked is used only if it is read-only.
- With `--json` only JSON is printed; what is said goes to standard error.
- The pill shows its progress without file names.

## When it does not find the disk

- **No Windows disk listed:** `lsblk -f` shows whether the volume is `ntfs` or `BitLocker`. A volume under 4 GiB, a
  recovery partition and the volume this system runs from are never offered. A disk another program mounted
  read-write must be unmounted first.
- **Files missing that were just made in Windows:** Windows may have been hibernated or have Fast Startup on, so its
  latest changes were not written. The person shuts Windows down fully (Shift with Shut down) and runs it again.
- **"That key did not open the disk":** the recovery key is typed again; it is on the Microsoft account page of whoever
  set the computer up.
- For another computer's disk that is not Windows, `ame system bring-over` is the same idea; for an old Amethystora
  computer on the network, `ame system move`.
