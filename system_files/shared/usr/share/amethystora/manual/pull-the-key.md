# Pull the key

A USB device on a cord to your wrist or your keys: if the computer is snatched, the device comes out and the screen
locks, or the computer powers off. It is off as the image ships, and in no profile.

## Setting it up

Plug in the device, then choose it and what happens when it is pulled out:

```bash
ame security pull-key device      # which device: it lists the ones plugged in
ame security pull-key lock        # the screen locks
ame security pull-key poweroff    # the computer powers off
ame security pull-key off
```

The same switch is in Security › Settings › Logins. Turning it on shows what it costs first and asks.

- The device is named by its vendor, product and **serial number**. A hub, and a device without a serial number of its
  own, cannot be told from others of its make, so they are not offered.
- **Allow the device first** if USB protection is on (`ame security usb allow`): a blocked device is never plugged in,
  so there is nothing to pull out.
- **Choose a device no program can make leave the bus**: a plain USB stick or a security key, not a phone or a development
  board. A program of your account that can reset the chosen device (a phone rebooting into its loader, a board taking a
  firmware command) can make it drop off the bus for a second, which locks every session on the computer, or powers it
  off, without anyone pulling it.
- One device only. To change it, run `ame security pull-key device` again.

## What it does and does not do

- **Lock** locks every session on the computer, as the lock key does. Plugging the device back in unlocks nothing. It
  relies on GNOME's lock screen: an account that turned the lock screen off (the `disable-lock-screen` setting) is not
  locked, and Security's report says so when the lock screen is turned off for the whole computer.
- **Power off** shuts the computer down in order, which saves what the system keeps, but it does not wait for an app
  that holds the shutdown back. What you had not saved is lost. If the disk is not encrypted, powering off only stops
  anyone using the computer: the disk can still be read ([disk encryption](disk-encryption.md)).
- It is a tether, not a key. The serial number of a device is no secret, and a device with the same number counts as
  yours. It does not tell you apart from anyone else holding the cord.
- It waits one second after the device goes: a loose plug or a hub that resets, and the device comes back, does
  nothing. It also does nothing while the computer is going to sleep, and for ten seconds after it wakes, when its USB
  devices are found again one by one. A device pulled out within those ten seconds after waking is not noticed.
- Any pull counts, whoever makes it and whatever the reason: a knocked cable locks the screen too.
- Off, there is no rule and nothing runs. Turning it off by any command (a profile, `amethystora-security-config`) takes the rule
  away; a key edited to off by hand in the settings file leaves it until the device is next pulled, which takes it away.

The AI agent may turn it on, never off, and never choose the device. Security's report names it under **Off unless you
turned it on**. It is not in the setup file, since the device is this machine's.
