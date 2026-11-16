# Kits

Someone who does electronics, music or security work needs a dozen apps before the computer is theirs,
and has to know what they are called. A kit is that dozen, picked once, shown to you first and installed
in one go. Each app comes from Flathub, and a kit changes nothing else.

```bash
ame apps kit list             # the kits, and how much of each is here
ame apps kit show electronics # each app in it, and why
ame apps kit add electronics  # install what is missing, after showing it and asking
```

[Control](control.md)'s **Apps** page has the same list under **Kits**, with **Show** and **Add** on each.
Both open a terminal, since adding asks first.

## The kits

| Kit | For | Apps |
| --- | --- | --- |
| Electronics | Draw schematics, lay out circuit boards, simulate circuits and program microcontrollers | KiCad, LibrePCB, Arduino IDE, Qucs-S, QElectroTech, GTKWave, OpenSCAD |
| CAD and 3D printing | Design a part, slice it and print it | FreeCAD, OpenSCAD, LibreCAD, Blender, PrusaSlicer, OrcaSlicer, UltiMaker Cura |
| Music production | Record, arrange, mix and score music | Ardour, LMMS, Hydrogen, MuseScore, Audacity, Carla, qpwgraph |
| Streaming | Stream or record video, edit it and make the pictures around it | OBS Studio, Kdenlive, Easy Effects, Audacity, Inkscape, Krita, VLC |
| Game development | Make a game: the engine, the art, the levels and the sound | Godot Engine, Blender, Krita, Inkscape, Tiled, LibreSprite, Pixelorama, Audacity |
| Data science | Look at data, test an idea and draw the result | JASP, GNU Octave, LabPlot, Cantor, DB Browser for SQLite, DBeaver Community, QGIS |
| Security lab | Look at traffic, programs and web apps you have the right to test | Wireshark, ZAP, Ghidra, Cutter, ImHex, Boxes |

The apps are free software, picked for what the work needs, from those Flathub has. A kit is a starting
point: it is not a list of the only apps for the work, and you can add or remove any of them yourself.

## Adding a kit

`ame apps kit add electronics` shows the kit's name and what it is for, then each app with the reason it
is there. It then runs `ame setup apply` on the kit's file, which lists what it would install and asks
**Go ahead?** before anything is fetched. An app you have already, in the computer's installation or your
own, is left as it is, so adding a kit twice, or two kits that share an app, installs each app once. It
never takes anything away, and nothing is installed into the system image.

The apps are installed for every account on the computer, as Flathub's apps are, and update with the
rest. Like every Flatpak here they run without X11, and are sandboxed as
[Flatpak apps are](software.md#what-flatpak-apps-may-not-do).

## Taking a kit away

```bash
ame apps kit remove electronics
```

This lists the kit's apps that are installed and asks about each one, so that you keep what you use. An
app a second kit also names, or that you installed for yourself, is asked about like the rest; say no
and it stays. An app's data goes to the trash, and `ame apps undo-uninstall APP` brings the app and its
data back until the trash is emptied.

## What a kit does not hold

- **Libraries and command-line tools.** The data science kit has the apps; Python, R and Jupyter packages
  come from Homebrew or a container ([Packages from other distributions](containers.md)).
- **Anything that is not an app from Flathub:** no setting, no Homebrew package, no container and no
  remote. A kit is a [setup file](setup.md) with its apps part only, which is why `ame setup apply` reads it
  and refuses what it does not know.
- **Security that is not an app.** The security lab kit reads captures and takes programs apart. It
  turns on none of Amethystora's own protection and takes none away.

### Your own kit

Write the apps you want in a setup file, as [Your setup in a file](setup.md) describes, keep it in git and
run `ame setup apply FILE` on a new machine: that is how a kit from anyone else is used. The kits above are
the image's own and live in `/usr/share/amethystora/kits`.

## Questions

**An app is not in the kit I wanted.** The kits are short on purpose. Find the app in Bazaar, or with
`flatpak search`, and install it as any other.

**An install stopped part way.** Run the same command again: it installs what is still missing.
