# Games and Android apps

Neither comes set up, because each needs something the image keeps from apps that do not need it. One
command each sets them up, says first what it changes, and takes it all away again. The switches on
[Control](control.md)'s **Apps** page open the same commands in a terminal.

## Games

```bash
ame apps gaming        # asks first; ame apps gaming on sets it up without the menu
```

This installs **Steam** from Flathub, with **ProtonPlus**, which adds other versions of Proton, and two
tools Steam's games can use: the **MangoHud** overlay and Valve's **gamescope** compositor. It also offers
**Heroic**, for the Epic, GOG and Amazon stores, and **Lutris**, for games from anywhere else.

### What it grants

- **X11, to Steam and its launchers.** Every Flatpak is refused X11 here, because an app on X11 can read
  what you type into other X11 apps ([what Flatpak apps may not do](software.md#what-flatpak-apps-may-not-do)).
  Steam and the Windows games it runs through Proton draw on nothing else, so X11 is granted back to Steam
  and the launchers you add, for your account alone. The Security app's **Apps** page lists it
  ([App permissions](app-permissions.md)).
- **`/dev/uinput`, for Steam Input,** which makes every controller work in every game through a virtual
  controller. The image keeps it from apps, since a virtual keyboard can type into any window. Setting up
  gaming gives it back to whoever sits at the machine, and so to every app that may reach all of `/dev`, the
  Chromium browsers among them ([Switches](security-switches.md#switches), `ame security virtual-input`).
  Taking gaming away takes it back from the next restart, unless OpenTabletDriver still needs it.

### Launch options

In a game's **Properties** in Steam, under **Launch Options**:

| Launch option | Does |
| --- | --- |
| `mangohud %command%` | The overlay: frame rate, frame times, temperatures |
| `gamemoderun %command%` | The CPU's performance mode while the game runs, through GameMode |
| `gamescope -f -- %command%` | The game in its own compositor, full screen, which helps with games that dislike Wayland |

### Controllers

Game controllers need nothing set up: Xbox, PlayStation, Nintendo and Steam controllers, 8BitDo, and the
rest Steam knows of. Microsoft's wireless adapter for Xbox controllers needs Microsoft's firmware first,
`ame apps xbox-adapter on` ([Hardware](devices.md#game-controllers)).

### More launchers, or none

**Add another launcher** adds Heroic or Lutris later, and **Take it all away** uninstalls them all, with
their games, and takes back what was granted:

```bash
ame apps gaming launchers
ame apps gaming off
```

## Will it run?

The commonest disappointment after moving from Windows is an online game whose anti-cheat refuses Linux. Ask before
a long download. The answer comes from a community list of games and the state of their anti-cheat on Linux, Are We
Anti-Cheat Yet?, whose copy is in the image: asking reads no network.

```bash
ame apps will-it-run Elden Ring     # a name, or the list's own id (elden-ring)
```

Or type `game: elden ring` in the [search](search.md#settings-windows-and-more); `ame desktop search game off` turns
that off. When you open the installer of a game the list knows (Valorant, League of Legends, Roblox), the terminal
says the answer before it offers anything ([Windows programs](windows-programs.md)).

- **It says what the list says, and the day the entry changed.** *Supported*: it runs, because the maker turned the
  anti-cheat on for Linux or it works under Wine and Proton as it is. *Running*: it runs without harm to online play,
  but may need tinkering. *Planned*: the maker plans Linux support and has not yet. *Broken* and *Denied*: it does not
  run online, or the maker has said it will not.
- **It never says a game will run.** The list knows the anti-cheat, not your game, your graphics driver or the
  game's own bugs, and the maker can change a game in the next update. ProtonDB is the place for how a game plays.
- **A name that only resembles an entry is not an answer.** The list's closest entry is shown as that and nothing
  more: ask for it by its own name. A game the list lacks gets *The list does not say*.
- Steam, Heroic and Lutris have their own install buttons, which this cannot reach. Ask before you press them.

## While you play

A backup, a container upgrade or a banner in the middle of a game is what makes a computer feel unfit for gaming.
**While you play** keeps them out of the way and gives everything back when the game ends. It is off until you turn it on
(`ame apps gaming` offers it once), and Control's **Apps** page has the same switch:

```bash
ame desktop while-playing on     # or off
```

It reacts to a game that asks GameMode for its mode, as `gamemoderun %command%` in Steam's launch options does:

- **Banners wait.** They stay in the list, and the pill says how many when the game ends. Calls, alarms and urgent
  banners still come through.
- **The power mode is performance,** while you are plugged in only. On the battery it is left alone.
- **Your timed backup and the containers' upgrade wait,** six hours at most, even if the game never ends. One you start
  yourself still runs, the system update and the whole-machine scan are never held, and what was skipped runs after.

The pill shows **Playing**, and its card lists what is held. **Let them run** gives it all back while the game goes on.
Everything also goes back when the last game ends, when GameMode leaves and when the screen locks (the unlock looks
again). While the switch is off, nothing is listened to.

## A faster CPU scheduler for games

The kernel decides which program runs on which CPU core and for how long, and its own scheduler suits nearly
everything. A sched-ext scheduler is a small program the kernel hands that job to, and one made for a kind
of work can do it better:

```bash
ame system scheduler
```

| Scheduler | For |
| --- | --- |
| `kernel` | Everything: the kernel's own, and the default |
| `lavd` | Games, smooth while other work runs: made for gaming handhelds and laptops |
| `bpfland` | A desktop that stays responsive while something heavy builds or renders |
| `flash` | Steady timing, for audio and music work |

Control's **System** page offers the same four. The choice holds after a restart, and
`ame system scheduler kernel` puts the kernel's own back.

### If it goes wrong

If a sched-ext scheduler stops, the kernel takes over again by itself, so the worst one can do is make
things slower. If the kernel will not take the one chosen, the command shows what the loader said and leaves
the kernel's own in place.

## Android apps

```bash
ame apps android       # asks first; ame apps android on sets it up without the menu
```

**Waydroid** runs Android, LineageOS 20, in a container beside your desktop, and the Android apps you
install appear in the app grid like any other. Setting it up downloads Android from Waydroid's servers,
about a gigabyte.

### Getting apps

It comes without Google's apps and Play Store, whose apps come with Google's own terms: get apps from
F-Droid, or install an `.apk` you downloaded:

```bash
waydroid app install ~/Downloads/some-app.apk
```

### Starting and stopping it

Open **Waydroid** from the app grid; the first start takes a minute. Its container service runs as root, so
it is on only once you set it up, and you can stop it when you are not using it:

| Command | Does |
| --- | --- |
| `ame apps android start` | Start Android, and open it |
| `ame apps android stop` | Stop it, until you start it again |
| `ame apps android off` | Remove Android, with every app and everything saved in it |

Waydroid cannot draw with NVIDIA's driver, so on the NVIDIA images Android draws in software: fine for most
apps, slow for games.
