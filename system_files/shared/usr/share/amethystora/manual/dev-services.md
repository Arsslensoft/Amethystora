# Services for a project

A database for a project, a cache, a mail catcher: one line each, in a container of your own, listening on this
computer only. No compose file, and nothing to clean up afterwards unless you want it.

```bash
ame dev service add postgres          # make it: nothing runs yet
ame dev service start postgres        # run it
ame dev service list                  # what you have, whether it runs, and where
```

## What you can add

| Name | What it is | Port |
| --- | --- | --- |
| `postgres` | PostgreSQL 18 | 5432 |
| `mariadb` | MariaDB 11.8 | 3306 |
| `valkey`, or `redis` | Valkey 9, which Redis clients talk to | 6379 |
| `mailpit` | A mail catcher: your program sends mail to it, and you read it in a browser | 1025 for mail, 8025 for the page |

`ame dev service add` with no name lists them. The second word names the one you make, so that a project can have its
own: `ame dev service add postgres shop`, then `start shop`. `--port 5440` picks the port; without it the usual one is
used, or the next free one when something holds it.

## What it makes

- **A container of your own.** podman runs it as you, never as root, from a file in
  `~/.config/containers/systemd`. It is yours to edit.
- **Loopback only.** The port is published on `127.0.0.1`, so a program on this computer reaches it and nothing on
  the network does.
- **Not at login.** It runs when you start it and stops when you stop it. `--at-login` starts it when you log in.
- **A password, if it needs one,** made when you add it and kept in `~/.config/amethystora/dev-services/NAME.env`, which only
  you can read. `list` and `start` say where the file is, and never print the password. PostgreSQL and MariaDB make a user
  and a database called `dev`.
- **Its data in a volume,** `amethystora-dev-NAME`, so that it survives `stop` and a restart.
- **An image pinned by digest.** The first `start` says what it pulls and how big it is (14 to 120 MB), and pulls that
  exact image.

```bash
ame dev service stop postgres
ame dev service remove postgres       # asks, in a terminal, before the data goes
```

`remove` takes the service away and, in a terminal, asks whether to delete its data too: type `DELETE` to delete it,
anything else keeps it. Without a terminal it never deletes data. Kept data keeps its password in the `.env` file, and
`ame dev service add` with the same name uses both again.

## Which program holds a port

```bash
ame dev ports                         # each port your programs and containers listen on
ame dev ports --json                  # the same, for a program
```

It lists the program, the project folder it runs in, and for a container its name and labels. A port a service of
yours holds is named as that service. Ports of other accounts and of the system show as "another account, or the
system", with nothing more: you can only look at your own.

Security's [watcher](security-watcher.md) looks at programs that listen beyond this computer. A service here listens on
`127.0.0.1` only, so it is never one of them; the same container published on every address would be.

## Where the images come from

Each is the maker's own image from Docker Hub, pulled by digest on your computer, never carried in the system:
PostgreSQL, MariaDB, Valkey (the open fork of Redis, under the BSD licence) and Mailpit (MIT). They are brought up to date
with the system's own updates, to the newest build of the same version. Moving to a new major version, PostgreSQL 19 for
instance, is a change of the system's, since it changes what the data on disk is.
