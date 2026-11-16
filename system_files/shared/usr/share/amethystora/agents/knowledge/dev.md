# Developer helpers: a service in one line, the port that is taken, the card in a container

Written for AI agents. All of it runs as the user, in rootless podman, and none of it needs root.

## A database or a mail catcher for a project

`ame dev service add NAME [AS]` makes one, `start AS` runs it, `stop AS` stops it, `remove AS` takes it away, `list` shows
them (`--json` for you). NAME is `postgres`, `mariadb`, `valkey` (also `redis`) or `mailpit`; AS is what the person calls it.
Only `list` is yours to run (`ame dev service list --json`); `add`, `start`, `stop` and `remove` are the person's, since
they pull an image, run a container and delete data: hand the command over with `run`.

- It is a quadlet in `~/.config/containers/systemd/amethystora-dev-AS.container`, so the unit is
  `amethystora-dev-AS.service` in the user's manager, and `journalctl --user -u amethystora-dev-AS` says why it did not start.
- The port is published on `127.0.0.1` only, the usual port or the next free one (`--port N` picks). Nothing starts at
  login unless `--at-login` was given.
- The password, when the service has one, is in `~/.config/amethystora/dev-services/AS.env` (mode 0600). Never read it
  out or put it in a command line: tell the person where the file is.
- The data is in the podman volume `amethystora-dev-AS`. `remove` asks, in a terminal, before it deletes the data; without
  a terminal it keeps it, and a service made again with the same name takes the old password back.
- The images are the makers' own, pinned by digest in `/usr/share/amethystora/dev-services`. The first `start` pulls
  one (14 to 120 MB) and says so.

## Which program holds this port

`ame dev ports --json` lists the account's listening TCP ports: `port`, `address`, `scope` (`loopback`, `every-address`),
`program`, `folder` (the project folder, inside the home), `container` (`name`, `labels`, `service`) and `other_account`
(true for a port whose program only another account or the system can name). It reads only the user's own: another
account's port is a number and nothing more. Use it for "address already in use" before suggesting a kill.

## Does the graphics card work in a container

`ame dev gpu --json` goes from the cards to the host to a container and stops at the first step that fails; each step has
a sentence in `text` and, when there is one, the command in `fix`. It changes nothing. Plain `ame dev gpu` fetches
nothing; `--pull` and `--deep` fetch an image and are the person's. The playbook is `gpu-compute`.
