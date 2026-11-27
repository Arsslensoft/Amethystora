# Sync and backups

Sync keeps a copy of the vault in an account of yours on a Kemlock Server, Vaultwarden or Bitwarden; the sealed backup keeps one
that only the recovery key opens.

## Sync

`ame vault sync connect ADDRESS` (or **Sync** in the window) connects one account, on a Kemlock Server or on a Vaultwarden or Bitwarden
server. From then on what the vault holds that syncs becomes items in that account, and the account's changes come back. It is **off** until you connect, and
from then on the address is on *What this machine sends* (`ame security sends`).

![The vault and your server](media/vault-sync-server.webm)

`ame vault sync status`, `now`, `off`, `kind KIND off|on` and `choose KIND ID on|off` do the rest.

### Kemlock Server

For a new connection the vault asks the server what it is: one that answers like a Kemlock Server is connected through its own API, with nothing to
choose. A connection stays on the API it has: one made through Bitwarden's API moves to Kemlock's only when you choose it, with
`ame vault sync connect ADDRESS kemlock` or **Move to Kemlock's own items** on the **Sync** page, which say first what it does and ask. A connection is one back end, a Kemlock Server or a Vaultwarden or Bitwarden one; `ame vault sync status` and **Sync** say which.
`ame vault sync connect ADDRESS bitwarden` uses the Bitwarden API of a Kemlock Server instead.

- **What syncs.** Every kind, plain, as Kemlock's own items (a login, a code, backup codes, an SSH key, a key, a certificate, a note),
  so the Kemlock app and web vault open what the vault wrote, and the vault opens what they wrote. **Every kind starts On but keys,
  certificates and protected files**, which start Off as on Vaultwarden and Bitwarden: connecting an account is no yes to sending a
  private key. Turn them On, and it asks first; turn any kind off the same way. A file goes as the item's own file, up to 16 MiB; a
  larger one stays here, with the reason on its page.
- **Signing in.** The master password makes a key with Argon2id and proves itself with OPAQUE, so the server never sees it. A key made
  with less work than Kemlock's default (64 MiB, three passes) is shown to you and asked about; far less is refused. A second step is
  an authenticator code, an email code (sent when asked for) or a recovery code, which turns the account's second steps off, so it says
  so first. Passkeys and single sign-on are not done. An account made through Bitwarden's API is enrolled the first time: the Bitwarden
  hash of the password is sent once to give it Kemlock keys, and the terminal says so.
- **The move.** Only when you choose it, items the vault already holds in an account as Bitwarden copies move to Kemlock's own items. They keep
  their ids; the Bitwarden copies are left on the server as they are and are not updated any more, so Bitwarden's apps and browser extension no
  longer see what changes; nothing is deleted. Keys, certificates and files that were Off stay Off until you turn them On. Turning a kind or an
  item off later removes from the server only the copies the vault made; what a Kemlock app made stays there.
- **Not done:** spaces, Sends, emergency access and live updates (the vault looks every 15 minutes, as it always does).
- **Tried** against Kemlock Server's own image. Bitwarden's extension does not read these items: open them in the Kemlock app or web vault.

### What goes, and how

Each kind is one switch, **Off** or **On**, one click each on the **Sync** page or
`ame vault sync kind KIND off|on` (`KIND` is `passwords`, `codes`, `backup-codes`, `keys`, `certificates` or `files`). Everything
goes as it is, plain: what Bitwarden has no item type for goes as a secure note. You are asked once for a kind, and its choice covers every item of it, those set to **Ask every time** and those added
later included. An item's own choice (its page, or `ame vault sync choose`) wins; choosing on an item's page what its kind does
takes the item's own away.

| In the vault | What Bitwarden's apps open | Until you choose |
|---|---|---|
| Password | A Login | On |
| Authenticator code | The `totp` of the matching Login, or a Login of its own | On |
| Backup codes | A secure note | On |
| Key | An SSH key item where the server keeps one; any other key a secure note with its private part in a hidden field | Off |
| Certificate | A secure note: the chain in its text, the private key in a hidden field, its kind and expiry as plain fields | Off |
| Protected file | A secure note named after it, the file as its attachment (a folder as a `.tar` of what it holds) | Off |

That is Vaultwarden and Bitwarden. On a Kemlock Server (above) every kind but keys, certificates and files is On from the start,
and each goes as Kemlock's own item.

- **Never sent**, whatever is chosen: non-exportable keys, the root, your CA's key, the recovery key and a hidden vault. This
  computer's identity certificate is not covered by the Certificates switch; only its own choice sends it.
- **Switching a kind or item** off takes what the vault wrote out of the server's copy: a note the
  vault made goes to the server's trash, and a Login another app made keeps its own folder and fields but loses the password,
  name and codes the vault wrote. Nothing is destroyed there.
- A file the server lost is sent again by `ame vault sync now accept`.

### What On means

- **On** is the account's own encryption alone: every client of the account opens it (Bitwarden's apps and browser extension, or
  the Kemlock apps), which is the point, and the server's encryption is all that protects it. An item changed in another app comes back; changed on both
  sides, both are kept. A note of ours that no longer reads as a key or certificate, or a key of another kind, is left as it is here
  and said, never deleted. An SSH key made in another app comes in as a key only while **Keys** is on; a certificate or file made
  elsewhere does not, since nothing says it is one.
- **There is no sealed choice any more.** Earlier versions could send an item as a note only this vault opens. A kind or item set
  that way **waits for you**: nothing of it is sent, and its note on the server is left as it is, since what you said yes to was a
  copy only this vault opens. `ame vault sync status` lists what waits. Turn it **On** (it asks first) and at the next sync the note is
  replaced by the item's plain form: the plain copy is written first, and only then the old note goes to the server's trash, never
  deleted; if the plain copy cannot be written, the note stays and the vault tries again. Turn it **Off** and the note goes to the
  trash while the item stays here. `ame vault sync kind keys sealed` says so.

### Files

On Vaultwarden and Bitwarden, files (anything larger than a note or field, and every protected file) are attachments of the item's
own note, made once and never changed: a changed file is a new item, and the old one goes to the server's trash. They go only to the server you connected,
never to a storage address a server names.

- Vaultwarden keeps them, with no limit but its own.
- Bitwarden's own servers keep files at a storage host this vault never contacts, so **there only what fits one note or field
  syncs**; the rest stays here, with the reason on the item's page. A Bitwarden server of your own needs premium.
- A Kemlock Server keeps them itself, up to 16 MiB each.
- If a server does not take files, or keeps them elsewhere, the vault says so, asks once and stays quiet until `ame vault sync now`.

### When it syncs, and what the server learns

- **Only while the vault is open**: on opening, a little after a change, and every 15 minutes. It waits on a metered connection.
  The vault is the source and the server a copy: a server that is down stops nothing.
- **Whoever opens the vault can reach that whole account**, because its key is kept in the vault. Use an account of its own for the
  vault. On Vaultwarden and Bitwarden the personal API key is the better login: no master-password hash is sent and no second step is asked;
  a master password is used once and not kept. A Kemlock Server has no such key: its password never leaves this computer.
- **The server learns** how many items there are, of which kind, how long each is and when it changed, not what is in them. Plain
  items are as unreadable to it as a password, but every app of the account opens them, and a tampering server can rearrange them
  or try to trick an app. Keep your most sensitive items **Off**, and use a server you trust.
- **A server with its own certificate authority** is trusted for this connection alone, by a fingerprint you compare first.

### When it stops and asks

- When many items go or come at once (five in one run, or a few a day for a week), or an account asks for more than 256 MiB of
  memory to make its key. Nothing is written until `ame vault sync now accept`.
- **Conflicts never lose anything.** Changed on both sides, both are kept, the server's marked. A deletion goes to each side's
  trash for 30 days. If many items vanish from the server at once, it stops and asks.

### Behind it, and what is not supported

- **A service in between.** The service holding your keys has no network. A second one, `amethystora-vault-net`, has the network and
  no key, sees only what the server sees, and reaches no host but yours.
- **Not supported:** organizations (their items are left alone), Bitwarden's newer encryption (the sync stops and writes nothing),
  folders and Send. **Last seen working:** Vaultwarden 1.37.5. Bitwarden's own server has never been tried here, and its protocol
  is not promised to a program like this one.

## Backing up and moving

The vault's files are in `/var/lib/amethystora/vault`, not your home, so neither the hourly snapshots nor the Backups app hold them,
and nothing of your account can delete or swap them.

- **A sealed backup.** `ame vault backup` (or **Back up now**) writes `~/.local/share/amethystora/vault-backup/vault-DATE.avb`:
  everything the vault holds, sealed so that **only the recovery key opens it**. A stolen backup has no password to guess, and
  writing one needs no open vault. The daily backup runs it before each run and keeps seven. It holds every vault, hidden ones too.
- **Restoring.** `ame vault restore FILE` asks for the recovery key, then for a new way to open the vault.
- **This computer's root and its CAs are in no backup.** A reinstalled computer has a new root, which whoever trusted the old one
  must be given. A restored vault keeps its old certificates and chain, still valid for whoever trusts the old root.
- `ame vault forget` removes every vault of your account, after you type `FORGET`.
- Your setup file and its backup never name the Vault, and an image's policy has nothing about it.
