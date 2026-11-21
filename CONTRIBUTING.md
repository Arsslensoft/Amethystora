# CONTRIBUTING

Thanks for helping out!

This repository builds the Amethystora images. Open an issue or pull request on [arsslensoft/amethystora](https://github.com/arsslensoft/amethystora).

Amethystora is based on [Universal Blue](https://universal-blue.org). Its desktop layer lives in this repository, under `system_files/shared`, and is not pulled from upstream, so changes to it are made here.

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/).

## Pull requests

A pull request merges once the maintainer has approved it, every review thread is resolved, and these checks
pass:

- **Lint**: `pre-commit` and ShellCheck on the files you changed, the `just` recipes' format, and the
  translations and manual checks the image build runs. `pre-commit run --all-files` and `just check` run
  the first ones on your machine.
- **Title**: the title is a Conventional Commit (`fix(dock): ...`), since it becomes the commit's subject
  when the pull request is squashed. A `feat` title is shown to users in What's new, so write it in plain
  words.
- **Dependencies**: nothing the change adds has a known serious vulnerability.
- **DCO**: every commit is signed off (below).
- **Licences**: the Rust crates built into the apps are under a licence `apps/deny.toml` allows, from crates.io.
  `cargo deny --manifest-path apps/Cargo.toml check licenses bans sources` runs it on your machine.
- **Security**: the change adds no workflow risk that `zizmor` finds and `main` does not have, no secret in its
  commits (`gitleaks`; a made-up one in a test is fine, elsewhere mark its line with `gitleaks:allow`), and no crate
  with a known advisory.
- **Lab**: the image is built from your change, installed on a virtual machine with Secure Boot and a TPM,
  signed in, and the smoke suites run in it (`tests/vm/README.md`, On GitHub), about an hour and a half. With the
  label `lab`, every suite runs, from the next push. A change to Markdown alone runs none.

CodeRabbit reviews every push. It requests changes while one of its findings that matters, or one of its
checks (the licences and credits, a test with every change of behaviour, the security defaults), is open, and
approves once they are settled: answer or fix each of its comments and resolve the thread. CodeQL scans the code
and the workflows. The six images are built for every pull request too, which takes about an hour.

### Signing off (DCO)

Each commit carries a `Signed-off-by:` line with your name and the address you commit with, by which you
certify the [Developer Certificate of Origin](https://developercertificate.org): that you wrote the change, or
otherwise have the right to submit it under the project's licence. `git commit -s` adds it; for commits made
already, `git rebase --signoff origin/main` and push again. Only a person can certify it: a coding agent never
signs off for you, so sign off its commits yourself once you have read them.

## Translating

Amethystora's own apps, the security report and the manual are meant to be translated on Weblate, but
the project there is not set up yet. Until it is, send a translation as a pull request that adds or
changes only the files of your language, in the places below.

What there is to translate, and how each is to be set up on Weblate:

| What | Weblate file format | File mask | Base or template file |
| --- | --- | --- | --- |
| Each app: `manual`, `security`, `update`, `logs`, `notes`, `control`, `backups` | JSON file (monolingual), with the flag `icu-message-format` | `system_files/shared/usr/lib/amethystora-<app>/resources/app/locale/*.json` | `.../locale/en.json` |
| The security report, the app permissions, the `ame` commands' prompts and messages, the notifications and the top bar widgets' menu | gettext PO file, with the "Update PO files to match POT (msgmerge)" add-on | `po/*.po` | `po/amethystora.pot` |
| The manual's pages | Markdown file, one component per page, found by the "Component discovery" add-on with `system_files/shared/usr/share/amethystora/manual/(?P<language>[^/]+)/(?P<component>[^/]+)\.md` | `system_files/shared/usr/share/amethystora/manual/*/<page>.md` | `system_files/shared/usr/share/amethystora/manual/<page>.md` |
| The hotkeys page, set up by hand because its English is one folder up | Markdown file | `system_files/shared/usr/share/amethystora/manual/*/keybindings.md` | `system_files/shared/usr/share/amethystora/keybindings.md` |

A few things to keep in mind when translating:

- The manual's `whats-new.md` is written by each build from its changes and is never translated: leave it out of
  Weblate (the build fails on a `manual/<language>/whats-new.md`).
- The apps' messages are ICU MessageFormat: keep `{name}` as it is, and give a plural every form your
  language has (`{count, plural, one {...} few {...} other {...}}`).
- The report's messages, the `ame` commands' and the notifications' are shell text: keep `${NAME}` as it is. A notification is translated for each account, in the language its owner chose, whichever service sent it. The states `ok`, `check` and `off` sit
  in a column seven letters wide.
- In the manual, keep commands, paths, key names and the targets of links (`updates.md#rolling-back`)
  exactly as they are: only what people read changes.

When the English changes, run `node build_files/shared/check-translations.js --write --po po
system_files/shared`, which rewrites each app's `locale/en.json` and `po/amethystora.pot` from the code,
and commit them with the change. The build runs the same check and fails on a catalog that does not
match the code.
