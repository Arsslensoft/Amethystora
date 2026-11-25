# Governance

Amethystora is a small project with one maintainer, who is accountable for what ships. This page says
how decisions are made, so that they are predictable and so that the project can grow past one person.

## Roles

- **Owner and maintainer**: Arsslen Idadi ([@iarsslen](https://github.com/iarsslen)). Reviews and
  merges pull requests, decides what goes in, holds the image signing key, the Secure Boot key and the
  module signing key, and enforces the [Code of Conduct](CODE_OF_CONDUCT.md) and the
  [security policy](SECURITY.md).
- **Contributors**: anyone who opens an issue, a pull request, a translation, or helps another user.
  They follow [CONTRIBUTING.md](CONTRIBUTING.md).
- **Maintainers (more than one)**: the owner may invite regular, trusted contributors with write
  access. They review and merge, and answer for what they merge; they never hold the signing keys.

## How decisions are made

- **Pull requests** are merged through the merge queue once the required checks pass, every commit is
  signed off ([DCO](CONTRIBUTING.md#signing-off-dco)), the title follows Conventional Commits, every
  review thread is resolved and a code owner ([CODEOWNERS](.github/CODEOWNERS)) has approved.
- **Larger changes** (a feature, a new package source, a security default, a change to how the images
  are built or signed) are agreed in an issue first.
- **Disagreement** is settled by discussion on the issue or pull request, looking for what is best for
  the people who run Amethystora. If it isn't settled, the owner decides, and says why.
- **What never changes without the owner's explicit decision**: the licence; that images are signed and
  a machine takes only signed images; that every security feature is a switch the owner of the machine
  controls; and the absence of telemetry of Amethystora's own.

## Releases

Only `main` publishes. The stable images are built every week, and again when Fedora pushes a security
update; each build is signed with cosign, attested and published with its SBOM. A stable build is
tagged `stable-YYYYMMDD` and gets a release with its changelog.

## Becoming a maintainer

Contributors who have had several changes merged, reviewed others' work well, and kept to the rules
here may be invited by the owner. A maintainer who is inactive for a year, or who doesn't keep to the
Code of Conduct, loses write access, with thanks.

## Changing this page

By a pull request the owner approves.
