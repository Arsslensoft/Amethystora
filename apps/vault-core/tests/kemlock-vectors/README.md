# Kemlock test vectors

Known-answer vectors for the byte formats of Kemlock Server's `docs/crypto.md` (version 1), copied from the
`test-vectors/` folder of github.com/Arsslensoft/Kemlock-Server at commit
`05a71bbf2b36e80ccd9ac6c703816e14cf426e65`. They are public domain, [CC0-1.0](LICENSE): the server's own licence is
AGPL-3.0, and none of its code is here, only these files, which its README says any client may copy.

Only the files the Vault's personal client holds itself to are copied: `account-keys`, `argon2id`, `bundle`, `kem1`, `kx1`,
`legacy-ids`, `manifest`, `opaque`, `password-wrap`, `phrase`, `private-keys`, `sealed-box`, `sig1`, and `send` (for its
`KMA1` file). Every file is byte for byte the upstream's; `SHA256SUMS` lists the copies (`sha256sum -c SHA256SUMS`) and the
upstream lists the same sums. Update them by copying the files again, never by editing one.

`src/kemlock/vectors.rs` holds the code to every case, the cases that must be refused included.
