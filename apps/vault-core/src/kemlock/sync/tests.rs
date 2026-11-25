//! Runs against a Kemlock Server of our own (`fake.rs`): discovery, DPoP end to end, tokens, sign-in, every kind of item both ways
//! with the examples of `spec-items.md` section 4, the run (revisions, conflicts, tombstones, the signed manifest, files, the guard),
//! every attack a client can refuse, two clients on one account, and the move from Bitwarden's copies. A vault here is a map, applied
//! the way the service applies a run's groups (`tests/common.rs`).

mod attacks;
mod common;
mod discovery;
mod dpop_tokens;
mod engine_runs;
mod items_both_ways;
mod moving;
mod signing_in;
mod tokens;
