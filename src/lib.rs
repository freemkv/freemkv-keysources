//! Pluggable AACS key sources for libfreemkv.
//!
//! libfreemkv performs no key lookup — it is handed a [`Key`] and derives down
//! the AACS chain to decrypt. This crate provides the published [`KeySource`]
//! implementations that do the lookup:
//!
//! - [`KeydbSource`] — a local `keydb.cfg` (source #1).
//! - [`OnlineSource`] — a remote key service (source #2).
//! - [`MapfileSource`] — the persisted unit key from a rip mapfile (source #3).
//!
//! Applications (autorip, the `freemkv` CLI) choose and order the sources from
//! their own config — the local-vs-online policy is just which impls they plug
//! in — then resolve and hand the resulting key to `Disc::decrypt_with`.
//!
//! Sources are dumb: they enumerate the raw material they hold as candidate
//! keys and do NO derivation or validation. The caller tries the candidates in
//! order and keeps the first that decrypts a sample ([`resolve_first`]).

mod keydb;
mod mapfile;
mod online;

pub use keydb::KeydbSource;
pub use mapfile::MapfileSource;
pub use online::OnlineSource;

// Re-exported for downstream convenience so apps need only depend on this crate
// for the source-side types.
pub use libfreemkv::{DiscInputs, Key, KeySource};

use libfreemkv::Result;

/// Try each source's candidate keys in order and return the first that the
/// `accept` predicate approves — the *validate-before-return* policy.
///
/// `accept` is the caller's validation (typically: clone the disc, apply the
/// key with `Disc::decrypt_with`, decrypt a sample sector, and check it looks
/// like cleartext). It lives with the caller because only the caller can read
/// disc content. A stale or wrong candidate is rejected and the next is tried,
/// so a wrong keydb entry transparently falls through to the next source.
///
/// `Ok(None)` means no source offered a candidate the validator accepted; an
/// `Err` from any source's `resolve` is propagated.
pub fn resolve_first<F>(
    sources: &[&dyn KeySource],
    inputs: &DiscInputs,
    mut accept: F,
) -> Result<Option<Key>>
where
    F: FnMut(&Key) -> bool,
{
    for src in sources {
        for key in src.resolve(inputs)? {
            if accept(&key) {
                return Ok(Some(key));
            }
        }
    }
    Ok(None)
}
