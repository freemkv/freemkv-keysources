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
//! Sources are dumb and stateful: each hands its candidate keys out one at a
//! time via [`KeySource::next_key`], in its own best order, and reports
//! exhaustion. Compose several with [`MultiSource`] in the caller's chosen
//! order. Resolving those candidates against a disc, and reading the encrypted
//! content-sample units a key server validates on, is decryption *mechanism* —
//! it lives in the library (`libfreemkv::resolve_and_apply`,
//! `libfreemkv::read_encrypted_units`), not here. A source only ever looks a key
//! up and hands it back; what's done with the key is not its concern.

mod keydb;
mod mapfile;
mod online;
mod paths;

pub use keydb::KeydbSource;
pub use mapfile::MapfileSource;
pub use online::{OnlineSource, validate_keyserver_url};
pub use paths::{default_keydb_path, existing_keydb_path, keydb_search_paths};

// Re-exported for downstream convenience so apps need only depend on this crate
// for the source-side types.
pub use libfreemkv::{DiscInputs, Key, KeySource};

/// An ordered composition of key sources, driven as one. `next_key` exhausts
/// the first source (one candidate per call), then the next, … then `None`.
/// **The caller supplies the list AND the order** — local-first `[Keydb,
/// Online]`, online-first `[Online, Keydb]`, resume `[Mapfile, Keydb]`, etc. —
/// so the "which sources, in what order" policy lives entirely with the
/// application, not the library. `MultiSource` is itself a [`KeySource`], so it
/// nests and composes.
pub struct MultiSource {
    sources: Vec<Box<dyn KeySource>>,
    idx: usize,
}

impl MultiSource {
    /// Compose the given sources, tried in the order supplied.
    pub fn new(sources: Vec<Box<dyn KeySource>>) -> Self {
        Self { sources, idx: 0 }
    }
}

impl KeySource for MultiSource {
    fn next_key(&mut self, inputs: &DiscInputs) -> Option<Key> {
        while self.idx < self.sources.len() {
            if let Some(key) = self.sources[self.idx].next_key(inputs) {
                return Some(key);
            }
            self.idx += 1; // this source is spent — advance to the next
        }
        None
    }

    fn needs_samples(&self) -> bool {
        self.sources.iter().any(|s| s.needs_samples())
    }

    fn errored(&self) -> bool {
        self.sources.iter().any(|s| s.errored())
    }
}
