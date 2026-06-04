//! Mapfile cache source (source #3).
//!
//! A rip's ddrescue-style mapfile persists the resolved unit keys in its
//! `# freemkv-uk:` header (written at sweep time when the disc was keyed). On
//! resume / deferred mux, that mapfile is the fastest source — the keys are
//! already resolved, no keydb parse and no network round-trip. This source
//! reads them back as a terminal [`Key::Unit`] candidate.
//!
//! It is keyed by the mapfile path (the disc identity is implicit in which
//! mapfile belongs to which rip), so it ignores [`DiscInputs`].

use std::path::PathBuf;

use libfreemkv::disc::mapfile::Mapfile;
use libfreemkv::{DiscInputs, Key, KeySource, Result};

/// A [`KeySource`] backed by a rip mapfile's persisted unit keys.
pub struct MapfileSource {
    path: PathBuf,
}

impl MapfileSource {
    /// A mapfile source reading the given `*.mapfile` path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl KeySource for MapfileSource {
    fn resolve(&self, _inputs: &DiscInputs) -> Result<Vec<Key>> {
        // A missing/unreadable/keyless mapfile simply offers nothing.
        let Ok(map) = Mapfile::load(&self.path) else {
            return Ok(Vec::new());
        };
        let uks = map.unit_keys();
        if uks.is_empty() {
            Ok(Vec::new())
        } else {
            Ok(vec![Key::Unit(uks.to_vec())])
        }
    }
}
