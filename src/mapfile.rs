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
use libfreemkv::{DiscInputs, Key, KeySource};

/// A [`KeySource`] backed by a rip mapfile's persisted unit keys.
pub struct MapfileSource {
    path: PathBuf,
    /// The mapfile holds exactly one (terminal) UK set, so it is read once —
    /// this flips true after the first `next_key`.
    asked: bool,
}

impl MapfileSource {
    /// A mapfile source reading the given `*.mapfile` path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            asked: false,
        }
    }
}

impl KeySource for MapfileSource {
    fn next_key(&mut self, _inputs: &DiscInputs) -> Option<Key> {
        if self.asked {
            return None;
        }
        self.asked = true;
        // A missing/unreadable/keyless mapfile simply offers nothing.
        let map = Mapfile::load(&self.path).ok()?;
        let uks = map.unit_keys();
        (!uks.is_empty()).then(|| Key::Unit(uks.to_vec()))
    }
}
