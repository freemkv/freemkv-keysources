//! Pluggable AACS key sources for libfreemkv.
//!
//! libfreemkv owns the AACS crypto; this crate provides the published
//! [`KeySource`] implementations that look a disc up and drive the boil-down
//! primitives down to terminal Unit Keys:
//!
//! - [`KeydbSource`] — a local `keydb.cfg` (source #1).
//! - [`OnlineSource`] — a remote key service (source #2).
//!
//! Applications (autorip, the `freemkv` CLI) choose and order the sources from
//! their own config — the local-vs-online policy is just which impls they plug
//! in — then resolve and hand the resulting key to `Disc::decrypt_with`.
//!
//! Each source resolves a disc's terminal **Unit Keys** in one shot via
//! [`KeySource::get_uk`], driving libfreemkv's boil-down crypto primitives for
//! whatever level of material it holds. Compose several with [`MultiSource`] in
//! the caller's chosen order. Reading the encrypted content-sample units a key
//! server validates on, and applying the resolved keys against a disc, is
//! decryption *mechanism* — it lives in the library
//! (`libfreemkv::resolve_and_apply`, `libfreemkv::read_encrypted_units`), not
//! here.

mod keydb;
/// The `keydb.cfg` parser (`KeyDb`, `DiscEntry`, …). Public: parsing the keydb
/// is not secret — freemkv uses it, and so do tools that build a disc registry
/// from it (e.g. a per-disc Volume-ID index).
pub mod keydb_format;
mod online;
mod paths;

pub use keydb::{KeydbSource, UpdateResult};
pub use keydb_format::{DiscEntry, KeyDb};
pub use online::{OnlineSource, validate_keyserver_url};
pub use paths::{default_keydb_path, existing_keydb_path, keydb_search_paths};

// Re-exported for downstream convenience so apps need only depend on this crate
// for the source-side types.
pub use libfreemkv::aacs::UnitKey;
pub use libfreemkv::keysource::ResolveCtx;
pub use libfreemkv::{DiscInputs, KeySource};

/// An ordered composition of key sources, driven as one. [`MultiSource::get_uk`]
/// tries each inner source in order and returns the first non-empty Unit Key
/// set. **The caller supplies the list AND the order** — local-first `[Keydb,
/// Online]`, online-first `[Online, Keydb]`, etc. —
/// so the "which sources, in what order" policy lives entirely with the
/// application, not the library. `MultiSource` is itself a [`KeySource`], so it
/// nests and composes.
pub struct MultiSource {
    sources: Vec<Box<dyn KeySource>>,
}

impl MultiSource {
    /// Compose the given sources, tried in the order supplied.
    pub fn new(sources: Vec<Box<dyn KeySource>>) -> Self {
        Self { sources }
    }
}

impl KeySource for MultiSource {
    /// Try each inner source in order; the FIRST to return a non-empty Unit Key
    /// set wins. An inner source that returns empty OR errors is treated as "no
    /// key here" and the next is tried (a single source failure never blocks the
    /// chain). All sources exhausted → empty.
    fn get_uk(&self, ctx: &dyn ResolveCtx) -> Result<Vec<UnitKey>, libfreemkv::Error> {
        for s in &self.sources {
            if let Ok(uks) = s.get_uk(ctx) {
                if !uks.is_empty() {
                    return Ok(uks);
                }
            }
        }
        Ok(Vec::new())
    }

    /// UNION every inner source's host certs (filtered at the given MKB
    /// generation). Without this a composed source would hide an inner source's
    /// cert from the OEM cert-auth route — the gap this fixes.
    fn host_certs(&self, mkb: Option<u32>) -> Vec<libfreemkv::aacs::HostCert> {
        self.sources
            .iter()
            .flat_map(|s| s.host_certs(mkb))
            .collect()
    }

    fn label(&self) -> &'static str {
        "multi"
    }
}
