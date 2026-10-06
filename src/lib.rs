//! Pluggable AACS key sources for libfreemkv.
//!
//! libfreemkv owns the AACS crypto; this crate provides [`KeySource`] impls that look a disc up
//! and drive the boil-down primitives to terminal Unit Keys: [`KeydbSource`] (local
//! `keydb.cfg`) and [`OnlineSource`] (remote key service). Applications choose and order
//! sources, then resolve and hand the key to `Disc::decrypt_with`; compose several with
//! [`MultiSource`].

mod keydb;
/// The `keydb.cfg` parser (`KeyDb`, `DiscEntry`, …). Public: parsing the keydb
/// is not secret — freemkv uses it, and so do tools that build a disc registry
/// from it (e.g. a per-disc Volume-ID index).
pub mod keydb_format;
mod online;
mod paths;

pub use keydb::{KeydbSource, UpdateResult};
pub use keydb_format::{DiscEntry, KeyDb};
#[cfg(feature = "test-hooks")]
pub use online::set_last_decode_reachability;
pub use online::{
    DecodeReachability, KeyserverUrlFault, KeyserverUrlRejection, MIN_SAMPLE_UNITS, OnlineSource,
    check_keyserver_url, check_keyserver_url_static, take_last_decode_reachability,
    validate_keyserver_url,
};
pub use paths::{default_keydb_path, existing_keydb_path, keydb_search_paths};

// Re-exported for downstream convenience so apps need only depend on this crate
// for the source-side types.
pub use libfreemkv::aacs::types::UnitKey;
pub use libfreemkv::keysource::ResolveCtx;
pub use libfreemkv::{DiscInputs, KeySource};

// VUK -> the disc's terminal Unit Keys (positional index), one AES-ECB-decrypt
// per encrypted title key, via `aacs::derive::decrypt_unit_key`. Replaces the
// removed libfreemkv `aacs::boil::uk_from_vuk` wrapper.
pub(crate) fn uks_from_vuk(vuk: &[u8; 16], enc_title_keys: &[[u8; 16]]) -> Vec<UnitKey> {
    enc_title_keys
        .iter()
        .enumerate()
        .map(|(i, e)| UnitKey::new(i as u32, libfreemkv::aacs::derive::decrypt_unit_key(vuk, e)))
        .collect()
}

/// An ordered composition of key sources, driven as one.
///
/// [`MultiSource::get_unit_keys`] tries each inner source in order and returns the first
/// non-empty Unit Key set (and [`MultiSource::get_fmts_indexes`] does the same for the forensic
/// set). The caller supplies the list AND the order — local-first `[Keydb, Online]`,
/// online-first `[Online, Keydb]`, etc. `MultiSource` is itself a [`KeySource`], so it nests
/// and composes.
pub struct MultiSource {
    sources: Vec<Box<dyn KeySource>>,
}

impl MultiSource {
    /// Compose the given sources, tried in the order supplied.
    pub fn new(sources: Vec<Box<dyn KeySource>>) -> Self {
        Self { sources }
    }
}

// Drive `sources` in order, returning the first non-empty result and preserving Ok/Err when
// nothing resolves. `get` selects the trait method so the base and forensic paths share one
// implementation.
fn first_non_empty(
    sources: &[Box<dyn KeySource>],
    get: impl Fn(&dyn KeySource, &dyn ResolveCtx) -> Result<Vec<UnitKey>, libfreemkv::Error>,
    ctx: &dyn ResolveCtx,
) -> Result<Vec<UnitKey>, libfreemkv::Error> {
    let mut first_failure: Option<libfreemkv::Error> = None;
    for s in sources {
        match get(s.as_ref(), ctx) {
            Ok(uks) if !uks.is_empty() => return Ok(uks),
            Ok(_) => {}
            Err(e) => {
                if first_failure.is_none() {
                    first_failure = Some(e);
                }
            }
        }
    }
    match first_failure {
        // At least one source could not answer, and nothing else had a key: the
        // composition does NOT know that this disc has no key.
        Some(e) => Err(e),
        // Every source answered; none holds a key. The genuine miss.
        None => Ok(Vec::new()),
    }
}

impl KeySource for MultiSource {
    // First inner source to return a non-empty base Unit Key set wins. All
    // exhausted -> `Ok(empty)` if all answered, else the first failure (see
    // [`MultiSource`]).
    fn get_unit_keys(&self, ctx: &dyn ResolveCtx) -> Result<Vec<UnitKey>, libfreemkv::Error> {
        first_non_empty(&self.sources, |s, c| s.get_unit_keys(c), ctx)
    }

    // De-conflated counterpart: first inner source with keys wins; else the
    // richest miss survives composition (a MATCHED inner source beats a plain
    // miss). Same Err/Ok failure contract as `get_unit_keys`.
    fn resolve_unit_keys(
        &self,
        ctx: &dyn ResolveCtx,
    ) -> Result<libfreemkv::keysource::UnitKeyResolution, libfreemkv::Error> {
        let mut first_failure: Option<libfreemkv::Error> = None;
        let mut matched: Option<libfreemkv::keysource::UnitKeyResolution> = None;
        for s in &self.sources {
            match s.resolve_unit_keys(ctx) {
                Ok(r) if !r.keys.is_empty() => return Ok(r),
                Ok(r) => {
                    if r.matched && matched.is_none() {
                        matched = Some(r);
                    }
                }
                Err(e) => {
                    if first_failure.is_none() {
                        first_failure = Some(e);
                    }
                }
            }
        }
        if let Some(r) = matched {
            return Ok(r);
        }
        match first_failure {
            Some(e) => Err(e),
            None => Ok(libfreemkv::keysource::UnitKeyResolution::default()),
        }
    }

    // Forensic-index counterpart to `get_unit_keys`, same failure-preserving
    // rule. A source with no forensic material (keydb, via the trait default)
    // contributes empty and is skipped; today the online source answers.
    fn get_fmts_indexes(&self, ctx: &dyn ResolveCtx) -> Result<Vec<UnitKey>, libfreemkv::Error> {
        first_non_empty(&self.sources, |s, c| s.get_fmts_indexes(c), ctx)
    }

    /// UNION every inner source's host certs, in source order (`mkb` is passed
    /// through unchanged). Without this a composed source would hide an inner
    /// source's cert from the OEM cert-auth route — the gap this fixes.
    fn host_certs(&self, mkb: Option<u32>) -> Vec<libfreemkv::aacs::types::HostCert> {
        self.sources
            .iter()
            .flat_map(|s| s.host_certs(mkb))
            .collect()
    }

    fn label(&self) -> &'static str {
        "multi"
    }

    // KU3-6: depends on samples if ANY inner source does, so a nested
    // sample-dependent source keeps getting the per-piece ask.
    fn answer_depends_on_samples(&self) -> bool {
        self.sources.iter().any(|s| s.answer_depends_on_samples())
    }

    // Same `any(inner)` rule (KU-K1 review): `resolve` retries the composition
    // whenever any inner source's last failure was transport-class.
    fn last_failure_was_transport(&self) -> bool {
        self.sources.iter().any(|s| s.last_failure_was_transport())
    }

    // KU J23: any inner source that consumes the VID makes the composition one.
    fn uses_vid(&self) -> bool {
        self.sources.iter().any(|s| s.uses_vid())
    }
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
