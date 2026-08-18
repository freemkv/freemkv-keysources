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
//! [`KeySource::get_unit_keys`], driving libfreemkv's boil-down crypto primitives for
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
pub use online::{MIN_SAMPLE_UNITS, OnlineSource, validate_keyserver_url};
pub use paths::{default_keydb_path, existing_keydb_path, keydb_search_paths};

// Re-exported for downstream convenience so apps need only depend on this crate
// for the source-side types.
pub use libfreemkv::aacs::types::UnitKey;
pub use libfreemkv::keysource::ResolveCtx;
pub use libfreemkv::{DiscInputs, KeySource};

/// VUK → the disc's terminal Unit Keys (positional index), one AES-ECB-decrypt
/// per encrypted title key. Composes the raw `aacs::derive::decrypt_unit_key`
/// primitive directly — replaces the removed libfreemkv `aacs::boil::uk_from_vuk`
/// wrapper (that veneer is gone; libfreemkv owns only the AES).
pub(crate) fn uks_from_vuk(vuk: &[u8; 16], enc_title_keys: &[[u8; 16]]) -> Vec<UnitKey> {
    enc_title_keys
        .iter()
        .enumerate()
        .map(|(i, e)| UnitKey::new(i as u32, libfreemkv::aacs::derive::decrypt_unit_key(vuk, e)))
        .collect()
}

/// An ordered composition of key sources, driven as one.
/// [`MultiSource::get_unit_keys`] tries each inner source in order and returns
/// the first non-empty Unit Key set (and [`MultiSource::get_fmts_indexes`] does
/// the same for the forensic set). **The caller supplies the list AND the
/// order** — local-first `[Keydb,
/// Online]`, online-first `[Online, Keydb]`, etc. —
/// so the "which sources, in what order" policy lives entirely with the
/// application, not the library. `MultiSource` is itself a [`KeySource`], so it
/// nests and composes.
///
/// **A source that could not ANSWER is not a source that answered "no key".**
/// When no inner source produces keys, the composition returns `Err` if any
/// inner source failed, and `Ok(empty)` only when every source genuinely
/// answered and none held a key. This mirrors libfreemkv's own resolver
/// (`keysource::drive_unit_keys`, which tracks an `errored` flag, and
/// `source_failure`, which stamps the first failure onto the disc) — a
/// composition that swallowed the `Err` would hand the resolver a clean
/// `Ok(empty)`, and an outage would once again be reported to the operator as
/// `E7022 No key source has a decryption key for this disc`.
pub struct MultiSource {
    sources: Vec<Box<dyn KeySource>>,
}

impl MultiSource {
    /// Compose the given sources, tried in the order supplied.
    pub fn new(sources: Vec<Box<dyn KeySource>>) -> Self {
        Self { sources }
    }
}

/// Drive `sources` in order and return the first non-empty result — preserving
/// the Ok/Err distinction when nothing resolves.
///
/// A source failure never BLOCKS the chain (a later source is still tried, and a
/// later success still wins outright, error or no error), but it is not
/// forgotten either: with no keys anywhere, the FIRST failure is returned. First
/// (not last) matches libfreemkv's `source_failure` rule, so the most-preferred
/// source's reason is the one the operator is told about, in the same order the
/// caller expressed a preference for successes.
///
/// `get` selects which trait method to drive, so the base and forensic paths
/// share ONE implementation of this rule and cannot drift apart — the forensic
/// half carried the identical bug.
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
    /// Try each inner source in order; the FIRST to return a non-empty base Unit
    /// Key set wins, even if an earlier source failed. All sources exhausted →
    /// `Ok(empty)` if they all ANSWERED, or the first source failure if any could
    /// not (see [`MultiSource`]).
    fn get_unit_keys(&self, ctx: &dyn ResolveCtx) -> Result<Vec<UnitKey>, libfreemkv::Error> {
        first_non_empty(&self.sources, |s, c| s.get_unit_keys(c), ctx)
    }

    /// Forensic-index counterpart: try each inner source's `get_fmts_indexes` in
    /// the same order and return the first non-empty set, under the same
    /// failure-preserving rule. A source with no forensic material (the keydb,
    /// via the trait default) contributes empty and is skipped; on today's discs
    /// the online source answers.
    fn get_fmts_indexes(&self, ctx: &dyn ResolveCtx) -> Result<Vec<UnitKey>, libfreemkv::Error> {
        first_non_empty(&self.sources, |s, c| s.get_fmts_indexes(c), ctx)
    }

    /// UNION every inner source's host certs (filtered at the given MKB
    /// generation). Without this a composed source would hide an inner source's
    /// cert from the OEM cert-auth route — the gap this fixes.
    fn host_certs(&self, mkb: Option<u32>) -> Vec<libfreemkv::aacs::types::HostCert> {
        self.sources
            .iter()
            .flat_map(|s| s.host_certs(mkb))
            .collect()
    }

    fn label(&self) -> &'static str {
        "multi"
    }
}
