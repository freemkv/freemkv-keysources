//! Pluggable AACS key sources for libfreemkv.
//!
//! libfreemkv owns the AACS crypto; this crate provides [`KeySource`] impls
//! that look a disc up and drive the boil-down primitives to terminal Unit
//! Keys: [`KeydbSource`] (local `keydb.cfg`) and [`OnlineSource`] (remote key
//! service). Applications choose and order sources, then resolve and hand
//! the key to `Disc::decrypt_with`; compose several with [`MultiSource`].
//! See docs/lib-scope.md for the mechanism-vs-policy split with libfreemkv.

mod keydb;
/// The `keydb.cfg` parser (`KeyDb`, `DiscEntry`, …). Public: parsing the keydb
/// is not secret — freemkv uses it, and so do tools that build a disc registry
/// from it (e.g. a per-disc Volume-ID index).
pub mod keydb_format;
mod online;
mod paths;

pub use keydb::{KeydbSource, UpdateResult};
pub use keydb_format::{DiscEntry, KeyDb};
pub use online::{
    DecodeReachability, MIN_SAMPLE_UNITS, OnlineSource, take_last_decode_reachability,
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
/// [`MultiSource::get_unit_keys`] tries each inner source in order and
/// returns the first non-empty Unit Key set (and
/// [`MultiSource::get_fmts_indexes`] does the same for the forensic set). The
/// caller supplies the list AND the order — local-first `[Keydb, Online]`,
/// online-first `[Online, Keydb]`, etc. `MultiSource` is itself a
/// [`KeySource`], so it nests and composes. See docs/lib-scope.md for the
/// `Err`-vs-`Ok(empty)` failure contract.
pub struct MultiSource {
    sources: Vec<Box<dyn KeySource>>,
}

impl MultiSource {
    /// Compose the given sources, tried in the order supplied.
    pub fn new(sources: Vec<Box<dyn KeySource>>) -> Self {
        Self { sources }
    }
}

// Drive `sources` in order, returning the first non-empty result and
// preserving Ok/Err when nothing resolves. `get` selects the trait method so
// the base and forensic paths share one implementation. See docs/lib-scope.md.
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

    // Forensic-index counterpart to `get_unit_keys`, same failure-preserving
    // rule. A source with no forensic material (keydb, via the trait default)
    // contributes empty and is skipped; today the online source answers.
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

#[cfg(test)]
mod tests {
    use super::*;
    use libfreemkv::aacs::types::HostCert;

    // A minimal KeySource that only supplies host certs — the sole MultiSource
    // behaviour under test. It never resolves a unit key.
    struct CertOnly {
        certs: Vec<HostCert>,
    }
    impl KeySource for CertOnly {
        fn get_unit_keys(&self, _ctx: &dyn ResolveCtx) -> Result<Vec<UnitKey>, libfreemkv::Error> {
            Ok(Vec::new())
        }
        fn host_certs(&self, _mkb: Option<u32>) -> Vec<HostCert> {
            self.certs.clone()
        }
    }

    // A host cert tagged with a distinct marker byte so a returned set can be
    // identified exactly. Synthetic bytes only; no real key material.
    fn cert(marker: u8) -> HostCert {
        HostCert {
            private_key: [marker; 20],
            certificate: vec![marker; 92],
            private_key_v2: None,
            certificate_v2: None,
        }
    }

    fn boxed(certs: Vec<HostCert>) -> Box<dyn KeySource> {
        Box::new(CertOnly { certs }) as Box<dyn KeySource>
    }

    /// `MultiSource::host_certs` must UNION every inner source's certs. Without
    /// this a composed source hides an inner source's cert from the OEM
    /// cert-auth route — the gap the union closes.
    #[test]
    fn multi_source_host_certs_unions_every_inner_source() {
        let multi = MultiSource::new(vec![
            boxed(vec![cert(0x01)]),
            boxed(vec![cert(0x02), cert(0x03)]),
        ]);
        let mut markers: Vec<u8> = multi
            .host_certs(Some(50))
            .iter()
            .map(|c| c.certificate[0])
            .collect();
        markers.sort_unstable();
        assert_eq!(
            markers,
            vec![0x01, 0x02, 0x03],
            "certs from every inner source must be unioned"
        );
    }

    /// With no inner source holding a cert, the union is empty (not an error).
    #[test]
    fn multi_source_host_certs_empty_when_no_source_has_one() {
        let multi = MultiSource::new(vec![boxed(vec![]), boxed(vec![])]);
        assert!(multi.host_certs(None).is_empty());
    }

    /// The `mkb` generation must reach each inner source so its OWN revocation
    /// filter can act; a source that drops everything at a given generation is
    /// honoured by the union.
    #[test]
    fn multi_source_host_certs_passes_mkb_through_to_inner_sources() {
        struct GenAware;
        impl KeySource for GenAware {
            fn get_unit_keys(
                &self,
                _c: &dyn ResolveCtx,
            ) -> Result<Vec<UnitKey>, libfreemkv::Error> {
                Ok(Vec::new())
            }
            fn host_certs(&self, mkb: Option<u32>) -> Vec<HostCert> {
                match mkb {
                    // Modelled on a cert revoked in MKBv72.
                    Some(g) if g >= 72 => Vec::new(),
                    _ => vec![cert(0xaa)],
                }
            }
        }
        let multi = MultiSource::new(vec![Box::new(GenAware) as Box<dyn KeySource>]);
        assert_eq!(multi.host_certs(Some(50)).len(), 1, "usable below gen 72");
        assert!(
            multi.host_certs(Some(72)).is_empty(),
            "the gen must reach the inner source's filter"
        );
    }
}
