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

// A source whose `answer_depends_on_samples` is fixed to the given value —
// the only behaviour KSK2 exercises.
struct FixedDependency(bool);
impl KeySource for FixedDependency {
    fn get_unit_keys(&self, _ctx: &dyn ResolveCtx) -> Result<Vec<UnitKey>, libfreemkv::Error> {
        Ok(Vec::new())
    }
    fn answer_depends_on_samples(&self) -> bool {
        self.0
    }
}

// KSK2: `MultiSource::answer_depends_on_samples` is `any(inner)`, so nesting
// a sample-dependent online source under a sample-independent keydb still
// gets the per-piece ask (`resolve` must not treat the pair as keydb-only).
#[test]
fn multi_source_answer_depends_on_samples_is_any_inner() {
    let all_independent = MultiSource::new(vec![
        Box::new(FixedDependency(false)) as Box<dyn KeySource>,
        Box::new(FixedDependency(false)) as Box<dyn KeySource>,
    ]);
    assert!(!all_independent.answer_depends_on_samples());

    let keydb_then_online = MultiSource::new(vec![
        Box::new(FixedDependency(false)) as Box<dyn KeySource>,
        Box::new(FixedDependency(true)) as Box<dyn KeySource>,
    ]);
    assert!(keydb_then_online.answer_depends_on_samples());
}

// A source whose `uses_vid` is fixed to the given value.
struct FixedVid(bool);
impl KeySource for FixedVid {
    fn get_unit_keys(&self, _ctx: &dyn ResolveCtx) -> Result<Vec<UnitKey>, libfreemkv::Error> {
        Ok(Vec::new())
    }
    fn uses_vid(&self) -> bool {
        self.0
    }
}

// KU J23: like `answer_depends_on_samples`, a composed source uses the VID if any
// inner one does, so a nested online source still makes a Missing piece VID-derivable.
#[test]
fn multi_source_uses_vid_is_any_inner() {
    let neither = MultiSource::new(vec![
        Box::new(FixedVid(false)) as Box<dyn KeySource>,
        Box::new(FixedVid(false)) as Box<dyn KeySource>,
    ]);
    assert!(!neither.uses_vid());
    let keydb_then_online = MultiSource::new(vec![
        Box::new(FixedVid(false)) as Box<dyn KeySource>,
        Box::new(FixedVid(true)) as Box<dyn KeySource>,
    ]);
    assert!(keydb_then_online.uses_vid());
}

// A source whose `last_failure_was_transport` is fixed to the given value.
struct FixedTransport(bool);
impl KeySource for FixedTransport {
    fn get_unit_keys(&self, _ctx: &dyn ResolveCtx) -> Result<Vec<UnitKey>, libfreemkv::Error> {
        Ok(Vec::new())
    }
    fn last_failure_was_transport(&self) -> bool {
        self.0
    }
}

// For consistency with `answer_depends_on_samples` (KU3-6): a composed
// source's last-failure verdict is `any(inner)` too, so `resolve` retries
// the composition whenever ANY inner source's last failure was transport.
#[test]
fn multi_source_last_failure_was_transport_is_any_inner() {
    let none_transport = MultiSource::new(vec![
        Box::new(FixedTransport(false)) as Box<dyn KeySource>,
        Box::new(FixedTransport(false)) as Box<dyn KeySource>,
    ]);
    assert!(!none_transport.last_failure_was_transport());

    let one_transport = MultiSource::new(vec![
        Box::new(FixedTransport(false)) as Box<dyn KeySource>,
        Box::new(FixedTransport(true)) as Box<dyn KeySource>,
    ]);
    assert!(one_transport.last_failure_was_transport());
}

/// The `mkb` generation must reach each inner source so its OWN revocation
/// filter can act; a source that drops everything at a given generation is
/// honoured by the union.
#[test]
fn multi_source_host_certs_passes_mkb_through_to_inner_sources() {
    struct GenAware;
    impl KeySource for GenAware {
        fn get_unit_keys(&self, _c: &dyn ResolveCtx) -> Result<Vec<UnitKey>, libfreemkv::Error> {
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
