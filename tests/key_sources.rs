//! Fixture-based integration tests for the published key sources.
//!
//! These exercise the *public* surface of `freemkv-keysources` end-to-end —
//! real files on disk, the real `KeyDb`/`Mapfile` parsers from libfreemkv, and
//! the `KeySource` trait (`get_uk` over a `ResolveCtx`) the applications drive.
//!
//! Covered:
//! - `KeydbSource`: terminal unit-key lookup by disc hash through a real
//!   `keydb.cfg`; the exe-local path helpers; MKB-aware host-cert serving.
//! - `OnlineSource`: SSRF/scheme validation and the unconfigured no-op.
//! - `MultiSource`: caller-supplied ordering / precedence, host-cert UNION,
//!   and nesting.

use std::io::Write;
use std::path::{Path, PathBuf};

use freemkv_keysources::{
    DiscInputs, KeySource, KeydbSource, MultiSource, OnlineSource, UnitKey, default_keydb_path,
    existing_keydb_path, keydb_search_paths, validate_keyserver_url,
};
use libfreemkv::keysource::{DiscInputsCtx, ResolveCtx};

// ── fixture helpers ─────────────────────────────────────────────────────────

/// A unique scratch dir for one test, removed on `Drop` so fixtures never leak.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "fmk_ks_{}_{}_{:?}",
            tag,
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }

    fn write(&self, name: &str, body: &str) -> PathBuf {
        let p = self.0.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        p
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Bare `DiscInputs` keyed only by disc hash — the lookup key a keydb uses.
fn inputs(hash: &str) -> DiscInputs {
    DiscInputs {
        disc_hash: hash.into(),
        volume_id: [0u8; 16],
        mkb: Vec::new(),
        unit_key_ro: Vec::new(),
        samples: Vec::new(),
        volume_label: None,
    }
}

/// Resolve a source through the public trait over a `DiscInputsCtx`.
fn resolve(src: &dyn KeySource, inp: &DiscInputs) -> Vec<UnitKey> {
    let ctx = DiscInputsCtx::new(inp, 2);
    src.get_uk(&ctx)
        .expect("get_uk must not error for these fixtures")
}

// ── KeydbSource: real-file lookup by disc hash ──────────────────────────────

const DISC_HASH: &str = "0xaabbccddaabbccddaabbccddaabbccddaabbccdd";

/// A `keydb.cfg` with one per-disc entry carrying a **terminal** unit key (the
/// `U` token) plus a universal DK pool. The terminal UK path needs no on-disc
/// crypto inputs, so it round-trips through a bare `DiscInputs`.
fn keydb_with_unit_key() -> String {
    format!(
        "; fixture keydb\n\
         | DK | DEVICE_KEY 0x{dk} | DEVICE_NODE 0x0001 | KEY_UV 0x00000002 | KEY_U_MASK_SHIFT 0x00\n\
         {hash} = FIXTURE_DISC | U | 1-0x{uk}\n",
        dk = "22".repeat(16),
        hash = DISC_HASH,
        uk = "11".repeat(16),
    )
}

#[test]
fn keydb_source_resolves_terminal_unit_key_by_hash() {
    let s = Scratch::new("keydb_hit");
    let path = s.write("keydb.cfg", &keydb_with_unit_key());

    let src = KeydbSource::new(&path);
    let uks = resolve(&src, &inputs(DISC_HASH));
    assert_eq!(uks.len(), 1, "the disc's terminal unit key is resolved");
    assert_eq!(
        uks[0].key, [0x11u8; 16],
        "key bytes come straight from the keydb"
    );
    // CPS number 1 in the keydb → positional idx 0 (resolver re-adds the +1).
    assert_eq!(uks[0].idx, 0, "stored CPS num 1 maps to positional idx 0");
}

#[test]
fn keydb_source_hash_miss_yields_nothing() {
    let s = Scratch::new("keydb_miss");
    let path = s.write("keydb.cfg", &keydb_with_unit_key());

    let src = KeydbSource::new(&path);
    let uks = resolve(&src, &inputs("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"));
    assert!(
        uks.is_empty(),
        "a hash miss resolves no keys from the keydb"
    );
}

#[test]
fn keydb_source_missing_file_is_silent_ok_empty() {
    // A missing keydb is not an error — it simply offers no keys, so a later
    // source in the chain can still supply them.
    let src = KeydbSource::new("/nonexistent/path/keydb.cfg");
    let inp = inputs(DISC_HASH);
    let ctx = DiscInputsCtx::new(&inp, 2);
    assert!(
        src.get_uk(&ctx)
            .expect("missing keydb is Ok, not Err")
            .is_empty()
    );
}

#[test]
fn keydb_source_label_is_keydb() {
    assert_eq!(KeydbSource::new("/nonexistent/keydb.cfg").label(), "keydb");
}

// ── KeydbSource: MKB-aware host-cert serving from a file ────────────────────

#[test]
fn keydb_source_serves_host_cert_from_hc_row() {
    let s = Scratch::new("keydb_hc");
    // `| HC |` row with all-zero placeholder material (never a real key).
    let line = format!(
        "| HC | HOST_PRIV_KEY 0x{} | HOST_CERT 0x{}\n",
        "00".repeat(20),
        "00".repeat(92)
    );
    let path = s.write("keydb.cfg", &line);

    let src = KeydbSource::new(&path);
    // Inherent (no-MKB, scan-options) form.
    assert_eq!(
        src.host_certs().len(),
        1,
        "inherent host_certs sees the HC row"
    );
    // Trait form now wires the MKB generation through (no revocation annotation
    // → always returned).
    let via_trait = KeySource::host_certs(&src, Some(70));
    assert_eq!(via_trait.len(), 1, "trait host_certs sees the HC row");
    assert_eq!(via_trait[0].certificate.len(), 92);
}

#[test]
fn keydb_source_host_certs_empty_when_file_missing() {
    let src = KeydbSource::new("/nonexistent/keydb.cfg");
    assert!(src.host_certs().is_empty());
    assert!(KeySource::host_certs(&src, None).is_empty());
}

// ── path policy: exe-local, local-only ──────────────────────────────────────

fn expected_local() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("keydb.cfg")))
}

#[test]
fn search_paths_is_exactly_exe_local() {
    let paths = keydb_search_paths();
    match expected_local() {
        Some(expected) => assert_eq!(
            paths,
            vec![expected],
            "search list must be exactly [<exe dir>/keydb.cfg], no OS fallback"
        ),
        None => assert!(paths.is_empty(), "no exe dir → empty, never an OS fallback"),
    }
}

#[test]
fn default_path_matches_search_head() {
    assert_eq!(default_keydb_path(), expected_local());
    assert_eq!(
        default_keydb_path(),
        keydb_search_paths().into_iter().next()
    );
}

#[test]
fn existing_keydb_path_reflects_disk_state() {
    let head_exists = keydb_search_paths()
        .first()
        .map(|p| p.exists())
        .unwrap_or(false);
    assert_eq!(existing_keydb_path().is_some(), head_exists);
}

// ── OnlineSource: validation + unconfigured no-op (no network in CI) ─────────

#[test]
fn online_source_unconfigured_is_silent_no_op() {
    // Empty base URL → a clean "no service" empty, no network.
    let src = OnlineSource::new("", "");
    assert!(resolve(&src, &inputs(DISC_HASH)).is_empty());
}

#[test]
fn online_source_metadata() {
    let src = OnlineSource::new("https://example.invalid/keys", "tok");
    assert_eq!(src.label(), "online");
    // No host-cert serving today — a no-op empty, no network touched.
    assert!(KeySource::host_certs(&src, None).is_empty());
}

#[test]
fn validate_keyserver_url_gates_scheme_and_ssrf() {
    assert!(validate_keyserver_url("https://8.8.8.8/keys").is_ok());
    assert!(validate_keyserver_url("http://127.0.0.1/keys").is_err());
    // SSRF blocking is IP-based, not scheme-gated: https://<private-IP> is rejected too.
    assert!(validate_keyserver_url("https://127.0.0.1/keys").is_err());
    assert!(validate_keyserver_url("http://169.254.169.254/latest/meta-data/").is_err());
    assert!(validate_keyserver_url("http://[::1]:9000/keys").is_err());
    assert!(validate_keyserver_url("ftp://example.com/keys").is_err());
    assert!(validate_keyserver_url("").is_err());
}

// ── MultiSource: ordering, precedence, aggregation, nesting ─────────────────

/// A scripted source for composition tests: returns a fixed Unit Key set.
struct ScriptedSource {
    keys: Vec<UnitKey>,
    label: &'static str,
}

impl ScriptedSource {
    fn new(label: &'static str, keys: Vec<UnitKey>) -> Self {
        Self { keys, label }
    }
}

impl KeySource for ScriptedSource {
    fn get_uk(&self, _ctx: &dyn ResolveCtx) -> Result<Vec<UnitKey>, libfreemkv::Error> {
        Ok(self.keys.clone())
    }
    fn label(&self) -> &'static str {
        self.label
    }
}

fn uk(b: u8) -> UnitKey {
    UnitKey {
        idx: 0,
        key: [b; 16],
    }
}

#[test]
fn multi_source_first_non_empty_wins_in_caller_order() {
    // Caller supplies [A, B]; A is non-empty so A's keys win.
    let a = ScriptedSource::new("A", vec![uk(0xa1)]);
    let b = ScriptedSource::new("B", vec![uk(0xb1)]);
    let multi = MultiSource::new(vec![Box::new(a), Box::new(b)]);
    let got = resolve(&multi, &inputs("x"));
    assert_eq!(got, vec![uk(0xa1)], "A (first, non-empty) wins");
}

#[test]
fn multi_source_order_is_reversible() {
    // The SAME two sources in the opposite order yield the opposite precedence.
    let a = ScriptedSource::new("A", vec![uk(0xa1)]);
    let b = ScriptedSource::new("B", vec![uk(0xb1)]);
    let multi = MultiSource::new(vec![Box::new(b), Box::new(a)]);
    let got = resolve(&multi, &inputs("x"));
    assert_eq!(got, vec![uk(0xb1)], "B-first ordering wins");
}

#[test]
fn multi_source_skips_empty_sources() {
    // An empty source in front is transparently skipped to the next.
    let empty = ScriptedSource::new("empty", vec![]);
    let real = ScriptedSource::new("real", vec![uk(0xc1)]);
    let multi = MultiSource::new(vec![Box::new(empty), Box::new(real)]);
    assert_eq!(resolve(&multi, &inputs("x")), vec![uk(0xc1)]);
}

#[test]
fn multi_source_unions_host_certs() {
    // A real keydb (1 HC row) composed with a cert-less scripted source: the
    // composed `host_certs` must UNION — i.e. surface the keydb's cert (the gap
    // this migration fixes; previously a composed source hid inner certs).
    let s = Scratch::new("multi_hc");
    let line = format!(
        "| HC | HOST_PRIV_KEY 0x{} | HOST_CERT 0x{}\n",
        "00".repeat(20),
        "00".repeat(92)
    );
    let keydb = s.write("keydb.cfg", &line);

    let multi = MultiSource::new(vec![
        Box::new(ScriptedSource::new("plain", vec![])),
        Box::new(KeydbSource::new(&keydb)),
    ]);
    let certs = KeySource::host_certs(&multi, None);
    assert_eq!(
        certs.len(),
        1,
        "the inner keydb's cert must be visible through the union"
    );
}

#[test]
fn multi_source_nests() {
    // MultiSource is itself a KeySource, so it composes inside another. Inner
    // [empty, A] then outer B: A (first non-empty) wins.
    let inner = MultiSource::new(vec![
        Box::new(ScriptedSource::new("empty", vec![])),
        Box::new(ScriptedSource::new("A", vec![uk(0xa1)])),
    ]);
    let outer = MultiSource::new(vec![
        Box::new(inner),
        Box::new(ScriptedSource::new("B", vec![uk(0xb1)])),
    ]);
    assert_eq!(resolve(&outer, &inputs("x")), vec![uk(0xa1)]);
}

#[test]
fn multi_source_real_keydb_resolves_through_chain() {
    // End-to-end with the REAL keydb source over a fixture file inside a chain:
    // a no-key scripted source first, then the keydb that actually resolves.
    let s = Scratch::new("multi_real");
    let keydb = s.write("keydb.cfg", &keydb_with_unit_key());

    let multi = MultiSource::new(vec![
        Box::new(ScriptedSource::new("plain", vec![])),
        Box::new(KeydbSource::new(&keydb)),
    ]);
    let got = resolve(&multi, &inputs(DISC_HASH));
    assert_eq!(
        got.len(),
        1,
        "the keydb resolves the disc once the empty source is skipped"
    );
    assert_eq!(
        got[0].key, [0x11u8; 16],
        "the keydb's terminal UK is returned"
    );
}

/// The `Path`-typed constructor accepts a borrowed path.
#[test]
fn keydb_source_accepts_borrowed_path() {
    let s = Scratch::new("keydb_borrow");
    let path: &Path = &s.path("keydb.cfg");
    std::fs::write(path, keydb_with_unit_key()).unwrap();
    let src = KeydbSource::new(path);
    assert_eq!(resolve(&src, &inputs(DISC_HASH)).len(), 1);
}
