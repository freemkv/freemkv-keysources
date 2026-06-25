//! Fixture-based integration tests for the published key sources.
//!
//! These exercise the *public* surface of `freemkv-keysources` end-to-end —
//! real files on disk, the real `KeyDb`/`Mapfile` parsers from libfreemkv, and
//! the `KeySource` trait the applications drive — rather than the pure
//! `candidates_from` unit tests that already live next to the source code.
//!
//! Covered:
//! - `KeydbSource`: lookup by disc hash through a real `keydb.cfg` file; the
//!   exe-local `keydb_search_paths` / default / existing path helpers; host-cert
//!   serving from a `| HC |` row.
//! - `MapfileSource`: terminal `Key::Unit` read back from a rip mapfile's
//!   `# freemkv-uk:` header; one-shot exhaustion; missing-file silence.
//! - `OnlineSource`: SSRF/scheme validation and the unconfigured no-op (no
//!   network is touched in CI).
//! - `MultiSource`: caller-supplied ordering / precedence, exhaustion advance,
//!   `needs_samples`/`errored` aggregation, and nesting.

use std::io::Write;
use std::path::{Path, PathBuf};

use freemkv_keysources::{
    DiscInputs, Key, KeySource, KeydbSource, MapfileSource, MultiSource, OnlineSource,
    default_keydb_path, existing_keydb_path, keydb_search_paths, validate_keyserver_url,
};

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

/// Drain a source completely into the ordered list of candidates it yields.
/// `Key` does not implement `PartialEq`, so callers compare via [`tags`].
fn drain(src: &mut dyn KeySource, inp: &DiscInputs) -> Vec<Key> {
    let mut out = Vec::new();
    while let Some(k) = src.next_key(inp) {
        out.push(k);
    }
    out
}

/// A comparable fingerprint for a `Key` (which has no `PartialEq`): the variant
/// plus its first identifying byte, enough to assert ordering deterministically.
fn tag(k: &Key) -> (u8, u8) {
    match k {
        Key::Device(_) => (0, 0),
        Key::Processing(p) => (1, p.first().map(|b| b[0]).unwrap_or(0)),
        Key::Media(m) => (2, m.first().map(|b| b[0]).unwrap_or(0)),
        Key::Volume(v) => (3, v[0]),
        Key::Unit(u) => (4, u.first().map(|(_, b)| b[0]).unwrap_or(0)),
        // `Key` is #[non_exhaustive]; any future variant gets a distinct tag.
        _ => (255, 0),
    }
}

fn tags(ks: &[Key]) -> Vec<(u8, u8)> {
    ks.iter().map(tag).collect()
}

// ── KeydbSource: real-file lookup by disc hash ──────────────────────────────

const DISC_HASH: &str = "0xaabbccddaabbccddaabbccddaabbccddaabbccdd";

/// A `keydb.cfg` with one per-disc entry (VUK only) plus a universal DK pool.
/// `0xHASH = TITLE | V | 0xVUK` is the disc-entry shape libfreemkv parses.
fn keydb_with_disc_entry() -> String {
    format!(
        "; fixture keydb\n\
         | DK | DEVICE_KEY 0x{dk} | DEVICE_NODE 0x0001 | KEY_UV 0x00000002 | KEY_U_MASK_SHIFT 0x00\n\
         {hash} = FIXTURE_DISC | V | 0x{vuk}\n",
        dk = "22".repeat(16),
        hash = DISC_HASH,
        vuk = "11".repeat(16),
    )
}

#[test]
fn keydb_source_looks_up_disc_by_hash_from_file() {
    let s = Scratch::new("keydb_hit");
    let path = s.write("keydb.cfg", &keydb_with_disc_entry());

    let mut src = KeydbSource::new(&path);
    let cands = drain(&mut src, &inputs(DISC_HASH));

    // The disc's own VUK (hash hit) must be the FIRST candidate, ahead of the
    // universal device-key pool fallback.
    assert!(
        matches!(cands.first(), Some(Key::Volume(v)) if *v == [0x11u8; 16]),
        "per-disc VUK from the hash hit must rank first, got {cands:?}"
    );
    assert!(
        cands.iter().any(|k| matches!(k, Key::Device(_))),
        "the universal device-key pool is still offered as a fallback"
    );
}

#[test]
fn keydb_source_hash_miss_yields_only_universal_pool() {
    let s = Scratch::new("keydb_miss");
    let path = s.write("keydb.cfg", &keydb_with_disc_entry());

    // A different disc: no per-disc entry, so no Volume/Unit candidate — only
    // the universal DK pool the library walks against the disc's own MKB.
    let mut src = KeydbSource::new(&path);
    let cands = drain(
        &mut src,
        &inputs("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
    );

    assert_eq!(cands.len(), 1, "hash miss offers only the universal pool");
    assert!(matches!(cands[0], Key::Device(_)));
}

#[test]
fn keydb_source_missing_file_is_silent_not_errored() {
    // A missing keydb is not an error — it simply offers no candidates, so a
    // later source in the chain can still supply the key.
    let mut src = KeydbSource::new("/nonexistent/path/keydb.cfg");
    assert!(src.next_key(&inputs(DISC_HASH)).is_none());
    assert!(!src.errored(), "a missing keydb must not flag errored()");
}

#[test]
fn keydb_source_label_and_needs_samples() {
    let src = KeydbSource::new("/nonexistent/keydb.cfg");
    assert_eq!(src.label(), "keydb");
    // A keydb can hand out a terminal Key::Unit applied as-is, so it must demand
    // ciphertext samples for validation.
    assert!(src.needs_samples());
}

// ── KeydbSource: host-cert serving from a file ──────────────────────────────

#[test]
fn keydb_source_serves_host_cert_from_hc_row() {
    let s = Scratch::new("keydb_hc");
    // `| HC |` row with all-zero placeholder material (never a real key) — same
    // convention libfreemkv's own parse_host_cert test uses.
    let line = format!(
        "| HC | HOST_PRIV_KEY 0x{} | HOST_CERT 0x{}\n",
        "00".repeat(20),
        "00".repeat(92)
    );
    let path = s.write("keydb.cfg", &line);

    let src = KeydbSource::new(&path);
    // Both the inherent method and the trait method must surface the cert — the
    // OEM/AACS cert-auth route collects through the trait.
    let inherent = src.host_certs();
    let via_trait = KeySource::host_certs(&src);
    assert_eq!(inherent.len(), 1, "inherent host_certs sees the HC row");
    assert_eq!(via_trait.len(), 1, "trait host_certs sees the HC row");
    assert_eq!(via_trait[0].certificate.len(), 92);
}

#[test]
fn keydb_source_host_certs_empty_when_file_missing() {
    let src = KeydbSource::new("/nonexistent/keydb.cfg");
    assert!(src.host_certs().is_empty());
    assert!(KeySource::host_certs(&src).is_empty());
}

// ── path policy: exe-local, local-only ──────────────────────────────────────

/// The exe-local keydb path, computed the way the module does — under
/// `cargo test` `current_exe()` is the integration-test binary under `target/`.
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
    // The exe-local path almost certainly does not exist under target/ during a
    // test run; existing_keydb_path() returns Some only when the head path is
    // actually present on disk. Assert the two agree.
    let head_exists = keydb_search_paths()
        .first()
        .map(|p| p.exists())
        .unwrap_or(false);
    assert_eq!(existing_keydb_path().is_some(), head_exists);
}

// ── MapfileSource: persisted unit keys read back from a mapfile ─────────────

/// A minimal ddrescue-style mapfile carrying two persisted unit keys in its
/// `# freemkv-uk:` header plus one data line (the "current state" + region).
fn mapfile_with_keys() -> String {
    "# Rescue Logfile. Created by freemkv test\n\
     # freemkv-uk: 0:11111111111111111111111111111111\n\
     # freemkv-uk: 1:22222222222222222222222222222222\n\
     0x0 0x200 +\n"
        .to_string()
}

#[test]
fn mapfile_source_reads_persisted_unit_keys() {
    let s = Scratch::new("mapfile_keys");
    let path = s.write("rip.mapfile", &mapfile_with_keys());

    let mut src = MapfileSource::new(&path);
    // MapfileSource ignores DiscInputs — disc identity is implicit in the path.
    let first = src.next_key(&inputs("ignored"));
    match first {
        Some(Key::Unit(uks)) => {
            assert_eq!(
                uks,
                vec![(0u32, [0x11u8; 16]), (1u32, [0x22u8; 16])],
                "both persisted unit keys must be read back, in order"
            );
        }
        other => panic!("expected terminal Key::Unit from the mapfile, got {other:?}"),
    }
}

#[test]
fn mapfile_source_is_one_shot() {
    let s = Scratch::new("mapfile_oneshot");
    let path = s.write("rip.mapfile", &mapfile_with_keys());

    let mut src = MapfileSource::new(&path);
    assert!(
        src.next_key(&inputs("x")).is_some(),
        "first ask yields the UK set"
    );
    assert!(
        src.next_key(&inputs("x")).is_none(),
        "the mapfile holds exactly one UK set — a second ask is exhausted"
    );
}

#[test]
fn mapfile_source_missing_or_keyless_offers_nothing() {
    // Missing file: silent None, not an error.
    let mut missing = MapfileSource::new("/nonexistent/rip.mapfile");
    assert!(missing.next_key(&inputs("x")).is_none());
    assert!(!missing.errored());

    // A mapfile with NO freemkv-uk header (unresolved / VID-only): nothing.
    let s = Scratch::new("mapfile_keyless");
    let path = s.write(
        "rip.mapfile",
        "# Rescue Logfile. Created by freemkv test\n0x0 0x200 +\n",
    );
    let mut keyless = MapfileSource::new(&path);
    assert!(
        keyless.next_key(&inputs("x")).is_none(),
        "a keyless mapfile offers no candidate"
    );
}

// ── OnlineSource: validation + unconfigured no-op (no network in CI) ─────────

#[test]
fn online_source_unconfigured_is_silent_no_op() {
    // Empty base URL → a clean "no service" None, no network, not an error.
    let mut src = OnlineSource::new("", "");
    assert!(src.next_key(&inputs(DISC_HASH)).is_none());
    assert!(
        !src.errored(),
        "an unconfigured online source is not errored"
    );
}

#[test]
fn online_source_one_shot_after_unconfigured_ask() {
    let mut src = OnlineSource::new("", "");
    assert!(src.next_key(&inputs(DISC_HASH)).is_none());
    // `asked` latched — a second ask is a no-op None regardless.
    assert!(src.next_key(&inputs(DISC_HASH)).is_none());
}

#[test]
fn online_source_metadata() {
    let src = OnlineSource::new("https://example.invalid/keys", "tok");
    assert_eq!(src.label(), "online");
    assert!(
        src.needs_samples(),
        "the key service validates against ciphertext"
    );
    // No host-cert serving today — a no-op empty, no network touched.
    assert!(KeySource::host_certs(&src).is_empty());
}

#[test]
fn validate_keyserver_url_gates_scheme_and_ssrf() {
    // Public literal IP (no DNS) passes.
    assert!(validate_keyserver_url("https://8.8.8.8/keys").is_ok());
    // Internal / metadata / bad-scheme are rejected at config time.
    assert!(validate_keyserver_url("http://127.0.0.1/keys").is_err());
    assert!(validate_keyserver_url("http://169.254.169.254/latest/meta-data/").is_err());
    assert!(validate_keyserver_url("http://[::1]:9000/keys").is_err());
    assert!(validate_keyserver_url("ftp://example.com/keys").is_err());
    assert!(validate_keyserver_url("").is_err());
}

// ── MultiSource: ordering, precedence, aggregation, nesting ─────────────────

/// A scripted source for composition tests: yields its queued keys in order,
/// then None, and reports its configured `needs_samples`/`errored`.
struct ScriptedSource {
    queue: std::vec::IntoIter<Key>,
    needs_samples: bool,
    errored: bool,
    label: &'static str,
}

impl ScriptedSource {
    fn new(label: &'static str, keys: Vec<Key>) -> Self {
        Self {
            queue: keys.into_iter(),
            needs_samples: false,
            errored: false,
            label,
        }
    }
    fn with_needs_samples(mut self, v: bool) -> Self {
        self.needs_samples = v;
        self
    }
    fn with_errored(mut self, v: bool) -> Self {
        self.errored = v;
        self
    }
}

impl KeySource for ScriptedSource {
    fn next_key(&mut self, _inputs: &DiscInputs) -> Option<Key> {
        self.queue.next()
    }
    fn needs_samples(&self) -> bool {
        self.needs_samples
    }
    fn errored(&self) -> bool {
        self.errored
    }
    fn label(&self) -> &'static str {
        self.label
    }
}

fn vol(b: u8) -> Key {
    Key::Volume([b; 16])
}

#[test]
fn multi_source_preserves_caller_order() {
    // Caller supplies [A, B]; MultiSource must exhaust A fully before B,
    // preserving within-source order — the "which sources, in what order"
    // policy lives entirely with the caller.
    let a = ScriptedSource::new("A", vec![vol(0xa1), vol(0xa2)]);
    let b = ScriptedSource::new("B", vec![vol(0xb1)]);
    let mut multi = MultiSource::new(vec![Box::new(a), Box::new(b)]);

    let got = drain(&mut multi, &inputs("x"));
    assert_eq!(
        tags(&got),
        tags(&[vol(0xa1), vol(0xa2), vol(0xb1)]),
        "A is exhausted (in order) before B is consulted"
    );
}

#[test]
fn multi_source_order_is_reversible() {
    // The SAME two sources in the opposite order yield the opposite precedence —
    // proving the order is the caller's, not baked in.
    let a = ScriptedSource::new("A", vec![vol(0xa1)]);
    let b = ScriptedSource::new("B", vec![vol(0xb1)]);
    let mut multi = MultiSource::new(vec![Box::new(b), Box::new(a)]);

    let got = drain(&mut multi, &inputs("x"));
    assert_eq!(
        tags(&got),
        tags(&[vol(0xb1), vol(0xa1)]),
        "B-first ordering wins"
    );
}

#[test]
fn multi_source_skips_empty_sources() {
    // An empty source in the middle is transparently skipped to the next.
    let empty = ScriptedSource::new("empty", vec![]);
    let real = ScriptedSource::new("real", vec![vol(0xc1)]);
    let mut multi = MultiSource::new(vec![Box::new(empty), Box::new(real)]);

    assert_eq!(tags(&drain(&mut multi, &inputs("x"))), tags(&[vol(0xc1)]));
}

#[test]
fn multi_source_aggregates_needs_samples_and_errored() {
    // needs_samples / errored are OR-aggregated across the composed sources.
    let plain = ScriptedSource::new("plain", vec![]);
    let sampler = ScriptedSource::new("sampler", vec![]).with_needs_samples(true);
    let multi = MultiSource::new(vec![Box::new(plain), Box::new(sampler)]);
    assert!(
        multi.needs_samples(),
        "any source needing samples propagates"
    );

    let ok = ScriptedSource::new("ok", vec![]);
    let bad = ScriptedSource::new("bad", vec![]).with_errored(true);
    let multi2 = MultiSource::new(vec![Box::new(ok), Box::new(bad)]);
    assert!(multi2.errored(), "any errored source propagates");

    // All-clean composition reports neither.
    let c1 = ScriptedSource::new("c1", vec![]);
    let c2 = ScriptedSource::new("c2", vec![]);
    let clean = MultiSource::new(vec![Box::new(c1), Box::new(c2)]);
    assert!(!clean.needs_samples());
    assert!(!clean.errored());
}

#[test]
fn multi_source_nests() {
    // MultiSource is itself a KeySource, so it composes inside another
    // MultiSource — inner [A, B] then outer C: order A, B, C.
    let a = ScriptedSource::new("A", vec![vol(0xa1)]);
    let b = ScriptedSource::new("B", vec![vol(0xb1)]);
    let inner = MultiSource::new(vec![Box::new(a), Box::new(b)]);
    let c = ScriptedSource::new("C", vec![vol(0xc1)]);
    let mut outer = MultiSource::new(vec![Box::new(inner), Box::new(c)]);

    assert_eq!(
        tags(&drain(&mut outer, &inputs("x"))),
        tags(&[vol(0xa1), vol(0xb1), vol(0xc1)]),
        "nested MultiSource preserves the flattened caller order"
    );
}

#[test]
fn multi_source_real_keydb_then_mapfile_precedence() {
    // End-to-end precedence with the REAL sources over fixture files: a
    // keydb-first chain hands the keydb's per-disc VUK ahead of the mapfile's
    // terminal UK. (Resume chains flip this to [Mapfile, Keydb].)
    let s = Scratch::new("multi_real");
    let keydb = s.write("keydb.cfg", &keydb_with_disc_entry());
    let map = s.write("rip.mapfile", &mapfile_with_keys());

    let mut multi = MultiSource::new(vec![
        Box::new(KeydbSource::new(&keydb)),
        Box::new(MapfileSource::new(&map)),
    ]);
    let got = drain(&mut multi, &inputs(DISC_HASH));

    // First candidate is the keydb's VUK (hash hit), proving keydb precedes the
    // mapfile; the mapfile's terminal Unit appears later in the chain.
    assert!(
        matches!(got.first(), Some(Key::Volume(v)) if *v == [0x11u8; 16]),
        "keydb VUK leads the keydb-first chain, got {got:?}"
    );
    assert!(
        got.iter()
            .any(|k| matches!(k, Key::Unit(uks) if uks.contains(&(0u32, [0x11u8; 16])))),
        "the mapfile's terminal unit keys follow once the keydb is exhausted"
    );
    // KeydbSource needs samples → the composed chain demands them too.
    assert!(multi.needs_samples());
}

/// A keydb file that exists but exercises the `Path`-typed constructor with a
/// borrowed path (the apps pass `&Path`/`PathBuf` interchangeably).
#[test]
fn keydb_source_accepts_borrowed_path() {
    let s = Scratch::new("keydb_borrow");
    let path: &Path = &s.path("keydb.cfg");
    std::fs::write(path, keydb_with_disc_entry()).unwrap();
    let mut src = KeydbSource::new(path);
    assert!(src.next_key(&inputs(DISC_HASH)).is_some());
}
