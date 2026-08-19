//! AACS Key Database parsing — KEYDB.cfg format.
//!
//! Byte-faithful copy of libfreemkv's `aacs::keydb` parser, relocated so the
//! keydb.cfg format lives with the key sources that consume it. The parsing
//! logic is identical; the only deviation is [`KeyDb::load`], which returns a
//! standalone [`std::io::Result`] here instead of `libfreemkv::error::Result`
//! (so the format crate carries no dependency on libfreemkv's error type).
//
// The parser is copied verbatim, so it carries the full KeyDb/DiscEntry API
// even though this crate's consumer (`keydb.rs`) only exercises a subset
// (`load`, `find_disc`, `iter_disc_entries`, and the public fields read by
// `KeydbSource::unit_keys_from` / `KeydbSource::host_certs`). NOTE: an earlier
// revision of this comment cited a `candidates_from` function — no such
// function has ever existed in this crate; the real consumer is
// `KeydbSource::unit_keys_from` (keydb.rs), which reads `unit_keys`, `vuk`,
// `media_key` AND `vid` (`vid` is load-bearing for the MK+VID derivation the
// kat_c / kat_d KATs pin — it is NOT unused). The genuinely unused items —
// `empty`, `find_vuk`, `DiscEntry::title` — are part of the faithful copy and
// are retained rather than pruned; allow dead_code so the byte-for-byte copy
// compiles clean without diverging from the libfreemkv original.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;

use libfreemkv::aacs::types::{DeviceKey, HostCert};

/// A keydb per-disc unit key: the CPS-unit number paired with its 16-byte key.
pub type NumberedUnitKey = (u32, [u8; 16]);

/// Upper bound on the on-disk keydb.cfg size accepted by [`KeyDb::load`].
/// The public UHD keydb is ~62 MiB and growing; 128 MiB is generous
/// headroom while still bounding the worst-case allocation from a hostile or
/// corrupt file.
const MAX_KEYDB_BYTES: u64 = 128 * 1024 * 1024;

/// Upper bound on parsed disc entries. The real public keydb carries
/// ~170k+ entries, so the cap sits well above that while still bounding
/// memory against a pathological input. Surplus lines are ignored.
const MAX_DISC_ENTRIES: usize = 500_000;

/// Parsed AACS key database.
///
/// NO `#[derive(Debug)]`: see the hand-written redacting impl below. The
/// derive dumped every processing key and all ~181k discs' key material into
/// any `{:?}`.
pub struct KeyDb {
    /// Device keys for MKB processing
    pub device_keys: Vec<DeviceKey>,
    /// Processing keys (pre-computed media keys for specific MKB versions)
    pub processing_keys: Vec<[u8; 16]>,
    /// Host certificate + private key for SCSI authentication, paired with the
    /// keydb's revocation metadata (libfreemkv's `HostCert` stays pure; the
    /// `Revoked in MKBv<N>` annotation is tracked in this crate).
    pub host_certs: Vec<KeydbHostCert>,
    /// Per-disc VUK entries indexed by disc hash (hex lowercase).
    ///
    /// The key is `Arc<str>` and is the SAME allocation as the entry's own
    /// [`DiscEntry::disc_hash`] — the map used to own a second `String` clone
    /// of every hash, ~13 MB of pure duplication across the real keydb's 181k
    /// entries (and now that [`crate::KeydbSource`] caches the parsed db for
    /// the process lifetime, that duplication is resident, not transient).
    /// `Arc<str>: Borrow<str>`, so lookups still take a plain `&str`.
    pub disc_entries: HashMap<Arc<str>, DiscEntry>,
}

// Key material must never reach a log, a panic message, or a bug report. Both
// types below carry raw AACS key bytes, and both are public API, so a
// `#[derive(Debug)]` on either is a leak of the crown jewels: `{:?}` on a
// loaded `KeyDb` printed every processing key plus every disc's Media Key,
// VID, VUK and Unit Keys. libfreemkv's equivalent types (`aacs::types`:
// `DeviceKey`, `HostCert`, `Vid`, `MediaKey`, `Vuk`, `ProcessingKey`,
// `UnitKey`, its own `DiscEntry`) all hand-write a redacting `Debug` for
// exactly this reason; this crate's copy of the parser dropped that
// convention when it was relocated. These restore it, field-for-field in the
// same style (`<redacted>` for key bytes, a `_len` for key-bearing
// collections). Pinned by `keydb_debug_is_redacted` /
// `disc_entry_debug_is_redacted`.

impl std::fmt::Debug for KeyDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyDb")
            .field("device_keys_len", &self.device_keys.len())
            .field("processing_keys_len", &self.processing_keys.len())
            .field("host_certs_len", &self.host_certs.len())
            .field("disc_entries_len", &self.disc_entries.len())
            .finish()
    }
}

impl std::fmt::Debug for DiscEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiscEntry")
            .field("disc_hash", &self.disc_hash)
            .field("title", &self.title)
            .field("media_key", &self.media_key.map(|_| "<redacted>"))
            .field("vid", &self.vid.map(|_| "<redacted>"))
            .field("vuk", &self.vuk.map(|_| "<redacted>"))
            .field("unit_keys_len", &self.unit_keys.len())
            .field("mkb_version", &self.mkb_version)
            .field("volume_size", &self.volume_size)
            .field("is_uhd", &self.is_uhd)
            .finish()
    }
}

/// A keydb host certificate together with its revocation generation.
///
/// libfreemkv's [`HostCert`] is intentionally crypto-pure and carries no
/// revocation state; the keydb's `; Revoked in MKBv<N>` comment is parsed
/// here and stored alongside the cert so callers can filter by MKB generation
/// without modifying the library type.
#[derive(Debug, Clone)]
pub struct KeydbHostCert {
    /// The pure libfreemkv host certificate + private key(s).
    pub cert: HostCert,
    /// The MKB generation at which this host cert was revoked, parsed from a
    /// `; Revoked in MKBv<N>` comment. `None` when the cert carries no such
    /// annotation (treated as never-revoked).
    pub revoked_at_mkb: Option<u32>,
}

/// A per-disc entry from the key database.
///
/// NO `#[derive(Debug)]`: see the hand-written redacting impl above.
#[derive(Clone)]
pub struct DiscEntry {
    /// Disc hash (20 bytes, hex). `Arc<str>` so the entry and the
    /// [`KeyDb::disc_entries`] key that points at it share ONE allocation
    /// instead of two.
    pub disc_hash: Arc<str>,
    /// Disc title
    pub title: String,
    /// Media Key (16 bytes) — from MKB processing
    pub media_key: Option<[u8; 16]>,
    /// Volume ID — the AACS VID (the keydb `I` token), 16 bytes. NOT the disc's
    /// identity (that's `disc_hash`); this is the per-disc Volume ID used to
    /// derive the VUK.
    pub vid: Option<[u8; 16]>,
    /// Volume Unique Key (16 bytes) — decrypts title keys
    pub vuk: Option<[u8; 16]>,
    /// Unit keys (title keys) indexed by CPS unit number
    pub unit_keys: Vec<NumberedUnitKey>,
    /// MKB version parsed from the trailing `; MKBv<N>` comment, if present.
    pub mkb_version: Option<u32>,
    /// Volume size in bytes parsed from `VolumeSize: <N>` in the comment.
    pub volume_size: Option<u64>,
    /// True if the comment contains the literal `(UHD)` flag.
    pub is_uhd: bool,
}

/// Parse a hex string like "0xABCD..." into bytes.
///
/// Operates on bytes, not `&str` char boundaries: the keydb is
/// third-party content, so a non-ASCII scalar (e.g. a 4-byte UTF-8
/// codepoint) must not panic on a mid-codepoint slice. Any non-hex
/// byte yields `None`.
pub(crate) fn parse_hex(s: &str) -> Option<Vec<u8>> {
    // The one workspace hex parser (strips an optional 0x/0X, byte-based).
    libfreemkv::hex::parse_hex_bytes(s)
}

/// Read the run of consecutive ASCII decimal digits immediately following the
/// first occurrence of `marker` in `text`, parsing them with `parse`.
///
/// Operates on raw bytes so untrusted third-party comment text (which may carry
/// non-ASCII scalars) never panics on a char boundary. Returns `None` when the
/// marker is absent or no digits follow it. Whitespace between the marker and
/// the digits is skipped, so this serves both `MKBv<N>` (no gap) and
/// `VolumeSize: <N>` (a space before the number).
fn parse_digits_after<T: std::str::FromStr>(text: &str, marker: &str) -> Option<T> {
    let bytes = text.as_bytes();
    let start = text.find(marker)? + marker.len();
    let mut i = start;
    // Skip any whitespace between the marker and the digits.
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    let digit_start = i;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i == digit_start {
        return None;
    }
    // The digit run is pure ASCII, so this slice is a valid str.
    std::str::from_utf8(&bytes[digit_start..i])
        .ok()?
        .parse()
        .ok()
}

/// Parse the host-cert revocation generation from a `Revoked in MKBv<N>`
/// comment on a `| HC |`/`| HC2 |` line. `None` when absent.
fn parse_revoked_at_mkb(line: &str) -> Option<u32> {
    parse_digits_after(line, "Revoked in MKBv")
}

/// Parse hex into a fixed-size array.
pub(crate) fn parse_hex16(s: &str) -> Option<[u8; 16]> {
    libfreemkv::hex::parse_hex_fixed::<16>(s)
}

pub(crate) fn parse_hex20(s: &str) -> Option<[u8; 20]> {
    libfreemkv::hex::parse_hex_fixed::<20>(s)
}

/// What [`KeyDb::parse`] threw away, by reason.
///
/// The parser is fed a THIRD-PARTY file: a mirror can serve a truncated or
/// byte-shifted download that is still valid UTF-8, still contains enough
/// recognisable rows to pass `KeydbSource::save`'s "at least one entry" check,
/// and is then atomically committed as the new keydb — after which every disc
/// past the corruption point silently resolves nothing. Before this counter,
/// each malformed `| DK` / `| PK` / `| HC` / `| HC2` / `0x…` row was dropped by
/// an `if let Some(..) = .. { }` with no `else`, no counter and no log, so that
/// file was indistinguishable from a healthy one at every layer above.
///
/// The counts are logged ONCE per parse (a per-line log would be 181k lines on
/// a real keydb, which is why the rate limit is "one summary", never "hide the
/// count").
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ParseStats {
    /// `| DK` rows that parsed as neither a positioned nor an orphan device key.
    pub dk_rejected: usize,
    /// `| PK` rows whose key field did not yield 16 bytes.
    pub pk_rejected: usize,
    /// `| HC` rows rejected (bad hex, short cert, missing field).
    pub hc_rejected: usize,
    /// `| HC2` rows rejected (bad hex, wrong priv length, short cert).
    pub hc2_rejected: usize,
    /// `0x… = …` disc rows the field parser refused outright.
    pub disc_rejected: usize,
    /// Disc rows dropped because [`MAX_DISC_ENTRIES`] was already reached.
    pub disc_over_cap: usize,
    /// Disc rows that REPLACED an earlier row with the same hash (last wins).
    /// Not necessarily corruption, but never something to discover silently:
    /// a duplicated hash means one of the two rows' keys is now unreachable.
    pub disc_duplicate: usize,
}

impl ParseStats {
    /// Total rows the parser refused. Excludes duplicates, which were parsed
    /// successfully and merely overwrote a sibling.
    fn rejected(&self) -> usize {
        self.dk_rejected
            + self.pk_rejected
            + self.hc_rejected
            + self.hc2_rejected
            + self.disc_rejected
            + self.disc_over_cap
    }

    /// Emit the one summary line, if there is anything to say. Returns whether
    /// a line was emitted — the only way a test can observe the warning without
    /// a `tracing` subscriber dependency, and the seam
    /// [`crate::KeydbSource::cached_db`] counts to prove the warning survives
    /// the cache.
    ///
    /// `pub(crate)` because [`crate::KeydbSource`] re-emits it on a CACHE HIT
    /// too: the cache short-circuits `parse`, so without that the corruption
    /// summary for a given file fired once per process and a long-running daemon
    /// went on serving the damaged keydb in silence forever after.
    pub(crate) fn log(&self) -> bool {
        if self.rejected() == 0 && self.disc_duplicate == 0 {
            return false;
        }
        tracing::warn!(
            target: "freemkv::keysource",
            dk_rejected = self.dk_rejected,
            pk_rejected = self.pk_rejected,
            hc_rejected = self.hc_rejected,
            hc2_rejected = self.hc2_rejected,
            disc_rejected = self.disc_rejected,
            disc_over_cap = self.disc_over_cap,
            disc_duplicate = self.disc_duplicate,
            "keydb.cfg lines were rejected while parsing; the file may be truncated or corrupt (keys past the damage will not resolve)"
        );
        true
    }
}

/// True when `line` opens a per-disc row. The `0x` prefix is matched
/// CASE-INSENSITIVELY: `parse_hex` in this same file deliberately tolerates
/// `0x` and `0X` (and is tested for it), so a case-sensitive `starts_with("0x")`
/// here would drop an uppercase `0X…` disc row on the floor with no diagnostic
/// while every other hex field in the format accepted it. Shared with
/// `KeydbSource::save`, whose entry count must stay in EXACT lockstep with what
/// this parser accepts.
pub(crate) fn is_disc_entry_line(line: &str) -> bool {
    (line.starts_with("0x") || line.starts_with("0X")) && line.contains(" = ")
}

impl KeyDb {
    /// Construct an empty KeyDb. Used by unit tests; production code
    /// reaches a populated KeyDb via [`KeyDb::load`] or [`KeyDb::parse`].
    pub fn empty() -> Self {
        KeyDb {
            device_keys: Vec::new(),
            processing_keys: Vec::new(),
            host_certs: Vec::new(),
            disc_entries: HashMap::new(),
        }
    }

    /// Parse a KEYDB.cfg file from a string.
    ///
    /// Lines the parser cannot use are counted and summarised in ONE
    /// `tracing::warn!` (see [`ParseStats`]) — they are never dropped silently.
    pub fn parse(data: &str) -> Self {
        let (db, stats) = Self::parse_counted(data);
        stats.log();
        db
    }

    /// [`Self::parse`] without the log — the seam the rejection-counting tests
    /// assert on (a `tracing` subscriber would be the only other way to observe
    /// a count, and the count is the thing under test, not its formatting).
    pub(crate) fn parse_counted(data: &str) -> (Self, ParseStats) {
        let mut stats = ParseStats::default();
        let mut db = KeyDb {
            device_keys: Vec::new(),
            processing_keys: Vec::new(),
            host_certs: Vec::new(),
            disc_entries: HashMap::new(),
        };

        for line in data.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
                continue;
            }

            // Device Key.
            // Two shapes are accepted:
            //   1. Positioned DK: `| DK | DEVICE_KEY 0x... | DEVICE_NODE 0x... | KEY_UV 0x... | KEY_U_MASK_SHIFT 0x...`
            //      → loaded into `device_keys` (deterministic tree walk via `calc_pk_from_dk`).
            //   2. Orphan DK: `| DK | DEVICE_KEY 0x...` with no position fields.
            //      → loaded into `processing_keys` (brute walker / terminal validation).
            // Per AACS spec a "PK" IS a DK at terminal position, so both row types
            // are DKs in the unified model; only the metadata differs.
            if line.starts_with("| DK") {
                if let Some(dk) = Self::parse_device_key(line) {
                    db.device_keys.push(dk);
                } else if let Some(key) = Self::parse_orphan_dk(line) {
                    db.processing_keys.push(key);
                } else {
                    stats.dk_rejected += 1;
                }
                continue;
            }

            // Processing Key
            if line.starts_with("| PK") {
                if let Some(pk) = Self::parse_processing_key(line) {
                    db.processing_keys.push(pk);
                } else {
                    stats.pk_rejected += 1;
                }
                continue;
            }

            // Host Certificate (AACS 2.0).
            //
            // An HC2 row normally augments the preceding HC (AACS 1.0) row.
            // KEYDB line ordering is third-party, so an HC2 row may appear
            // before any HC row; rather than silently dropping the AACS 2.0
            // credentials, carry them on a fresh HostCert with an empty v1
            // cert (the v1 private_key/certificate stay zero/empty and are
            // ignored by the v1 handshake, which guards on cert length).
            if line.starts_with("| HC2") {
                if let Some((pk, cert, revoked_at_mkb)) = Self::parse_host_cert_v2(line) {
                    if let Some(hc) = db.host_certs.last_mut() {
                        hc.cert.private_key_v2 = Some(pk);
                        hc.cert.certificate_v2 = Some(cert);
                        // The `; Revoked in MKBv<N>` annotation can live on the
                        // HC2 line rather than the preceding HC line; carry it
                        // onto the combined cert if the HC line had none, so the
                        // revocation isn't silently dropped.
                        if hc.revoked_at_mkb.is_none() {
                            hc.revoked_at_mkb = revoked_at_mkb;
                        }
                    } else {
                        db.host_certs.push(KeydbHostCert {
                            cert: HostCert {
                                private_key: [0u8; 20],
                                certificate: Vec::new(),
                                private_key_v2: Some(pk),
                                certificate_v2: Some(cert),
                            },
                            revoked_at_mkb,
                        });
                    }
                } else {
                    stats.hc2_rejected += 1;
                }
                continue;
            }

            // Host Certificate (AACS 1.0)
            if line.starts_with("| HC") {
                if let Some(hc) = Self::parse_host_cert(line) {
                    db.host_certs.push(hc);
                } else {
                    stats.hc_rejected += 1;
                }
                continue;
            }

            // Disc entry: starts with 0x / 0X (see `is_disc_entry_line`).
            if is_disc_entry_line(line) {
                // The cap is a memory bound against a pathological file, but
                // hitting it means real discs are being dropped — count it, the
                // way `load`'s size/UTF-8 caps produce a diagnostic.
                if db.disc_entries.len() >= MAX_DISC_ENTRIES {
                    stats.disc_over_cap += 1;
                    continue;
                }
                match Self::parse_disc_entry(line) {
                    // The map key IS the entry's own `disc_hash` allocation
                    // (`Arc` clone, no second copy of the string).
                    Some(entry) => {
                        if db
                            .disc_entries
                            .insert(entry.disc_hash.clone(), entry)
                            .is_some()
                        {
                            stats.disc_duplicate += 1;
                        }
                    }
                    None => stats.disc_rejected += 1,
                }
            }
        }

        (db, stats)
    }

    /// Load a KEYDB.cfg from disk.
    ///
    /// A read failure (missing/unreadable file, non-UTF-8 content) surfaces
    /// as an [`std::io::Error`] (the cap-exceeded case as
    /// [`std::io::ErrorKind::InvalidData`]). Note that [`Self::parse`] itself
    /// is lenient: a syntactically valid but key-less file parses to an empty
    /// [`KeyDb`] rather than an error — callers needing a non-empty db must
    /// check the parsed contents.
    pub fn load(path: &std::path::Path) -> std::io::Result<Self> {
        let (db, stats) = Self::load_counted(std::fs::File::open(path)?, path)?;
        stats.log();
        Ok(db)
    }

    /// [`Self::load`] from an ALREADY-OPEN file, without the log.
    ///
    /// Two callers need this seam, both in [`crate::KeydbSource`]:
    ///
    /// * The identity stamp and the bytes must come from the SAME descriptor.
    ///   Stat-the-path-then-load-the-path is two independent resolutions of one
    ///   name, so an atomic rename landing between them stored a stamp
    ///   describing one file next to the parsed contents of another — and the
    ///   cache then served that pairing until the stamp changed again. `fstat`
    ///   on the open handle cannot be pointed at a different inode.
    /// * The rejection counts have to be RETAINED, not just logged, so a cache
    ///   hit can re-emit them.
    pub(crate) fn load_counted(
        f: std::fs::File,
        path: &std::path::Path,
    ) -> std::io::Result<(Self, ParseStats)> {
        // Read through a hard `take` cap rather than trusting a stat. A
        // `metadata` pre-check is only advisory: it is skipped entirely when the
        // stat fails, and it reports len 0 for a FIFO or character device, so
        // `--keydb /dev/zero` passed the guard and then read forever (NUL is
        // valid UTF-8, so it did not even fail the decode — it just grew until
        // the process was OOM-killed). Reading one byte past the cap accepts an
        // exactly-at-cap file and rejects anything larger, matching
        // `read_capped_to_string` on the download path.
        use std::io::Read;
        let mut buf = Vec::new();
        f.take(MAX_KEYDB_BYTES + 1).read_to_end(&mut buf)?;
        if buf.len() as u64 > MAX_KEYDB_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "keydb.cfg exceeds {MAX_KEYDB_BYTES} byte cap: {}",
                    path.display()
                ),
            ));
        }
        let data = String::from_utf8(buf).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("keydb.cfg is not valid UTF-8: {}", path.display()),
            )
        })?;
        Ok(Self::parse_counted(&data))
    }

    /// Look up a disc by its hash. Returns the VUK if found.
    pub fn find_vuk(&self, disc_hash: &str) -> Option<[u8; 16]> {
        let hash = disc_hash
            .trim()
            .to_lowercase()
            .trim_start_matches("0x")
            .to_string();
        // Try with 0x prefix and without. parse_disc_entry only stores keys
        // from lines that began with "0x", so every stored key carries the
        // prefix and the no-prefix fallback is currently unreachable; it is
        // retained as a defensive match for the prefix-agnostic lookup contract.
        self.disc_entries
            .get(format!("0x{hash}").as_str())
            .or_else(|| self.disc_entries.get(hash.as_str()))
            .and_then(|e| e.vuk)
    }

    /// Look up a disc by its hash. Returns the full entry.
    pub fn find_disc(&self, disc_hash: &str) -> Option<&DiscEntry> {
        let hash = disc_hash
            .trim()
            .to_lowercase()
            .trim_start_matches("0x")
            .to_string();
        // The no-prefix fallback below is currently unreachable (every stored
        // key carries the "0x" prefix, see find_vuk); kept as a defensive
        // match for the prefix-agnostic lookup contract.
        self.disc_entries
            .get(format!("0x{hash}").as_str())
            .or_else(|| self.disc_entries.get(hash.as_str()))
    }

    /// Iterate every disc entry. Used by Path 3 (scan for matching VID).
    pub fn iter_disc_entries(&self) -> impl Iterator<Item = &DiscEntry> {
        self.disc_entries.values()
    }

    /// The host certs usable at MKB generation `mkb`.
    ///
    /// A cert annotated `Revoked in MKBv<R>` is unusable once the disc's MKB
    /// generation reaches `R` (an AACS MKB revokes a cert from its own
    /// generation onward), so it is included only while `gen < R`. When `mkb`
    /// is `None` the disc's generation is unknown and cannot be filtered, so
    /// every cert is returned; certs with no revocation annotation are always
    /// returned.
    pub fn host_certs(&self, mkb: Option<u32>) -> Vec<HostCert> {
        self.host_certs
            .iter()
            .filter(|hc| match (hc.revoked_at_mkb, mkb) {
                (None, _) => true,
                (Some(_), None) => true,
                (Some(revoked), Some(disc_gen)) => disc_gen < revoked,
            })
            .map(|hc| hc.cert.clone())
            .collect()
    }

    /// Standalone keydb accessor: the disc's Volume ID (the keydb `I` token),
    /// looked up by the same disc-hash form [`Self::find_disc`] accepts. Pure
    /// file lookup; no crypto/derivation.
    pub fn get_vid(&self, disc_hash: &str) -> Option<[u8; 16]> {
        self.find_disc(disc_hash).and_then(|e| e.vid)
    }

    /// Standalone keydb accessor: the disc's stored unit (title) keys, cloned.
    /// Empty when the disc is absent or carries no unit keys. Pure file lookup.
    pub fn get_uk(&self, disc_hash: &str) -> Vec<NumberedUnitKey> {
        self.find_disc(disc_hash)
            .map(|e| e.unit_keys.clone())
            .unwrap_or_default()
    }

    /// Standalone keydb accessor: `(disc_hash, unit_keys)` for every disc entry
    /// that carries at least one unit key. Pure file lookup.
    pub fn get_uks(&self) -> Vec<(String, Vec<NumberedUnitKey>)> {
        self.disc_entries
            .values()
            .filter(|e| !e.unit_keys.is_empty())
            .map(|e| (e.disc_hash.to_string(), e.unit_keys.clone()))
            .collect()
    }

    /// Serialize back to keydb.cfg text — the INVERSE of [`Self::parse`], so the
    /// keydb wire format lives in ONE place (parse + emit together). Emits, in a
    /// deterministic order: host certs, device keys, processing keys, then one
    /// line per disc entry (sorted by hash). `parse(to_keydb_cfg(kd))` reproduces
    /// every field (see `round_trips_through_parse`). Used by the key-import tool
    /// to export a complete keydb.cfg (keys + host certs + VIDs).
    ///
    /// The trailing `; <comment>` (MKB version / volume size / UHD) is emitted
    /// ONLY after a `U` (unit-keys) field — that is the one place the parser
    /// splits the value on `;`. Gluing a comment onto an `M`/`I`/`V` value would
    /// make `parse_hex16` reject the whole field, so a comment-bearing entry that
    /// has no unit keys drops its comment (keys always survive; the metadata is a
    /// derivable hint). Real per-disc rows that carry metadata also carry keys.
    pub fn to_keydb_cfg(&self) -> String {
        fn hx(b: &[u8]) -> String {
            use std::fmt::Write;
            let mut s = String::with_capacity(b.len() * 2);
            for x in b {
                let _ = write!(s, "{x:02x}");
            }
            s
        }
        let mut out = String::new();

        // Host certs (AACS 1.0): | HC | HOST_PRIV_KEY 0x.. | HOST_CERT 0x.. ; Revoked in MKBv<N>
        // AACS 2.0 credentials ride a sibling `| HC2 |` line; emit it too so a
        // round-trip through `to_keydb_cfg` never silently drops v2 host certs.
        for hc in &self.host_certs {
            out.push_str("| HC | HOST_PRIV_KEY 0x");
            out.push_str(&hx(&hc.cert.private_key));
            out.push_str(" | HOST_CERT 0x");
            out.push_str(&hx(&hc.cert.certificate));
            if let Some(n) = hc.revoked_at_mkb {
                out.push_str(" ; Revoked in MKBv");
                out.push_str(&n.to_string());
            }
            out.push('\n');
            // AACS 2.0 (HC2): inverse of `parse_host_cert_v2`.
            if let (Some(pk2), Some(cert2)) = (
                hc.cert.private_key_v2.as_ref(),
                hc.cert.certificate_v2.as_ref(),
            ) {
                out.push_str("| HC2 | HOST_PRIV_KEY 0x");
                out.push_str(&hx(pk2));
                out.push_str(" | HOST_CERT 0x");
                out.push_str(&hx(cert2));
                out.push('\n');
            }
        }

        // Device keys: | DK | DEVICE_KEY 0x.. | DEVICE_NODE 0x.. | KEY_UV 0x.. | KEY_U_MASK_SHIFT 0x..
        for dk in &self.device_keys {
            out.push_str("| DK | DEVICE_KEY 0x");
            out.push_str(&hx(&dk.key));
            out.push_str(&format!(
                " | DEVICE_NODE 0x{:04x} | KEY_UV 0x{:08x} | KEY_U_MASK_SHIFT 0x{:02x}\n",
                dk.node, dk.uv, dk.u_mask_shift
            ));
        }

        // Processing keys: | PK | 0x..
        for pk in &self.processing_keys {
            out.push_str("| PK | 0x");
            out.push_str(&hx(pk));
            out.push('\n');
        }

        // Per-disc entries, sorted by hash for a deterministic, diff-friendly file.
        let mut hashes: Vec<&Arc<str>> = self.disc_entries.keys().collect();
        hashes.sort();
        for h in hashes {
            let d = &self.disc_entries[&**h];
            // `parse` keeps the `hash_part` verbatim, so the stored `disc_hash`
            // already carries its `0x` prefix — emit it as-is (prefixing another
            // `0x` would double it on re-parse).
            out.push_str(h);
            out.push_str(" = ");
            // Parse stores the title VERBATIM (parens and all), so emitting it
            // bare round-trips through parse. Empty → "Unknown".
            if d.title.is_empty() {
                out.push_str("Unknown");
            } else {
                out.push_str(&d.title);
            }
            if let Some(mk) = d.media_key {
                out.push_str(" | M | 0x");
                out.push_str(&hx(&mk));
            }
            if let Some(id) = d.vid {
                out.push_str(" | I | 0x");
                out.push_str(&hx(&id));
            }
            if let Some(vuk) = d.vuk {
                out.push_str(" | V | 0x");
                out.push_str(&hx(&vuk));
            }
            if !d.unit_keys.is_empty() {
                out.push_str(" | U |");
                for (n, k) in &d.unit_keys {
                    out.push_str(&format!(" {}-0x{}", n, hx(k)));
                }
                // Comment only after U (the one ;-split field) so it can't corrupt
                // a preceding hex value on re-parse.
                if d.mkb_version.is_some() || d.volume_size.is_some() || d.is_uhd {
                    out.push_str(" ;");
                    if let Some(v) = d.mkb_version {
                        out.push_str(&format!(" MKBv{v}"));
                    }
                    if let Some(sz) = d.volume_size {
                        out.push_str(&format!(" VolumeSize: {sz}"));
                    }
                    if d.is_uhd {
                        out.push_str(" (UHD)");
                    }
                }
            }
            out.push('\n');
        }
        out
    }
}

// ── Private parsers (re-open the inherent impl) ─────────────────────────────

impl KeyDb {
    fn parse_device_key(line: &str) -> Option<DeviceKey> {
        // | DK | DEVICE_KEY 0x... | DEVICE_NODE 0x... | KEY_UV 0x... | KEY_U_MASK_SHIFT 0x...
        let key_str = line.split("DEVICE_KEY").nth(1)?.split('|').next()?.trim();
        let node_str = line.split("DEVICE_NODE").nth(1)?.split('|').next()?.trim();
        let uv_str = line.split("KEY_UV").nth(1)?.split('|').next()?.trim();
        let shift_str = line
            .split("KEY_U_MASK_SHIFT")
            .nth(1)?
            .split(';')
            .next()?
            .split('|')
            .next()?
            .trim();

        Some(DeviceKey {
            key: parse_hex16(key_str)?,
            // Canonical hex parsers (one prefix/case rule for the whole workspace)
            // — NOT an ad-hoc `from_str_radix(trim_start_matches("0x"))`, whose
            // case-sensitive strip silently dropped an uppercase-`0X` value.
            node: libfreemkv::hex::parse_hex_u16(node_str)?,
            uv: libfreemkv::hex::parse_hex_u32(uv_str)?,
            u_mask_shift: libfreemkv::hex::parse_hex_u8(shift_str)?,
        })
    }

    fn parse_processing_key(line: &str) -> Option<[u8; 16]> {
        // | PK | 0x...
        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() >= 3 {
            let key_str = parts[2].split(';').next()?.trim();
            return parse_hex16(key_str);
        }
        None
    }

    /// Parse an orphan DK row: a `| DK |` line carrying only the
    /// `DEVICE_KEY` field (no position metadata). The key is then
    /// treated like a terminal/unpositioned label by the resolver
    /// (Path 2's brute walker). Returns `None` if the line carries
    /// any position field — those are positioned DKs and parsed by
    /// [`Self::parse_device_key`] instead.
    fn parse_orphan_dk(line: &str) -> Option<[u8; 16]> {
        if line.contains("DEVICE_NODE")
            || line.contains("KEY_UV")
            || line.contains("KEY_U_MASK_SHIFT")
        {
            return None;
        }
        let key_str = line
            .split("DEVICE_KEY")
            .nth(1)?
            .split('|')
            .next()?
            .split(';')
            .next()?
            .trim();
        parse_hex16(key_str)
    }

    fn parse_host_cert(line: &str) -> Option<KeydbHostCert> {
        // | HC | HOST_PRIV_KEY 0x... | HOST_CERT 0x... ; Revoked in MKBv<N>
        let priv_str = line
            .split("HOST_PRIV_KEY")
            .nth(1)?
            .split('|')
            .next()?
            .trim();
        let cert_str = line
            .split("HOST_CERT")
            .nth(1)?
            .split(';')
            .next()?
            .split('|')
            .next()?
            .trim();

        let certificate = parse_hex(cert_str)?;
        // AACS 1.0 host certs are 92 bytes; drop malformed/short rows at
        // parse time so the handshake never attempts junk (mirrors the v2
        // path, which enforces >= 132).
        if certificate.len() < 92 {
            return None;
        }

        Some(KeydbHostCert {
            cert: HostCert {
                private_key: parse_hex20(priv_str)?,
                certificate,
                private_key_v2: None,
                certificate_v2: None,
            },
            revoked_at_mkb: parse_revoked_at_mkb(line),
        })
    }

    /// Parse AACS 2.0 host cert: `| HC2 | HOST_PRIV_KEY 0x... | HOST_CERT 0x...`
    /// Returns the private key, the cert bytes, and the `Revoked in MKBv<N>`
    /// generation (if the line carries that comment).
    fn parse_host_cert_v2(line: &str) -> Option<([u8; 32], Vec<u8>, Option<u32>)> {
        let priv_str = line
            .split("HOST_PRIV_KEY")
            .nth(1)?
            .split('|')
            .next()?
            .trim();
        let cert_str = line
            .split("HOST_CERT")
            .nth(1)?
            .split(';')
            .next()?
            .split('|')
            .next()?
            .trim();

        let priv_bytes = parse_hex(priv_str)?;
        if priv_bytes.len() != 32 {
            return None;
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&priv_bytes);

        let cert = parse_hex(cert_str)?;
        if cert.len() < 132 {
            return None;
        }

        Some((pk, cert, parse_revoked_at_mkb(line)))
    }

    fn parse_disc_entry(line: &str) -> Option<DiscEntry> {
        // 0x<hash> = <title> | D | <date> | M | 0x<mk> | I | 0x<id> | V | 0x<vuk> | U | <unit_keys> ; <comment>
        let (hash_part, rest) = line.split_once(" = ")?;
        let disc_hash: Arc<str> = Arc::from(hash_part.trim().to_lowercase());

        // The trailing `;` comment (e.g.
        // "; MKBv76/BEE/FindVUK 1.74 - VolumeSize: 81309007872 (UHD)") carries
        // metadata the key fields don't. Capture everything after the FIRST ';'
        // on the line, then extract MKB version / volume size / UHD flag.
        let comment = line.split_once(';').map(|(_, c)| c).unwrap_or("");
        // MKBv token: literal "MKBv" immediately followed by decimal digits.
        let mkb_version: Option<u32> = parse_digits_after(comment, "MKBv");
        // VolumeSize token: "VolumeSize:" then whitespace then a byte count.
        let volume_size: Option<u64> = parse_digits_after(comment, "VolumeSize:");
        // UHD flag: literal "(UHD)" anywhere in the comment.
        let is_uhd = comment.contains("(UHD)");

        // Title = everything between `= ` and the first ` | ` field (or the
        // trailing `;` comment), kept VERBATIM (trimmed). This is a FAITHFUL copy
        // of the keydb title, so it must round-trip exactly: a previous version
        // extracted a `(...)` substring as a "display title", but that TRUNCATED
        // real titles that legitimately contain parentheses ("Lawrence of Arabia
        // (Restored Version) – Disc 2 …" → "Restored Version") and broke
        // serialize→parse idempotence. Display prettification, if wanted, belongs
        // in the title-display layer, NOT this codec.
        let before_fields = rest.split(" | ").next().unwrap_or("");
        // A title-only entry (no key fields) carries its `;` comment on the same
        // chunk — strip it so the comment doesn't leak into the title.
        let title = before_fields
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_string();

        // Parse fields by tag
        let mut media_key = None;
        let mut vid = None;
        let mut vuk = None;
        let mut unit_keys = Vec::new();

        let parts: Vec<&str> = rest.split(" | ").collect();
        // Field scan starts at index 1: `parts[0]` is ALWAYS the title chunk and
        // must be excluded, otherwise a disc whose title happens to be a field tag
        // letter ("M", "I", "V", "U", "D") — e.g. `= M | M | 0x…` — would have the
        // title eaten as a tag and shadow the real field. (Broke round-trip.)
        let mut i = 1;
        while i < parts.len() {
            match parts[i].trim() {
                // M/I/V strip a trailing `; comment` before hex-parsing, exactly
                // as the U arm below does: when the disc row's LAST field is one
                // of these (no U field after it), a real keydb.cfg glues the
                // `; MKBv…` comment onto that value, and parse_hex16 of
                // "0x… ; MKBv64" fails — silently dropping a key the file
                // actually holds. A hex16 never contains ';', so the split is safe.
                "M" => {
                    if i + 1 < parts.len() {
                        media_key =
                            parse_hex16(parts[i + 1].split(';').next().unwrap_or("").trim());
                        i += 1;
                    }
                }
                "I" => {
                    if i + 1 < parts.len() {
                        vid = parse_hex16(parts[i + 1].split(';').next().unwrap_or("").trim());
                        i += 1;
                    }
                }
                "V" => {
                    if i + 1 < parts.len() {
                        vuk = parse_hex16(parts[i + 1].split(';').next().unwrap_or("").trim());
                        i += 1;
                    }
                }
                "U" if i + 1 < parts.len() => {
                    // Unit keys: "1-0xKEY" or "1-0xKEY ; comment"
                    let uk_str = parts[i + 1].split(';').next().unwrap_or("").trim();
                    for uk in uk_str.split(' ') {
                        let uk = uk.trim();
                        if let Some((num, key)) = uk.split_once('-')
                            && let Ok(n) = num.parse::<u32>()
                            && let Some(k) = parse_hex16(key)
                        {
                            unit_keys.push((n, k));
                        }
                    }
                    i += 1;
                }
                _ => {}
            }
            i += 1;
        }

        Some(DiscEntry {
            disc_hash,
            title,
            media_key,
            vid,
            vuk,
            unit_keys,
            mkb_version,
            volume_size,
            is_uhd,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `load` must enforce `MAX_KEYDB_BYTES` through a bounded read, not a stat.
    ///
    /// Regression: the cap used to be a `std::fs::metadata` pre-check followed by
    /// an unbounded `read_to_string`. That is not a cap — it is skipped when the
    /// stat fails, and a FIFO or character device reports len 0, so the guard
    /// passed and the read never terminated. NUL bytes are valid UTF-8, so
    /// `--keydb /dev/zero` did not even fail the decode; it allocated until the
    /// process died. Asserts both edges of the boundary so a future cap change
    /// cannot quietly re-introduce an off-by-one.
    #[test]
    fn load_enforces_the_size_cap_at_both_edges() {
        let dir = std::env::temp_dir()
            .join("fmkv-keydb-cap")
            .join(format!("{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        // Exactly at the cap is accepted. Use a comment line so `parse` is happy
        // and the content is valid UTF-8 of a known length.
        let at = dir.join("at_cap.cfg");
        let body = vec![b'#'; MAX_KEYDB_BYTES as usize];
        std::fs::write(&at, &body).unwrap();
        assert!(
            KeyDb::load(&at).is_ok(),
            "a file exactly at MAX_KEYDB_BYTES must load"
        );

        // One byte over is rejected as InvalidData, not truncated and not OOM.
        let over = dir.join("over_cap.cfg");
        let mut body = vec![b'#'; MAX_KEYDB_BYTES as usize];
        body.push(b'#');
        std::fs::write(&over, &body).unwrap();
        let err = KeyDb::load(&over).expect_err("over-cap file must be rejected");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// `to_keydb_cfg` is the exact inverse of `parse`: parse a known line set,
    /// serialize it, re-parse, and every field survives — device key, processing
    /// key, host cert (priv key + cert + revocation), and the per-disc M/I(vid)/V/U
    /// keys plus the MKBv/UHD comment metadata. Both sides go through `parse`, so
    /// internal key forms (e.g. the `0x`-prefixed disc-hash) match by construction.
    #[test]
    fn to_keydb_cfg_round_trips_through_parse() {
        let h = |b: u8, n: usize| format!("{b:02x}").repeat(n);
        let cert = h(0x99, 92); // AACS 1.0 host cert is 92 bytes
        let src = format!(
            "| HC | HOST_PRIV_KEY 0x{priv20} | HOST_CERT 0x{cert} ; Revoked in MKBv72\n\
             | DK | DEVICE_KEY 0x{k16} | DEVICE_NODE 0x0a00 | KEY_UV 0x00000e23 | KEY_U_MASK_SHIFT 0x0b\n\
             | PK | 0x{pk16}\n\
             0x{hash20} = TestDisc | M | 0x{mk16} | I | 0x{id16} | V | 0x{vuk16} | U | 1-0x{u1} 2-0x{u2} ; MKBv76 VolumeSize: 81309007872 (UHD)\n",
            hash20 = h(0xab, 20),
            priv20 = h(0x88, 20),
            cert = cert,
            k16 = h(0x66, 16),
            pk16 = h(0x77, 16),
            mk16 = h(0x11, 16),
            id16 = h(0x22, 16),
            vuk16 = h(0x33, 16),
            u1 = h(0x44, 16),
            u2 = h(0x55, 16),
        );
        let a = KeyDb::parse(&src);
        let b = KeyDb::parse(&a.to_keydb_cfg());

        // Per-disc entry: every field round-trips.
        assert_eq!(a.disc_entries.len(), 1);
        assert_eq!(b.disc_entries.len(), 1);
        let ea = a.disc_entries.values().next().unwrap();
        let eb = b.disc_entries.values().next().unwrap();
        assert_eq!(ea.disc_hash, eb.disc_hash);
        assert_eq!(ea.title, eb.title, "title");
        assert_eq!(ea.media_key, eb.media_key, "M");
        assert_eq!(ea.vid, eb.vid, "I/vid");
        assert_eq!(ea.vuk, eb.vuk, "V");
        assert_eq!(ea.unit_keys, eb.unit_keys, "U");
        assert_eq!(ea.mkb_version, eb.mkb_version, "MKBv");
        assert_eq!(ea.is_uhd, eb.is_uhd, "UHD");
        // Concrete values (not just self-consistency).
        assert_eq!(ea.vid, Some([0x22u8; 16]));
        assert_eq!(ea.vuk, Some([0x33u8; 16]));
        assert_eq!(ea.unit_keys, vec![(1, [0x44u8; 16]), (2, [0x55u8; 16])]);
        assert_eq!(ea.mkb_version, Some(76));
        assert!(ea.is_uhd);

        // Device key, processing key, host cert all survive byte-for-byte.
        assert_eq!(a.device_keys.len(), b.device_keys.len());
        assert_eq!(a.device_keys[0].key, b.device_keys[0].key);
        assert_eq!(a.device_keys[0].node, b.device_keys[0].node);
        assert_eq!(a.device_keys[0].uv, b.device_keys[0].uv);
        assert_eq!(a.device_keys[0].u_mask_shift, b.device_keys[0].u_mask_shift);
        assert_eq!(a.processing_keys, b.processing_keys);
        assert_eq!(a.host_certs.len(), 1);
        assert_eq!(b.host_certs.len(), 1);
        assert_eq!(
            a.host_certs[0].cert.private_key,
            b.host_certs[0].cert.private_key
        );
        assert_eq!(
            a.host_certs[0].cert.certificate,
            b.host_certs[0].cert.certificate
        );
        assert_eq!(
            a.host_certs[0].revoked_at_mkb,
            b.host_certs[0].revoked_at_mkb
        );
        assert_eq!(b.host_certs[0].revoked_at_mkb, Some(72));
    }

    /// REAL-DATA IDEMPOTENCE — the "load + serialize back-to-back" check.
    ///
    /// Parse the full keydb → serialize (S1) → parse S1 → serialize again (S2).
    /// S1 MUST equal S2 byte-for-byte. This is the right invariant: a raw
    /// keydb.cfg has formatting variance (whitespace, optional fields, comment
    /// style) that our CANONICAL serializer normalizes, so `text == to_keydb_cfg`
    /// is NOT expected — but once normalized, a re-load+re-serialize must be
    /// stable. Idempotence here proves `parse` is lossless on its own output and
    /// `to_keydb_cfg` is deterministic. Also asserts no rows are dropped.
    /// REQUIRES a real keydb; `#[ignore]` by default. Run with:
    /// `KEYDB_PATH=/path/to/keydb.cfg cargo test --release -- --ignored`.
    ///
    /// It used to carry no `#[ignore]` and `return` early when `KEYDB_PATH` was
    /// unset — so CI ran it, asserted NOTHING about 181k-entry behaviour, and
    /// reported green. A skip has to be visible in the test output to mean
    /// anything, and an ignored test that is RUN without its fixture must fail
    /// loudly rather than silently pass.
    #[test]
    #[ignore = "needs a real keydb.cfg: KEYDB_PATH=<path> cargo test -- --ignored"]
    fn to_keydb_cfg_is_idempotent_on_real_keydb() {
        let path = real_keydb_path();
        let db1 = KeyDb::load(&path).unwrap();
        let s1 = db1.to_keydb_cfg();
        let db2 = KeyDb::parse(&s1);
        let s2 = db2.to_keydb_cfg();
        assert_eq!(s1.len(), s2.len(), "serialized byte length drifted");
        assert!(s1 == s2, "to_keydb_cfg is NOT idempotent (S1 != S2)");
        // No rows lost crossing the round trip.
        assert_eq!(
            db1.disc_entries.len(),
            db2.disc_entries.len(),
            "disc-entry count drift"
        );
        assert_eq!(db1.device_keys.len(), db2.device_keys.len(), "DK drift");
        assert_eq!(
            db1.processing_keys.len(),
            db2.processing_keys.len(),
            "PK drift"
        );
        assert_eq!(db1.host_certs.len(), db2.host_certs.len(), "HC drift");
    }

    /// REAL-SCALE parser health: a genuine published keydb must parse with ZERO
    /// rejected rows. This is the assertion the rejection counter exists to
    /// make possible — a corrupt or byte-shifted mirror download differs from a
    /// healthy one precisely here, and nothing above the parser can tell them
    /// apart. `#[ignore]` by default; run with:
    /// `KEYDB_PATH=/path/to/keydb.cfg cargo test --release -- --ignored`.
    #[test]
    #[ignore = "needs a real keydb.cfg: KEYDB_PATH=<path> cargo test -- --ignored"]
    fn a_real_keydb_parses_with_no_rejected_rows() {
        let path = real_keydb_path();
        let text = std::fs::read_to_string(&path).expect("keydb must be readable");
        let (db, stats) = KeyDb::parse_counted(&text);
        assert!(
            db.disc_entries.len() > 170_000,
            "expected a full-size keydb, got {} entries",
            db.disc_entries.len()
        );
        assert_eq!(
            stats.rejected(),
            0,
            "a healthy keydb must not lose rows to the parser: {stats:?}"
        );
        assert_eq!(
            stats.disc_duplicate, 0,
            "duplicate disc hashes make one row's keys unreachable: {stats:?}"
        );
    }

    /// Get KEYDB path from KEYDB_PATH environment variable. Returns None if not set or not found.
    fn keydb_path() -> Option<std::path::PathBuf> {
        let path = std::path::PathBuf::from(std::env::var("KEYDB_PATH").ok()?);
        if path.exists() { Some(path) } else { None }
    }

    /// The real keydb for the `#[ignore]`d real-scale tests, or a LOUD failure.
    ///
    /// The old pattern (`match keydb_path() { Some(p) => p, None => return }`)
    /// on a non-ignored test is the worst of both worlds: CI ran the test,
    /// asserted nothing, and reported success. These tests are `#[ignore]`d, so
    /// running one at all is an explicit request — and an explicit request with
    /// no fixture must fail, not quietly pass.
    fn real_keydb_path() -> std::path::PathBuf {
        keydb_path().expect(
            "KEYDB_PATH must point at a real keydb.cfg; run: \
             KEYDB_PATH=/path/to/keydb.cfg cargo test --release -- --ignored",
        )
    }

    #[test]
    fn test_parse_disc_entry() {
        // All-zero placeholders — synthetic; no real key material in code.
        let z40 = "00".repeat(20);
        let z32 = "00".repeat(16);
        let line = format!(
            "0x{z40} = SAMPLE_FILM (Sample Film) | D | 2024-01-01 | M | 0x{z32} | I | 0x{z32} | V | 0x{z32} | U | 1-0x{z32} ; MKBv77"
        );
        let entry = KeyDb::parse_disc_entry(&line).unwrap();
        assert_eq!(entry.title, "SAMPLE_FILM (Sample Film)"); // faithful, verbatim
        assert!(entry.media_key.is_some());
        assert!(entry.vuk.is_some());
        assert_eq!(entry.unit_keys.len(), 1);
        assert_eq!(entry.unit_keys[0].0, 1);
    }

    #[test]
    fn disc_entry_strips_a_comment_glued_to_a_trailing_v_field() {
        // A real keydb.cfg row whose LAST field is V (no U after it) with the
        // `; MKBv…` comment glued straight onto the hex value. The U arm already
        // strips such a comment; before M/I/V did too, parse_hex16 saw
        // "0x00… ; MKBv64" and silently dropped the VUK — the disc then reported
        // no key despite the file holding one.
        let z40 = "00".repeat(20);
        let z32 = "00".repeat(16);
        let line =
            format!("0x{z40} = SAMPLE (Sample) | M | 0x{z32} | I | 0x{z32} | V | 0x{z32} ; MKBv64");
        let entry = KeyDb::parse_disc_entry(&line).unwrap();
        assert!(entry.media_key.is_some(), "M key must survive");
        assert!(
            entry.vuk.is_some(),
            "a VUK with a trailing ; comment must not be dropped"
        );
    }

    // NOTE: key fields below use obvious repeated-byte / zero placeholders
    // (0x01.., 0x02.., 0x03.., 0x00..). NEVER put real — or real-looking — host,
    // device, or processing key material in code; these tests exercise the
    // parser's field-splitting only, not any genuine key.

    #[test]
    fn test_parse_device_key() {
        let line = "| DK | DEVICE_KEY 0x00000000000000000000000000000000 | DEVICE_NODE 0x0800 | KEY_UV 0x00000400 | KEY_U_MASK_SHIFT 0x17 ; MKBv01-MKBv48";
        let dk = KeyDb::parse_device_key(line).unwrap();
        assert_eq!(dk.node, 0x0800);
        assert_eq!(dk.u_mask_shift, 0x17);
    }

    #[test]
    fn test_orphan_dk_row_loads_into_processing_keys() {
        // `| DK |` row without position fields = an orphan DK. Per the
        // unified model the resolver treats it like a terminal/PK
        // candidate: it lands in `processing_keys` and the brute walker
        // handles it.
        let cfg = r#"
| DK | DEVICE_KEY 0x01010101010101010101010101010101 ; orphan, no position fields
| DK | DEVICE_KEY 0x02020202020202020202020202020202 | DEVICE_NODE 0x0800 | KEY_UV 0x00000400 | KEY_U_MASK_SHIFT 0x17 ; positioned MKBv01-MKBv48
| PK | 0x03030303030303030303030303030303 ; legacy PK row still works
"#;
        let db = KeyDb::parse(cfg);
        assert_eq!(
            db.device_keys.len(),
            1,
            "positioned DK row should land in device_keys"
        );
        // Orphan DK + legacy PK row both end up in processing_keys.
        assert_eq!(
            db.processing_keys.len(),
            2,
            "orphan DK row + legacy PK row both belong in processing_keys"
        );
        assert_eq!(db.processing_keys[0][..4], [0x01, 0x01, 0x01, 0x01]);
        assert_eq!(db.processing_keys[1][..4], [0x03, 0x03, 0x03, 0x03]);
    }

    #[test]
    fn test_parse_orphan_dk_rejects_lines_with_position_fields() {
        // The parser must NOT pick up a positioned DK row as an orphan
        // (that would double-count). parse_orphan_dk explicitly checks.
        let positioned = "| DK | DEVICE_KEY 0x02020202020202020202020202020202 | DEVICE_NODE 0x0800 | KEY_UV 0x00000400 | KEY_U_MASK_SHIFT 0x17";
        assert!(
            KeyDb::parse_orphan_dk(positioned).is_none(),
            "positioned DK must not match orphan parser"
        );
        let orphan = "| DK | DEVICE_KEY 0x01010101010101010101010101010101";
        let key = KeyDb::parse_orphan_dk(orphan).expect("orphan should parse");
        assert_eq!(key[..4], [0x01, 0x01, 0x01, 0x01]);
    }

    #[test]
    fn test_parse_host_cert() {
        // 20-byte priv + 92-byte cert, all zeros — placeholders, not a key.
        let line = format!(
            "| HC | HOST_PRIV_KEY 0x{} | HOST_CERT 0x{} ; Revoked",
            "00".repeat(20),
            "00".repeat(92)
        );
        let hc = KeyDb::parse_host_cert(&line).unwrap();
        assert_eq!(hc.cert.private_key, [0u8; 20]);
        assert_eq!(hc.cert.certificate.len(), 92);
    }

    #[test]
    fn test_parse_hex_rejects_non_ascii_without_panic() {
        // A 4-byte UTF-8 scalar has byte-len 4 (passes the even check); the
        // old &str-slice path panicked on the mid-codepoint boundary. The
        // byte-wise parser must instead return None.
        assert!(parse_hex("😀").is_none());
        // Mixed: leading hex then a 2-byte UTF-8 scalar (byte-len even).
        assert!(parse_hex("ABé").is_none());
        // Sanity: well-formed hex still parses.
        assert_eq!(parse_hex("0x00FF"), Some(vec![0x00, 0xFF]));
        // Odd byte length still rejected.
        assert!(parse_hex("ABC").is_none());
    }

    #[test]
    fn test_hc2_before_hc_is_not_dropped() {
        // An HC2 row appearing before any HC row must still land its AACS 2.0
        // credentials on a HostCert rather than being silently discarded.
        let cfg = format!(
            "| HC2 | HOST_PRIV_KEY 0x{} | HOST_CERT 0x{}\n",
            "00".repeat(32),
            "00".repeat(132)
        );
        let db = KeyDb::parse(&cfg);
        assert_eq!(
            db.host_certs.len(),
            1,
            "HC2-only row must create a HostCert"
        );
        assert!(db.host_certs[0].cert.private_key_v2.is_some());
        assert!(db.host_certs[0].cert.certificate_v2.is_some());
        assert!(
            db.host_certs[0].cert.certificate.is_empty(),
            "v1 cert stays empty for an HC2-only carrier"
        );
    }

    #[test]
    fn test_hc2_after_hc_augments_existing() {
        let cfg = format!(
            "| HC | HOST_PRIV_KEY 0x{} | HOST_CERT 0x{}\n| HC2 | HOST_PRIV_KEY 0x{} | HOST_CERT 0x{}\n",
            "00".repeat(20),
            "00".repeat(92),
            "00".repeat(32),
            "00".repeat(132)
        );
        let db = KeyDb::parse(&cfg);
        assert_eq!(db.host_certs.len(), 1, "HC2 augments the preceding HC");
        assert_eq!(db.host_certs[0].cert.certificate.len(), 92);
        assert!(db.host_certs[0].cert.certificate_v2.is_some());
    }

    #[test]
    fn test_parse_host_cert_rejects_short_v1_cert() {
        // A too-short AACS 1.0 cert must be dropped at parse time.
        let line = format!(
            "| HC | HOST_PRIV_KEY 0x{} | HOST_CERT 0x{}",
            "00".repeat(20),
            "00".repeat(10)
        );
        assert!(KeyDb::parse_host_cert(&line).is_none());
    }

    /// REQUIRES a real keydb; `#[ignore]` by default. Run with:
    /// `KEYDB_PATH=/path/to/keydb.cfg cargo test --release -- --ignored`.
    #[test]
    #[ignore = "needs a real keydb.cfg: KEYDB_PATH=<path> cargo test -- --ignored"]
    fn test_parse_full_keydb() {
        let path = real_keydb_path();

        let db = KeyDb::load(&path).unwrap();

        assert_eq!(db.device_keys.len(), 4);
        assert_eq!(db.processing_keys.len(), 3);
        assert!(!db.host_certs.is_empty());
        assert!(db.disc_entries.len() > 170000);

        // Look up any disc entry carrying a full key set.
        let entry = db
            .disc_entries
            .values()
            .find(|e| e.vuk.is_some() && e.media_key.is_some() && !e.unit_keys.is_empty())
            .expect("no disc entry with a full key set");
        assert!(entry.media_key.is_some());
        assert!(entry.vuk.is_some());
        assert!(!entry.unit_keys.is_empty());

        eprintln!(
            "Parsed {} disc entries, {} DK, {} PK",
            db.disc_entries.len(),
            db.device_keys.len(),
            db.processing_keys.len()
        );
    }

    /// `load_counted` must read the HANDLE it was given, never re-resolve the
    /// path. `KeydbSource::cached_db` stamps the open file with `fstat` and then
    /// parses from that same descriptor precisely so the recorded identity and
    /// the parsed bytes cannot describe two different files; the moment this
    /// function re-opens the path, that guarantee is gone and an atomic rename
    /// landing in between stores one file's stamp beside another file's keys —
    /// a mismatch the cache then serves as if it were valid.
    ///
    /// The race itself cannot be scheduled deterministically in-process, so the
    /// SEAM is what is pinned: with the path already replaced, the handle's
    /// contents must still win. Catches the mutation that restores an internal
    /// `File::open(path)`.
    #[cfg(unix)]
    #[test]
    fn load_counted_reads_the_handle_not_the_path() {
        let dir = std::env::temp_dir().join(format!(
            "fmk-keysources-load-seam-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keydb.cfg");
        let other = dir.join("replacement.cfg");
        let row = |k: &str| format!("0xaabb = T | U | 1-0x{k}\n");
        std::fs::write(&path, row(&"01".repeat(16))).unwrap();
        std::fs::write(&other, row(&"02".repeat(16))).unwrap();

        let handle = std::fs::File::open(&path).unwrap();
        // The path now names a DIFFERENT inode; the handle still names the old
        // one, exactly as it would mid-race.
        std::fs::rename(&other, &path).unwrap();

        let (db, _) = KeyDb::load_counted(handle, &path).expect("the open handle is still valid");
        assert_eq!(
            db.disc_entries
                .values()
                .next()
                .expect("one entry")
                .unit_keys[0]
                .1,
            [0x01u8; 16],
            "the parse must come from the handle that was stamped, not from a re-opened path"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    // ── Debug redaction: key material must never reach a log or a panic ────

    /// The only key bytes in these fixtures are the byte 0x5A repeated; the
    /// assertion is that NO run of them survives into the formatted string, in
    /// either the hex or the Rust-array rendering a derived `Debug` produces.
    fn assert_no_key_bytes(what: &str, rendered: &str) {
        assert!(
            !rendered.contains("90"),
            "{what} Debug leaked a decimal key byte: {rendered}"
        );
        assert!(
            !rendered.contains("5a") && !rendered.contains("5A"),
            "{what} Debug leaked a hex key byte: {rendered}"
        );
        // A derived `Debug` over `[u8; 16]` / `Vec<[u8; 16]>` renders a byte
        // array — `[90, 90, ...]`. A redacting impl never emits one. Matched as
        // "a `[` immediately followed by a digit" rather than "any `[`", because
        // callers legitimately render a `Vec` OF redacting structs
        // (`{:?}` on `KeyDb::host_certs`), whose own `[` opens a list of
        // `Name { .. }` — never a byte. Every byte-array rendering, decimal or
        // nested, still starts `[<digit>` (or `[[<digit>`), and the two byte
        // checks above catch the payload independently.
        let bytes = rendered.as_bytes();
        assert!(
            !rendered
                .match_indices('[')
                .any(|(i, _)| bytes.get(i + 1).is_some_and(u8::is_ascii_digit)),
            "{what} Debug rendered a raw byte array: {rendered}"
        );
    }

    /// `{:?}` on a `DiscEntry` must not print the Media Key, VID, VUK or any
    /// Unit Key. Catches the mutation that restores `#[derive(Debug)]`: the
    /// derive renders `media_key: Some([90, 90, ...])`, so a single `{:?}` in a
    /// caller's log or panic message published a disc's whole key set.
    #[test]
    fn disc_entry_debug_is_redacted() {
        let e = DiscEntry {
            disc_hash: Arc::from("0xaabb"),
            title: "T".into(),
            media_key: Some([0x5A; 16]),
            vid: Some([0x5A; 16]),
            vuk: Some([0x5A; 16]),
            unit_keys: vec![(1, [0x5A; 16])],
            mkb_version: Some(76),
            volume_size: Some(1),
            is_uhd: true,
        };
        let rendered = format!("{e:?}");
        assert_no_key_bytes("DiscEntry", &rendered);
        // The non-secret identifying fields are still useful and still printed.
        assert!(rendered.contains("0xaabb"), "{rendered}");
        assert!(rendered.contains("unit_keys_len"), "{rendered}");
    }

    /// `{:?}` on a whole `KeyDb` must print COUNTS only. The derive dumped every
    /// processing key plus all ~181k disc entries' key material — the single
    /// worst leak in the crate, since a `KeyDb` is what a key source holds.
    #[test]
    fn keydb_debug_is_redacted() {
        let mut db = KeyDb::empty();
        db.processing_keys.push([0x5A; 16]);
        db.device_keys.push(DeviceKey {
            key: [0x5A; 16],
            node: 1,
            uv: 2,
            u_mask_shift: 3,
        });
        db.host_certs.push(KeydbHostCert {
            cert: HostCert {
                private_key: [0x5A; 20],
                certificate: vec![0x5A; 92],
                private_key_v2: None,
                certificate_v2: None,
            },
            revoked_at_mkb: None,
        });
        let e = DiscEntry {
            disc_hash: Arc::from("0xaabb"),
            title: "T".into(),
            media_key: Some([0x5A; 16]),
            vid: None,
            vuk: Some([0x5A; 16]),
            unit_keys: vec![(1, [0x5A; 16])],
            mkb_version: None,
            volume_size: None,
            is_uhd: false,
        };
        db.disc_entries.insert(e.disc_hash.clone(), e);

        let rendered = format!("{db:?}");
        assert_no_key_bytes("KeyDb", &rendered);
        assert!(
            rendered.contains("disc_entries_len"),
            "counts, not contents: {rendered}"
        );
        assert!(
            rendered.contains("processing_keys_len"),
            "counts, not contents: {rendered}"
        );
    }

    /// The SIBLING type. `KeyDb`'s hand-written `Debug` prints
    /// `host_certs_len`, so it protects the whole-db rendering and nothing else
    /// — [`KeyDb::host_certs`] is a public field, and `{:?}` on ONE element of
    /// it walks a completely different code path: `KeydbHostCert`'s derive,
    /// then `HostCert`'s impl. That path carries the AACS host PRIVATE key, the
    /// only key material in the crate that authenticates US rather than opening
    /// a disc.
    ///
    /// It is safe today only because `libfreemkv::HostCert` hand-writes a
    /// redacting `Debug` (`aacs::types`, `private_key: "<redacted>"` +
    /// `certificate_len`) — an EXTERNAL guarantee this crate silently inherits
    /// through the derive, with nothing on this side pinning it. This test pins
    /// it: it catches a libfreemkv upgrade that swaps that impl for
    /// `#[derive(Debug)]`, which would leak the host private key out of this
    /// crate's public API with no diff in this repository at all.
    ///
    /// Rendered three ways because callers reach the cert three ways: the whole
    /// `Vec` (`?db.host_certs`), one element, and the inner `HostCert` a caller
    /// gets back from `KeyDb::host_certs(mkb)`.
    #[test]
    fn host_cert_debug_is_redacted_including_the_sibling_wrapper() {
        let hc = KeydbHostCert {
            cert: HostCert {
                private_key: [0x5A; 20],
                certificate: vec![0x5A; 92],
                private_key_v2: Some([0x5A; 32]),
                certificate_v2: Some(vec![0x5A; 132]),
            },
            revoked_at_mkb: Some(76),
        };
        assert_no_key_bytes("KeydbHostCert", &format!("{hc:?}"));
        assert_no_key_bytes("Vec<KeydbHostCert>", &format!("{:?}", vec![hc.clone()]));
        assert_no_key_bytes("HostCert", &format!("{:?}", hc.cert));
        // Positive half: the private keys must be present-but-masked, not
        // omitted. A `Debug` that simply dropped the fields would satisfy the
        // negative assertions above while hiding that a key is held at all.
        assert_eq!(
            format!("{hc:?}").matches("<redacted>").count(),
            2,
            "both host private keys (1.0 and 2.0) must render as <redacted>: {hc:?}"
        );
        // The non-secret revocation field is what the wrapper exists for and is
        // still printed — redaction must not become "print nothing useful".
        assert!(
            format!("{hc:?}").contains("76"),
            "the revocation generation is not secret and must survive: {hc:?}"
        );
    }

    /// The `Vec<DeviceKey>` on the other public `KeyDb` field, for the same
    /// reason: `device_keys` is reachable element-wise and each entry holds a
    /// 16-byte device key. Also inherited from libfreemkv's redacting impl.
    #[test]
    fn device_key_debug_is_redacted() {
        let dk = DeviceKey {
            key: [0x5A; 16],
            node: 1,
            uv: 2,
            u_mask_shift: 3,
        };
        assert_no_key_bytes("DeviceKey", &format!("{dk:?}"));
        assert_no_key_bytes("Vec<DeviceKey>", &format!("{:?}", vec![dk]));
    }

    // ── Parser rejection accounting ────────────────────────────────────────

    /// Every malformed row the parser drops must be COUNTED, per reason. The
    /// mutation this catches: restoring the bare `if let Some(x) = .. { }` with
    /// no `else`, which is how a byte-shifted mirror download passed `save()`'s
    /// "at least one entry" validation, was atomically committed as the new
    /// keydb, and then resolved nothing for every disc past the damage — with
    /// not one line of log to notice it by.
    #[test]
    fn parse_counts_every_rejected_row_by_reason() {
        let good_pk = format!("| PK | 0x{}", "ab".repeat(16));
        let cfg = format!(
            "{good_pk}\n\
             | DK | DEVICE_KEY 0xZZ | DEVICE_NODE 0x0800 | KEY_UV 0x00000400 | KEY_U_MASK_SHIFT 0x17\n\
             | PK | 0xnothex\n\
             | HC | HOST_PRIV_KEY 0x00 | HOST_CERT 0x00\n\
             | HC2 | HOST_PRIV_KEY 0x00 | HOST_CERT 0x00\n\
             0xdeadbeef and no equals sign here\n"
        );
        let (db, stats) = KeyDb::parse_counted(&cfg);
        assert_eq!(stats.dk_rejected, 1, "the bad DK row must be counted");
        assert_eq!(stats.pk_rejected, 1, "the bad PK row must be counted");
        assert_eq!(stats.hc_rejected, 1, "the short HC row must be counted");
        assert_eq!(stats.hc2_rejected, 1, "the short HC2 row must be counted");
        assert_eq!(stats.rejected(), 4, "four rows rejected in total");
        // The one GOOD row still loaded — counting must not change parsing.
        assert_eq!(db.processing_keys, vec![[0xABu8; 16]]);
        // A `0x` line with no " = " is not a disc row at all, so it is not a
        // rejection (it is a comment-shaped line the format allows).
        assert_eq!(stats.disc_rejected, 0);
    }

    /// A duplicated disc hash silently last-wins through `HashMap::insert`:
    /// one of the two rows' keys becomes unreachable. Not necessarily
    /// corruption, but never something to discover silently.
    #[test]
    fn parse_counts_duplicate_disc_hashes() {
        let k1 = "01".repeat(16);
        let k2 = "02".repeat(16);
        let cfg = format!("0xAAAA = T | U | 1-0x{k1}\n0xaaaa = T | U | 1-0x{k2}\n");
        let (db, stats) = KeyDb::parse_counted(&cfg);
        assert_eq!(db.disc_entries.len(), 1, "same hash ⇒ one entry survives");
        assert_eq!(
            stats.disc_duplicate, 1,
            "the overwritten row must be counted, not vanish"
        );
        // Last wins — pinned so the counter documents the ACTUAL behaviour.
        assert_eq!(db.get_uk("0xaaaa"), vec![(1, [0x02u8; 16])]);
    }

    /// Hitting `MAX_DISC_ENTRIES` drops real discs, so it must produce a
    /// diagnostic like `load`'s size / UTF-8 caps do — not a bare `continue`.
    /// Driven through the cap constant itself so it cannot rot if the cap moves.
    #[test]
    fn parse_counts_disc_rows_dropped_over_the_entry_cap() {
        let k = "01".repeat(16);
        let mut cfg = String::with_capacity((MAX_DISC_ENTRIES + 2) * 16);
        for i in 0..MAX_DISC_ENTRIES + 2 {
            cfg.push_str(&format!("0x{i:x} = T | U | 1-0x{k}\n"));
        }
        let (db, stats) = KeyDb::parse_counted(&cfg);
        assert_eq!(
            db.disc_entries.len(),
            MAX_DISC_ENTRIES,
            "cap still enforced"
        );
        assert_eq!(
            stats.disc_over_cap, 2,
            "the two rows dropped by the cap must be counted"
        );
    }

    /// A disc row rejected by the FIELD parser is counted separately from one
    /// dropped by the cap.
    #[test]
    fn parse_counts_unparseable_disc_row() {
        // ` = ` present (so it IS a disc row) but `split_once(" = ")` succeeds
        // and the entry parses — to get a genuine rejection the row must fail
        // `parse_disc_entry`, which only returns None without a " = ". Nothing
        // in today's grammar can be a disc row AND fail, so the counter is
        // proven by construction elsewhere; assert the healthy case is zero so
        // a future parser change that starts rejecting rows cannot do it
        // silently.
        let k = "01".repeat(16);
        let (_, stats) = KeyDb::parse_counted(&format!("0xAAAA = T | U | 1-0x{k}\n"));
        assert_eq!(stats.rejected(), 0, "a healthy keydb rejects nothing");
        assert_eq!(stats.disc_duplicate, 0);
    }

    // ── `0X` disc rows / the save() lockstep ────────────────────────────────

    /// The disc-row test is `starts_with("0x")` — CASE-SENSITIVE, while
    /// `parse_hex` in this same file deliberately accepts `0x` AND `0X` (and is
    /// tested for it). An uppercase `0X…` row was therefore dropped with no
    /// diagnostic at all: not parsed, not counted, not logged. Catches the
    /// mutation that removes the `0X` arm of `is_disc_entry_line`.
    #[test]
    fn disc_row_with_uppercase_0x_prefix_is_parsed() {
        let v = "33".repeat(16);
        let db = KeyDb::parse(&format!("0XABCDEF = T | V | 0x{v}\n"));
        assert_eq!(
            db.disc_entries.len(),
            1,
            "an uppercase 0X disc row must parse, like every other hex field"
        );
        // The hash is lowercased on the way in, so lookup is unaffected.
        assert_eq!(db.find_vuk("0xabcdef"), Some([0x33u8; 16]));
        assert!(is_disc_entry_line("0XAA = T"));
        assert!(is_disc_entry_line("0xaa = T"));
        // Still not a disc row without the " = " separator.
        assert!(!is_disc_entry_line("0XAABBCC"));
    }

    // ── One allocation per disc hash, not two ──────────────────────────────

    /// The map key and the entry's own `disc_hash` must be the SAME allocation.
    /// They used to be two `String`s (`insert(entry.disc_hash.clone(), entry)`),
    /// ~13 MB of duplicate hash text across the real keydb's 181k entries — now
    /// resident for the process lifetime, since `KeydbSource` caches the parse.
    #[test]
    fn disc_hash_is_stored_once_not_twice() {
        let v = "33".repeat(16);
        let db = KeyDb::parse(&format!("0xABCDEF = T | V | 0x{v}\n"));
        let (key, entry) = db.disc_entries.iter().next().expect("one entry");
        assert!(
            Arc::ptr_eq(key, &entry.disc_hash),
            "the map key must BE the entry's disc_hash allocation, not a clone"
        );
    }

    // ════════════════════════════════════════════════════════════════════
    // Hardening additions
    // ════════════════════════════════════════════════════════════════════

    // ── parse_hex / parse_hex16 / parse_hex20 ──────────────────────────────

    #[test]
    fn parse_hex_strips_lower_and_upper_prefixes() {
        // Both lower- and upper-case prefixes are stripped (trim_start_matches
        // "0x" then "0X"). Without one of those strips a value would be off by
        // a nibble or fail length checks.
        assert_eq!(parse_hex("0xABCD"), Some(vec![0xAB, 0xCD]));
        assert_eq!(parse_hex("0XABCD"), Some(vec![0xAB, 0xCD]));
        assert_eq!(parse_hex("ABCD"), Some(vec![0xAB, 0xCD]));
    }

    #[test]
    fn parse_hex_mixed_case_nibbles() {
        // to_digit(16) accepts both cases.
        assert_eq!(parse_hex("aB"), Some(vec![0xAB]));
        assert_eq!(parse_hex("Ff00"), Some(vec![0xFF, 0x00]));
    }

    #[test]
    fn parse_hex_rejects_non_hex_digit() {
        // 'G' is not a hex digit → None (not silently 0).
        assert!(parse_hex("0xGG").is_none());
        assert!(parse_hex("12ZZ").is_none());
    }

    #[test]
    fn parse_hex_empty_is_empty_vec() {
        // Empty (or bare "0x") → Some(empty): even byte-length 0 passes, and
        // there are no nibbles to reject. parse_hex16/20 then reject on length.
        assert_eq!(parse_hex(""), Some(vec![]));
        assert_eq!(parse_hex("0x"), Some(vec![]));
    }

    #[test]
    fn parse_hex16_enforces_exactly_16_bytes() {
        assert!(parse_hex16(&format!("0x{}", "00".repeat(15))).is_none());
        assert!(parse_hex16(&format!("0x{}", "00".repeat(17))).is_none());
        assert_eq!(
            parse_hex16(&format!("0x{}", "00".repeat(16))),
            Some([0u8; 16])
        );
    }

    #[test]
    fn parse_hex20_enforces_exactly_20_bytes() {
        assert!(parse_hex20(&format!("0x{}", "00".repeat(19))).is_none());
        assert_eq!(
            parse_hex20(&format!("0x{}", "11".repeat(20))),
            Some([0x11u8; 20])
        );
    }

    // ── Disc entry field parsing ───────────────────────────────────────────

    #[test]
    fn disc_entry_hash_is_lowercased() {
        // The disc_hash key is lowercased so HashMap lookups are
        // case-insensitive (find_disc lowercases its query too).
        let z32 = "00".repeat(16);
        let line = format!("0xABCDEF = T | M | 0x{z32}");
        let e = KeyDb::parse_disc_entry(&line).unwrap();
        assert_eq!(&*e.disc_hash, "0xabcdef");
    }

    #[test]
    fn disc_entry_title_kept_verbatim_even_with_parens() {
        // Faithful copy: the title is kept VERBATIM, parens and all — NOT reduced
        // to the parenthesised substring (which truncated real multi-paren titles
        // and broke serialize→parse idempotence).
        let line = "0x00 = RAW_NAME (Display Name) | M | 0x".to_string() + &"00".repeat(16);
        let e = KeyDb::parse_disc_entry(&line).unwrap();
        assert_eq!(e.title, "RAW_NAME (Display Name)");
    }

    #[test]
    fn disc_entry_title_without_parens_uses_whole() {
        let line = "0x00 = PlainTitle | M | 0x".to_string() + &"00".repeat(16);
        let e = KeyDb::parse_disc_entry(&line).unwrap();
        assert_eq!(e.title, "PlainTitle");
    }

    #[test]
    fn disc_entry_malformed_parens_falls_back_to_whole_title() {
        // The title is kept verbatim regardless of paren placement — a malformed
        // ')' before '(' is not special-cased; the whole string is the title.
        let line = "0x00 = FILM) (X | M | 0x".to_string() + &"00".repeat(16);
        let e = KeyDb::parse_disc_entry(&line).unwrap();
        assert_eq!(e.title, "FILM) (X");
    }

    #[test]
    fn disc_entry_parses_all_tagged_fields() {
        // M, I, V, U each populate their field. U accepts "n-0xKEY".
        let m = "11".repeat(16);
        let i = "22".repeat(16);
        let v = "33".repeat(16);
        let u = "44".repeat(16);
        let line = format!("0xAA = T | M | 0x{m} | I | 0x{i} | V | 0x{v} | U | 2-0x{u}");
        let e = KeyDb::parse_disc_entry(&line).unwrap();
        assert_eq!(e.media_key, Some([0x11u8; 16]));
        assert_eq!(e.vid, Some([0x22u8; 16]));
        assert_eq!(e.vuk, Some([0x33u8; 16]));
        assert_eq!(e.unit_keys, vec![(2, [0x44u8; 16])]);
    }

    #[test]
    fn disc_entry_multiple_unit_keys_space_separated() {
        // The U field carries space-separated "n-0xKEY" pairs.
        let k1 = "01".repeat(16);
        let k2 = "02".repeat(16);
        let line = format!("0xAA = T | U | 1-0x{k1} 2-0x{k2}");
        let e = KeyDb::parse_disc_entry(&line).unwrap();
        assert_eq!(e.unit_keys, vec![(1, [0x01u8; 16]), (2, [0x02u8; 16])]);
    }

    #[test]
    fn disc_entry_unit_key_strips_trailing_comment() {
        // "U | 1-0xKEY ; comment" — the ';' comment must be stripped before
        // splitting unit keys.
        let k = "05".repeat(16);
        let line = format!("0xAA = T | U | 1-0x{k} ; MKBv77 note");
        let e = KeyDb::parse_disc_entry(&line).unwrap();
        assert_eq!(e.unit_keys, vec![(1, [0x05u8; 16])]);
    }

    #[test]
    fn disc_entry_skips_unparseable_unit_key_pair() {
        // A bad nibble in one unit key drops just that pair (parse_hex16 →
        // None), keeping the valid ones — no panic, no half-garbage key.
        let good = "07".repeat(16);
        let line = format!("0xAA = T | U | 1-0xZZ 2-0x{good}");
        let e = KeyDb::parse_disc_entry(&line).unwrap();
        assert_eq!(e.unit_keys, vec![(2, [0x07u8; 16])]);
    }

    #[test]
    fn disc_entry_field_with_short_hex_is_none_not_panic() {
        // A 30-hex-char (15-byte) M value fails parse_hex16 → media_key None.
        let short = "00".repeat(15);
        let line = format!("0xAA = T | M | 0x{short}");
        let e = KeyDb::parse_disc_entry(&line).unwrap();
        assert!(e.media_key.is_none());
    }

    // ── find_disc / find_vuk: prefix-agnostic lookup ───────────────────────

    #[test]
    fn find_disc_matches_with_and_without_0x_and_case() {
        let v = "33".repeat(16);
        let line = format!("0xABCDEF = T | V | 0x{v}");
        let db = KeyDb::parse(&line);
        // Stored key is "0xabcdef". Query in several shapes.
        assert!(db.find_disc("0xABCDEF").is_some());
        assert!(db.find_disc("ABCDEF").is_some()); // no prefix
        assert!(db.find_disc("0xabcdef").is_some());
        assert!(db.find_disc("  0xAbCdEf  ").is_some()); // padded + mixed case
        assert_eq!(db.find_vuk("ABCDEF"), Some([0x33u8; 16]));
        assert!(db.find_disc("0xDEADBE").is_none());
    }

    // ── Comments / blank lines / unknown lines ─────────────────────────────

    #[test]
    fn parse_ignores_comments_and_blank_lines() {
        let cfg = "\n; a comment\n# another\n   \n";
        let db = KeyDb::parse(cfg);
        assert!(db.device_keys.is_empty());
        assert!(db.processing_keys.is_empty());
        assert!(db.disc_entries.is_empty());
        assert!(db.host_certs.is_empty());
    }

    #[test]
    fn parse_empty_or_keyless_file_is_lenient_not_error() {
        // parse() never errors; a keyless file is an empty KeyDb (documented
        // contract — load() errors only on read failure, not empty content).
        let db = KeyDb::parse("; nothing here\n");
        assert_eq!(db.disc_entries.len(), 0);
    }

    #[test]
    fn parse_device_key_requires_all_four_fields() {
        // Missing KEY_U_MASK_SHIFT → parse_device_key returns None; with no
        // position fields at all it would be an orphan DK instead. Here the
        // line has DEVICE_NODE + KEY_UV but no shift → neither parser accepts
        // it as a positioned DK, and parse_orphan_dk rejects it (has position
        // fields), so nothing is loaded.
        let line = "| DK | DEVICE_KEY 0x00000000000000000000000000000000 | DEVICE_NODE 0x0800 | KEY_UV 0x00000400";
        assert!(KeyDb::parse_device_key(line).is_none());
        let db = KeyDb::parse(line);
        assert!(db.device_keys.is_empty());
        assert!(db.processing_keys.is_empty());
    }

    #[test]
    fn parse_device_key_accepts_uppercase_0x_prefix() {
        // Regression: node/uv/shift parsed via a case-sensitive
        // `trim_start_matches("0x")`, so an uppercase `0X` prefix was not
        // stripped, `from_str_radix` failed, and the WHOLE device key was
        // silently dropped. All four fields must parse regardless of prefix case.
        let line = "| DK | DEVICE_KEY 0x000102030405060708090A0B0C0D0E0F \
                    | DEVICE_NODE 0X0001 | KEY_UV 0X00000002 | KEY_U_MASK_SHIFT 0X03";
        let dk = KeyDb::parse_device_key(line).expect("uppercase 0X prefix must parse");
        assert_eq!(dk.node, 1);
        assert_eq!(dk.uv, 2);
        assert_eq!(dk.u_mask_shift, 3);
    }

    #[test]
    fn parse_host_cert_v2_rejects_wrong_priv_len_and_short_cert() {
        // v2 priv must be exactly 32 bytes; cert must be >= 132.
        let bad_priv = format!(
            "| HC2 | HOST_PRIV_KEY 0x{} | HOST_CERT 0x{}",
            "00".repeat(31),
            "00".repeat(132)
        );
        assert!(KeyDb::parse_host_cert_v2(&bad_priv).is_none());
        let short_cert = format!(
            "| HC2 | HOST_PRIV_KEY 0x{} | HOST_CERT 0x{}",
            "00".repeat(32),
            "00".repeat(131)
        );
        assert!(KeyDb::parse_host_cert_v2(&short_cert).is_none());
    }

    #[test]
    fn parse_processing_key_pk_row() {
        // "| PK | 0x..." → 16-byte processing key. A trailing comment is
        // stripped at ';'.
        let line = format!("| PK | 0x{} ; MKBv64", "AB".repeat(16));
        let pk = KeyDb::parse_processing_key(&line).unwrap();
        assert_eq!(pk, [0xABu8; 16]);
    }

    // ── Disc-entry comment metadata: MKBv / VolumeSize / UHD ────────────────

    #[test]
    fn disc_entry_comment_uhd_mkb_and_volume_size() {
        // Canonical UHD comment grammar.
        let z = "00".repeat(16);
        let line = format!(
            "0xAA = T | M | 0x{z} | U | 1-0x{z} ; MKBv76/BEE/FindVUK 1.74 - VolumeSize: 81309007872 (UHD)"
        );
        let e = KeyDb::parse_disc_entry(&line).unwrap();
        assert_eq!(e.mkb_version, Some(76));
        assert_eq!(e.volume_size, Some(81_309_007_872));
        assert!(e.is_uhd);
    }

    #[test]
    fn disc_entry_comment_bd_is_not_uhd() {
        // "(BD)" comment ⇒ is_uhd false, VolumeSize still parsed.
        let z = "00".repeat(16);
        let line =
            format!("0xAA = T | M | 0x{z} ; MKBv68/FindVUK 1.24 - VolumeSize: 37672976384 (BD)");
        let e = KeyDb::parse_disc_entry(&line).unwrap();
        assert!(!e.is_uhd);
        assert_eq!(e.volume_size, Some(37_672_976_384));
        assert_eq!(e.mkb_version, Some(68));
    }

    #[test]
    fn disc_entry_no_comment_all_metadata_none_and_fields_still_parse() {
        // Regression: with NO trailing comment the three new fields default to
        // None/false AND the U/M/I/V fields still parse correctly.
        let m = "11".repeat(16);
        let i = "22".repeat(16);
        let v = "33".repeat(16);
        let u = "44".repeat(16);
        let line = format!("0xAA = T | M | 0x{m} | I | 0x{i} | V | 0x{v} | U | 2-0x{u}");
        let e = KeyDb::parse_disc_entry(&line).unwrap();
        assert_eq!(e.mkb_version, None);
        assert_eq!(e.volume_size, None);
        assert!(!e.is_uhd);
        // Unchanged field parsing.
        assert_eq!(e.media_key, Some([0x11u8; 16]));
        assert_eq!(e.vid, Some([0x22u8; 16]));
        assert_eq!(e.vuk, Some([0x33u8; 16]));
        assert_eq!(e.unit_keys, vec![(2, [0x44u8; 16])]);
    }

    // ── Host-cert revocation: parse + host_certs(mkb) filter ────────────────

    #[test]
    fn host_cert_revoked_parses_and_filters_by_mkb() {
        let revoked_line = format!(
            "| HC | HOST_PRIV_KEY 0x{} | HOST_CERT 0x{} ; Revoked in MKBv72",
            "00".repeat(20),
            "11".repeat(92),
        );
        let hc = KeyDb::parse_host_cert(&revoked_line).unwrap();
        assert_eq!(hc.revoked_at_mkb, Some(72));

        let db = KeyDb::parse(&revoked_line);
        assert_eq!(db.host_certs.len(), 1);
        // Revoked in MKBv72 ⇒ unusable at gen >= 72, usable below it.
        assert!(
            db.host_certs(Some(72)).is_empty(),
            "a cert revoked in MKBv72 must be excluded at gen 72"
        );
        assert_eq!(
            db.host_certs(Some(71)).len(),
            1,
            "still usable at gen 71 (below the revocation generation)"
        );
        assert_eq!(
            db.host_certs(None).len(),
            1,
            "unknown disc MKB ⇒ cannot filter ⇒ cert returned"
        );
    }

    #[test]
    fn host_cert_without_revocation_included_for_all_mkb() {
        let line = format!(
            "| HC | HOST_PRIV_KEY 0x{} | HOST_CERT 0x{}",
            "00".repeat(20),
            "22".repeat(92),
        );
        let hc = KeyDb::parse_host_cert(&line).unwrap();
        assert_eq!(hc.revoked_at_mkb, None);

        let db = KeyDb::parse(&line);
        assert_eq!(db.host_certs(Some(99)).len(), 1);
        assert_eq!(db.host_certs(Some(1)).len(), 1);
        assert_eq!(db.host_certs(None).len(), 1);
    }

    #[test]
    fn hc2_revocation_propagates_when_hc_has_none() {
        // The HC line carries no annotation; the revocation lives on the HC2
        // line. The combined cert must still be filtered by that generation
        // rather than being treated as never-revoked.
        let cfg = format!(
            "| HC | HOST_PRIV_KEY 0x{} | HOST_CERT 0x{}\n| HC2 | HOST_PRIV_KEY 0x{} | HOST_CERT 0x{} ; Revoked in MKBv72\n",
            "00".repeat(20),
            "00".repeat(92),
            "00".repeat(32),
            "00".repeat(132),
        );
        let db = KeyDb::parse(&cfg);
        assert_eq!(db.host_certs.len(), 1, "HC2 augments the preceding HC");
        assert_eq!(db.host_certs[0].revoked_at_mkb, Some(72));
        assert!(
            db.host_certs(Some(72)).is_empty(),
            "combined cert revoked in MKBv72 must be excluded at gen 72"
        );
        assert_eq!(
            db.host_certs(Some(71)).len(),
            1,
            "still usable below gen 72"
        );
    }

    // ── Standalone accessors: get_vid / get_uk / get_uks ────────────────────

    #[test]
    fn get_vid_hit_and_miss() {
        let i = "22".repeat(16);
        let line = format!("0xABCDEF = T | I | 0x{i}");
        let db = KeyDb::parse(&line);
        // Hit — prefix-agnostic, same form find_disc accepts.
        assert_eq!(db.get_vid("ABCDEF"), Some([0x22u8; 16]));
        assert_eq!(db.get_vid("0xabcdef"), Some([0x22u8; 16]));
        // Miss.
        assert_eq!(db.get_vid("0xDEADBE"), None);
    }

    #[test]
    fn get_uk_hit_and_miss() {
        let k1 = "01".repeat(16);
        let k2 = "02".repeat(16);
        let line = format!("0xABCDEF = T | U | 1-0x{k1} 2-0x{k2}");
        let db = KeyDb::parse(&line);
        assert_eq!(
            db.get_uk("ABCDEF"),
            vec![(1, [0x01u8; 16]), (2, [0x02u8; 16])]
        );
        // Miss ⇒ empty.
        assert!(db.get_uk("0xDEADBE").is_empty());
    }

    #[test]
    fn get_uks_lists_only_entries_with_unit_keys() {
        let k = "03".repeat(16);
        let v = "33".repeat(16);
        let with_uk = format!("0xAAAA = T | U | 1-0x{k}");
        // An entry with only a VUK (no unit keys) must be excluded.
        let no_uk = format!("0xBBBB = T | V | 0x{v}");
        let db = KeyDb::parse(&format!("{with_uk}\n{no_uk}\n"));
        let uks = db.get_uks();
        assert_eq!(uks.len(), 1, "only the entry with unit keys is listed");
        assert_eq!(uks[0].0, "0xaaaa");
        assert_eq!(uks[0].1, vec![(1, [0x03u8; 16])]);
    }

    // ════════════════════════════════════════════════════════════════════
    // KEYDB-parser integration tests relocated from libfreemkv.
    //
    // These exercise the parser (KeyDb::load) end-to-end against a real
    // keydb.cfg and feed its material into libfreemkv's AACS crypto
    // (derive_vuk, then decrypt_unit + is_clean_ts). They live here now that the
    // parser lives here. All are KEYDB_PATH-env-gated and no-op in CI when
    // the env is unset; they must still COMPILE.
    // ════════════════════════════════════════════════════════════════════

    /// REQUIRES a real keydb; `#[ignore]` by default. Run with:
    /// `KEYDB_PATH=/path/to/keydb.cfg cargo test --release -- --ignored`.
    #[test]
    #[ignore = "needs a real keydb.cfg: KEYDB_PATH=<path> cargo test -- --ignored"]
    fn test_vuk_derivation() {
        // Pick any UHD entry with a known MK, VID, and VUK from KEYDB.
        // VUK = AES-DEC(MK, VID) XOR VID
        let path = real_keydb_path();

        let db = KeyDb::load(&path).unwrap();

        // Find a disc with both MK, vid, and VUK so we can verify derivation
        let entry = db
            .disc_entries
            .values()
            .find(|e| e.media_key.is_some() && e.vid.is_some() && e.vuk.is_some())
            .expect("No disc with MK + VID + VUK");

        let mk = entry.media_key.unwrap();
        let vid = entry.vid.unwrap();
        let expected_vuk = entry.vuk.unwrap();

        let derived = libfreemkv::aacs::derive::derive_vuk(&mk, &vid);
        assert_eq!(
            derived, expected_vuk,
            "VUK derivation failed for disc: {} (hash {})",
            entry.title, entry.disc_hash
        );
        eprintln!("VUK derivation verified for: {}", entry.title);
    }

    /// REQUIRES a real keydb AND an encrypted unit dump; `#[ignore]` by default.
    /// Run with: `KEYDB_PATH=<keydb.cfg> ENCRYPTED_UNIT_PATH=<unit.bin> \
    /// cargo test --release -- --ignored`.
    #[test]
    #[ignore = "needs KEYDB_PATH + ENCRYPTED_UNIT_PATH: cargo test -- --ignored"]
    fn test_decrypt_real_unit() {
        // Try decrypting a real encrypted aligned unit from a UHD sample.
        // This disc is AACS 2.0 (BEE) so unit key alone won't work —
        // we need bus decryption first. But this verifies the pipeline.
        // Path comes from ENCRYPTED_UNIT_PATH (same env-driven pattern as the
        // KEYDB_PATH fixture); no-ops in CI when unset.
        let unit_path = std::path::PathBuf::from(
            std::env::var("ENCRYPTED_UNIT_PATH")
                .expect("ENCRYPTED_UNIT_PATH must point at an encrypted aligned unit"),
        );
        assert!(
            unit_path.exists(),
            "ENCRYPTED_UNIT_PATH does not exist: {}",
            unit_path.display()
        );

        let original = std::fs::read(&unit_path).unwrap();
        assert_eq!(original.len(), libfreemkv::aacs::content::ALIGNED_UNIT_LEN);
        assert!(
            !libfreemkv::aacs::content::is_clean(&original, libfreemkv::disc::ContentFormat::BdTs),
            "Unit should be encrypted"
        );

        let kp = real_keydb_path();
        let db = KeyDb::load(&kp).unwrap();

        // Candidate entries: any UHD entry that carries unit keys.
        let candidate_entries: Vec<&DiscEntry> = db
            .disc_entries
            .values()
            .filter(|e| !e.unit_keys.is_empty())
            .collect();

        eprintln!("Found {} entries with unit keys", candidate_entries.len());
        // Without candidates nothing below runs and the test would "pass" having
        // exercised nothing — a parser regression that dropped every unit key
        // would look exactly like the expected AACS 2.0 outcome.
        assert!(
            !candidate_entries.is_empty(),
            "the fixture keydb must carry at least one entry with unit keys"
        );

        // Try each entry's unit keys: apply the key, then ask whether it opened
        // the unit (the segregated primitives — decrypt, then structural check).
        let mut attempts = 0usize;
        let mut any_key_changed_the_unit = false;
        for entry in &candidate_entries {
            for (_, key) in &entry.unit_keys {
                let mut unit = original.clone();
                libfreemkv::aacs::content::decrypt_unit(&mut unit, key);
                attempts += 1;
                any_key_changed_the_unit |= unit != original;
                if libfreemkv::aacs::content::is_clean(&unit, libfreemkv::disc::ContentFormat::BdTs)
                {
                    eprintln!("SUCCESS: Decrypted with entry {}", entry.disc_hash);
                    // Count TS sync bytes
                    let ts = (0..32).filter(|&i| unit[4 + i * 192] == 0x47).count();
                    eprintln!("  TS sync bytes: {}/32", ts);
                    return;
                }
            }
        }

        // Reaching here is the EXPECTED outcome for the AACS 2.0 (BEE) sample
        // this test was written against: the unit is still bus-encrypted, so no
        // unit key alone can open it. That makes "no key worked" an unusable
        // assertion — which is exactly why this test used to end in an
        // `eprintln!` and fall off the end, i.e. pass unconditionally. A no-op
        // `decrypt_unit`, an `is_clean` stuck at `false`, or a parser that
        // yielded zero keys would all have produced this same clean exit.
        //
        // What CAN be asserted regardless of the sample: the pipeline actually
        // ran, and the decrypt primitive actually transformed the bytes.
        assert!(attempts > 0, "no unit key was tried at all");
        assert!(
            any_key_changed_the_unit,
            "decrypt_unit left the aligned unit byte-identical for all {attempts} keys — \
             the decrypt primitive is a no-op, not a failed key"
        );
        eprintln!(
            "No unit key worked over {attempts} attempts \
             (expected for AACS 2.0 BEE disc — needs read_data_key)"
        );
    }

    /// REQUIRES a real keydb; `#[ignore]` by default. Run with:
    /// `KEYDB_PATH=/path/to/keydb.cfg cargo test --release -- --ignored`.
    #[test]
    #[ignore = "needs a real keydb.cfg: KEYDB_PATH=<path> cargo test -- --ignored"]
    fn test_resolve_keys_vuk_path() {
        // Test the full resolve chain using VUK path
        let path = real_keydb_path();
        let db = KeyDb::load(&path).unwrap();

        // Find any BD entry that carries a VUK and unit keys, then exercise
        // the lookup-by-hash + VUK-derivation chain against it.
        // `expect`, not an early `return`: returning here asserted NOTHING while
        // reporting success, so a parser regression that stopped populating
        // `vid`/`vuk` — the very fields this test exists to exercise — would make
        // the `find` miss and ship green. If the fixture genuinely has no such
        // entry, that is a broken fixture and must be loud.
        let entry = db
            .disc_entries
            .values()
            .find(|e| e.vuk.is_some() && !e.unit_keys.is_empty() && e.vid.is_some())
            .expect("the fixture keydb must carry an entry with VUK + unit keys + VID");
        let vuk = entry.vuk.unwrap();
        let vid = entry.vid.unwrap();
        let hash_hex = format!("0x{}", libfreemkv::hex::strip_hex_prefix(&entry.disc_hash));

        // We need the actual Unit_Key_RO.inf from the disc to compute disc hash.
        // Since we don't have it, we can at least test that the KEYDB lookup
        // works with a known hash.
        let found = db.find_disc(&hash_hex);
        assert!(found.is_some());
        assert_eq!(found.unwrap().vuk, Some(vuk));

        // Verify VUK derivation if we have MK + VID
        if let Some(mk) = entry.media_key {
            let derived = libfreemkv::aacs::derive::derive_vuk(&mk, &vid);
            assert_eq!(derived, vuk, "VUK derivation mismatch");
            eprintln!("VUK derivation verified");
        }
    }
}
