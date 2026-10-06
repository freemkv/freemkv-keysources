//! AACS Key Database parsing — KEYDB.cfg format.
//!
//! Byte-faithful copy of libfreemkv's `aacs::keydb` parser, relocated so the
//! keydb.cfg format lives with the key sources that consume it. The parsing
//! logic is identical; the only deviation is [`KeyDb::load`], which returns a
//! standalone [`std::io::Result`] here instead of `libfreemkv::error::Result`
//! (so the format crate carries no dependency on libfreemkv's error type).
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;

use libfreemkv::aacs::types::{DeviceKey, HostCert};

/// A keydb per-disc unit key: the CPS-unit number paired with its 16-byte key.
pub type NumberedUnitKey = (u32, [u8; 16]);

/// Upper bound on the keydb.cfg byte size (the public UHD keydb is ~62 MiB;
/// 128 MiB bounds a hostile/corrupt file). The SINGLE definition for the crate:
/// [`KeyDb::load`] uses it as the on-disk load cap and [`crate::KeydbSource`]
/// re-uses it as the decompression-bomb cap on the save/update path, so the two
/// can never drift out of lockstep.
pub(crate) const MAX_KEYDB_BYTES: u64 = 128 * 1024 * 1024;

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

// Key material must never leak via `{:?}`; both types below carry raw AACS key bytes.

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

// Parse a hex string like "0xABCD..." into bytes. Operates on bytes, not
// `&str` char boundaries: the keydb is third-party content, so a non-ASCII
// scalar must not panic on a mid-codepoint slice. Non-hex byte -> `None`.
pub(crate) fn parse_hex(s: &str) -> Option<Vec<u8>> {
    // The one workspace hex parser (strips an optional 0x/0X, byte-based).
    libfreemkv::hex::parse_hex_bytes(s)
}

// Read digits right after the first `marker` in `text`. Byte-based so
// untrusted comment text never panics on a char boundary; skips whitespace
// before the digits, serving both `MKBv<N>` and `VolumeSize: <N>`.
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

// What `KeyDb::parse` threw away, by reason.
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
    }

    // Emit the one summary line, if there is anything to say; returns whether
    // it fired (tests use this). `pub(crate)` so `KeydbSource` can re-emit it
    // on a cache hit too, keeping the warning from going silent forever.
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
            disc_duplicate = self.disc_duplicate,
            "keydb.cfg lines were rejected while parsing; the file may be truncated or corrupt (keys past the damage will not resolve)"
        );
        true
    }
}

// True when `line` opens a per-disc row. Matches `0x`/`0X` case-insensitively
// (like `parse_hex`) so an uppercase row isn't silently dropped. Shared with
// `KeydbSource::save`, whose entry count must match what this parser accepts.
pub(crate) fn is_disc_entry_line(line: &str) -> bool {
    (line.starts_with("0x") || line.starts_with("0X")) && line.contains(" = ")
}

/// True when `line` is a row `KeyDb::parse` would actually ACCEPT into the db — a disc row OR a
/// DK/PK/HC/HC2 row that its real parser accepts, not merely one carrying the right `| XX`
/// prefix. `KeydbSource::save`'s "won't persist unparseable content" guard counts entries with
/// THIS, so a syntactically prefixed but malformed DK/PK/HC row (right prefix, bad hex/short
/// cert) can no longer inflate the entry count past the `entries > 0` check. Mirrors the
/// dispatch in [`KeyDb::parse_counted`] exactly.
pub(crate) fn is_parseable_entry_line(line: &str) -> bool {
    let line = line.trim();
    if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
        return false;
    }
    // Order matches `parse_counted`: HC2 before HC (both share the `| HC`
    // prefix); an orphan DK (no position fields) still counts as a DK.
    if line.starts_with("| DK") {
        return KeyDb::parse_device_key(line).is_some() || KeyDb::parse_orphan_dk(line).is_some();
    }
    if line.starts_with("| PK") {
        return KeyDb::parse_processing_key(line).is_some();
    }
    if line.starts_with("| HC2") {
        return KeyDb::parse_host_cert_v2(line).is_some();
    }
    if line.starts_with("| HC") {
        return KeyDb::parse_host_cert(line).is_some();
    }
    is_disc_entry_line(line) && KeyDb::parse_disc_entry(line).is_some()
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

        // Strip a leading UTF-8 BOM (U+FEFF): it is NOT trim()-able whitespace, so
        // it would cling to line 1's `0x…` hash and silently drop the first disc
        // row (a keydb saved by a Windows editor).
        let data = data.strip_prefix('\u{feff}').unwrap_or(data);

        for line in data.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
                continue;
            }

            // Device Key: positioned rows -> `device_keys` (tree walk); orphan
            // rows (no position fields) -> `processing_keys` (brute walker).
            // Per AACS a "PK" IS a DK at terminal position, so both are DKs here.
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

            // Host Certificate (AACS 2.0). Normally augments the preceding HC
            // (AACS 1.0) row, but an HC2 row may appear first (third-party line
            // ordering); then it's carried on a fresh HostCert with an empty v1 cert.
            if line.starts_with("| HC2") {
                if let Some((pk, cert, revoked_at_mkb)) = Self::parse_host_cert_v2(line) {
                    if let Some(hc) = db.host_certs.last_mut() {
                        hc.cert.private_key_v2 = Some(pk);
                        hc.cert.certificate_v2 = Some(cert);
                        // The revocation annotation can live on the HC2 line
                        // instead of the HC line; carry it onto the combined
                        // cert if the HC line had none, so it isn't lost.
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

            // Gate on the `0x` PREFIX alone (not `is_disc_entry_line`, which also
            // needs " = "): a malformed `0x…` row is COUNTED as rejected, never
            // silently dropped. No entry cap — a keydb must hold every row.
            if line.starts_with("0x") || line.starts_with("0X") {
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

    // `Self::load` from an ALREADY-OPEN file, without the log.
    pub(crate) fn load_counted(
        f: std::fs::File,
        path: &std::path::Path,
    ) -> std::io::Result<(Self, ParseStats)> {
        // Read through a hard `take` cap rather than trusting a stat: a
        // `metadata` pre-check reports len 0 for a FIFO/char device (e.g. would
        // read `/dev/zero` forever). One byte past cap matches `read_capped_to_string`.
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
        // Try with 0x prefix and without; every stored key currently carries
        // the prefix, so the no-prefix fallback is a defensive match kept for
        // the prefix-agnostic lookup contract.
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
        // No-prefix fallback below (every stored key carries "0x", see
        // find_vuk); kept as a defensive match for the lookup contract.
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
    #[deprecated(note = "use host_certs_ranked; host cert selection takes no disc input")]
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

    /// Every host cert, best first, with no disc input: certs with no `Revoked in
    /// MKBv<N>` note in file order, then revoked ones by latest revocation (a later
    /// revocation is the better bet without knowing the disc's generation).
    pub fn host_certs_ranked(&self) -> Vec<HostCert> {
        let mut ranked: Vec<&KeydbHostCert> = self.host_certs.iter().collect();
        // Stable sort: ties (every unannotated cert, equal revocations) keep file order.
        ranked.sort_by_key(|hc| {
            let r = hc.revoked_at_mkb;
            (r.is_some(), std::cmp::Reverse(r.unwrap_or(0)))
        });
        ranked.into_iter().map(|hc| hc.cert.clone()).collect()
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

    // Parse an orphan DK row: `| DK |` with only `DEVICE_KEY` (no position
    // metadata), treated as terminal/unpositioned by the brute walker. `None`
    // if a position field is present — those are positioned DKs (`parse_device_key`).
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

        // The trailing `;` comment (e.g. "; MKBv76/BEE/FindVUK 1.74 -
        // VolumeSize: 81309007872 (UHD)") carries metadata the key fields
        // don't; capture everything after the FIRST ';' on the line.
        let comment = line.split_once(';').map(|(_, c)| c).unwrap_or("");
        let mkb_version: Option<u32> = parse_digits_after(comment, "MKBv");
        let volume_size: Option<u64> = parse_digits_after(comment, "VolumeSize:");
        let is_uhd = comment.contains("(UHD)");

        // Title kept VERBATIM (trimmed), a faithful copy for exact round-trip.
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
        // Field scan starts at index 1: `parts[0]` is ALWAYS the title chunk;
        // excluding it stops a title matching a field-tag letter ("M"/"I"/"V"/
        // "U"/"D") from being eaten as a tag and shadowing the real field.
        let mut i = 1;
        while i < parts.len() {
            match parts[i].trim() {
                // M/I/V strip a trailing `; comment` before hex-parsing (like the
                // U arm below): when one of these is the row's LAST field, the
                // comment gets glued on and parse_hex16 would otherwise fail.
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
#[path = "keydb_format_tests.rs"]
mod tests;
