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
// `candidates_from`/`host_certs`). The unused items — `empty`, `find_vuk`,
// `DiscEntry::{title, vid}` — are part of the faithful copy and are
// retained rather than pruned; allow dead_code so the byte-for-byte copy
// compiles clean without diverging from the libfreemkv original.
#![allow(dead_code)]

use std::collections::HashMap;

use libfreemkv::aacs::types::{DeviceKey, HostCert};

/// A keydb per-disc unit key: the CPS-unit number paired with its 16-byte key.
pub type NumberedUnitKey = (u32, [u8; 16]);

/// Upper bound on the on-disk keydb.cfg size accepted by [`KeyDb::load`].
/// The real public UHD keydb is a few MiB; 64 MiB is generous headroom while
/// still bounding the worst-case allocation from a hostile/corrupt file.
const MAX_KEYDB_BYTES: u64 = 64 * 1024 * 1024;

/// Upper bound on parsed disc entries. The real public keydb carries
/// ~170k+ entries, so the cap sits well above that while still bounding
/// memory against a pathological input. Surplus lines are ignored.
const MAX_DISC_ENTRIES: usize = 500_000;

/// Parsed AACS key database.
#[derive(Debug)]
pub struct KeyDb {
    /// Device keys for MKB processing
    pub device_keys: Vec<DeviceKey>,
    /// Processing keys (pre-computed media keys for specific MKB versions)
    pub processing_keys: Vec<[u8; 16]>,
    /// Host certificate + private key for SCSI authentication, paired with the
    /// keydb's revocation metadata (libfreemkv's `HostCert` stays pure; the
    /// `Revoked in MKBv<N>` annotation is tracked in this crate).
    pub host_certs: Vec<KeydbHostCert>,
    /// Per-disc VUK entries indexed by disc hash (hex lowercase)
    pub disc_entries: HashMap<String, DiscEntry>,
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
#[derive(Debug, Clone)]
pub struct DiscEntry {
    /// Disc hash (20 bytes, hex)
    pub disc_hash: String,
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
    pub fn parse(data: &str) -> Self {
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
                }
                continue;
            }

            // Processing Key
            if line.starts_with("| PK") {
                if let Some(pk) = Self::parse_processing_key(line) {
                    db.processing_keys.push(pk);
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
                }
                continue;
            }

            // Host Certificate (AACS 1.0)
            if line.starts_with("| HC") {
                if let Some(hc) = Self::parse_host_cert(line) {
                    db.host_certs.push(hc);
                }
                continue;
            }

            // Disc entry: starts with 0x
            if line.starts_with("0x") && line.contains(" = ") {
                if db.disc_entries.len() >= MAX_DISC_ENTRIES {
                    continue;
                }
                if let Some(entry) = Self::parse_disc_entry(line) {
                    db.disc_entries.insert(entry.disc_hash.clone(), entry);
                }
            }
        }

        db
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
        // Stat-and-cap before reading so a hostile/corrupt file can't force an
        // unbounded allocation. A file strictly over the cap is rejected (a
        // file exactly at MAX_KEYDB_BYTES is accepted, matching the `>` guard
        // and libfreemkv's original at-cap-is-allowed semantics).
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.len() > MAX_KEYDB_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "keydb.cfg exceeds {MAX_KEYDB_BYTES} byte cap: {}",
                        path.display()
                    ),
                ));
            }
        }
        let data = std::fs::read_to_string(path)?;
        Ok(Self::parse(&data))
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
            .get(&format!("0x{hash}"))
            .or_else(|| self.disc_entries.get(&hash))
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
            .get(&format!("0x{hash}"))
            .or_else(|| self.disc_entries.get(&hash))
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
            .map(|e| (e.disc_hash.clone(), e.unit_keys.clone()))
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
        let mut hashes: Vec<&String> = self.disc_entries.keys().collect();
        hashes.sort();
        for h in hashes {
            let d = &self.disc_entries[h];
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
            node: u16::from_str_radix(node_str.trim_start_matches("0x"), 16).ok()?,
            uv: u32::from_str_radix(uv_str.trim_start_matches("0x"), 16).ok()?,
            u_mask_shift: u8::from_str_radix(shift_str.trim_start_matches("0x"), 16).ok()?,
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
        let disc_hash = hash_part.trim().to_lowercase();

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
                "M" => {
                    if i + 1 < parts.len() {
                        media_key = parse_hex16(parts[i + 1].trim());
                        i += 1;
                    }
                }
                "I" => {
                    if i + 1 < parts.len() {
                        vid = parse_hex16(parts[i + 1].trim());
                        i += 1;
                    }
                }
                "V" => {
                    if i + 1 < parts.len() {
                        vuk = parse_hex16(parts[i + 1].trim());
                        i += 1;
                    }
                }
                "U" => {
                    if i + 1 < parts.len() {
                        // Unit keys: "1-0xKEY" or "1-0xKEY ; comment"
                        let uk_str = parts[i + 1].split(';').next().unwrap_or("").trim();
                        for uk in uk_str.split(' ') {
                            let uk = uk.trim();
                            if let Some((num, key)) = uk.split_once('-') {
                                if let Ok(n) = num.parse::<u32>() {
                                    if let Some(k) = parse_hex16(key) {
                                        unit_keys.push((n, k));
                                    }
                                }
                            }
                        }
                        i += 1;
                    }
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

    /// `to_keydb_cfg` is the exact inverse of `parse`: parse a known line set,
    /// serialize it, re-parse, and every field survives — device key, processing
    /// key, host cert (priv key + cert + revocation), and the per-disc M/I(vid)/V/U
    /// keys plus the MKBv/UHD comment metadata. Both sides go through `parse`, so
    /// internal key forms (e.g. the `0x`-prefixed disc-hash) match by construction.
    #[test]
    fn to_keydb_cfg_round_trips_through_parse() {
        let h = |b: u8, n: usize| {
            std::iter::repeat(format!("{b:02x}"))
                .take(n)
                .collect::<String>()
        };
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
    /// Skipped unless `KEYDB_PATH` points at a real keydb.cfg.
    #[test]
    fn to_keydb_cfg_is_idempotent_on_real_keydb() {
        let path = match keydb_path() {
            Some(p) => p,
            None => return,
        };
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

    /// Get KEYDB path from KEYDB_PATH environment variable. Returns None if not set or not found.
    fn keydb_path() -> Option<std::path::PathBuf> {
        let path = std::path::PathBuf::from(std::env::var("KEYDB_PATH").ok()?);
        if path.exists() { Some(path) } else { None }
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

    #[test]
    fn test_parse_full_keydb() {
        let path = match keydb_path() {
            Some(p) => p,
            None => return,
        }; // skip if not available

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
        assert_eq!(e.disc_hash, "0xabcdef");
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
    // (derive_vuk / decrypt_unit_try_keys). They live here now that the
    // parser lives here. All are KEYDB_PATH-env-gated and no-op in CI when
    // the env is unset; they must still COMPILE.
    // ════════════════════════════════════════════════════════════════════

    #[test]
    fn test_vuk_derivation() {
        // Pick any UHD entry with a known MK, VID, and VUK from KEYDB.
        // VUK = AES-DEC(MK, VID) XOR VID
        let path = match keydb_path() {
            Some(p) => p,
            None => return,
        };

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

    #[test]
    fn test_decrypt_real_unit() {
        // Try decrypting a real encrypted aligned unit from a UHD sample.
        // This disc is AACS 2.0 (BEE) so unit key alone won't work —
        // we need bus decryption first. But this verifies the pipeline.
        // Path comes from ENCRYPTED_UNIT_PATH (same env-driven pattern as the
        // KEYDB_PATH fixture); no-ops in CI when unset.
        let unit_path = match std::env::var("ENCRYPTED_UNIT_PATH").ok() {
            Some(p) => std::path::PathBuf::from(p),
            None => return,
        };
        if !unit_path.exists() {
            return;
        }

        let original = std::fs::read(&unit_path).unwrap();
        assert_eq!(original.len(), libfreemkv::aacs::content::ALIGNED_UNIT_LEN);
        assert!(
            libfreemkv::aacs::content::ts_sync_destroyed(&original),
            "Unit should be encrypted"
        );

        let kp = match keydb_path() {
            Some(p) => p,
            None => return,
        };
        let db = KeyDb::load(&kp).unwrap();

        // Candidate entries: any UHD entry that carries unit keys.
        let candidate_entries: Vec<&DiscEntry> = db
            .disc_entries
            .values()
            .filter(|e| !e.unit_keys.is_empty())
            .collect();

        eprintln!("Found {} entries with unit keys", candidate_entries.len());

        // Try each entry's unit keys
        for entry in &candidate_entries {
            let keys: Vec<[u8; 16]> = entry.unit_keys.iter().map(|(_, k)| *k).collect();
            let mut unit = original.clone();

            if let Some(res) = libfreemkv::aacs::content::decrypt_unit_try_keys(&mut unit, &keys) {
                eprintln!(
                    "SUCCESS: Decrypted with entry {} ({res:?})",
                    entry.disc_hash
                );
                // Count TS sync bytes
                let ts = (0..32).filter(|&i| unit[4 + i * 192] == 0x47).count();
                eprintln!("  TS sync bytes: {}/32", ts);
                return;
            }
        }

        // Expected: none work because this is AACS 2.0 and needs bus decryption first
        eprintln!("No unit key worked (expected for AACS 2.0 BEE disc — needs read_data_key)");
    }

    #[test]
    fn test_resolve_keys_vuk_path() {
        // Test the full resolve chain using VUK path
        let path = match keydb_path() {
            Some(p) => p,
            None => return,
        };
        let db = KeyDb::load(&path).unwrap();

        // Find any BD entry that carries a VUK and unit keys, then exercise
        // the lookup-by-hash + VUK-derivation chain against it.
        let entry = db
            .disc_entries
            .values()
            .find(|e| e.vuk.is_some() && !e.unit_keys.is_empty() && e.vid.is_some());
        if entry.is_none() {
            return;
        }
        let entry = entry.unwrap();
        let vuk = entry.vuk.unwrap();
        let vid = entry.vid.unwrap();
        let hash_hex = format!("0x{}", entry.disc_hash.trim_start_matches("0x"));

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
