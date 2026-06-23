//! `keydb.cfg` key source (source #1).
//!
//! Parses a local `keydb.cfg` and enumerates the material it holds for a disc
//! as candidate [`Key`]s, most-specific first. It does NO derivation — picking
//! which device key applies, or which media key verifies, is the MKB walk, and
//! that lives in libfreemkv (`Disc::decrypt_with`). The candidate order lets
//! the library try each path the keydb could satisfy:
//!
//! 1. per-disc VUK (hash hit)        → `Key::Volume`
//! 2. per-disc unit keys (hash hit)  → `Key::Unit`
//! 3. per-disc media key (hash hit)  → `Key::Media`
//! 4. device-key pool (universal)    → `Key::Device`  (lib walks the MKB)
//! 5. processing-key pool            → `Key::Processing`
//! 6. media-key pool (all entries)   → `Key::Media`   (lib brutes vs the MKB)

use std::path::PathBuf;

use libfreemkv::aacs::{HostCert, KeyDb};
use libfreemkv::{DiscInputs, Key, KeySource};

/// A [`KeySource`] backed by a local `keydb.cfg` file.
pub struct KeydbSource {
    path: PathBuf,
    /// Lazily-built candidate list (UK ▸ VK ▸ MK ▸ DK ▸ …) plus its cursor —
    /// the keydb owns the order and hands one candidate per `next_key`. `None`
    /// until the first `next_key` parses the file.
    cursor: Option<std::vec::IntoIter<Key>>,
}

impl KeydbSource {
    /// A keydb source reading the given `keydb.cfg` path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            cursor: None,
        }
    }

    /// The host certificate(s) in this keydb — the second kind of data the one
    /// keydb file holds (alongside decryption keys). The app passes these to the
    /// live-drive scan as `DriveCredentials` for the AACS handshake. Empty if
    /// the keydb is missing/unreadable or carries no host cert.
    pub fn host_certs(&self) -> Vec<HostCert> {
        match KeyDb::load(&self.path) {
            Ok(db) => db.host_certs,
            Err(_) => Vec::new(),
        }
    }

    /// Build the ordered candidate list from a parsed keydb. Pure (no I/O), so
    /// it is unit-testable without a file on disk.
    ///
    /// Order = cheapest + most authoritative first: **UK ▸ VK ▸ MK ▸ DK**. The
    /// UK is the final per-CPS-unit content key — zero derivation, directly
    /// usable — so it is tried first; the VUK needs one derivation step, an MK
    /// two, and the device-key pool the full MKB walk (AACS-1.0-only, slowest),
    /// so it is the last-resort fallback. Trying the UK first is also what lets a
    /// stale/wrong per-disc VUK be skipped in favour of a good UK in the SAME
    /// entry (`decrypt_with` rejects the VUK; the loop falls through to the UK).
    fn candidates_from(db: &KeyDb, inputs: &DiscInputs) -> Vec<Key> {
        let mut out = Vec::new();

        // Per-disc hit (most specific). find_disc normalizes the hash form.
        if let Some(entry) = db.find_disc(&inputs.disc_hash) {
            // UK first — terminal content key, no derivation.
            if !entry.unit_keys.is_empty() {
                out.push(Key::Unit(entry.unit_keys.clone()));
            }
            // VK next — one step (decrypt Unit_Key_RO.inf).
            if let Some(vuk) = entry.vuk {
                out.push(Key::Volume(vuk));
            }
            // MK — two steps (derive the VUK, then the unit keys).
            if let Some(mk) = entry.media_key {
                out.push(Key::Media(vec![mk]));
            }
        }

        // Universal material — the library walks/brutes it against this disc's
        // MKB and VID.
        if !db.device_keys.is_empty() {
            out.push(Key::Device(db.device_keys.clone()));
        }
        if !db.processing_keys.is_empty() {
            out.push(Key::Processing(db.processing_keys.clone()));
        }

        // Media-key pool across every entry: an MK is MKB-scoped, so a sibling
        // disc's MK may verify against this disc (the path-2.5 brute). Hand the
        // whole pool; the library picks the one that verifies.
        let mk_pool: Vec<[u8; 16]> = db.iter_disc_entries().filter_map(|e| e.media_key).collect();
        if !mk_pool.is_empty() {
            out.push(Key::Media(mk_pool));
        }

        out
    }
}

impl KeySource for KeydbSource {
    /// Expose the keydb's host certs through the trait — the OEM/AACS cert-auth
    /// route collects them across every source via this method. Delegates to the
    /// inherent [`KeydbSource::host_certs`] (same `| HC |`/`| HC2 |` rows parsed
    /// by libfreemkv's keydb parser); no new parsing.
    fn host_certs(&self) -> Vec<HostCert> {
        KeydbSource::host_certs(self)
    }

    /// The keydb can hand out a per-disc **terminal** `Key::Unit` (a UK entry
    /// keyed on `disc_hash` alone — see `candidates_from`). Unlike a derived key
    /// (Device/Processing/Media/Volume), a terminal UK is applied as-is by
    /// `Disc::decrypt_with`: it is NOT re-derived through the MKB-verified AACS
    /// resolver, so a UK entry whose hash matches the disc but whose key bytes
    /// are wrong would commit and mux undecryptable video as "success". The only
    /// thing that disproves a wrong UK is descrambling real ciphertext, so this
    /// source requires content samples — without them `decrypt_with` skips
    /// validation and the wrong UK is taken. Returning `true` makes every
    /// consumer (autorip resume/mux-worker AND the CLI) sample units before
    /// resolving, so a keydb UK is ciphertext-validated on every path.
    fn needs_samples(&self) -> bool {
        true
    }

    fn label(&self) -> &'static str {
        "keydb"
    }

    fn next_key(&mut self, inputs: &DiscInputs) -> Option<Key> {
        // On the first ask, parse the keydb once and build the ordered candidate
        // list; later asks just advance the cursor. A missing/unreadable keydb
        // is not an error — it simply yields no candidates (another source may
        // have the key), the same as the library's own loader.
        if self.cursor.is_none() {
            let cands = match KeyDb::load(&self.path) {
                Ok(db) => Self::candidates_from(&db, inputs),
                Err(_) => Vec::new(),
            };
            self.cursor = Some(cands.into_iter());
        }
        self.cursor.as_mut().and_then(Iterator::next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libfreemkv::aacs::{DeviceKey, DiscEntry};
    use std::collections::HashMap;

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

    fn dk() -> DeviceKey {
        DeviceKey {
            key: [0x22u8; 16],
            node: 1,
            uv: 2,
            u_mask_shift: 0,
        }
    }

    fn entry_with_vuk(hash: &str, vuk: [u8; 16]) -> DiscEntry {
        DiscEntry {
            disc_hash: hash.into(),
            title: String::new(),
            media_key: None,
            disc_id: None,
            vuk: Some(vuk),
            unit_keys: Vec::new(),
        }
    }

    #[test]
    fn per_disc_vuk_ranks_before_device_pool() {
        let mut entries = HashMap::new();
        entries.insert("0xaabb".into(), entry_with_vuk("0xaabb", [0x11u8; 16]));
        let db = KeyDb {
            device_keys: vec![dk()],
            processing_keys: Vec::new(),
            host_certs: Vec::new(),
            disc_entries: entries,
        };

        let cands = KeydbSource::candidates_from(&db, &inputs("0xaabb"));
        assert!(
            matches!(cands.first(), Some(Key::Volume(v)) if *v == [0x11u8; 16]),
            "the disc's own VUK must be the first (most specific) candidate"
        );
        assert!(
            cands.iter().any(|k| matches!(k, Key::Device(_))),
            "the universal device-key pool is still offered as a fallback"
        );
    }

    #[test]
    fn per_disc_uk_ranks_before_vuk() {
        // An entry with BOTH a UK and a VUK (the dual-key shape) must hand the
        // terminal UK out first, so a stale/wrong VUK never pre-empts a good UK.
        let mut entries = HashMap::new();
        let mut e = entry_with_vuk("0xaabb", [0x11u8; 16]);
        e.unit_keys = vec![(1, [0x22u8; 16])];
        entries.insert("0xaabb".into(), e);
        let db = KeyDb {
            device_keys: Vec::new(),
            processing_keys: Vec::new(),
            host_certs: Vec::new(),
            disc_entries: entries,
        };

        let cands = KeydbSource::candidates_from(&db, &inputs("0xaabb"));
        assert!(
            matches!(cands.first(), Some(Key::Unit(_))),
            "the terminal UK must be the first candidate"
        );
        assert!(
            matches!(cands.get(1), Some(Key::Volume(v)) if *v == [0x11u8; 16]),
            "the VUK follows the UK"
        );
    }

    #[test]
    fn no_disc_hit_offers_only_universal_material() {
        let db = KeyDb {
            device_keys: vec![dk()],
            processing_keys: Vec::new(),
            host_certs: Vec::new(),
            disc_entries: HashMap::new(),
        };
        // A disc with no per-disc entry: no Volume/Unit candidate, just the pool.
        let cands = KeydbSource::candidates_from(&db, &inputs("0xdeadbeef"));
        assert!(cands.iter().all(|k| matches!(k, Key::Device(_))));
        assert_eq!(cands.len(), 1);
    }

    #[test]
    fn empty_keydb_offers_nothing() {
        let db = KeyDb {
            device_keys: Vec::new(),
            processing_keys: Vec::new(),
            host_certs: Vec::new(),
            disc_entries: HashMap::new(),
        };
        assert!(KeydbSource::candidates_from(&db, &inputs("0xaabb")).is_empty());
    }

    /// Regression: a keydb can hand out a per-disc terminal `Key::Unit` that
    /// `Disc::decrypt_with` applies WITHOUT re-deriving through the MKB-verified
    /// AACS resolver. The only thing that disproves a wrong UK is descrambling
    /// ciphertext, so the source MUST request content samples — otherwise the
    /// autorip resume/mux-worker path (which only samples when some source
    /// reports `needs_samples()`) resolves with empty samples and commits a
    /// wrong UK as success. Was `false` (inherited default); must be `true`.
    #[test]
    fn keydb_source_needs_samples() {
        let src = KeydbSource::new("/nonexistent/path/keydb.cfg");
        assert!(
            src.needs_samples(),
            "keydb emits terminal Key::Unit entries that need ciphertext validation"
        );
    }

    /// No keydb (or a LibreDrive deployment) → no host credentials, not an
    /// error. (The positive parse is NOT tested here — it would require host
    /// key material, which must never appear in code.)
    #[test]
    fn host_certs_empty_when_keydb_missing() {
        assert!(
            KeydbSource::new("/nonexistent/path/keydb.cfg")
                .host_certs()
                .is_empty()
        );
    }

    /// The KeySource TRAIT method exposes the keydb's host cert(s) — this is the
    /// path the OEM/AACS cert-auth route collects certs through. A keydb with a
    /// `| HC |` row must surface a HostCert via `KeySource::host_certs`, so the
    /// handshake (which iterates `opts.key_sources[..].host_certs()`) finds it.
    /// Placeholder all-zero material (never a real key) — same convention as
    /// libfreemkv's own `parse_host_cert` test.
    #[test]
    fn trait_host_certs_returns_keydb_hc_row() {
        let dir = std::env::temp_dir().join(format!("fmk_hc_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keydb.cfg");
        let line = format!(
            "| HC | HOST_PRIV_KEY 0x{} | HOST_CERT 0x{}\n",
            "00".repeat(20),
            "00".repeat(92)
        );
        std::fs::write(&path, line).unwrap();

        let src = KeydbSource::new(&path);
        // Consult through the TRAIT, exactly as the OEM route does.
        let certs = KeySource::host_certs(&src);
        assert_eq!(certs.len(), 1, "trait host_certs must surface the HC row");
        assert_eq!(certs[0].certificate.len(), 92);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Zero certs from a (missing) keydb through the TRAIT method — the OEM route
    /// sees an empty vec here and, with no other source supplying a cert, fails
    /// gracefully with `AacsNoHostCert` rather than panicking.
    #[test]
    fn trait_host_certs_empty_when_keydb_missing() {
        let src = KeydbSource::new("/nonexistent/path/keydb.cfg");
        assert!(KeySource::host_certs(&src).is_empty());
    }
}
