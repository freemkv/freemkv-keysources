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

use libfreemkv::aacs::KeyDb;
use libfreemkv::{DiscInputs, Key, KeySource, Result};

/// A [`KeySource`] backed by a local `keydb.cfg` file.
pub struct KeydbSource {
    path: PathBuf,
}

impl KeydbSource {
    /// A keydb source reading the given `keydb.cfg` path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Build the ordered candidate list from a parsed keydb. Pure (no I/O), so
    /// it is unit-testable without a file on disk.
    fn candidates_from(db: &KeyDb, inputs: &DiscInputs) -> Vec<Key> {
        let mut out = Vec::new();

        // Per-disc hit (most specific). find_disc normalizes the hash form.
        if let Some(entry) = db.find_disc(&inputs.disc_hash) {
            if let Some(vuk) = entry.vuk {
                out.push(Key::Volume(vuk));
            }
            if !entry.unit_keys.is_empty() {
                out.push(Key::Unit(entry.unit_keys.clone()));
            }
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
    fn resolve(&self, inputs: &DiscInputs) -> Result<Vec<Key>> {
        // A missing keydb is not an error — another source may have the key.
        // (Parse/format problems surface as an empty/partial keydb, same as the
        // library's own loader; this source never fails the whole resolve.)
        let db = match KeyDb::load(&self.path) {
            Ok(db) => db,
            Err(_) => return Ok(Vec::new()),
        };
        Ok(Self::candidates_from(&db, inputs))
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
}
