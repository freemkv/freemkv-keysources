//! `keydb.cfg` key source (source #1).
//!
//! Parses a local `keydb.cfg`, looks the disc up by hash, and derives the
//! disc's terminal **Unit Keys** itself by driving libfreemkv's boil-down
//! primitives ([`uk_from_vuk`] / [`vuk_from_mk`] / [`mk_from_pk`] /
//! [`mk_from_dk`]) — never re-implementing AES. The path it picks mirrors the
//! OLD candidate order (which libfreemkv's resolver used to walk) EXACTLY,
//! cheapest-first:
//!
//! 1. per-disc **Unit Keys** (hash hit)  → returned terminal, no derivation.
//! 2. per-disc **VUK** (hash hit)        → [`uk_from_vuk`] over the disc's
//!    encrypted title keys.
//! 3. a **Media Key**, then [`vuk_from_mk`] → [`uk_from_vuk`]. The MK comes
//!    from, in order: the disc's stored MK (hash hit); the keydb's
//!    **Processing Key** pool walked against THIS disc's MKB via [`mk_from_pk`];
//!    or the device-key pool via [`mk_from_dk`]. The PK and DK pools resolve the
//!    Media Key WITHOUT a VID; the final [`vuk_from_mk`] still needs one. The
//!    VID is the unlocker's physical VID ([`ResolveCtx::vid`]) when present, else
//!    the keydb entry's OWN stored VID (the `I` field, `disc_id`) for the
//!    non-physical / ISO path. With no VID from either source the MK path cannot
//!    complete — return nothing.
//!
//! The cross-disc MK-pool brute (trying OTHER discs' stored media keys against
//! this disc) stays RETIRED: every MK path here is anchored to the matched
//! disc's own MKB or stored material.
//!
//! The library still OWNS the crypto; this source owns only which primitive to
//! call with which material. Returning an empty `Vec` is a genuine "no key for
//! this disc here".

use std::path::PathBuf;

use libfreemkv::aacs::{
    HostCert, MediaKey, UnitKey, Vid, Vuk, mk_from_dk, mk_from_pk, uk_from_vuk, vuk_from_mk,
};
use libfreemkv::keysource::ResolveCtx;
use libfreemkv::{Error, KeySource};

use crate::keydb_format::KeyDb;

/// A [`KeySource`] backed by a local `keydb.cfg` file.
pub struct KeydbSource {
    path: PathBuf,
}

impl KeydbSource {
    /// A keydb source reading the given `keydb.cfg` path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The host certificate(s) in this keydb — the second kind of data the one
    /// keydb file holds (alongside decryption keys). The app passes these to the
    /// live-drive scan as `DriveCredentials` for the AACS handshake. Empty if
    /// the keydb is missing/unreadable or carries no host cert.
    ///
    /// Inherent, no-MKB form: this is used by the **scan-options** builder,
    /// which runs before the disc's MKB generation is known, so no revocation
    /// filtering is applied (passes `None`). The [`KeySource::host_certs`] TRAIT
    /// method wires the real MKB generation through for revocation filtering.
    pub fn host_certs(&self) -> Vec<HostCert> {
        match KeyDb::load(&self.path) {
            Ok(db) => db.host_certs(None),
            Err(_) => Vec::new(),
        }
    }

    /// Derive this disc's terminal Unit Keys from a parsed keydb. Pure (no I/O),
    /// so it is unit-testable against an in-memory `KeyDb` without a file on
    /// disk. Empty `Vec` = no key for this disc from this keydb.
    ///
    /// CPS-unit numbering: a returned [`UnitKey::idx`] is the POSITIONAL index
    /// libfreemkv's `resolve_and_apply` turns into the canonical CPS-unit number
    /// `idx + 1`. For the terminal per-disc unit-key path we therefore map the
    /// keydb's stored CPS number `num` to `idx = num - 1`, so the committed
    /// number is byte-identical to the keydb's `num` (and to what the OLD
    /// `Key::Unit(entry.unit_keys)` path committed). For the VUK / MK paths the
    /// boil primitive already yields 0-based positional indices, matching
    /// `parse_unit_key_ro`'s `(i + 1)` after the resolver's `+ 1`.
    fn unit_keys_from(db: &KeyDb, ctx: &dyn ResolveCtx) -> Vec<UnitKey> {
        // Per-disc hit (most specific). find_disc normalizes the hash form.
        // Without a matched entry this keydb has no per-disc material (Unit Keys
        // / VUK / Media Key / stored VID) to anchor a derivation for the disc, so
        // it resolves nothing. (The PK and DK pools are global, but the
        // cross-disc MK-pool brute — trying OTHER discs' media keys against this
        // disc — stays retired; a PK/DK pool only ever resolves a disc reached
        // through its own matched entry below.)
        let Some(entry) = db.find_disc(ctx.disc_hash()) else {
            return Vec::new();
        };

        // 1. Terminal Unit Keys — directly usable, no derivation. Preserve the
        //    keydb's CPS numbering through the resolver's `+ 1` (idx = num - 1).
        if !entry.unit_keys.is_empty() {
            return entry
                .unit_keys
                .iter()
                .map(|(num, key)| UnitKey {
                    idx: num.saturating_sub(1),
                    key: *key,
                })
                .collect();
        }

        // The disc's encrypted title keys (from Unit_Key_RO.inf) — what every
        // VUK-or-deeper path decrypts into the terminal keys. Empty when the
        // scan captured no Unit_Key_RO.inf, in which case nothing can derive.
        let enc_title_keys = match ctx.enc_title_keys() {
            Ok(k) => k,
            Err(_) => return Vec::new(),
        };

        // 2. Per-disc VUK — one step, no VID needed (it directly decrypts the
        //    encrypted title keys).
        if let Some(vuk) = entry.vuk {
            return uk_from_vuk(Vuk(vuk), enc_title_keys);
        }

        // 3. Media Key path. Resolve a Media Key for THIS disc, then derive the
        //    VUK + Unit Keys from it. Source order, cheapest-first:
        //      a. the disc's stored MK (hash hit) — already the Media Key.
        //      b. the keydb's Processing Key pool walked against this disc's MKB
        //         via `mk_from_pk` (Subset-Difference cvalue walk; no VID). This
        //         is the restored PK path — a leaked/precomputed PK resolves the
        //         Media Key directly for real discs.
        //      c. the device-key pool via `mk_from_dk` (the AACS-1.0 variant
        //         walk; needs the MKB and a VID, and has no in-tree integrator
        //         KCD so it errs for real discs today — kept for faithfulness).
        //    The MK itself (a/b) carries no VID, but the final `vuk_from_mk`
        //    needs one. Locked VID-per-path rule: physical (unlocker) VID first,
        //    else the keydb entry's stored VID (`I` field) for the ISO /
        //    non-physical path, else cannot derive.
        let vid = ctx.vid().or_else(|| entry.disc_id.map(Vid));
        let mkb = ctx.mkb().unwrap_or(&[]);

        let mk: Option<MediaKey> = entry
            .media_key
            .map(MediaKey)
            // PK pool: validated against this disc's own MKB, no VID needed here.
            .or_else(|| mk_from_pk(&db.processing_keys, mkb).ok())
            // DK pool: mk_from_dk folds the VID into the variant walk; it needs
            // the same VID the VUK step will use.
            .or_else(|| vid.and_then(|v| mk_from_dk(&db.device_keys, mkb, v).ok()));

        let Some(mk) = mk else {
            return Vec::new();
        };
        let Some(vid) = vid else {
            // Locked VID-per-path rule: an MK with no VID from either source
            // cannot derive a VUK — never guess.
            return Vec::new();
        };

        uk_from_vuk(vuk_from_mk(mk, vid), enc_title_keys)
    }
}

impl KeySource for KeydbSource {
    /// Resolve this disc's terminal Unit Keys from the keydb. A missing /
    /// unreadable keydb is not an error — it simply yields no keys (another
    /// source may have them), the same as the library's own loader.
    fn get_uk(&self, ctx: &dyn ResolveCtx) -> Result<Vec<UnitKey>, Error> {
        match KeyDb::load(&self.path) {
            Ok(db) => Ok(Self::unit_keys_from(&db, ctx)),
            Err(_) => Ok(Vec::new()),
        }
    }

    /// Expose the keydb's host certs through the trait — the OEM/AACS cert-auth
    /// route collects them across every source via this method. Wires the disc's
    /// MKB generation through for revocation filtering (the keydb parser's
    /// `; Revoked in MKBv<N>` annotation): a cert revoked at generation `R` is
    /// withheld once the disc's generation reaches `R`.
    fn host_certs(&self, mkb: Option<u32>) -> Vec<HostCert> {
        match KeyDb::load(&self.path) {
            Ok(db) => db.host_certs(mkb),
            Err(_) => Vec::new(),
        }
    }

    fn label(&self) -> &'static str {
        "keydb"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keydb_format::DiscEntry;
    use libfreemkv::aacs::{DeviceKey, derive_vuk};
    use std::collections::HashMap;

    // ── A test ResolveCtx, so get_uk's path selection can be exercised without
    //    a real Disc. Each accessor returns exactly what a case needs. ──────────
    struct MockCtx {
        disc_hash: String,
        vid: Option<Vid>,
        mkb: Vec<u8>,
        enc_title_keys: Vec<[u8; 16]>,
    }
    impl ResolveCtx for MockCtx {
        fn disc_hash(&self) -> &str {
            &self.disc_hash
        }
        fn title(&self) -> Option<&str> {
            None
        }
        fn vid(&self) -> Option<Vid> {
            self.vid
        }
        fn mkb(&self) -> Result<&[u8], Error> {
            Ok(&self.mkb)
        }
        fn enc_title_keys(&self) -> Result<&[[u8; 16]], Error> {
            Ok(&self.enc_title_keys)
        }
        fn samples(&self, _n: usize) -> Result<Vec<Vec<u8>>, Error> {
            Ok(Vec::new())
        }
    }

    fn ctx(hash: &str, enc: Vec<[u8; 16]>, vid: Option<Vid>) -> MockCtx {
        MockCtx {
            disc_hash: hash.into(),
            vid,
            mkb: Vec::new(),
            enc_title_keys: enc,
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

    fn blank_entry(hash: &str) -> DiscEntry {
        DiscEntry {
            disc_hash: hash.into(),
            title: String::new(),
            media_key: None,
            disc_id: None,
            vuk: None,
            unit_keys: Vec::new(),
            mkb_version: None,
            volume_size: None,
            is_uhd: false,
        }
    }

    fn db_with(entry: DiscEntry, device_keys: Vec<DeviceKey>) -> KeyDb {
        let mut entries = HashMap::new();
        entries.insert(entry.disc_hash.clone(), entry);
        KeyDb {
            device_keys,
            processing_keys: Vec::new(),
            host_certs: Vec::new(),
            disc_entries: entries,
        }
    }

    /// The committed `(cps, key)` pairs libfreemkv's `resolve_and_apply` derives
    /// from a source's Unit Keys: positional `idx` → canonical CPS number
    /// `idx + 1`. The KATs compare against THIS to prove byte-identical parity
    /// with the OLD `Key::Unit` / resolver-derived commit.
    fn committed(uks: &[UnitKey]) -> Vec<(u32, [u8; 16])> {
        uks.iter()
            .map(|u| (u.idx.saturating_add(1), u.key))
            .collect()
    }

    const HASH: &str = "0xaabb";

    // ── KAT (a): disc with terminal Unit Keys ─────────────────────────────────
    /// A hash hit carrying terminal unit keys is returned as-is — the committed
    /// `(cps, key)` pairs are byte-identical to the keydb's stored numbering,
    /// exactly what the OLD `Key::Unit(entry.unit_keys)` path committed.
    #[test]
    fn kat_a_disc_with_unit_keys_is_terminal_and_preserves_cps_numbering() {
        let mut e = blank_entry(HASH);
        e.unit_keys = vec![(1, [0xA0u8; 16]), (2, [0xB1u8; 16])];
        // Even with a VUK present, the terminal UK must win (cheapest path).
        e.vuk = Some([0x11u8; 16]);
        let db = db_with(e, Vec::new());

        let got = KeydbSource::unit_keys_from(&db, &ctx(HASH, Vec::new(), None));
        assert_eq!(
            committed(&got),
            vec![(1u32, [0xA0u8; 16]), (2u32, [0xB1u8; 16])],
            "terminal keydb unit keys must commit byte-identically to the stored (cps, key) pairs"
        );
    }

    // ── KAT (b): disc with VUK ────────────────────────────────────────────────
    /// A hash hit with only a VUK derives the terminal keys via `uk_from_vuk`
    /// over the disc's encrypted title keys — byte-identical to the OLD
    /// `Key::Volume(vuk)` → resolver path (which called the same primitive).
    #[test]
    fn kat_b_disc_with_vuk_derives_via_uk_from_vuk() {
        let vuk = [0x5Au8; 16];
        // Two encrypted title keys (arbitrary ciphertext; both sides decrypt the
        // SAME bytes, which is the parity claim).
        let enc = vec![[0x31u8; 16], [0xCDu8; 16]];

        let mut e = blank_entry(HASH);
        e.vuk = Some(vuk);
        let db = db_with(e, Vec::new());

        let got = KeydbSource::unit_keys_from(&db, &ctx(HASH, enc.clone(), None));
        // Reference: the boil primitive directly — the OLD derivation.
        let expect = uk_from_vuk(Vuk(vuk), &enc);
        assert_eq!(
            got, expect,
            "VUK path must equal uk_from_vuk(vuk, enc_title_keys)"
        );
        // And the committed numbering is 1-based positional.
        assert_eq!(
            committed(&got).iter().map(|(n, _)| *n).collect::<Vec<_>>(),
            vec![1, 2]
        );
    }

    // ── KAT (c): disc with MK + physical (unlock) VID ─────────────────────────
    /// A hash hit with a Media Key and a physical VID (from the unlocker) derives
    /// `MK → VUK → UK`. The PHYSICAL VID must be used in preference to the keydb's
    /// stored VID — proven by giving the entry a DIFFERENT stored VID and showing
    /// the result tracks the physical one.
    #[test]
    fn kat_c_disc_with_mk_uses_physical_vid_over_keydb_vid() {
        let mk = [0x77u8; 16];
        let vid_phys = [0x42u8; 16];
        let vid_keydb = [0x99u8; 16]; // deliberately different — must NOT be used
        let enc = vec![[0x10u8; 16]];

        let mut e = blank_entry(HASH);
        e.media_key = Some(mk);
        e.disc_id = Some(vid_keydb);
        let db = db_with(e, Vec::new());

        let got = KeydbSource::unit_keys_from(&db, &ctx(HASH, enc.clone(), Some(Vid(vid_phys))));
        // Reference uses the PHYSICAL VID.
        let expect = uk_from_vuk(vuk_from_mk(MediaKey(mk), Vid(vid_phys)), &enc);
        assert_eq!(got, expect, "MK path must use the physical (unlock) VID");
        // Sanity: it must NOT match the keydb-VID derivation (different VID →
        // different VUK → different keys), proving the right VID was selected.
        let wrong = uk_from_vuk(vuk_from_mk(MediaKey(mk), Vid(vid_keydb)), &enc);
        assert_ne!(
            got, wrong,
            "must not derive with the keydb VID when a physical VID exists"
        );
    }

    // ── KAT (d): disc with MK + keydb VID (ISO path, no physical VID) ──────────
    /// A hash hit with a Media Key but NO physical VID falls back to the keydb
    /// entry's stored VID (`disc_id`, the `I` field) — the non-physical / ISO
    /// path — and derives `MK → VUK → UK` against it.
    #[test]
    fn kat_d_disc_with_mk_falls_back_to_keydb_vid() {
        let mk = [0x77u8; 16];
        let vid_keydb = [0x99u8; 16];
        let enc = vec![[0x10u8; 16], [0x20u8; 16]];

        let mut e = blank_entry(HASH);
        e.media_key = Some(mk);
        e.disc_id = Some(vid_keydb);
        let db = db_with(e, Vec::new());

        // ctx.vid() == None → ISO path.
        let got = KeydbSource::unit_keys_from(&db, &ctx(HASH, enc.clone(), None));
        let expect = uk_from_vuk(vuk_from_mk(MediaKey(mk), Vid(vid_keydb)), &enc);
        assert_eq!(
            got, expect,
            "MK path must use the keydb VID when no physical VID is present"
        );
    }

    // ── KAT (e): disc with MK + NO VID anywhere → empty ───────────────────────
    /// A hash hit with a Media Key but neither a physical VID nor a stored keydb
    /// VID cannot derive a VUK — the locked VID-per-path rule. It must return
    /// EMPTY, never a guessed/zero-VID key (wrong-keys safety).
    #[test]
    fn kat_e_disc_with_mk_no_vid_returns_empty() {
        let mut e = blank_entry(HASH);
        e.media_key = Some([0x77u8; 16]);
        e.disc_id = None; // no keydb VID
        let db = db_with(e, Vec::new());

        // ctx.vid() == None and no keydb VID → cannot derive.
        let got = KeydbSource::unit_keys_from(&db, &ctx(HASH, vec![[0x10u8; 16]], None));
        assert!(
            got.is_empty(),
            "MK with no VID source must yield no keys, never a guess"
        );
    }

    /// Build a 4-byte MKB record header (type + 3-byte big-endian total length,
    /// header included) and append `body`. No crypto — just the record framing
    /// libfreemkv's MKB parser expects.
    fn mkb_record(rec_type: u8, body: &[u8]) -> Vec<u8> {
        let total = 4 + body.len();
        let mut rec = vec![
            rec_type,
            ((total >> 16) & 0xFF) as u8,
            ((total >> 8) & 0xFF) as u8,
            (total & 0xFF) as u8,
        ];
        rec.extend_from_slice(body);
        rec
    }

    // ── KAT (f): disc with NO per-disc MK, resolved via the keydb PK pool ──────
    /// Owner decision #1 (AACS): a keydb Processing Key must be walked against
    /// the matched disc's own MKB to recover the Media Key, then driven down the
    /// full chain `PK → MK → VUK → UK`. The disc entry carries NO stored MK/VUK/
    /// UK — the only key material is a global `PK` row — and the result must be
    /// the real Unit Keys, byte-identical to deriving from the recovered MK.
    ///
    /// The MKB + PK use a known-answer construction (a planted PK whose derived
    /// MK satisfies the synthetic verify record); the constants are precomputed
    /// AES vectors so this crate needs no AES primitive of its own. They mirror
    /// libfreemkv's `boil::mk_from_pk_drives_full_chain_to_uks` KAT.
    #[test]
    fn kat_f_disc_with_pk_pool_yields_uks() {
        // Planted PK and the MK it resolves to (see libfreemkv boil.rs KAT).
        let pk: [u8; 16] = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, 0x00,
        ];
        let mk: [u8; 16] = [
            0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD,
            0xAE, 0xAF,
        ];
        // cvalue = AES-E(pk, mk_raw); verify = AES-E(mk, magic||pad); SD uv.
        let cv: [u8; 16] = [
            0x72, 0x23, 0x96, 0x80, 0xB5, 0xC5, 0x2B, 0x9D, 0x63, 0xE9, 0xEC, 0x92, 0xCF, 0xAF,
            0xDE, 0x1B,
        ];
        let mk_dv: [u8; 16] = [
            0x05, 0xA7, 0x4C, 0xC9, 0xD0, 0x2E, 0x9F, 0x4B, 0x42, 0xDF, 0x2C, 0x0A, 0xAD, 0x79,
            0x58, 0xF4,
        ];
        let uv: [u8; 4] = [0x00, 0x00, 0x04, 0x00];

        // Synthetic MKB: type/version (0x10), verify (0x86), one-entry SD index
        // (0x04 = [u_mask_shift=0][uv]), one-entry cvalue table (0x05).
        let mut sd = vec![0u8];
        sd.extend_from_slice(&uv);
        let mut mkb = Vec::new();
        mkb.extend_from_slice(&mkb_record(0x10, &[0, 0, 0, 0x20, 0, 0, 0, 0x52]));
        mkb.extend_from_slice(&mkb_record(0x86, &mk_dv));
        mkb.extend_from_slice(&mkb_record(0x04, &sd));
        mkb.extend_from_slice(&mkb_record(0x05, &cv));

        // Disc entry with NO stored MK/VUK/UK — only the global PK pool can resolve.
        let e = blank_entry(HASH);
        let mut db = db_with(e, Vec::new());
        db.processing_keys = vec![pk];

        let enc = vec![[0x10u8; 16], [0x20u8; 16]];
        let vid_phys = [0x42u8; 16];
        let ctx = MockCtx {
            disc_hash: HASH.into(),
            vid: Some(Vid(vid_phys)),
            mkb,
            enc_title_keys: enc.clone(),
        };

        let got = KeydbSource::unit_keys_from(&db, &ctx);
        assert!(!got.is_empty(), "PK pool must yield Unit Keys for the disc");
        // Byte-identical to deriving from the recovered MK via the public chain.
        let expect = uk_from_vuk(vuk_from_mk(MediaKey(mk), Vid(vid_phys)), &enc);
        assert_eq!(
            got, expect,
            "PK path must equal MK → VUK → UK from the recovered Media Key"
        );
    }

    /// A PK pool that does NOT resolve the disc's MKB yields nothing — never a
    /// wrong key. (Same MKB as KAT (f) but a corrupt PK.)
    #[test]
    fn pk_pool_that_does_not_validate_yields_no_key() {
        let mk_dv: [u8; 16] = [
            0x05, 0xA7, 0x4C, 0xC9, 0xD0, 0x2E, 0x9F, 0x4B, 0x42, 0xDF, 0x2C, 0x0A, 0xAD, 0x79,
            0x58, 0xF4,
        ];
        let cv: [u8; 16] = [
            0x72, 0x23, 0x96, 0x80, 0xB5, 0xC5, 0x2B, 0x9D, 0x63, 0xE9, 0xEC, 0x92, 0xCF, 0xAF,
            0xDE, 0x1B,
        ];
        let uv: [u8; 4] = [0x00, 0x00, 0x04, 0x00];
        let mut sd = vec![0u8];
        sd.extend_from_slice(&uv);
        let mut mkb = Vec::new();
        mkb.extend_from_slice(&mkb_record(0x10, &[0, 0, 0, 0x20, 0, 0, 0, 0x52]));
        mkb.extend_from_slice(&mkb_record(0x86, &mk_dv));
        mkb.extend_from_slice(&mkb_record(0x04, &sd));
        mkb.extend_from_slice(&mkb_record(0x05, &cv));

        let mut db = db_with(blank_entry(HASH), Vec::new());
        db.processing_keys = vec![[0x00u8; 16]]; // does not validate

        let ctx = MockCtx {
            disc_hash: HASH.into(),
            vid: Some(Vid([0x42u8; 16])),
            mkb,
            enc_title_keys: vec![[0x10u8; 16]],
        };
        assert!(
            KeydbSource::unit_keys_from(&db, &ctx).is_empty(),
            "a non-validating PK pool must resolve nothing, never a wrong key"
        );
    }

    /// `vuk_from_mk` anchor: the VUK the MK path derives equals the library's own
    /// `derive_vuk(mk, vid)` (the pre-boil primitive) — pinning that the boil
    /// chain this source drives is the audited math, not a re-implementation.
    #[test]
    fn mk_path_vuk_matches_library_derive_vuk() {
        let mk = [0x3Cu8; 16];
        let vid = [0xA5u8; 16];
        assert_eq!(vuk_from_mk(MediaKey(mk), Vid(vid)).0, derive_vuk(&mk, &vid));
    }

    /// No per-disc entry → no key, even with a universal device-key pool present.
    /// Without a matched entry there is no per-disc anchor, so the global pools
    /// are never consulted (the cross-disc MK-pool brute stays retired).
    #[test]
    fn no_disc_hit_yields_no_key() {
        let db = db_with(blank_entry("0xother"), vec![dk()]);
        let got =
            KeydbSource::unit_keys_from(&db, &ctx(HASH, vec![[0x10u8; 16]], Some(Vid([1u8; 16]))));
        assert!(
            got.is_empty(),
            "a hash miss resolves nothing from the keydb"
        );
    }

    /// Empty keydb resolves nothing.
    #[test]
    fn empty_keydb_yields_no_key() {
        let db = KeyDb {
            device_keys: Vec::new(),
            processing_keys: Vec::new(),
            host_certs: Vec::new(),
            disc_entries: HashMap::new(),
        };
        assert!(KeydbSource::unit_keys_from(&db, &ctx(HASH, Vec::new(), None)).is_empty());
    }

    /// A missing keydb file is silent (Ok empty), never an error.
    #[test]
    fn get_uk_missing_keydb_is_ok_empty() {
        let src = KeydbSource::new("/nonexistent/path/keydb.cfg");
        let got = src
            .get_uk(&ctx(HASH, Vec::new(), None))
            .expect("missing keydb is not an error");
        assert!(got.is_empty());
    }

    #[test]
    fn label_is_keydb() {
        assert_eq!(KeydbSource::new("/nonexistent/keydb.cfg").label(), "keydb");
    }

    /// No keydb → no host credentials, not an error (inherent and trait forms).
    #[test]
    fn host_certs_empty_when_keydb_missing() {
        let src = KeydbSource::new("/nonexistent/path/keydb.cfg");
        assert!(src.host_certs().is_empty());
        assert!(KeySource::host_certs(&src, None).is_empty());
        assert!(KeySource::host_certs(&src, Some(68)).is_empty());
    }

    /// The TRAIT `host_certs` surfaces a `| HC |` row and now wires the MKB
    /// generation through. Placeholder all-zero material (never a real key).
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
        // A cert with no revocation annotation is returned for ANY mkb arg.
        let certs = KeySource::host_certs(&src, Some(70));
        assert_eq!(certs.len(), 1, "trait host_certs must surface the HC row");
        assert_eq!(certs[0].certificate.len(), 92);

        std::fs::remove_dir_all(&dir).ok();
    }
}
