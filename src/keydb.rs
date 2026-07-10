//! `keydb.cfg` key source (source #1).
//!
//! Parses a local `keydb.cfg`, looks the disc up by hash, and derives the
//! disc's terminal **Unit Keys** itself by composing libfreemkv's raw
//! `aacs::derive` primitives (`derive_vuk` / `decrypt_unit_key` /
//! `derive_media_key_from_pk` / `derive_media_key_from_dk`) — never
//! re-implementing AES. The path it picks mirrors the OLD candidate order
//! (which libfreemkv's resolver used to walk) EXACTLY, cheapest-first:
//!
//! 1. per-disc **Unit Keys** (hash hit)  → returned terminal, no derivation.
//! 2. per-disc **VUK** (hash hit)        → `uks_from_vuk` over the disc's
//!    encrypted title keys.
//! 3. a **Media Key**, then `derive_vuk` → `uks_from_vuk`. The MK comes
//!    from, in order: the disc's stored MK (hash hit); the keydb's
//!    **Processing Key** pool walked against THIS disc's MKB via
//!    `derive_media_key_from_pk`; or the device-key pool via
//!    `derive_media_key_from_dk`. The PK and DK pools resolve the
//!    Media Key WITHOUT a VID; the final `derive_vuk` still needs one. The
//!    VID is the unlocker's physical VID ([`ResolveCtx::vid`]) when present, else
//!    the keydb entry's OWN stored VID (the `I` field, `vid`) for the
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

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::uks_from_vuk;
use libfreemkv::aacs::derive::{derive_media_key_from_dk, derive_media_key_from_pk, derive_vuk};
use libfreemkv::aacs::types::{HostCert, MediaKey, UnitKey, Vid};
use libfreemkv::keysource::ResolveCtx;
use libfreemkv::{Error, KeySource};

use crate::keydb_format::KeyDb;

/// Upper bound on decompressed keydb size. The published keydb is a few MiB;
/// 64 MiB is a generous ceiling that still caps a decompression bomb (a tiny
/// zip/gz can otherwise inflate to GiB and OOM the daily refresh thread).
const MAX_KEYDB_BYTES: u64 = 64 * 1024 * 1024;

/// Result of a KEYDB save/update -- path written, entry count, and byte size.
#[derive(Debug)]
pub struct UpdateResult {
    pub path: PathBuf,
    pub entries: usize,
    pub bytes: usize,
}

/// A [`KeySource`] backed by a local `keydb.cfg` file.
pub struct KeydbSource {
    path: PathBuf,
}

impl KeydbSource {
    /// A keydb source reading the given `keydb.cfg` path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Validate, decompress, and crash-safely persist raw keydb bytes (plain
    /// text, `.zip`, or `.gz`) to THIS source's own [`path`](Self::path).
    ///
    /// The bytes are decompressed (zip / gz / plain), the result is checked for
    /// at least one recognisable keydb entry, then atomically written to the
    /// source's path (sibling-temp + fsync + rename + parent-dir fsync). The
    /// decompressed size is capped at [`MAX_KEYDB_BYTES`] so a decompression
    /// bomb can't OOM the caller (e.g. the daily-refresh thread). Writing to the
    /// source's own path — not a hardcoded default — means the caller decides
    /// the destination (CLI `--keydb`, the autorip service path, …).
    pub fn save(&self, bytes: &[u8]) -> Result<UpdateResult, Error> {
        let text = if bytes.starts_with(b"PK\x03\x04") {
            extract_zip(bytes)?
        } else if bytes.starts_with(&[0x1f, 0x8b]) {
            read_capped_to_string(flate2::read::GzDecoder::new(bytes))?
        } else {
            // Plain-text body: route through the same capped reader as the
            // gz/zip branches so an oversized uncompressed upload can't bypass
            // MAX_KEYDB_BYTES.
            read_capped_to_string(std::io::Cursor::new(bytes))?
        };

        let entries = text
            .lines()
            .filter(|l| {
                let t = l.trim();
                // Mirror KeyDb::parse's disc-entry rule EXACTLY (keydb_format.rs:
                // a "0x" line is only an entry if it also contains " = "), so
                // save() never validates + persists content that parses to zero
                // usable entries (e.g. a stray "0xDEADBEEF" comment line).
                (t.starts_with("0x") && t.contains(" = "))
                    || t.starts_with("| DK")
                    || t.starts_with("| PK")
                    || t.starts_with("| HC")
            })
            .count();

        if entries == 0 {
            return Err(Error::KeydbInvalid);
        }

        write_atomic(&self.path, &text)?;

        Ok(UpdateResult {
            path: self.path.clone(),
            entries,
            bytes: text.len(),
        })
    }

    /// Fetch keydb bytes from `url` via the caller-supplied `fetch` transport,
    /// then validate + save them to this source's path.
    ///
    /// The transport is INJECTED: this crate stays transport-agnostic on the
    /// update path so the application supplies its own TLS / SSRF-guarded fetch
    /// (the `freemkv` CLI passes its `keydb_fetch::fetch`). `fetch` returns the
    /// raw response body (plain text, `.zip`, or `.gz`); [`save`](Self::save)
    /// does the verify + atomic write.
    pub fn update(
        &self,
        fetch: impl Fn(&str) -> Result<Vec<u8>, Error>,
        url: &str,
    ) -> Result<UpdateResult, Error> {
        let bytes = fetch(url)?;
        self.save(&bytes)
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

        // UNION every source of terminal keys, then dedup — never first-hit. A
        // stored `unit_keys` list can be PARTIAL (the key-import tool only ever
        // sampled the CPS units reachable from a playlist, so an orphan unit's key may be
        // missing), while the per-disc VUK boils EVERY declared CPS unit. Taking
        // the stored list alone (the old return-at-first-path) would shadow the
        // VUK and silently drop the orphan unit's key. So gather both and keep a
        // unique-by-key list: the read path tries every key per unit, so an extra
        // or stale key is harmless — only a MISSING key hurts.
        let mut keys: Vec<UnitKey> = Vec::new();

        // 1. Terminal Unit Keys stored in the entry — directly usable, no
        //    derivation. Preserve the keydb's CPS numbering (idx = num - 1).
        for (num, key) in &entry.unit_keys {
            keys.push(UnitKey::new(num.saturating_sub(1), *key));
        }

        // The disc's encrypted title keys (from Unit_Key_RO.inf) — what every
        // VUK-or-deeper path decrypts into the terminal keys. Empty when the scan
        // captured no Unit_Key_RO.inf, in which case only the stored list (1)
        // contributes.
        let enc_title_keys = ctx.enc_title_keys().unwrap_or(&[]);
        if !enc_title_keys.is_empty() {
            // 2. Per-disc VUK — one step, no VID needed; boils ALL declared units.
            //    3. Else a Media Key path (stored MK / PK pool / DK pool) → VUK →
            //       all declared units. The MK itself carries no VID, but the
            //       final `vuk_from_mk` needs one: physical (unlocker) VID first,
            //       else the entry's stored VID (`I` field), else cannot derive.
            //       Either branch yields the COMPLETE declared set, so we take the
            //       first that resolves (VUK preferred — cheapest).
            let derived = if let Some(vuk) = entry.vuk {
                uks_from_vuk(&vuk, enc_title_keys)
            } else {
                let vid = ctx.vid().or_else(|| entry.vid.map(Vid));
                let mkb = ctx.mkb().unwrap_or(&[]);
                let mk: Option<MediaKey> = entry
                    .media_key
                    .map(MediaKey)
                    .or_else(|| derive_media_key_from_pk(mkb, &db.processing_keys).map(MediaKey))
                    // DK pool: the real Subset-Difference MKB walk. No VID at the MK
                    // step (it enters at the VUK step below); the VID guard follows.
                    .or_else(|| derive_media_key_from_dk(mkb, &db.device_keys).map(MediaKey));
                match (mk, vid) {
                    // VUK = derive_vuk(MK, VID), then boil the disc's encrypted
                    // title keys to the terminal Unit Keys.
                    (Some(mk), Some(vid)) => {
                        uks_from_vuk(&derive_vuk(&mk.0, &vid.0), enc_title_keys)
                    }
                    // Locked VID-per-path rule: an MK with no VID cannot derive.
                    _ => Vec::new(),
                }
            };
            keys.extend(derived);
        }

        // Unique by key value, first occurrence wins (stored numbering kept).
        let mut seen = std::collections::HashSet::new();
        keys.retain(|u| seen.insert(u.key));
        keys
    }
}

/// Read a decompressed stream into a `String` with a hard size ceiling.
/// Returns [`Error::KeydbInvalid`] if the input exceeds the cap, or
/// [`Error::KeydbParse`] if the bytes are not valid UTF-8.
fn read_capped_to_string<R: Read>(reader: R) -> Result<String, Error> {
    let mut buf = Vec::new();
    // Read one byte past the cap so an exactly-at-cap stream is accepted but
    // anything larger is rejected.
    reader
        .take(MAX_KEYDB_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|_| Error::KeydbParse)?;
    if buf.len() as u64 > MAX_KEYDB_BYTES {
        return Err(Error::KeydbInvalid);
    }
    String::from_utf8(buf).map_err(|_| Error::KeydbParse)
}

/// Extract the first `*.cfg` member of a zip archive as a capped `String`.
fn extract_zip(data: &[u8]) -> Result<String, Error> {
    let cursor = std::io::Cursor::new(data);
    let mut archive = zip::ZipArchive::new(cursor).map_err(|_| Error::KeydbParse)?;

    for i in 0..archive.len() {
        let file = archive.by_index(i).map_err(|_| Error::KeydbParse)?;
        if file.name().ends_with(".cfg") || file.name().ends_with(".CFG") {
            return read_capped_to_string(file);
        }
    }

    Err(Error::KeydbInvalid)
}

/// Write `text` to `path` crash-safely (create parent dir, write a sibling temp
/// file, fsync, then atomic rename, then fsync the parent dir).
///
/// keydb.cfg is the single source of AACS truth, and save/update run unattended
/// (first-boot download + daily-refresh thread, with a container restart on
/// every release). A bare in-place `fs::write` truncates the file before
/// writing, so a SIGKILL (docker stop's grace window), OOM-kill, power loss, or
/// ENOSPC mid-write would leave the keydb half-written — the prior good copy
/// already gone. A truncated keydb doesn't error at write time; it silently
/// breaks key resolution on every later AACS rip. Writing to a temp file then
/// renaming (POSIX rename is atomic within a filesystem) means an interrupted
/// update leaves the previous keydb fully intact.
///
/// The fsync MUST succeed before the rename: a `sync_all` failure (ENOSPC,
/// ESTALE on the bind-mounted volume) means the kernel never guaranteed the
/// bytes reached stable storage, so publishing them via rename would defeat
/// crash-safety. The temp name is unique per call (pid + monotonic counter) so a
/// concurrent update can't share a fixed temp path and rename a mangled file
/// over the keydb.
fn write_atomic(path: &Path, text: &str) -> Result<(), Error> {
    let werr = || Error::KeydbWrite {
        path: path.display().to_string(),
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| {
            tracing::warn!(error = %e, path = %path.display(), "keydb dir create failed");
            werr()
        })?;
    }
    let tmp = {
        use std::sync::atomic::{AtomicU64, Ordering};
        static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);
        path.with_extension(format!(
            "tmp.{}.{}",
            std::process::id(),
            TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ))
    };
    let write_result = (|| -> std::io::Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
        Ok(())
    })();
    if let Err(e) = write_result {
        let _ = std::fs::remove_file(&tmp);
        tracing::warn!(error = %e, path = %path.display(), "keydb write/fsync failed; keydb unchanged");
        return Err(werr());
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        tracing::warn!(error = %e, path = %path.display(), "keydb rename failed; keydb unchanged");
        return Err(werr());
    }
    // Durably commit the new dirent: on POSIX filesystems (ext2, some NFS) a
    // crash right after the rename can lose the directory entry even though the
    // rename returned. Best-effort (swallowed on failure); no-op on Windows.
    if let Some(dir) = path.parent() {
        libfreemkv::io::fsync::dir(dir);
    }
    Ok(())
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
    use libfreemkv::aacs::derive::derive_vuk;
    use libfreemkv::aacs::types::DeviceKey;
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
            vid: None,
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

    // ── KAT (a): disc with terminal Unit Keys, no enc_title_keys ──────────────
    /// Stored terminal unit keys are returned with their CPS numbering preserved.
    /// Here `enc_title_keys` is empty, so the VUK can't derive anything — only the
    /// stored list contributes, and it commits byte-identically to the stored
    /// `(cps, key)` pairs.
    #[test]
    fn kat_a_disc_with_unit_keys_is_terminal_and_preserves_cps_numbering() {
        let mut e = blank_entry(HASH);
        e.unit_keys = vec![(1, [0xA0u8; 16]), (2, [0xB1u8; 16])];
        // VUK present but no enc_title_keys → nothing to boil, stored stands.
        e.vuk = Some([0x11u8; 16]);
        let db = db_with(e, Vec::new());

        let got = KeydbSource::unit_keys_from(&db, &ctx(HASH, Vec::new(), None));
        assert_eq!(
            committed(&got),
            vec![(1u32, [0xA0u8; 16]), (2u32, [0xB1u8; 16])],
            "terminal keydb unit keys must commit byte-identically to the stored (cps, key) pairs"
        );
    }

    /// Orphan-unit completeness (the real keydb bug): an entry stores only `uk1`
    /// (the key-import tool sampled one reachable CPS unit) but ALSO carries the VUK,
    /// which boils BOTH declared units. The old return-at-first-path handed back
    /// just `[uk1]`, shadowing the VUK and silently dropping the orphan unit. The
    /// union must return BOTH — the stored uk1 AND the VUK-derived second unit.
    #[test]
    fn union_partial_stored_plus_vuk_yields_all_declared_units() {
        let vuk = [0x5Au8; 16];
        let enc = vec![[0x31u8; 16], [0xCDu8; 16]]; // two declared CPS units
        let derived = crate::uks_from_vuk(&vuk, &enc); // [d0, d1]

        let mut e = blank_entry(HASH);
        e.unit_keys = vec![(1, [0xA0u8; 16])]; // PARTIAL: only uk1 stored
        e.vuk = Some(vuk);
        let db = db_with(e, Vec::new());

        let got = KeydbSource::unit_keys_from(&db, &ctx(HASH, enc.clone(), None));
        let got_keys: Vec<[u8; 16]> = got.iter().map(|u| u.key).collect();
        assert!(got_keys.contains(&[0xA0u8; 16]), "the stored uk1 is kept");
        assert!(
            got_keys.contains(&derived[1].key),
            "the VUK-derived SECOND CPS unit is added, not shadowed by the partial stored list"
        );
        assert!(
            got.len() >= 2,
            "a partial stored list must no longer shadow the complete VUK"
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
        let expect = crate::uks_from_vuk(&vuk, &enc);
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
        e.vid = Some(vid_keydb);
        let db = db_with(e, Vec::new());

        let got = KeydbSource::unit_keys_from(&db, &ctx(HASH, enc.clone(), Some(Vid(vid_phys))));
        // Reference uses the PHYSICAL VID.
        let expect = crate::uks_from_vuk(&derive_vuk(&mk, &vid_phys), &enc);
        assert_eq!(got, expect, "MK path must use the physical (unlock) VID");
        // Sanity: it must NOT match the keydb-VID derivation (different VID →
        // different VUK → different keys), proving the right VID was selected.
        let wrong = crate::uks_from_vuk(&derive_vuk(&mk, &vid_keydb), &enc);
        assert_ne!(
            got, wrong,
            "must not derive with the keydb VID when a physical VID exists"
        );
    }

    // ── KAT (d): disc with MK + keydb VID (ISO path, no physical VID) ──────────
    /// A hash hit with a Media Key but NO physical VID falls back to the keydb
    /// entry's stored VID (`vid`, the `I` field) — the non-physical / ISO
    /// path — and derives `MK → VUK → UK` against it.
    #[test]
    fn kat_d_disc_with_mk_falls_back_to_keydb_vid() {
        let mk = [0x77u8; 16];
        let vid_keydb = [0x99u8; 16];
        let enc = vec![[0x10u8; 16], [0x20u8; 16]];

        let mut e = blank_entry(HASH);
        e.media_key = Some(mk);
        e.vid = Some(vid_keydb);
        let db = db_with(e, Vec::new());

        // ctx.vid() == None → ISO path.
        let got = KeydbSource::unit_keys_from(&db, &ctx(HASH, enc.clone(), None));
        let expect = crate::uks_from_vuk(&derive_vuk(&mk, &vid_keydb), &enc);
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
        e.vid = None; // no keydb VID
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
        let expect = crate::uks_from_vuk(&derive_vuk(&mk, &vid_phys), &enc);
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

    // ── save / update (moved from libfreemkv::keydb) ──────────────────────────

    // Per project convention, tests never touch /tmp (wiped on reboot). Anchor
    // scratch under the crate's target/ (gitignored), not /tmp.
    fn scratch(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(0);
        let n = CTR.fetch_add(1, Ordering::Relaxed);
        let d = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/test-scratch")
            .join(format!("keydb-save-{}-{}-{}", std::process::id(), tag, n));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The headline behaviour of the move: `save` writes to the SOURCE'S OWN
    /// path, never a hardcoded default. Creates the parent dir, reports the
    /// destination, and round-trips the content.
    #[test]
    fn save_writes_to_the_sources_own_path() {
        let dir = scratch("save-path");
        let target = dir.join("nested").join("mykeys.cfg");
        let src = KeydbSource::new(&target);

        let body = b"0xDEADBEEFDEADBEEFDEADBEEFDEADBEEF = Test\n";
        let result = src.save(body).expect("save must succeed");

        assert_eq!(
            result.path, target,
            "save must write to the source's own path, not a default"
        );
        assert_eq!(result.entries, 1, "one 0x entry");
        assert!(target.exists(), "keydb file must exist at the source path");
        assert!(
            std::fs::read_to_string(&target)
                .unwrap()
                .contains("0xDEADBEEF"),
            "content must round-trip"
        );
    }

    /// `update` runs the injected fetch, then saves the returned bytes to the
    /// source's path — the transport is supplied by the caller, never built
    /// here.
    #[test]
    fn update_uses_injected_fetch_then_saves_to_path() {
        let dir = scratch("update-path");
        let target = dir.join("k.cfg");
        let src = KeydbSource::new(&target);

        let body = b"0xAABBCCDDAABBCCDDAABBCCDDAABBCCDD = Test\n".to_vec();
        let result = src
            .update(|_url| Ok(body.clone()), "http://example.test/keydb.zip")
            .expect("update must succeed with a good fetch");

        assert_eq!(result.path, target, "update must save to the source's path");
        assert_eq!(result.entries, 1);
        assert!(target.exists());
    }

    /// A failing injected fetch propagates as-is; nothing is written.
    #[test]
    fn update_propagates_fetch_error_and_writes_nothing() {
        let dir = scratch("update-err");
        let target = dir.join("k.cfg");
        let src = KeydbSource::new(&target);

        let result = src.update(
            |_| {
                Err(Error::KeydbConnect {
                    host: "x".to_string(),
                })
            },
            "http://x/",
        );
        assert!(matches!(result, Err(Error::KeydbConnect { .. })));
        assert!(!target.exists(), "a fetch failure must write no keydb");
    }

    /// `save` rejects bytes with no recognisable keydb entries.
    #[test]
    fn save_rejects_empty_text() {
        let dir = scratch("save-empty");
        let src = KeydbSource::new(dir.join("k.cfg"));
        let garbage = b"this is not a keydb\njust random text\n";
        assert!(matches!(src.save(garbage), Err(Error::KeydbInvalid)));
    }

    /// `save` recognises gzip magic (0x1f 0x8b) and routes to the gz decoder; a
    /// truncated gzip is a parse/invalid error, never a plain-text UTF-8 error.
    #[test]
    fn save_recognises_gzip_magic() {
        let dir = scratch("save-gz");
        let src = KeydbSource::new(dir.join("k.cfg"));
        let bad_gz = [0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03];
        match src.save(&bad_gz).unwrap_err() {
            Error::KeydbParse | Error::KeydbInvalid => {}
            e => panic!("wrong error kind for truncated gzip: {e:?}"),
        }
    }

    /// `save` recognises ZIP magic (PK\x03\x04) and routes to extract_zip; a
    /// truncated zip is a parse/invalid error, never a plain-text UTF-8 error.
    #[test]
    fn save_recognises_zip_magic() {
        let dir = scratch("save-zip");
        let src = KeydbSource::new(dir.join("k.cfg"));
        let bad_zip = b"PK\x03\x04garbage that is not a real zip";
        match src.save(bad_zip).unwrap_err() {
            Error::KeydbParse | Error::KeydbInvalid => {}
            e => panic!("wrong error for bad zip: {e:?}"),
        }
    }

    /// `read_capped_to_string` rejects input over the cap (decompression-bomb
    /// guard) and accepts exactly at the cap.
    #[test]
    fn read_capped_to_string_enforces_size_cap() {
        let too_big = vec![b'A'; (MAX_KEYDB_BYTES + 1) as usize];
        assert!(matches!(
            read_capped_to_string(std::io::Cursor::new(too_big)),
            Err(Error::KeydbInvalid)
        ));
        let at_cap = vec![b'A'; MAX_KEYDB_BYTES as usize];
        assert!(read_capped_to_string(std::io::Cursor::new(at_cap)).is_ok());
        // Non-UTF-8 is a parse error, not the size error.
        assert!(matches!(
            read_capped_to_string(std::io::Cursor::new(vec![0xFFu8, 0xFE])),
            Err(Error::KeydbParse)
        ));
    }

    /// `write_atomic` replaces an existing file in place and leaves no stray
    /// temp sibling.
    #[test]
    fn write_atomic_replaces_existing_and_leaves_no_temp() {
        let dir = scratch("atomic");
        let path = dir.join("freemkv").join("keydb.cfg");

        write_atomic(&path, "0xAAAA = old\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "0xAAAA = old\n");
        write_atomic(&path, "0xBBBB = new\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "0xBBBB = new\n");

        let leftovers: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "stray temp files: {leftovers:?}");
    }

    /// A failed write (parent path is a file → ENOTDIR on create_dir_all) leaves
    /// the prior keydb intact and surfaces KeydbWrite.
    #[test]
    fn write_atomic_failure_preserves_prior_keydb() {
        let dir = scratch("preserve");
        let good = dir.join("keydb.cfg");
        write_atomic(&good, "0xGOOD = keep\n").unwrap();

        let doomed = good.join("freemkv").join("keydb.cfg");
        assert!(matches!(
            write_atomic(&doomed, "0xBAD = partial\n"),
            Err(Error::KeydbWrite { .. })
        ));
        assert_eq!(std::fs::read_to_string(&good).unwrap(), "0xGOOD = keep\n");
    }
}
