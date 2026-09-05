//! `keydb.cfg` key source (source #1).
//!
//! Parses a local `keydb.cfg`, looks the disc up by hash, and derives the
//! disc's terminal **Unit Keys** by composing libfreemkv's raw
//! `aacs::derive` primitives — never re-implementing AES. The path mirrors
//! the OLD candidate order EXACTLY, cheapest-first: per-disc Unit Keys, then
//! VUK, then a Media Key (stored / PK pool / DK pool) via `derive_vuk`. See
//! docs/keydb.md#candidate-order for the full path and VID rules. The
//! library owns the crypto; this source owns only which primitive to call.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::uks_from_vuk;
use libfreemkv::aacs::derive::{derive_media_key_from_dk, derive_media_key_from_pk, derive_vuk};
use libfreemkv::aacs::types::{HostCert, MediaKey, UnitKey, Vid};
use libfreemkv::keysource::ResolveCtx;
use libfreemkv::{Error, KeySource};

use crate::keydb_format::KeyDb;

// Upper bound on decompressed keydb size (decompression-bomb cap): a tiny
// zip/gz could otherwise inflate to GiB and OOM the refresh thread. Mirrors
// keydb_format::MAX_KEYDB_BYTES (the on-disk load cap); keep the two equal.
const MAX_KEYDB_BYTES: u64 = 128 * 1024 * 1024;

/// Result of a KEYDB save/update -- path written, entry count, and byte size.
#[derive(Debug)]
pub struct UpdateResult {
    pub path: PathBuf,
    pub entries: usize,
    pub bytes: usize,
}

// Widest observed granularity of a filesystem's stored mtime (HFS+, many
// container/network filesystems record whole seconds); 2 s leaves rounding
// room. See docs/keydb.md#settle-proof for CacheEntry::is_settled's argument.
const MTIME_GRANULARITY: std::time::Duration = std::time::Duration::from_secs(2);

// The identity of the keydb file a cache entry was parsed from. `(len,
// modified)` alone is not an identity (see docs/keydb.md#file-identity for
// why); `dev`+`ino` plus CacheEntry::is_settled close the gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    /// Filesystem device id. `0` where unavailable.
    dev: u64,
    /// Inode number — the discriminator an atomic rename always changes. `0`
    /// where unavailable.
    ino: u64,
    len: u64,
    modified: Option<std::time::SystemTime>,
}

impl FileStamp {
    /// Stamp from a metadata block. Take it from `File::metadata` on an OPEN
    /// handle (an `fstat`), never from a second `std::fs::metadata` on the path:
    /// only the handle guarantees the stamp and the bytes describe one file.
    fn of(meta: &std::fs::Metadata) -> Self {
        // dev/ino are a Unix concept; Windows's rough equivalent is documented
        // unreliable on some filesystems, so the cross-platform fallback is
        // simply "no inode discriminator" (rule 2 alone is correct there).
        #[cfg(unix)]
        let (dev, ino) = {
            use std::os::unix::fs::MetadataExt;
            (meta.dev(), meta.ino())
        };
        #[cfg(not(unix))]
        let (dev, ino) = (0u64, 0u64);
        Self {
            dev,
            ino,
            len: meta.len(),
            modified: meta.modified().ok(),
        }
    }
}

/// One cached parse: the file identity it came from, WHEN that identity was
/// observed, the parsed database, and the parser's rejection counts.
struct CacheEntry {
    stamp: FileStamp,
    /// Wall-clock time at which `stamp` was read off the open handle. The whole
    /// point of storing it is [`Self::is_settled`].
    stamped_at: std::time::SystemTime,
    db: Arc<KeyDb>,
    /// Retained, not just logged: [`KeydbSource::cached_db`] re-emits the
    /// summary on every hit, because a cache hit skips `KeyDb::parse` and with
    /// it the one warning that a corrupt keydb is being served.
    stats: crate::keydb_format::ParseStats,
}

impl CacheEntry {
    // Whether this entry's stamp can be TRUSTED to change if the file changes.
    // Proof, cost, and the clock caveat are in docs/keydb.md#settle-proof;
    // don't weaken this without re-reading them.
    fn is_settled(&self, granularity: std::time::Duration) -> bool {
        self.stamp
            .modified
            .and_then(|m| self.stamped_at.duration_since(m).ok())
            .is_some_and(|age| age >= granularity)
    }
}

/// A [`KeySource`] backed by a local `keydb.cfg` file.
///
/// The parsed database is CACHED behind the file's identity stamp: a single
/// AACS-cert rip calls `host_certs()`, the trait `host_certs(mkb)`, and
/// `get_unit_keys`, and each used to re-read + re-parse the whole
/// ~62 MiB file. A replaced keydb is picked up on the next call, with one
/// narrow exception; see docs/keydb.md#keydbsource-cache for that exception
/// and the memory-residency tradeoff — do not weaken [`FileStamp`] or
/// [`CacheEntry::is_settled`] without re-reading it.
pub struct KeydbSource {
    path: PathBuf,
    // Mutex, not RwLock: the guarded section is a stamp compare + Arc clone,
    // so there's nothing for concurrent readers to win. Poisoning recovers
    // rather than propagates — a panic elsewhere must not poison every lookup.
    cache: Mutex<Option<CacheEntry>>,
    // Cache MISSES (real reads+parses). The only honest way to assert the
    // cache from a test, since timing is flaky and the parsed value is
    // identical either way.
    parses: AtomicUsize,
    // The `G` of CacheEntry::is_settled, as a field so tests can isolate the
    // two staleness discriminators one at a time (0 vs. a huge duration). See
    // docs/keydb.md#test-two-discriminators.
    mtime_granularity: std::time::Duration,
    // Corruption summaries emitted (see emit_parse_stats). Same rationale as
    // `parses`: avoids pulling a `tracing` subscriber into dev-dependencies.
    warnings: AtomicUsize,
}

impl KeydbSource {
    /// A keydb source reading the given `keydb.cfg` path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            cache: Mutex::new(None),
            parses: AtomicUsize::new(0),
            mtime_granularity: MTIME_GRANULARITY,
            warnings: AtomicUsize::new(0),
        }
    }

    // Log the parser's rejection summary and count the emission — the count
    // is the only way to assert, without a `tracing` dev-dependency, that the
    // corruption warning is NOT swallowed by the cache. See `cached_db`.
    fn emit_parse_stats(&self, stats: &crate::keydb_format::ParseStats) {
        if stats.log() {
            self.warnings.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Corruption summaries emitted so far. Test-only observability, paired with
    /// [`Self::parse_count`]: a corrupt keydb must warn once per LOOKUP, while
    /// still parsing once.
    #[cfg(test)]
    fn warning_count(&self) -> usize {
        self.warnings.load(Ordering::Relaxed)
    }

    /// Test-only: override the settle window (see the field's doc).
    #[cfg(test)]
    fn with_mtime_granularity(mut self, g: std::time::Duration) -> Self {
        self.mtime_granularity = g;
        self
    }

    // The parsed keydb, from cache when unchanged (errors mirror KeyDb::load).
    // ONE OPEN, ONE IDENTITY: stamp (fstat) and bytes share one handle. See
    // docs/keydb.md#cached-db-one-open for why a separate metadata()+load() pair was unsound.
    fn cached_db(&self) -> std::io::Result<Arc<KeyDb>> {
        let file = std::fs::File::open(&self.path)?;
        let stamp = FileStamp::of(&file.metadata()?);
        let stamped_at = std::time::SystemTime::now();
        // Fast path: a settled cache hit under a brief lock (stamp compare +
        // Arc clone). Re-emit the rejection summary on EVERY hit — a hit skips
        // `KeyDb::parse`, else a corrupt keydb warns once then serves silently.
        {
            let guard = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = guard.as_ref()
                && entry.stamp == stamp
                && entry.is_settled(self.mtime_granularity)
            {
                self.emit_parse_stats(&entry.stats);
                return Ok(entry.db.clone());
            }
        }
        // Miss: parse the ~62 MiB file OUTSIDE the lock so a reparse can't stall
        // every other worker. Stamp (fstat) and bytes still come from the ONE
        // open handle, preserving the one-open-one-identity invariant.
        let (db, stats) = KeyDb::load_counted(file, &self.path)?;
        let db = Arc::new(db);
        // Re-acquire and double-check: a peer may have installed the same
        // settled stamp while we parsed — adopt theirs and drop our redundant
        // parse rather than racing a lost update.
        let mut guard = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = guard.as_ref()
            && entry.stamp == stamp
            && entry.is_settled(self.mtime_granularity)
        {
            self.emit_parse_stats(&entry.stats);
            return Ok(entry.db.clone());
        }
        self.emit_parse_stats(&stats);
        self.parses.fetch_add(1, Ordering::Relaxed);
        *guard = Some(CacheEntry {
            stamp,
            stamped_at,
            db: db.clone(),
            stats,
        });
        Ok(db)
    }

    /// Drop the cached parse. Called after this source WRITES the file, so the
    /// next lookup re-reads it without depending on mtime resolution.
    fn invalidate_cache(&self) {
        *self.cache.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// Cache misses so far — the number of real file reads + parses. Test-only
    /// observability for the cache (see [`Self::cached_db`]).
    #[cfg(test)]
    fn parse_count(&self) -> usize {
        self.parses.load(Ordering::Relaxed)
    }

    // Turn a KeyDb::load failure into this source's verdict: MISSING is the
    // documented benign case (Ok/None); everything else is logged and
    // surfaced as an error, not silently reported as "no key". See docs/keydb.md#load-failure.
    fn load_failure(&self, e: &std::io::Error) -> Option<Error> {
        match e.kind() {
            std::io::ErrorKind::NotFound => None,
            std::io::ErrorKind::InvalidData => {
                tracing::warn!(
                    target: "freemkv::keysource",
                    path = %self.path.display(),
                    "keydb.cfg is unusable (over the size cap or not valid UTF-8) — this is a corrupt or truncated keydb, NOT a disc without a key"
                );
                Some(Error::KeydbInvalid)
            }
            kind => {
                tracing::warn!(
                    target: "freemkv::keysource",
                    path = %self.path.display(),
                    io_kind = ?kind,
                    "keydb.cfg could not be read — NOT a disc without a key"
                );
                Some(Error::KeydbLoad {
                    path: self.path.display().to_string(),
                })
            }
        }
    }

    /// Validate, decompress, and crash-safely persist raw keydb bytes (plain
    /// text, `.zip`, or `.gz`) to THIS source's own [`path`](Self::path).
    ///
    /// The bytes are decompressed (zip / gz / plain), checked for at least
    /// one recognisable keydb entry, then atomically written to the source's
    /// path (sibling-temp + fsync + rename + parent-dir fsync). Decompressed
    /// size is capped at [`MAX_KEYDB_BYTES`] (decompression-bomb guard).
    /// Writes to the source's own path, not a hardcoded default, so the
    /// caller decides the destination (CLI `--keydb`, the autorip service path).
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
                // Mirror KeyDb::parse's disc-entry rule EXACTLY by CALLING it,
                // so save() never persists content that parses to zero usable
                // entries. See docs/keydb.md#save-mirror-parse.
                crate::keydb_format::is_disc_entry_line(t)
                    || t.starts_with("| DK")
                    || t.starts_with("| PK")
                    || t.starts_with("| HC")
            })
            .count();

        if entries == 0 {
            return Err(Error::KeydbInvalid);
        }

        write_atomic(&self.path, &text)?;
        // The file this source reads was just replaced; drop the parsed copy.
        self.invalidate_cache();

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
        match self.cached_db() {
            Ok(db) => db.host_certs(None),
            // No error channel here (the scan-options builder wants a list), so
            // the failure can only be LOGGED — but it must not be invisible.
            Err(e) => {
                let _ = self.load_failure(&e);
                Vec::new()
            }
        }
    }

    // Derive this disc's terminal Unit Keys from a parsed keydb. Pure (no
    // I/O). Empty Vec = no key for this disc from this keydb. CPS-unit
    // numbering (idx = num - 1) is explained in docs/keydb.md#unit-keys-from.
    fn unit_keys_from(db: &KeyDb, ctx: &dyn ResolveCtx) -> Vec<UnitKey> {
        // Per-disc hit (most specific); find_disc normalizes the hash form.
        // Without a match there is no per-disc anchor, so the global PK/DK
        // pools are never consulted. See docs/keydb.md#unit-keys-per-disc-hit.
        let Some(entry) = db.find_disc(ctx.disc_hash()) else {
            return Vec::new();
        };

        // UNION every source of terminal keys, then dedup — never first-hit,
        // since a stored `unit_keys` list can be PARTIAL while the VUK boils
        // every declared unit. See docs/keydb.md#unit-keys-union.
        let mut keys: Vec<UnitKey> = Vec::new();

        // 1. Terminal Unit Keys stored in the entry — directly usable, no
        //    derivation. Preserve the keydb's CPS numbering (idx = num - 1).
        for (num, key) in &entry.unit_keys {
            // A valid CPS unit number is >= 1; num 0 would collide with unit 1
            // at idx 0 (num - 1), so skip it rather than mis-map two units.
            if *num == 0 {
                continue;
            }
            keys.push(UnitKey::new(num - 1, *key));
        }

        // The disc's encrypted title keys (from Unit_Key_RO.inf). Empty when
        // the scan captured none, in which case only the stored list (1)
        // contributes.
        let enc_title_keys = match ctx.enc_title_keys() {
            Ok(k) => k,
            Err(e) => {
                // Mirror online.rs: surface the read failure, then fall back to
                // empty (only the stored unit-key list can contribute).
                tracing::warn!(
                    target: "freemkv::keysource",
                    error = %e,
                    "keydb: disc encrypted title keys unreadable; deriving without them"
                );
                &[]
            }
        };
        if !enc_title_keys.is_empty() {
            // VUK path, else MK path (stored/PK/DK) → VUK. See
            // docs/keydb.md#unit-keys-vuk-or-mk for the VID rules.
            let derived = if let Some(vuk) = entry.vuk {
                uks_from_vuk(&vuk, enc_title_keys)
            } else {
                let vid = ctx.vid().or_else(|| entry.vid.map(Vid));
                let mkb = match ctx.mkb() {
                    Ok(m) => m,
                    Err(e) => {
                        // Mirror online.rs: log the failure, then fall back to
                        // empty (PK/DK derivation may then find no Media Key).
                        tracing::warn!(
                            target: "freemkv::keysource",
                            error = %e,
                            "keydb: disc MKB unreadable; media-key derivation may fail"
                        );
                        &[]
                    }
                };
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

// Write `text` to `path` crash-safely (temp file, fsync, atomic rename) so an
// interrupted update never leaves a half-written keydb. See
// docs/keydb.md#write-atomic for the fsync-before-rename argument.
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
        // The temp file is renamed onto keydb.cfg, which holds AACS key
        // material and the host private key/cert — create it 0600 on Unix so
        // umask can't leave the keys world-readable. Non-unix keeps create().
        #[cfg(unix)]
        let mut f = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?
        };
        #[cfg(not(unix))]
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
    // Resolve this disc's base per-CPS-unit Unit Keys from the keydb. A
    // MISSING keydb yields no keys (Ok(empty)); an UNUSABLE one is a source
    // failure (Err) — never conflated. See docs/keydb.md#get-unit-keys-trait.
    fn get_unit_keys(&self, ctx: &dyn ResolveCtx) -> Result<Vec<UnitKey>, Error> {
        match self.cached_db() {
            Ok(db) => Ok(Self::unit_keys_from(&db, ctx)),
            Err(e) => match self.load_failure(&e) {
                // Missing keydb: the documented benign miss.
                None => Ok(Vec::new()),
                // Corrupt / unreadable keydb: a SOURCE FAILURE, not a miss.
                Some(err) => Err(err),
            },
        }
    }

    // Expose the keydb's host certs through the trait, wiring the disc's MKB
    // generation through for revocation filtering. See
    // docs/keydb.md#host-certs-trait.
    fn host_certs(&self, mkb: Option<u32>) -> Vec<HostCert> {
        match self.cached_db() {
            Ok(db) => db.host_certs(mkb),
            // Vec-returning trait method: log the failure, return nothing.
            Err(e) => {
                let _ = self.load_failure(&e);
                Vec::new()
            }
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

    /// A fixed, in-the-past mtime — `touch -t CCYYMMDDhhmm.ss`.
    #[cfg(unix)]
    const PINNED_MTIME: &str = "202601011200.00";

    // Force a file's mtime to PINNED_MTIME so two different files can be
    // made bit-identical to a (len, mtime) stamp on purpose, rather than
    // hoping the filesystem produces that case. See docs/keydb.md#test-pinned-mtime.
    #[cfg(unix)]
    fn pin_mtime(p: &std::path::Path) {
        let ok = std::process::Command::new("touch")
            .arg("-t")
            .arg(PINNED_MTIME)
            .arg(p)
            .status()
            .expect("touch must run")
            .success();
        assert!(ok, "touch -t failed");
    }

    use libfreemkv::aacs::derive::derive_vuk;
    use libfreemkv::aacs::types::DeviceKey;
    use std::collections::HashMap;

    // ── A test ResolveCtx, so get_unit_keys's path selection can be exercised without
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

    // The committed (cps, key) pairs resolve_and_apply derives from a
    // source's Unit Keys (idx -> idx + 1). KATs compare against THIS. See
    // docs/keydb.md#test-committed.
    fn committed(uks: &[UnitKey]) -> Vec<(u32, [u8; 16])> {
        uks.iter()
            .map(|u| (u.idx.saturating_add(1), u.key))
            .collect()
    }

    const HASH: &str = "0xaabb";

    // MockCtx implements the full trait so it can stand in for a real disc,
    // but KeydbSource never calls title()/samples(); exercise them directly
    // so the mock's trait surface is proven correct too.
    #[test]
    fn mock_ctx_title_and_samples_are_stubbed_correctly() {
        let c = ctx(HASH, Vec::new(), None);
        assert_eq!(c.title(), None);
        assert_eq!(c.samples(4).unwrap(), Vec::<Vec<u8>>::new());
    }

    // KAT (a): disc with terminal Unit Keys, no enc_title_keys. Stored
    // terminal unit keys are returned with CPS numbering preserved. See
    // docs/keydb.md#test-kat-a.
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

    // A CPS unit number of 0 is invalid (valid numbering is >= 1); it must be
    // skipped, not mapped to idx 0 where `num - 1` would collide with unit 1.
    #[test]
    fn stored_unit_key_with_cps_number_zero_is_skipped() {
        let mut e = blank_entry(HASH);
        e.unit_keys = vec![(0, [0xEEu8; 16]), (1, [0xA0u8; 16])];
        let db = db_with(e, Vec::new());
        let got = KeydbSource::unit_keys_from(&db, &ctx(HASH, Vec::new(), None));
        let keys: Vec<[u8; 16]> = got.iter().map(|u| u.key).collect();
        assert!(
            !keys.contains(&[0xEEu8; 16]),
            "a unit-0 key must be dropped, never mapped onto idx 0"
        );
        assert_eq!(committed(&got), vec![(1u32, [0xA0u8; 16])]);
    }

    // Orphan-unit completeness (the real keydb bug): a PARTIAL stored list
    // plus a VUK that boils BOTH declared units must return BOTH, not shadow
    // the VUK with the partial list. See docs/keydb.md#test-orphan-union.
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

    // KAT (c): MK + physical (unlock) VID derives MK -> VUK -> UK. The
    // PHYSICAL VID must win over the keydb's stored VID. See
    // docs/keydb.md#test-kat-c.
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

    // KAT (f): disc with NO per-disc MK, resolved via the keydb PK pool
    // (PK -> MK -> VUK -> UK) with a known-answer MKB/PK construction. See
    // docs/keydb.md#test-kat-f.
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
            .get_unit_keys(&ctx(HASH, Vec::new(), None))
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

    // Caching: the 62 MiB / 181k-entry keydb is parsed ONCE. A single
    // AACS-cert rip drives this source at least three times; the mtime is
    // pinned into the PAST first, since an entry is only trusted once settled. See docs/keydb.md#test-repeated-lookups.
    #[cfg(unix)]
    #[test]
    fn repeated_lookups_parse_the_keydb_once() {
        let dir = scratch("cache-hit");
        let path = dir.join("keydb.cfg");
        let line = format!(
            "| HC | HOST_PRIV_KEY 0x{} | HOST_CERT 0x{}\n",
            "00".repeat(20),
            "00".repeat(92)
        );
        std::fs::write(&path, &line).unwrap();
        pin_mtime(&path);

        let src = KeydbSource::new(&path);
        assert_eq!(src.host_certs().len(), 1);
        assert_eq!(KeySource::host_certs(&src, Some(70)).len(), 1);
        assert!(
            src.get_unit_keys(&ctx(HASH, Vec::new(), None))
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            src.parse_count(),
            1,
            "three lookups over an unchanged file must parse it once"
        );
    }

    // The cache must not go stale: a keydb replaced UNDERNEATH the source has
    // a different size/mtime stamp and must be re-read. See
    // docs/keydb.md#test-changed-keydb.
    #[test]
    fn a_changed_keydb_file_is_reparsed() {
        let dir = scratch("cache-stamp");
        let path = dir.join("keydb.cfg");
        let hc = |b: &str, n: usize| {
            format!(
                "| HC | HOST_PRIV_KEY 0x{} | HOST_CERT 0x{}\n",
                "00".repeat(20),
                b.repeat(n)
            )
        };
        std::fs::write(&path, hc("00", 92)).unwrap();
        let src = KeydbSource::new(&path);
        assert_eq!(src.host_certs()[0].certificate.len(), 92);

        // A different LENGTH guarantees a different stamp regardless of the
        // filesystem's mtime resolution.
        std::fs::write(&path, hc("11", 100)).unwrap();
        assert_eq!(
            src.host_certs()[0].certificate.len(),
            100,
            "a replaced keydb must be re-read, not served from a stale cache"
        );
        assert_eq!(src.parse_count(), 2, "one parse per distinct file");
    }

    // Two stale-cache discriminators, tested ONE AT A TIME (each test
    // disables the other via `mtime_granularity`). Discriminator 1, the
    // inode: an ATOMIC RENAME must be re-read even with identical length and mtime. See docs/keydb.md#test-inode-rename.
    #[cfg(unix)]
    #[test]
    fn a_same_length_same_mtime_rename_is_still_re_read() {
        let dir = scratch("cache-inode");
        let path = dir.join("keydb.cfg");
        let replacement = dir.join("keydb.cfg.new");
        let body = |k: &str| format!("0xaabb = T | U | 1-0x{k}\n");

        std::fs::write(&path, body(&"01".repeat(16))).unwrap();
        pin_mtime(&path);
        let src = KeydbSource::new(&path).with_mtime_granularity(std::time::Duration::ZERO);
        assert_eq!(
            src.get_unit_keys(&ctx(HASH, Vec::new(), None)).unwrap()[0].key,
            [0x01u8; 16]
        );

        // Same length, same mtime, different inode.
        std::fs::write(&replacement, body(&"02".repeat(16))).unwrap();
        pin_mtime(&replacement);
        std::fs::rename(&replacement, &path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            body(&"01".repeat(16)).len() as u64,
            "the two keydbs must be the same size for this test to mean anything"
        );

        assert_eq!(
            src.get_unit_keys(&ctx(HASH, Vec::new(), None)).unwrap()[0].key,
            [0x02u8; 16],
            "a renamed-in keydb of the same size and mtime must not be served from the stale cache"
        );
        assert_eq!(src.parse_count(), 2, "the replacement must be re-parsed");
    }

    // Discriminator 2, the settle window: a keydb rewritten IN PLACE (same
    // inode/length, mtime forced back) must still be re-read while too young
    // to trust. See docs/keydb.md#test-inplace-rewrite.
    #[cfg(unix)]
    #[test]
    fn an_in_place_rewrite_under_an_unsettled_stamp_is_still_re_read() {
        use std::io::Write as _;
        let dir = scratch("cache-settle");
        let path = dir.join("keydb.cfg");
        let body = |k: &str| format!("0xaabb = T | U | 1-0x{k}\n");

        std::fs::write(&path, body(&"01".repeat(16))).unwrap();
        pin_mtime(&path);
        let ino_before = std::fs::metadata(&path)
            .map(|m| std::os::unix::fs::MetadataExt::ino(&m))
            .unwrap();
        let src = KeydbSource::new(&path)
            .with_mtime_granularity(std::time::Duration::from_secs(10 * 365 * 24 * 3600));
        assert_eq!(
            src.get_unit_keys(&ctx(HASH, Vec::new(), None)).unwrap()[0].key,
            [0x01u8; 16]
        );

        // Overwrite the SAME inode in place (no truncate, no rename), same
        // length, then force the mtime back: every field of the old stamp
        // matches.
        let mut f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        f.write_all(body(&"02".repeat(16)).as_bytes()).unwrap();
        f.sync_all().unwrap();
        drop(f);
        pin_mtime(&path);
        assert_eq!(
            std::fs::metadata(&path)
                .map(|m| std::os::unix::fs::MetadataExt::ino(&m))
                .unwrap(),
            ino_before,
            "the rewrite must reuse the inode for this test to mean anything"
        );

        assert_eq!(
            src.get_unit_keys(&ctx(HASH, Vec::new(), None)).unwrap()[0].key,
            [0x02u8; 16],
            "an in-place rewrite under an indistinguishable stamp must not be served from cache"
        );
    }

    // A corrupt-but-parseable keydb must keep saying so on EVERY hit, not
    // just the parse that produced the summary (a cache hit skips `parse`).
    // See docs/keydb.md#test-corrupt-warns.
    #[cfg(unix)]
    #[test]
    fn a_corrupt_keydb_warns_on_every_lookup_not_only_on_the_parse() {
        let dir = scratch("cache-warn");
        let path = dir.join("keydb.cfg");
        // Parseable (one good disc row) but damaged: two rows the parser must
        // reject and count.
        std::fs::write(
            &path,
            "0xaabb = T | U | 1-0x00112233445566778899aabbccddeeff\n\
             | PK | 0xnothex\n\
             | DK | DEVICE_KEY 0xZZ | DEVICE_NODE 0x0800 | KEY_UV 0x00000400 | KEY_U_MASK_SHIFT 0x17\n",
        )
        .unwrap();
        pin_mtime(&path);

        let src = KeydbSource::new(&path);
        for _ in 0..3 {
            assert!(
                !src.get_unit_keys(&ctx(HASH, Vec::new(), None))
                    .unwrap()
                    .is_empty(),
                "the healthy row must still resolve — corruption is not a source failure here"
            );
        }
        assert_eq!(
            src.parse_count(),
            1,
            "the cache must still do its job: one parse for three lookups"
        );
        assert_eq!(
            src.warning_count(),
            3,
            "the corruption summary must be re-emitted on every cache hit, not once per process"
        );
    }

    // A HEALTHY keydb must stay silent — the re-emission above must not turn
    // into a per-lookup log line for every operator with an intact file. See
    // docs/keydb.md#test-healthy-silent.
    #[cfg(unix)]
    #[test]
    fn a_healthy_keydb_warns_on_no_lookup() {
        let dir = scratch("cache-quiet");
        let path = dir.join("keydb.cfg");
        std::fs::write(
            &path,
            "0xaabb = T | U | 1-0x00112233445566778899aabbccddeeff\n",
        )
        .unwrap();
        pin_mtime(&path);

        let src = KeydbSource::new(&path);
        for _ in 0..3 {
            let _ = src.get_unit_keys(&ctx(HASH, Vec::new(), None)).unwrap();
        }
        assert_eq!(
            src.warning_count(),
            0,
            "an intact keydb must produce no corruption summary at all"
        );
    }

    // The cost side of the settle rule, asserted as a decision: a keydb
    // written just now is re-read on every lookup until quiet for the
    // granularity. See docs/keydb.md#test-fresh-not-trusted.
    #[test]
    fn a_freshly_written_keydb_is_not_trusted_from_cache() {
        let dir = scratch("cache-fresh");
        let path = dir.join("keydb.cfg");
        std::fs::write(
            &path,
            "0xaabb = T | U | 1-0x00112233445566778899aabbccddeeff\n",
        )
        .unwrap();

        let src = KeydbSource::new(&path);
        assert!(
            !src.get_unit_keys(&ctx(HASH, Vec::new(), None))
                .unwrap()
                .is_empty()
        );
        assert!(
            !src.get_unit_keys(&ctx(HASH, Vec::new(), None))
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            src.parse_count(),
            2,
            "a keydb whose mtime is younger than the granularity must be re-read, not trusted"
        );
    }

    // `save()` replaces the very file this source reads, so it drops the
    // cached parse ITSELF rather than trusting the (size, mtime) stamp — the
    // one change the stamp cannot see. See docs/keydb.md#test-save-invalidates.
    #[cfg(unix)]
    #[test]
    fn save_invalidates_the_cache_even_when_the_file_stamp_is_unchanged() {
        let dir = scratch("cache-save");
        let path = dir.join("keydb.cfg");
        let k1 = "01".repeat(16);
        let k2 = "02".repeat(16);
        let body = |k: &str| format!("0xaabb = T | U | 1-0x{k}\n");

        std::fs::write(&path, body(&k1)).unwrap();
        pin_mtime(&path);

        let src = KeydbSource::new(&path);
        let first = src.get_unit_keys(&ctx(HASH, Vec::new(), None)).unwrap();
        assert_eq!(first[0].key, [0x01u8; 16]);

        // Same byte length, written THROUGH this source, then stamped back so
        // (size, mtime) is bit-identical to what the cache recorded.
        src.save(body(&k2).as_bytes()).expect("save must succeed");
        pin_mtime(&path);
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            body(&k1).len() as u64,
            "the two keydbs must be the same size for this test to mean anything"
        );

        let second = src.get_unit_keys(&ctx(HASH, Vec::new(), None)).unwrap();
        assert_eq!(
            second[0].key, [0x02u8; 16],
            "a save through this source must invalidate its own cache, not wait for the stamp to change"
        );
    }

    // A corrupt keydb is a source FAILURE, not "this disc has no key": both
    // used to collapse into Ok(Vec::new()) with ZERO tracing. Only a MISSING
    // file is genuinely benign. See docs/keydb.md#test-corrupt-is-error.
    #[test]
    fn a_corrupt_keydb_is_an_error_not_an_empty_answer() {
        let dir = scratch("corrupt");
        let path = dir.join("keydb.cfg");
        // Invalid UTF-8 (a lone continuation byte) → InvalidData from load.
        std::fs::write(&path, [0x30u8, 0x78, 0xFF, 0xFE, 0x0A]).unwrap();

        let src = KeydbSource::new(&path);
        let err = src
            .get_unit_keys(&ctx(HASH, Vec::new(), None))
            .expect_err("a corrupt keydb must not look like a disc with no key");
        assert_eq!(
            err.code(),
            libfreemkv::error::E_KEYDB_INVALID,
            "an unusable keydb must report itself, not E7022"
        );
        assert_ne!(
            err.code(),
            libfreemkv::error::E_NO_DISC_KEY,
            "a corrupt keydb says NOTHING about whether this disc has a key"
        );
    }

    /// The contrast case, through the same code: a keydb that simply is not
    /// there stays the documented benign miss (`Ok(empty)`), so the fix above
    /// cannot have turned "no keydb configured" into a hard failure.
    #[test]
    fn a_missing_keydb_is_still_a_benign_empty() {
        let src = KeydbSource::new("/nonexistent/path/keydb.cfg");
        assert!(
            src.get_unit_keys(&ctx(HASH, Vec::new(), None))
                .expect("a missing keydb is not an error")
                .is_empty()
        );
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

    // A keydb.cfg over the size cap or not valid UTF-8 must surface as a
    // SOURCE FAILURE (KeydbInvalid), never a silent empty result.
    #[test]
    fn get_unit_keys_reports_invalid_utf8_keydb_as_a_failure() {
        let dir = scratch("load-failure-invalid");
        let path = dir.join("keydb.cfg");
        std::fs::write(&path, [0xffu8, 0xfe, 0x00, 0x01]).unwrap();
        let src = KeydbSource::new(&path);
        let err = src
            .get_unit_keys(&ctx(HASH, Vec::new(), None))
            .expect_err("non-UTF-8 keydb must be a failure, not an empty miss");
        assert!(matches!(err, Error::KeydbInvalid));
    }

    /// Any OTHER read failure (not "missing", not "invalid data") — e.g. the
    /// configured path is a directory, not a file — is also a source failure,
    /// distinct from `KeydbInvalid`.
    #[test]
    fn get_unit_keys_reports_unreadable_keydb_path_as_a_failure() {
        let dir = scratch("load-failure-unreadable");
        // Point the source AT a directory: `File::open` fails with an io::Error
        // whose kind is neither NotFound nor InvalidData.
        let src = KeydbSource::new(&dir);
        let err = src
            .get_unit_keys(&ctx(HASH, Vec::new(), None))
            .expect_err("an unreadable keydb path must be a failure, not an empty miss");
        assert!(matches!(err, Error::KeydbLoad { .. }));
    }

    /// `host_certs` (the `Vec`-returning trait method) hits the exact same
    /// `load_failure` branches, just via a swallowed log instead of `Err` —
    /// prove it returns empty rather than panicking on a corrupt keydb.
    #[test]
    fn host_certs_swallows_a_corrupt_keydb_into_an_empty_list() {
        let dir = scratch("load-failure-hostcerts");
        let path = dir.join("keydb.cfg");
        std::fs::write(&path, [0xffu8, 0xfe]).unwrap();
        let src = KeydbSource::new(&path);
        assert!(
            src.host_certs().is_empty(),
            "a corrupt keydb must yield no host certs, not panic"
        );
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

    // `extract_zip` on a WELL-FORMED zip with no `*.cfg`/`*.CFG` member must
    // return `Error::KeydbInvalid` — never a parse error or a silent pick.
    #[test]
    fn save_rejects_a_valid_zip_with_no_cfg_member() {
        use std::io::Write as _;
        let mut buf = Vec::new();
        {
            let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default();
            writer.start_file("readme.txt", opts).unwrap();
            writer.write_all(b"not a keydb").unwrap();
            writer.finish().unwrap();
        }
        assert!(buf.starts_with(b"PK\x03\x04"), "must be a real zip");

        let dir = scratch("save-zip-no-cfg");
        let src = KeydbSource::new(dir.join("k.cfg"));
        assert!(matches!(src.save(&buf), Err(Error::KeydbInvalid)));
    }

    /// `save` on a WELL-FORMED zip that DOES carry a `*.cfg` member routes
    /// through the success arm of `extract_zip` — proven distinct from the
    /// "no member found" and "truncated/corrupt zip" cases above.
    #[test]
    fn save_extracts_the_cfg_member_from_a_valid_zip() {
        use std::io::Write as _;
        let mut buf = Vec::new();
        {
            let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default();
            writer.start_file("ignored.txt", opts).unwrap();
            writer.write_all(b"not a keydb").unwrap();
            writer.start_file("KEYDB.cfg", opts).unwrap();
            writer
                .write_all(b"0xAABBCCDDAABBCCDDAABBCCDDAABBCCDD = Test\n")
                .unwrap();
            writer.finish().unwrap();
        }
        let dir = scratch("save-zip-with-cfg");
        let src = KeydbSource::new(dir.join("k.cfg"));
        let result = src
            .save(&buf)
            .expect("a zip carrying a .cfg member must extract");
        assert_eq!(result.entries, 1);
    }

    // `write_atomic` when the temp file cannot be CREATED (unwritable
    // parent) must clean up and surface `Error::KeydbWrite`.
    #[cfg(unix)]
    #[test]
    fn write_atomic_failure_when_temp_file_cannot_be_created() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("write-atomic-unwritable");
        let target = dir.join("keydb.cfg");
        // Parent dir exists (so create_dir_all is a no-op) but is read-only,
        // so `File::create(&tmp)` fails with permission denied.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        let result = write_atomic(&target, "0xAAAA = x\n");
        // Restore write permission so the scratch dir can be cleaned up by a
        // later test run regardless of outcome here.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(result, Err(Error::KeydbWrite { .. })));
    }

    /// `write_atomic` when the RENAME step fails (the temp file wrote fine,
    /// but the destination is an existing directory, so `rename` refuses)
    /// must surface `Error::KeydbWrite` and remove the orphaned temp file.
    #[test]
    fn write_atomic_failure_when_rename_target_is_a_directory() {
        let dir = scratch("write-atomic-rename-fail");
        // The "keydb path" is itself an existing directory — the temp file
        // writes fine (same parent), but renaming a file onto a directory
        // always fails.
        let target = dir.join("keydb.cfg");
        std::fs::create_dir_all(&target).unwrap();
        let result = write_atomic(&target, "0xAAAA = x\n");
        assert!(matches!(result, Err(Error::KeydbWrite { .. })));
        // No stray temp file left behind.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "stray temp files: {leftovers:?}");
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
