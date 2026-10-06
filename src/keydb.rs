//! `keydb.cfg` key source (source #1).
//!
//! Parses a local `keydb.cfg`, looks the disc up by hash, and derives the disc's terminal
//! **Unit Keys** by composing libfreemkv's raw `aacs::derive` primitives — never
//! re-implementing AES. The path mirrors the OLD candidate order EXACTLY, cheapest-first:
//! per-disc Unit Keys, then VUK, then a Media Key (stored / PK pool / DK pool) via
//! `derive_vuk`.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::uks_from_vuk;
use libfreemkv::aacs::derive::{derive_media_key_from_dk, derive_media_key_from_pk, derive_vuk};
use libfreemkv::aacs::trace::{KeyNode, MatchedEntry};
use libfreemkv::aacs::types::{HostCert, MediaKey, UnitKey, Vid};
use libfreemkv::keysource::{ResolveCtx, UnitKeyResolution};
use libfreemkv::{Error, KeySource};

use crate::keydb_format::KeyDb;
// Decompression-bomb cap on decompressed keydb size: a tiny zip/gz could
// inflate to GiB and OOM the refresh thread. Same constant `KeyDb::load`
// uses on-disk, defined once in keydb_format so the two can't drift.
use crate::keydb_format::MAX_KEYDB_BYTES;

/// Result of a KEYDB save/update -- path written, entry count, and byte size.
#[derive(Debug)]
pub struct UpdateResult {
    pub path: PathBuf,
    pub entries: usize,
    pub bytes: usize,
}

// Widest observed granularity of a filesystem's stored mtime (HFS+, many container/network
// filesystems record whole seconds); 2 s leaves rounding room.
const MTIME_GRANULARITY: std::time::Duration = std::time::Duration::from_secs(2);

// The identity of the keydb file a cache entry was parsed from. `(len, modified)` alone is not
// an identity; `dev`+`ino` plus CacheEntry::is_settled close the gap.
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
    // Require a settled identity before reusing a cached parse: coarse mtimes can hide
    // in-place edits within one timestamp tick. Missing/future mtimes use the age of
    // the observation; inode identity detects atomic replacement.
    fn is_settled(&self, granularity: std::time::Duration) -> bool {
        match self
            .stamp
            .modified
            .and_then(|m| self.stamped_at.duration_since(m).ok())
        {
            // The normal case: a real mtime that was already `granularity` in
            // the past when we stamped it, so any later write bumps the mtime
            // past our stamp and is detected. Trust it.
            Some(age) => age >= granularity,
            // No mtime (mtime-less FS) or a future mtime (clock skew): `duration_since`
            // yields None, so the mtime can't discriminate change — settle via inode
            // identity once this observation has itself aged past the granularity.
            None => std::time::SystemTime::now()
                .duration_since(self.stamped_at)
                .is_ok_and(|age| age >= granularity),
        }
    }
}

/// A [`KeySource`] backed by a local `keydb.cfg` file.
///
/// The parsed database is CACHED behind the file's identity stamp: a single AACS-cert rip calls
/// `host_certs()`, the trait `host_certs(mkb)`, and `get_unit_keys`, and each used to re-read +
/// re-parse the whole ~62 MiB file. A replaced keydb is picked up on the next call, with one
/// narrow exception.
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
    // The `G` of CacheEntry::is_settled, as a field so tests can isolate the two staleness
    // discriminators one at a time (0 vs. a huge duration).
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

    // The parsed keydb, from cache when unchanged (errors mirror KeyDb::load). ONE OPEN, ONE
    // IDENTITY: stamp (fstat) and bytes share one handle.
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

    // Turn a KeyDb::load failure into this source's verdict: MISSING is the documented benign
    // case (Ok/None); everything else is logged and surfaced as an error, not silently reported
    // as "no key".
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
            // Mirror KeyDb::parse by running the same parsers, not a prefix check: a
            // right-prefix row with bad hex / short cert parses to nothing, so a prefix count
            // let junk past `entries > 0`.
            .filter(|l| crate::keydb_format::is_parseable_entry_line(l))
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
    /// Best first ([`KeyDb::host_certs_ranked`]): this is what the scan-options
    /// builder hands the live-drive handshake as `DriveCredentials`.
    pub fn host_certs(&self) -> Vec<HostCert> {
        match self.cached_db() {
            Ok(db) => db.host_certs_ranked(),
            // No error channel here (the scan-options builder wants a list), so
            // the failure can only be LOGGED — but it must not be invisible.
            Err(e) => {
                let _ = self.load_failure(&e);
                Vec::new()
            }
        }
    }

    // Return terminal Unit Keys from a parsed keydb without I/O.
    // CPS unit numbers are one-based; the returned vector uses zero-based indexes.
    fn unit_keys_from(db: &KeyDb, ctx: &dyn ResolveCtx) -> Vec<UnitKey> {
        Self::resolve_from(db, ctx).keys
    }

    // De-conflated resolution: the keys PLUS whether the disc matched and — on a
    // keyless match — WHY nothing derived, so a matched-but-underivable disc is
    // never reported as a flat "no entry" (issue #46). Pure (no I/O).
    fn resolve_from(db: &KeyDb, ctx: &dyn ResolveCtx) -> KeydbResolution {
        // Per-disc hit (most specific); find_disc normalizes the hash form. Without a match
        // there is no per-disc anchor, so the global PK/DK pools are never consulted.
        let entries_loaded = db.disc_entries.len();
        let Some(entry) = db.find_disc(ctx.disc_hash()) else {
            return KeydbResolution::miss(entries_loaded);
        };

        // UNION every source of terminal keys, then dedup — never first-hit, since a stored
        // `unit_keys` list can be PARTIAL while the VUK boils every declared unit.
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

        // Why the keyless derivation could not finish, for the trace's miss
        // path. `None` once any key lands (or when there was no material to try).
        let mut miss_reason: Option<KeyNode> = None;

        if !enc_title_keys.is_empty() {
            // VUK path, else MK path (stored/PK/DK) → VUK.
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
                    // De-conflate the two reasons so the trace can say WHICH.
                    (Some(_), None) => {
                        miss_reason = Some(KeyNode::NoVid);
                        Vec::new()
                    }
                    (None, _) => {
                        miss_reason = Some(KeyNode::NoDerivableKey);
                        Vec::new()
                    }
                }
            };
            keys.extend(derived);
        }

        // Unique by key value, first occurrence wins (stored numbering kept).
        let mut seen = std::collections::HashSet::new();
        keys.retain(|u| seen.insert(u.key));

        // Booleans-and-lengths shape of the matched entry, for the app to log —
        // answers "what did the matched entry actually carry?" (issue #46).
        let shape = MatchedEntry {
            has_vuk: entry.vuk.is_some(),
            has_unit_keys: !entry.unit_keys.is_empty(),
            unit_keys_len: entry.unit_keys.len(),
            has_media_key: entry.media_key.is_some(),
            has_keydb_vid: entry.vid.is_some(),
            enc_title_keys_len: enc_title_keys.len(),
            vid_available: ctx.vid().is_some() || entry.vid.is_some(),
        };

        // On a match with no key: carry the specific reason if we have one, else
        // leave it empty for the library to render a bare `NoDerivableKey`.
        // KU J23: `NoVid` stays beside partial keys (the VID would derive the rest).
        let miss_path = match miss_reason {
            Some(n) if keys.is_empty() || n == KeyNode::NoVid => vec![n],
            _ => Vec::new(),
        };

        KeydbResolution {
            keys,
            matched: true,
            shape: Some(shape),
            miss_path,
            entries_loaded,
        }
    }
}

// The de-conflated result of a keydb lookup: keys plus enough context that a
// MATCHED-but-underivable disc is reported distinctly from a true miss. See
// [`KeydbSource::resolve_from`] and issue #46.
struct KeydbResolution {
    keys: Vec<UnitKey>,
    matched: bool,
    shape: Option<MatchedEntry>,
    miss_path: Vec<KeyNode>,
    // Per-disc entries loaded in the keydb — named in a true-miss verdict so a
    // reporter can confirm a wrong-pressing (`… not in keydb (N entries loaded)`).
    entries_loaded: usize,
}

impl KeydbResolution {
    // A true miss: the disc hash was not in the keydb at all.
    fn miss(entries_loaded: usize) -> Self {
        Self {
            keys: Vec::new(),
            matched: false,
            shape: None,
            miss_path: Vec::new(),
            entries_loaded,
        }
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

// Write `text` to `path` crash-safely (temp file, fsync, atomic rename) so an interrupted
// update never leaves a half-written keydb.
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
    // Resolve this disc's base per-CPS-unit Unit Keys from the keydb. A MISSING keydb yields no
    // keys (Ok(empty)); an UNUSABLE one is a source failure (Err) — never conflated.
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

    // De-conflated resolution (issue #46): besides the keys, report whether the
    // disc MATCHED, why nothing derived on a keyless match, and the matched
    // entry's shape to log — so a matched-no-key disc is not a mute "no entry".
    fn resolve_unit_keys(&self, ctx: &dyn ResolveCtx) -> Result<UnitKeyResolution, Error> {
        match self.cached_db() {
            Ok(db) => {
                let r = Self::resolve_from(&db, ctx);
                Ok(UnitKeyResolution {
                    keys: r.keys,
                    matched: r.matched,
                    miss_path: r.miss_path,
                    matched_entry: r.shape,
                    store_entries: Some(r.entries_loaded),
                })
            }
            Err(e) => match self.load_failure(&e) {
                // Missing keydb: the documented benign miss (nothing matched).
                None => Ok(UnitKeyResolution::default()),
                // Corrupt / unreadable keydb: a SOURCE FAILURE, not a miss.
                Some(err) => Err(err),
            },
        }
    }

    // The keydb's host certs, best first. `mkb` is ignored: cert selection takes no disc input.
    fn host_certs(&self, _mkb: Option<u32>) -> Vec<HostCert> {
        match self.cached_db() {
            Ok(db) => db.host_certs_ranked(),
            // Vec-returning trait method: log the failure, return nothing.
            Err(e) => {
                let _ = self.load_failure(&e);
                Vec::new()
            }
        }
    }

    // Keyed by disc hash, not by samples: asked once per resolve, not per
    // piece (KU §2.3 step 8, N-KU10; KSK1).
    fn answer_depends_on_samples(&self) -> bool {
        false
    }

    fn label(&self) -> &'static str {
        "keydb"
    }
}

#[cfg(test)]
#[path = "keydb_tests.rs"]
mod tests;
