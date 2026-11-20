//! `keydb.cfg` key source (source #1).
//!
//! Parses a local `keydb.cfg`, looks the disc up by hash, and derives the disc's terminal
//! **Unit Keys** by composing libfreemkv's raw `aacs::derive` primitives — never
//! re-implementing AES. The path mirrors the OLD candidate order EXACTLY, cheapest-first:
//! per-disc Unit Keys, then VUK, then a Media Key (stored / PK pool / DK pool) via
//! `derive_vuk`.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

use crate::uks_from_vuk;
use libfreemkv::aacs::derive::{derive_media_key_from_dk, derive_media_key_from_pk, derive_vuk};
use libfreemkv::aacs::trace::{KeyNode, MatchedEntry};
use libfreemkv::aacs::types::{DeviceKey, HostCert, MediaKey, UnitKey, Vid};
use libfreemkv::keysource::{ResolveCtx, UnitKeyResolution};
use libfreemkv::{Error, KeySource};

#[cfg(test)]
use crate::keydb_format::KeyDb;
use crate::keydb_format::{DiscEntry, rank_host_certs};
use crate::keydb_index::{KeydbIndex, Lookup};
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
/// observed, and the index built from it. The index keeps the parser's
/// rejection counts: [`KeydbSource::cached_index`] re-emits the summary on
/// every hit, because a cache hit skips the parse and with it the one warning
/// that a corrupt keydb is being served.
struct CacheEntry {
    stamp: FileStamp,
    /// Wall-clock time at which `stamp` was read off the open handle. The whole
    /// point of storing it is [`Self::is_settled`].
    stamped_at: std::time::SystemTime,
    index: Arc<KeydbIndex>,
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
///
/// The cache is an INDEX, not the parsed map: the global rows (device keys, processing keys,
/// host certs) plus, per disc row, its 20-byte hash and the byte offset of its line (~24 B a
/// row, ~4.3 MB for the 181k-row public keydb, against ~65 MB for a full [`crate::KeyDb`]). A
/// lookup binary-searches the hash and parses that one line from the file, with the same results
/// as [`crate::KeyDb::find_disc`] (a duplicated hash resolves to its last row). If the line no longer
/// holds the hash (the file changed under a stamp that looked unchanged), the index is rebuilt.
///
/// The cache lives behind an `Arc`, so a clone is cheap and SHARES it: every clone sees one
/// parse. [`KeydbSource::new`] makes a source with its own cache;
/// [`KeydbSource::shared`] hands out clones of one process-wide source per path, so a caller
/// that builds a fresh source per key acquisition still parses the file once.
#[derive(Clone)]
pub struct KeydbSource {
    inner: Arc<Inner>,
}

// The state every clone of one `KeydbSource` shares.
struct Inner {
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

impl Inner {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            cache: Mutex::new(None),
            parses: AtomicUsize::new(0),
            mtime_granularity: MTIME_GRANULARITY,
            warnings: AtomicUsize::new(0),
        }
    }

    fn invalidate(&self) {
        *self.cache.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

// The process-wide sources behind `KeydbSource::shared`, keyed by the path as given. Held
// strongly for the process lifetime: a later acquisition, after every earlier handle was
// dropped, must still find the parse.
static SHARED: LazyLock<Mutex<HashMap<PathBuf, Arc<Inner>>>> = LazyLock::new(Default::default);

// The shared source registered for `path`, if any. The registry lock is released on return,
// so callers never hold it while taking a cache lock.
fn shared_inner(path: &Path) -> Option<Arc<Inner>> {
    SHARED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(path)
        .cloned()
}

impl KeydbSource {
    /// A keydb source reading the given `keydb.cfg` path, with its OWN cache (clones of it
    /// share that cache; other sources do not). A long-lived process that builds sources
    /// repeatedly for lookups should use [`Self::shared`].
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            inner: Arc::new(Inner::new(path.into())),
        }
    }

    /// The process-wide keydb source for `path`: every call with the same path returns a
    /// clone of ONE source, so its parsed keydb survives the caller dropping each handle.
    ///
    /// The registry is keyed by the path exactly as given (no canonicalisation), so pass
    /// the same path every time; it holds each source for the process lifetime. The file
    /// is still re-checked on every lookup, so a replaced keydb is re-read exactly as with
    /// [`Self::new`], and [`Self::save`] / [`Self::update`] through ANY source for the same
    /// path also drop the shared cache.
    ///
    /// How the engine should call it: wherever it builds a keydb source for a lookup (the
    /// per-acquire key-source factory and the scan-time host-cert lookup), replace
    /// `Box::new(KeydbSource::new(path.clone()))` with
    /// `Box::new(KeydbSource::shared(path.clone()))`, and
    /// `KeydbSource::new(path).host_certs()` with `KeydbSource::shared(path).host_certs()`.
    /// Nothing else changes: the boxed handle is still dropped after each acquisition, only
    /// the cache behind it is kept. Writers (`save` / `update` from a settings or CLI
    /// updater) can keep using [`Self::new`].
    pub fn shared(path: impl Into<PathBuf>) -> Self {
        let mut registry = SHARED.lock().unwrap_or_else(|e| e.into_inner());
        let inner = registry
            .entry(path.into())
            .or_insert_with_key(|p| Arc::new(Inner::new(p.clone())))
            .clone();
        Self { inner }
    }

    // Log the parser's rejection summary and count the emission — the count
    // is the only way to assert, without a `tracing` dev-dependency, that the
    // corruption warning is NOT swallowed by the cache. See `cached_index`.
    fn emit_parse_stats(&self, stats: &crate::keydb_format::ParseStats) {
        if stats.log() {
            self.inner.warnings.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Corruption summaries emitted so far. Test-only observability, paired with
    /// [`Self::parse_count`]: a corrupt keydb must warn once per LOOKUP, while
    /// still parsing once.
    #[cfg(test)]
    fn warning_count(&self) -> usize {
        self.inner.warnings.load(Ordering::Relaxed)
    }

    /// Test-only: override the settle window (see the field's doc). Only on a fresh,
    /// unshared source: not one from [`Self::shared`], not one already cloned.
    #[cfg(test)]
    fn with_mtime_granularity(mut self, g: std::time::Duration) -> Self {
        Arc::get_mut(&mut self.inner)
            .expect("with_mtime_granularity needs a fresh, unshared source")
            .mtime_granularity = g;
        self
    }

    // The keydb index, from cache when unchanged (errors mirror KeyDb::load), plus the open
    // handle it describes. ONE OPEN, ONE IDENTITY: the stamp (fstat), the indexed bytes and the
    // row a lookup later reads all come from that one handle.
    fn cached_index(&self) -> std::io::Result<(Arc<KeydbIndex>, std::fs::File)> {
        let inner = &*self.inner;
        let file = std::fs::File::open(&inner.path)?;
        let stamp = FileStamp::of(&file.metadata()?);
        let stamped_at = std::time::SystemTime::now();
        // Fast path: a settled cache hit under a brief lock (stamp compare +
        // Arc clone). Re-emit the rejection summary on EVERY hit — a hit skips
        // the parse, else a corrupt keydb warns once then serves silently.
        {
            let guard = inner.cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = guard.as_ref()
                && entry.stamp == stamp
                && entry.is_settled(inner.mtime_granularity)
            {
                self.emit_parse_stats(&entry.index.stats);
                return Ok((entry.index.clone(), file));
            }
        }
        // Miss: index the ~62 MiB file OUTSIDE the lock so a rebuild can't stall
        // every other worker. Stamp (fstat) and bytes still come from the ONE
        // open handle, preserving the one-open-one-identity invariant.
        let index = Arc::new(KeydbIndex::build(&file, &inner.path)?);
        // Re-acquire and double-check: a peer may have installed the same
        // settled stamp while we parsed — adopt theirs and drop our redundant
        // parse rather than racing a lost update.
        let mut guard = inner.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = guard.as_ref()
            && entry.stamp == stamp
            && entry.is_settled(inner.mtime_granularity)
        {
            self.emit_parse_stats(&entry.index.stats);
            return Ok((entry.index.clone(), file));
        }
        self.emit_parse_stats(&index.stats);
        inner.parses.fetch_add(1, Ordering::Relaxed);
        *guard = Some(CacheEntry {
            stamp,
            stamped_at,
            index: index.clone(),
        });
        Ok((index, file))
    }

    // The disc row for `hash` (None on a miss) and the index it was found in. A row that no
    // longer holds the hash means the file changed under a stamp that looked unchanged: drop
    // that index and rebuild ONCE; a second mismatch (the file keeps changing) is a read error.
    fn lookup(&self, hash: &str) -> std::io::Result<(Arc<KeydbIndex>, Option<DiscEntry>)> {
        for _ in 0..2 {
            let (index, file) = self.cached_index()?;
            match index.find(&file, hash)? {
                Lookup::Found(entry) => return Ok((index, Some(entry))),
                Lookup::Missing => return Ok((index, None)),
                Lookup::Stale => self.drop_cached(&index),
            }
        }
        Err(std::io::Error::other(
            "keydb.cfg changed while a disc row was being read",
        ))
    }

    // Drop the cache if it still holds `stale` (a peer may already have replaced it).
    fn drop_cached(&self, stale: &Arc<KeydbIndex>) {
        let mut guard = self.inner.cache.lock().unwrap_or_else(|e| e.into_inner());
        if guard
            .as_ref()
            .is_some_and(|entry| Arc::ptr_eq(&entry.index, stale))
        {
            *guard = None;
        }
    }

    // Resolve `ctx` against the keydb file (see `resolve_entry`).
    fn resolve_indexed(&self, ctx: &dyn ResolveCtx) -> std::io::Result<KeydbResolution> {
        let (index, entry) = self.lookup(ctx.disc_hash())?;
        Ok(Self::resolve_entry(
            entry.as_ref(),
            index.entries(),
            &index.keys.processing_keys,
            &index.keys.device_keys,
            ctx,
        ))
    }

    /// Drop the cached parse, and the shared source's for the same path when that is a
    /// different source. Called after this source WRITES the file, so the next lookup
    /// through either re-reads it without depending on mtime resolution.
    fn invalidate_cache(&self) {
        self.inner.invalidate();
        if let Some(shared) = shared_inner(&self.inner.path)
            && !Arc::ptr_eq(&shared, &self.inner)
        {
            shared.invalidate();
        }
    }

    /// Cache misses so far — the number of real file reads + parses. Test-only
    /// observability for the cache (see [`Self::cached_index`]).
    #[cfg(test)]
    fn parse_count(&self) -> usize {
        self.inner.parses.load(Ordering::Relaxed)
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
                    path = %self.inner.path.display(),
                    "keydb.cfg is unusable (over the size cap or not valid UTF-8) — this is a corrupt or truncated keydb, NOT a disc without a key"
                );
                Some(Error::KeydbInvalid)
            }
            kind => {
                tracing::warn!(
                    target: "freemkv::keysource",
                    path = %self.inner.path.display(),
                    io_kind = ?kind,
                    "keydb.cfg could not be read — NOT a disc without a key"
                );
                Some(Error::KeydbLoad {
                    path: self.inner.path.display().to_string(),
                })
            }
        }
    }

    /// Validate, decompress (zip / gz / plain) and crash-safely persist raw keydb bytes to
    /// THIS source's own [`path`](Self::path), which the caller chose (CLI `--keydb`, the
    /// service path). The text must hold at least one recognisable keydb entry and is capped
    /// at [`MAX_KEYDB_BYTES`] (decompression-bomb guard); it is written by sibling temp,
    /// fsync, rename and parent-folder fsync. Existing sibling files are left alone,
    /// including old temporaries that may still belong to another writer.
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

        write_atomic(&self.inner.path, &text)?;
        // The file this source reads was just replaced; drop the parsed copy.
        self.invalidate_cache();

        Ok(UpdateResult {
            path: self.inner.path.clone(),
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
    /// Best first ([`crate::KeyDb::host_certs_ranked`]): this is what the scan-options
    /// builder hands the live-drive handshake as `DriveCredentials`.
    pub fn host_certs(&self) -> Vec<HostCert> {
        match self.cached_index() {
            Ok((index, _)) => rank_host_certs(&index.keys.host_certs),
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
    #[cfg(test)]
    fn unit_keys_from(db: &KeyDb, ctx: &dyn ResolveCtx) -> Vec<UnitKey> {
        Self::resolve_from(db, ctx).keys
    }

    // `resolve_entry` over a whole parsed `KeyDb` (the unit tests' seam).
    #[cfg(test)]
    fn resolve_from(db: &KeyDb, ctx: &dyn ResolveCtx) -> KeydbResolution {
        Self::resolve_entry(
            db.find_disc(ctx.disc_hash()),
            db.disc_entries.len(),
            &db.processing_keys,
            &db.device_keys,
            ctx,
        )
    }

    // De-conflated resolution: the keys PLUS whether the disc matched and — on a
    // keyless match — WHY nothing derived, so a matched-but-underivable disc is
    // never reported as a flat "no entry" (issue #46). Pure (no I/O): `entry` is the
    // disc's row (already looked up), `entries_loaded` the keydb's disc-entry count,
    // and the PK/DK pools the keydb's global keys.
    fn resolve_entry(
        entry: Option<&DiscEntry>,
        entries_loaded: usize,
        processing_keys: &[[u8; 16]],
        device_keys: &[DeviceKey],
        ctx: &dyn ResolveCtx,
    ) -> KeydbResolution {
        // Per-disc hit (most specific); the lookup normalized the hash form. Without a match
        // there is no per-disc anchor, so the global PK/DK pools are never consulted.
        let Some(entry) = entry else {
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
                    .or_else(|| derive_media_key_from_pk(mkb, processing_keys).map(MediaKey))
                    // DK pool: the real Subset-Difference MKB walk. No VID at the MK
                    // step (it enters at the VUK step below); the VID guard follows.
                    .or_else(|| derive_media_key_from_dk(mkb, device_keys).map(MediaKey));
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
        if file
            .name()
            .is_ok_and(|n| n.ends_with(".cfg") || n.ends_with(".CFG"))
        {
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
    use std::sync::atomic::{AtomicU64, Ordering};
    static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);
    // Pid alone repeats across restarts (fixed PID 1 in containers) and the
    // counter restarts at 0, so add the wall-clock nanos to make names unique
    // across processes and restarts.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    write_atomic_named(path, text, &mut || {
        let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        temp_path(path, std::process::id(), nanos, n)
    })
}

const TEMP_ATTEMPTS: usize = 16;

fn temp_path(path: &Path, pid: u32, nanos: u128, n: u64) -> PathBuf {
    path.with_extension(format!("tmp.{pid}.{nanos}.{n}"))
}

// Directory holding `path`; a bare relative name has an empty parent => ".".
fn temp_dir_of(path: &Path) -> &Path {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

// Try up to TEMP_ATTEMPTS candidate names; a name that exists (stale file,
// symlink, or a racing writer) just moves us to the next candidate.
fn write_atomic_named(
    path: &Path,
    text: &str,
    next_name: &mut dyn FnMut() -> PathBuf,
) -> Result<(), Error> {
    for _ in 0..TEMP_ATTEMPTS {
        let tmp = next_name();
        match open_temp(&tmp) {
            Ok(f) => return write_atomic_finish(path, text, &tmp, f),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                tracing::warn!(error = %e, path = %path.display(), "keydb temp create failed; keydb unchanged");
                return Err(Error::KeydbWrite {
                    path: path.display().to_string(),
                });
            }
        }
    }
    tracing::warn!(path = %path.display(), "keydb temp names exhausted; keydb unchanged");
    Err(Error::KeydbWrite {
        path: path.display().to_string(),
    })
}

// Exclusive creation also rejects stale files and symlinks; a collision never
// grants ownership.
fn open_temp(tmp: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(tmp)
}

#[cfg(test)]
fn write_atomic_with_temp(path: &Path, text: &str, tmp: &Path) -> Result<(), Error> {
    let f = open_temp(tmp).map_err(|_| Error::KeydbWrite {
        path: path.display().to_string(),
    })?;
    write_atomic_finish(path, text, tmp, f)
}

fn write_atomic_finish(
    path: &Path,
    text: &str,
    tmp: &Path,
    mut f: std::fs::File,
) -> Result<(), Error> {
    let werr = || Error::KeydbWrite {
        path: path.display().to_string(),
    };
    let write_result = (|| -> std::io::Result<()> {
        f.write_all(text.as_bytes())?;
        libfreemkv::io::durable_sync_file(&f, None, &mut |_, _| {})?;
        Ok(())
    })();
    drop(f);
    if let Err(e) = write_result {
        let _ = std::fs::remove_file(tmp);
        tracing::warn!(error = %e, path = %path.display(), "keydb write/fsync failed; keydb unchanged");
        return Err(werr());
    }
    if let Err(e) = std::fs::rename(tmp, path) {
        let _ = std::fs::remove_file(tmp);
        tracing::warn!(error = %e, path = %path.display(), "keydb rename failed; keydb unchanged");
        return Err(werr());
    }
    // Durably commit the new dirent (ext2, some NFS can lose it after a crash); best-effort,
    // no-op on Windows. `temp_dir_of`, not `parent()`: a bare relative name has parent "".
    libfreemkv::io::fsync::dir(temp_dir_of(path));
    Ok(())
}

impl KeySource for KeydbSource {
    // Resolve this disc's base per-CPS-unit Unit Keys from the keydb. A MISSING keydb yields no
    // keys (Ok(empty)); an UNUSABLE one is a source failure (Err) — never conflated.
    fn get_unit_keys(&self, ctx: &dyn ResolveCtx) -> Result<Vec<UnitKey>, Error> {
        match self.resolve_indexed(ctx) {
            Ok(r) => Ok(r.keys),
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
        match self.resolve_indexed(ctx) {
            Ok(r) => Ok(UnitKeyResolution {
                keys: r.keys,
                matched: r.matched,
                miss_path: r.miss_path,
                matched_entry: r.shape,
                store_entries: Some(r.entries_loaded),
            }),
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
        match self.cached_index() {
            Ok((index, _)) => rank_host_certs(&index.keys.host_certs),
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
