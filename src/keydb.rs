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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::uks_from_vuk;
use libfreemkv::aacs::derive::{derive_media_key_from_dk, derive_media_key_from_pk, derive_vuk};
use libfreemkv::aacs::types::{HostCert, MediaKey, UnitKey, Vid};
use libfreemkv::keysource::ResolveCtx;
use libfreemkv::{Error, KeySource};

use crate::keydb_format::KeyDb;

/// Upper bound on decompressed keydb size. The published keydb is a few MiB;
/// 128 MiB is a generous ceiling that still caps a decompression bomb (a tiny
/// zip/gz can otherwise inflate to GiB and OOM the daily refresh thread). The
/// public UHD keydb is ~62 MiB and growing, so 64 MiB was getting tight;
/// 128 MiB leaves years of headroom.
const MAX_KEYDB_BYTES: u64 = 128 * 1024 * 1024;

/// Result of a KEYDB save/update -- path written, entry count, and byte size.
#[derive(Debug)]
pub struct UpdateResult {
    pub path: PathBuf,
    pub entries: usize,
    pub bytes: usize,
}

/// Widest observed granularity of a filesystem's stored mtime. HFS+, many
/// container overlay filesystems and most network filesystems record whole
/// seconds; 2 s leaves room for that plus rounding. Used by
/// [`CacheEntry::is_settled`] — see the argument there.
const MTIME_GRANULARITY: std::time::Duration = std::time::Duration::from_secs(2);

/// The identity of the keydb file a cache entry was parsed from.
///
/// `(len, modified)` ALONE IS NOT AN IDENTITY. mtime is stored at whole-second
/// resolution on HFS+, on many container overlays and on most network
/// filesystems, so a writer that replaces `keydb.cfg` within the same second
/// with a file of the same byte length leaves `(len, modified)` bit-identical —
/// and the cache then serves the superseded parse for the rest of the process's
/// life. For a key database that is not a stale page: it is serving retired or
/// since-corrected keys while reporting success. The writers that hit this are
/// real and named in this crate's own docs: the daily-refresh job, a second
/// freemkv process, an operator's editor, a sync tool.
///
/// Two independent discriminators close it:
///
/// 1. `dev` + `ino`. Every writer that publishes ATOMICALLY (temp file, fsync,
///    rename — what [`KeydbSource::save`] does, and what any correct publisher
///    does) creates a NEW inode, so the stamp differs immediately and
///    unconditionally, whatever the clock or the mtime resolution did. Zero on
///    platforms without them (see [`Self::of`]), which costs nothing: rule 2
///    stands alone.
/// 2. A freshness rule on the cache entry — [`CacheEntry::is_settled`] — which
///    covers the residual in-place rewrite that reuses the inode.
///
/// What this still does NOT catch: a writer that FORGES the timestamp, i.e.
/// restores an mtime equal to the cached one (`touch -t`, `rsync --times`, a
/// tar/backup restore) into the SAME inode with the SAME length. Nothing short
/// of hashing the content can see that, and hashing 62 MiB per lookup is
/// precisely the cost the cache exists to remove (~141 ms × ≥3 loads per rip).
/// [`KeydbSource::save`] therefore keeps invalidating the cache directly, so the
/// one write path this crate owns never depends on any of the above.
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
        // dev/ino are a Unix concept. Windows has a rough equivalent
        // (volume serial + file index) but exposes it only through
        // `MetadataExt` methods that are documented as unreliable on some
        // filesystems; rule 2 alone is correct there, so the cross-platform
        // fallback is simply "no inode discriminator" rather than a shaky one.
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
    /// Whether this entry's stamp can be TRUSTED to change if the file changes.
    ///
    /// The proof, for a filesystem storing mtime at granularity `G`: suppose
    /// this entry was stamped at `stamped_at` with `stamped_at - modified >= G`,
    /// and some writer later rewrites the file in place at wall time
    /// `T > stamped_at`. The recorded mtime `m'` of that write is within one
    /// granule of `T`, so `m' >= T - G > stamped_at - G >= modified`. Hence
    /// `m' != modified` and the stamp DOES change. The ambiguous window is
    /// therefore exactly the one where the cached entry was stamped less than
    /// `G` after the file's own mtime — i.e. we looked at the file while it was
    /// still "hot" — and in that window the entry is refused and the file is
    /// re-read. Once the file has been quiet for `G`, its entry settles and the
    /// cache is fully effective again.
    ///
    /// Cost: after every keydb write, lookups re-parse for up to `G` (2 s).
    /// The published keydb is rewritten daily, so that is ~2 s of re-parsing per
    /// day against a cache that saves ~420 ms per rip.
    ///
    /// `modified: None` (a filesystem that reports no mtime) never settles: the
    /// only two discriminators left would be size and inode, so the entry is
    /// re-read every time rather than being trusted on a weaker basis.
    ///
    /// CLOCK CAVEAT: `stamped_at` is the local clock and `modified` is the
    /// filesystem's. On a network share whose server clock runs AHEAD of the
    /// client's by more than `G`, entries never settle (safe: more re-parsing).
    /// A server clock BEHIND the client's makes an entry settle early, which
    /// re-opens the same-second window it closes — the inode rule (1) is what
    /// covers the realistic writers there.
    fn is_settled(&self, granularity: std::time::Duration) -> bool {
        self.stamp
            .modified
            .and_then(|m| self.stamped_at.duration_since(m).ok())
            .is_some_and(|age| age >= granularity)
    }
}

/// A [`KeySource`] backed by a local `keydb.cfg` file.
///
/// The parsed database is CACHED behind the file's identity stamp. The
/// published keydb is ~62 MiB / ~181k entries and a single AACS-cert rip parses
/// it repeatedly — `host_certs()` for the drive handshake (freemkv's
/// `pipe.rs`/`engine.rs`, autorip's `keysource.rs` each build their own source),
/// then the trait `host_certs(mkb)` during resolution, then `get_unit_keys` —
/// and every one of those calls used to re-read all 62 MiB from disk and re-parse
/// it from scratch, because the struct held nothing but a `PathBuf`.
///
/// A keydb replaced underneath this source is picked up on the next call, with
/// ONE stated exception: a writer that rewrites the file in place, into the same
/// inode, at the same byte length, having restored the previous mtime exactly
/// (`touch -t` / `rsync --times` / a backup restore). Everything else — any
/// atomic rename, any length change, any real clock advance — changes the stamp.
/// [`FileStamp`] and [`CacheEntry::is_settled`] carry the full argument and the
/// clock caveats; do not weaken either without re-reading them. (The earlier
/// wording here — "an externally replaced keydb is still picked up" —
/// was simply false for a same-second, same-length replacement, which is the
/// common shape of a daily-refresh job on a whole-second-mtime filesystem.)
///
/// MEMORY RESIDENCY (accepted, and deliberately recorded rather than fixed
/// here): a hit keeps the entire parsed keydb — every disc's Media Key / VID /
/// VUK / Unit Keys, the processing- and device-key pools, and the host-cert
/// PRIVATE keys — resident for the process's life, where the pre-cache code held
/// one parse transiently. Nothing in this crate zeroizes on drop, so that
/// material was always exposed to a core dump or a swapped page; the cache
/// widens the WINDOW, it does not create the class. Closing it properly means
/// zeroize-on-drop across `KeyDb`, `DiscEntry` and libfreemkv's `aacs::types`
/// (which owns most of the buffers) — a cross-crate change, tracked separately,
/// NOT smuggled in behind a cache fix.
pub struct KeydbSource {
    path: PathBuf,
    /// `Mutex` (not `RwLock`): the guarded section is a stamp comparison plus an
    /// `Arc` clone, so there is nothing for concurrent readers to win. Poisoning
    /// is recovered from rather than propagated — a panic elsewhere must not
    /// turn every later key lookup into a panic.
    cache: Mutex<Option<CacheEntry>>,
    /// How many times the file was actually read + parsed (cache MISSES). The
    /// only honest way to assert the cache from a test: timing is flaky and the
    /// parsed value is identical either way. Cheap enough to keep in release.
    parses: AtomicUsize,
    /// The `G` of [`CacheEntry::is_settled`]. A field, not the constant inlined,
    /// so the two discriminators can be tested ONE AT A TIME: with `G` at zero
    /// every entry settles, which isolates the inode/len rule; with `G` enormous
    /// nothing settles, which isolates the freshness rule. Testing them together
    /// is how a stale-cache test ends up passing whether or not the fix is
    /// present — on APFS (nanosecond mtimes) the naive same-second scenario is
    /// simply not reproducible, so a test that "reproduces" it there is
    /// asserting nothing.
    mtime_granularity: std::time::Duration,
    /// How many corruption summaries were emitted (see
    /// [`KeydbSource::emit_parse_stats`]). Same rationale as `parses`: the
    /// alternative instrument is a `tracing` subscriber in dev-dependencies.
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

    /// Log the parser's rejection summary and count the emission.
    ///
    /// The count is the only way to assert, without pulling a `tracing`
    /// subscriber into dev-dependencies, that the corruption warning is NOT
    /// swallowed by the cache. See [`Self::cached_db`].
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

    /// The parsed keydb, from cache when the file is provably unchanged.
    ///
    /// Errors are the same ones [`KeyDb::load`] produces, unchanged: a missing
    /// file is `NotFound` (the documented benign case), an over-cap or non-UTF-8
    /// file is `InvalidData`. The stamp costs an `fstat`, not a 62 MiB read.
    ///
    /// ONE OPEN, ONE IDENTITY. The file is opened once and both the stamp
    /// (`fstat` on that handle) and, on a miss, the bytes come from it. The
    /// previous shape — `std::fs::metadata(path)` and then a separate
    /// `KeyDb::load(path)` — resolved the path TWICE with no atomicity between
    /// them, so a rename landing in the gap cached the new file's stamp beside
    /// the old file's contents (or the reverse); the pairing was then served,
    /// looking perfectly valid, until the stamp changed again. The stamp is read
    /// BEFORE the bytes on purpose: a write racing the read then leaves the OLD
    /// stamp cached, which the next call detects, whereas stamping afterwards
    /// would file torn content under a fresh-looking identity and pin it.
    fn cached_db(&self) -> std::io::Result<Arc<KeyDb>> {
        let file = std::fs::File::open(&self.path)?;
        let stamp = FileStamp::of(&file.metadata()?);
        let stamped_at = std::time::SystemTime::now();
        let mut guard = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = guard.as_ref()
            && entry.stamp == stamp
            && entry.is_settled(self.mtime_granularity)
        {
            // Re-emit the parser's rejection summary on EVERY hit, not just on
            // the parse that produced it. `KeyDb::parse` is what logs it, and a
            // hit skips `parse` entirely — so a daemon that cached a corrupt
            // keydb logged its rejected-row counts exactly once, at whatever
            // moment it first read the file, and then served that same damaged
            // database to every later rip in silence. Repetition is the correct
            // failure mode here: the line is emitted only when the file really
            // does have rejected or duplicate rows, and a warning an operator
            // can still see on the tenth rip is worth more than one they had to
            // catch on the first.
            self.emit_parse_stats(&entry.stats);
            return Ok(entry.db.clone());
        }
        let (db, stats) = KeyDb::load_counted(file, &self.path)?;
        self.emit_parse_stats(&stats);
        let db = Arc::new(db);
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

    /// Turn a [`KeyDb::load`] failure into this source's verdict.
    ///
    /// A MISSING keydb is the documented benign case: the app may simply not
    /// have one, another source may hold the key, and "no keydb" is genuinely
    /// "no key here". Everything else is NOT that: `InvalidData` is a keydb over
    /// the 128 MiB cap or one that is not valid UTF-8 — i.e. corrupt, truncated,
    /// or a half-finished download — and a permission/IO failure means the file
    /// could not be read at all. Reporting either as an empty result made a
    /// broken keydb indistinguishable from "this disc has no key" (the same
    /// conflation as the seven-hour 502), with no log to notice it by. Both are
    /// now logged AND surfaced as errors so the resolver reports a source
    /// failure instead of `E7022`.
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
                // Mirror KeyDb::parse's disc-entry rule EXACTLY by CALLING it
                // (`is_disc_entry_line`), so save() never validates + persists
                // content that parses to zero usable entries (e.g. a stray
                // "0xDEADBEEF" comment line) and the two can no longer drift —
                // they did drift once already, on the `0X` case rule.
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
    /// Resolve this disc's base per-CPS-unit Unit Keys from the keydb.
    ///
    /// A MISSING keydb is not an error — it simply yields no keys (another
    /// source may have them), the same as the library's own loader. A keydb that
    /// exists but cannot be USED (over the size cap, not UTF-8, unreadable) is a
    /// source failure and returns `Err`: it says nothing about whether this disc
    /// has a key, and reporting it as an empty result is the same
    /// looks-like-success failure as a 502 reported as `E7022`.
    ///
    /// The keydb carries no AACS 2.1 forensic index keys today, so it does not
    /// override `get_fmts_indexes` — the default (empty) opts it out, and an FMTS
    /// disc's forensic set comes from the online source.
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

    /// Expose the keydb's host certs through the trait — the OEM/AACS cert-auth
    /// route collects them across every source via this method. Wires the disc's
    /// MKB generation through for revocation filtering (the keydb parser's
    /// `; Revoked in MKBv<N>` annotation): a cert revoked at generation `R` is
    /// withheld once the disc's generation reaches `R`.
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

    /// Force a file's mtime to [`PINNED_MTIME`], so two different files can be
    /// made bit-identical to a `(len, mtime)` stamp on purpose. The cache tests
    /// that matter all depend on FORCING the indistinguishable case rather than
    /// hoping the filesystem produces it: on APFS (nanosecond mtimes) a
    /// same-second replacement is otherwise detected by mtime alone, and a test
    /// that relies on that passes with the fix reverted — which is worth nothing.
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

    /// `MockCtx` implements the full `ResolveCtx` trait so it can stand in for
    /// a real disc, but `KeydbSource` itself never calls `title()`/`samples()`
    /// (those matter to the online source, not the local keydb). Exercise
    /// them directly so the mock's trait surface is proven correct too.
    #[test]
    fn mock_ctx_title_and_samples_are_stubbed_correctly() {
        let c = ctx(HASH, Vec::new(), None);
        assert_eq!(c.title(), None);
        assert_eq!(c.samples(4).unwrap(), Vec::<Vec<u8>>::new());
    }

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

    // ── Caching: the 62 MiB / 181k-entry keydb is parsed ONCE ────────────────

    /// A single AACS-cert rip drives this source at least three times — the
    /// scan-options builder's inherent `host_certs()`, the trait
    /// `host_certs(mkb)` during the handshake, then `get_unit_keys` — and each
    /// call used to re-read and re-parse the WHOLE file, because `KeydbSource`
    /// held nothing but a `PathBuf`. Measured on the real 62 MiB / 184,860-entry
    /// keydb: ~140 ms per parse in `--release`, i.e. ~420 ms and ~186 MiB of
    /// file reads per rip, against ~1 µs for a cache hit.
    ///
    /// Catches the mutation that drops the cache (every call re-parses: count 3)
    /// and the mutation that makes the cache unconditional (see the
    /// invalidation tests below).
    ///
    /// The mtime is pinned into the PAST first, because a cache entry is only
    /// trusted once the file has been quiet for the mtime granularity
    /// ([`CacheEntry::is_settled`]) — a keydb written microseconds ago is
    /// deliberately re-read. Unix-only: pinning an mtime needs `touch -t` (no
    /// `filetime` dependency for a test).
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

    /// The cache must not go stale: a keydb replaced UNDERNEATH the source (the
    /// daily-refresh thread writing through a different `KeydbSource`, or an
    /// operator dropping in a new file) has a different size/mtime stamp and
    /// must be re-read. Catches the mutation that caches on first load and never
    /// re-stats — which would pin a rip to a keydb deleted hours earlier.
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

    // ── The two stale-cache discriminators, tested ONE AT A TIME ────────────
    //
    // The defect both of these pin: `(len, mtime)` is not a file identity. An
    // external writer — the daily-refresh job, a second freemkv process, an
    // editor, a sync tool — that replaces `keydb.cfg` inside one mtime granule
    // with a file of the SAME length leaves that pair bit-identical, and the
    // source then serves the superseded parse for the rest of the process's
    // life: retired or since-corrected keys, reported as success.
    //
    // Each test disables the OTHER discriminator through `mtime_granularity`, so
    // neither can pass on the strength of the one it is not testing, and neither
    // depends on the host filesystem's real mtime resolution (on APFS the naive
    // scenario is not reproducible at all).

    /// Discriminator 1, the inode: a keydb replaced by ATOMIC RENAME — how
    /// every correct publisher, including this crate's own `save()`, installs a
    /// new file — must be re-read even when length and mtime are identical.
    /// `mtime_granularity: 0` makes every entry settle, so ONLY dev+ino can
    /// distinguish the two files here.
    ///
    /// Catches the mutation that drops `dev`/`ino` from `FileStamp` (the
    /// original `(len, modified)` stamp): the source then keeps answering with
    /// the previous keydb's keys.
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

    /// Discriminator 2, the settle window: a keydb rewritten IN PLACE — same
    /// inode, same length, mtime forced back to the same value — must still be
    /// re-read while the cached entry is too young to trust. `mtime_granularity`
    /// is set to a decade so nothing ever settles, which is the same condition a
    /// real same-second, whole-second-mtime replacement creates and the only way
    /// to reproduce it deterministically on a nanosecond-mtime filesystem.
    ///
    /// Catches the mutation that deletes the `is_settled` check from
    /// `cached_db` (every stamp match trusted unconditionally, which is what the
    /// original code did): dev, ino, len and mtime are ALL identical here, so
    /// without the freshness rule the source serves the old keys forever.
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

    /// A corrupt-but-parseable keydb must keep saying so. `ParseStats::log` runs
    /// inside `KeyDb::parse`, and a cache hit skips `parse` — so once the cache
    /// landed, the rejected-row summary for a given file was emitted exactly
    /// ONCE for the entire life of the process, while that same damaged file
    /// went on being served to every subsequent rip. A long-running daemon
    /// (autorip) logs it at startup, the operator misses it in the startup noise
    /// or loses it to log rotation, and there is no second chance for as long as
    /// the process runs.
    ///
    /// Catches the mutation that deletes the `emit_parse_stats` call from the
    /// cache-HIT arm of `cached_db`: warnings would drop to 1 while the file is
    /// still served three times.
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

    /// A HEALTHY keydb must stay silent — the re-emission above must not turn
    /// into a per-lookup log line for every operator with an intact file.
    ///
    /// Catches the mutation that makes `emit_parse_stats` unconditional (drops
    /// `ParseStats::log`'s empty-counts early return).
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

    /// The cost side of the settle rule, asserted so it is a decision and not an
    /// accident: a keydb written just now is re-read on every lookup until it
    /// has been quiet for the granularity. That is the price of never serving a
    /// same-second replacement, and it is bounded — 2 s after each write of a
    /// file that is rewritten daily.
    ///
    /// Catches the mutation that widens the window to something unbounded (a
    /// granularity of hours would re-parse 62 MiB on every lookup all day) by
    /// pairing with `repeated_lookups_parse_the_keydb_once`, which proves the
    /// entry DOES settle once the mtime is in the past.
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

    /// `save()` replaces the very file this source reads, so it drops the cached
    /// parse ITSELF rather than trusting the (size, mtime) stamp: a same-size
    /// rewrite that lands inside the filesystem's timestamp granularity is the
    /// one change the stamp cannot see — and it is exactly the change this crate
    /// performs (the daily-refresh thread re-saving a keydb through the source
    /// it then reads from).
    ///
    /// The test forces that indistinguishable case rather than hoping for it:
    /// the file is written, stamped to a FIXED mtime, cached, re-saved with
    /// different keys of the SAME length, and stamped back to the same mtime. To
    /// the stamp the two files are identical, so only the explicit invalidation
    /// can produce the new key. Unix-only because pinning an mtime needs
    /// `touch -t` (no `filetime` dependency for one test).
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

    // ── A corrupt keydb is a source FAILURE, not "this disc has no key" ──────

    /// `KeyDb::load` fails distinguishably for a keydb that is over the 128 MiB
    /// cap or not valid UTF-8 — a truncated download, a half-written file, a
    /// binary blob dropped in by mistake. Both used to collapse into
    /// `Ok(Vec::new())` with ZERO tracing, i.e. into the benign "no key for this
    /// disc" the resolver reports as `E7022` — the same looks-like-success
    /// failure as the seven-hour 502. Only a MISSING file is genuinely benign.
    ///
    /// Catches the mutation that restores `Err(_) => Ok(Vec::new())`.
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

    /// A keydb.cfg that is over the size cap or not valid UTF-8
    /// (`std::io::ErrorKind::InvalidData`) must surface as a SOURCE FAILURE
    /// (`Error::KeydbInvalid`), never as a silent empty result — a corrupt
    /// keydb is not the same thing as "this disc has no key".
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

    /// `extract_zip` on a WELL-FORMED zip that carries no `*.cfg`/`*.CFG`
    /// member must fall through the whole member loop and return
    /// `Error::KeydbInvalid` — never a parse error, and never silently pick a
    /// non-keydb member.
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

    /// `write_atomic` when the temp file cannot be CREATED (permission
    /// denied on an existing, unwritable parent directory) must clean up and
    /// surface `Error::KeydbWrite`, distinct from the create_dir_all failure
    /// already pinned by `write_atomic_failure_preserves_prior_keydb`.
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
