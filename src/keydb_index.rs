//! A low-RAM index over a `keydb.cfg` file, for [`crate::KeydbSource`].
//!
//! [`KeyDb::parse`] builds a map of every disc row (~181k entries, ~60-70 MB resident). A
//! lookup needs ONE row, so this index keeps only what every lookup needs: the global rows
//! (device keys, processing keys, host certs; a few hundred), and per disc row its binary hash
//! plus the byte offset of its line. A lookup binary-searches the hash, then reads and parses
//! that one line with [`KeyDb::parse_disc_entry`]. ~24 B per row, ~4.3 MB for the real keydb.
//!
//! Parity with [`KeyDb`] is the contract: the same lines are accepted and rejected (one shared
//! dispatch, [`dispatch_line`], and one shared hash check, [`disc_row_hash`]), a duplicated
//! hash resolves to its LAST row, the parse statistics match, and queries are normalised
//! exactly like [`KeyDb::find_disc`].

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use crate::keydb_format::{
    DiscEntry, GlobalKeys, KeyDb, MAX_KEYDB_BYTES, ParseStats, disc_row_hash, dispatch_line,
    not_utf8_error, over_cap_error,
};

// Line offsets are stored as `u32`: every offset is below the load cap.
const _: () = assert!(MAX_KEYDB_BYTES < u32::MAX as u64);

/// Length, in hex digits, of a real AACS disc hash (SHA-1, 20 bytes).
const HASH_DIGITS: usize = 40;

/// The parsed global rows plus a hash -> line-offset index of the disc rows.
#[derive(Default)]
pub(crate) struct KeydbIndex {
    /// Device keys, processing keys and host certs, parsed exactly as [`KeyDb`] parses them.
    pub(crate) keys: GlobalKeys,
    /// One `(binary hash, line offset)` per distinct 40-digit hash, sorted by hash. A hash
    /// on several rows keeps its LAST row, as `KeyDb`'s map insert does.
    rows: Vec<([u8; 20], u32)>,
    /// Valid disc rows whose hash is not exactly 40 hex digits (the parser accepts any
    /// non-empty digit count), keyed by the stored lowercase `0x…` form. Normally empty.
    odd_rows: HashMap<Box<str>, u32>,
    /// The parse statistics `KeyDb::parse_counted` reports for the same text.
    pub(crate) stats: ParseStats,
}

/// What a lookup found.
pub(crate) enum Lookup {
    /// The disc's row.
    Found(DiscEntry),
    /// No row for the hash.
    Missing,
    /// The indexed line no longer holds that hash: the file changed after indexing.
    Stale,
}

/// Decode exactly 40 hex digits (either case) into a 20-byte hash.
fn hash20(digits: &[u8]) -> Option<[u8; 20]> {
    if digits.len() != HASH_DIGITS {
        return None;
    }
    let nibble = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    let mut out = [0u8; 20];
    for (slot, pair) in out.iter_mut().zip(digits.as_chunks::<2>().0) {
        *slot = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(out)
}

/// One raw line as `str::lines` yields it: without its `\n` / `\r\n` ending, and on the
/// file's first line without a UTF-8 BOM (which `KeyDb::parse_counted` strips from the
/// whole text, i.e. from line 1 only).
fn line_text(raw: &str, first_line: bool) -> &str {
    let line = raw.strip_suffix('\n').unwrap_or(raw);
    let line = line.strip_suffix('\r').unwrap_or(line);
    if first_line {
        line.strip_prefix('\u{feff}').unwrap_or(line)
    } else {
        line
    }
}

impl KeydbIndex {
    /// Index the keydb read from `file` (from its current position, normally the start).
    ///
    /// Errors match [`KeyDb::load`] for the same bytes: the read is capped at
    /// [`MAX_KEYDB_BYTES`] (over the cap -> `InvalidData`, checked first), and any non-UTF-8
    /// content -> `InvalidData`. The file is streamed line by line; checking each line's
    /// UTF-8 is the same as checking the whole file's, since `\n` never occurs inside a
    /// multi-byte sequence.
    pub(crate) fn build(file: &File, path: &Path) -> std::io::Result<Self> {
        let mut reader =
            BufReader::with_capacity(256 * 1024, Read::take(file, MAX_KEYDB_BYTES + 1));
        let mut keys = GlobalKeys::default();
        let mut stats = ParseStats::default();
        let mut rows: Vec<([u8; 20], u32)> = Vec::new();
        let mut odd_rows: HashMap<Box<str>, u32> = HashMap::new();
        let mut buf = Vec::new();
        let mut offset: u64 = 0;
        let mut utf8_ok = true;
        loop {
            buf.clear();
            let n = reader.read_until(b'\n', &mut buf)?;
            if n == 0 {
                break;
            }
            let start = offset;
            offset += n as u64;
            // After a UTF-8 failure keep reading only to apply the size cap first,
            // the order `KeyDb::load_counted` reports them in.
            if !utf8_ok {
                continue;
            }
            let Ok(raw) = std::str::from_utf8(&buf) else {
                utf8_ok = false;
                continue;
            };
            let Some(line) = dispatch_line(line_text(raw, start == 0), &mut keys, &mut stats)
            else {
                continue;
            };
            let Some(hash) = disc_row_hash(line) else {
                stats.disc_rejected += 1;
                continue;
            };
            // `start` is below the cap (asserted above), so it fits in a u32.
            let at = start as u32;
            // `disc_row_hash` guarantees `0x`/`0X` + ASCII hex digits.
            let digits = &hash.as_bytes()[2..];
            match hash20(digits) {
                Some(h) => rows.push((h, at)),
                None => {
                    if odd_rows
                        .insert(hash.to_ascii_lowercase().into_boxed_str(), at)
                        .is_some()
                    {
                        stats.disc_duplicate += 1;
                    }
                }
            }
        }
        if offset > MAX_KEYDB_BYTES {
            return Err(over_cap_error(path));
        }
        if !utf8_ok {
            return Err(not_utf8_error(path));
        }

        // Sort by (hash, offset), then keep each hash's LAST row: the retained element
        // takes the offset of every later duplicate folded into it.
        rows.sort_unstable();
        let before = rows.len();
        rows.dedup_by(|later, kept| {
            if later.0 == kept.0 {
                kept.1 = later.1;
                true
            } else {
                false
            }
        });
        stats.disc_duplicate += before - rows.len();
        rows.shrink_to_fit();
        odd_rows.shrink_to_fit();

        Ok(Self {
            keys,
            rows,
            odd_rows,
            stats,
        })
    }

    /// Distinct disc entries: `KeyDb::disc_entries.len()` for the same text.
    pub(crate) fn entries(&self) -> usize {
        self.rows.len() + self.odd_rows.len()
    }

    /// The line offset of `query`'s row, plus the stored hash form it must parse back to.
    /// Normalised exactly like [`KeyDb::find_disc`]: trim, lowercase, strip every leading
    /// `0x`, then match `0x` + the rest. (`find_disc`'s no-prefix fallback can never match:
    /// every stored hash starts with `0x` and the stripped query never does.)
    fn offset_of(&self, query: &str) -> (Option<u32>, String) {
        let lower = query.trim().to_lowercase();
        let hash = lower.trim_start_matches("0x");
        let key = format!("0x{hash}");
        let offset = match hash20(hash.as_bytes()) {
            Some(h) => self
                .rows
                .binary_search_by(|row| row.0.cmp(&h))
                .ok()
                .map(|i| self.rows[i].1),
            None => self.odd_rows.get(key.as_str()).copied(),
        };
        (offset, key)
    }

    /// Look `query` up, reading its one row from `file`: the handle whose stamp matched
    /// this index. A row that no longer parses to the queried hash reports [`Lookup::Stale`].
    pub(crate) fn find(&self, file: &File, query: &str) -> std::io::Result<Lookup> {
        let (Some(offset), key) = self.offset_of(query) else {
            return Ok(Lookup::Missing);
        };
        Ok(match read_entry(file, offset)? {
            Some(entry) if *entry.disc_hash == *key => Lookup::Found(entry),
            _ => Lookup::Stale,
        })
    }
}

/// Read and parse the one disc row whose line starts at `offset`. `None` when that line is
/// not valid UTF-8 or not a disc row: the file changed after it was indexed.
fn read_entry(file: &File, offset: u32) -> std::io::Result<Option<DiscEntry>> {
    let mut handle = file;
    handle.seek(SeekFrom::Start(u64::from(offset)))?;
    let mut reader = BufReader::new(Read::take(handle, MAX_KEYDB_BYTES + 1));
    let mut buf = Vec::new();
    reader.read_until(b'\n', &mut buf)?;
    let Ok(raw) = std::str::from_utf8(&buf) else {
        return Ok(None);
    };
    Ok(KeyDb::parse_disc_entry(line_text(raw, offset == 0).trim()))
}

#[cfg(test)]
#[path = "keydb_index_tests.rs"]
mod tests;
