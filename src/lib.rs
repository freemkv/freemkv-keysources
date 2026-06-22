//! Pluggable AACS key sources for libfreemkv.
//!
//! libfreemkv performs no key lookup — it is handed a [`Key`] and derives down
//! the AACS chain to decrypt. This crate provides the published [`KeySource`]
//! implementations that do the lookup:
//!
//! - [`KeydbSource`] — a local `keydb.cfg` (source #1).
//! - [`OnlineSource`] — a remote key service (source #2).
//! - [`MapfileSource`] — the persisted unit key from a rip mapfile (source #3).
//!
//! Applications (autorip, the `freemkv` CLI) choose and order the sources from
//! their own config — the local-vs-online policy is just which impls they plug
//! in — then resolve and hand the resulting key to `Disc::decrypt_with`.
//!
//! Sources are dumb and stateful: each hands its candidate keys out one at a
//! time via [`KeySource::next_key`], in its own best order, and reports
//! exhaustion. Compose several with [`MultiSource`] in the caller's chosen
//! order; [`resolve_and_apply`] drives the loop — handing each key to
//! `Disc::decrypt_with` (which validates against the disc's content samples) and
//! stopping at the first that decrypts, or reporting a genuine "no key" when
//! every source is spent.

mod keydb;
mod mapfile;
mod online;

pub use keydb::KeydbSource;
pub use mapfile::MapfileSource;
pub use online::OnlineSource;

// Re-exported for downstream convenience so apps need only depend on this crate
// for the source-side types.
pub use libfreemkv::{DiscInputs, Key, KeySource};

use libfreemkv::{Disc, DiscTitle, SectorSource};

/// An ordered composition of key sources, driven as one. `next_key` exhausts
/// the first source (one candidate per call), then the next, … then `None`.
/// **The caller supplies the list AND the order** — local-first `[Keydb,
/// Online]`, online-first `[Online, Keydb]`, resume `[Mapfile, Keydb]`, etc. —
/// so the "which sources, in what order" policy lives entirely with the
/// application, not the library. `MultiSource` is itself a [`KeySource`], so it
/// nests and composes.
pub struct MultiSource {
    sources: Vec<Box<dyn KeySource>>,
    idx: usize,
}

impl MultiSource {
    /// Compose the given sources, tried in the order supplied.
    pub fn new(sources: Vec<Box<dyn KeySource>>) -> Self {
        Self { sources, idx: 0 }
    }
}

impl KeySource for MultiSource {
    fn next_key(&mut self, inputs: &DiscInputs) -> Option<Key> {
        while self.idx < self.sources.len() {
            if let Some(key) = self.sources[self.idx].next_key(inputs) {
                return Some(key);
            }
            self.idx += 1; // this source is spent — advance to the next
        }
        None
    }

    fn needs_samples(&self) -> bool {
        self.sources.iter().any(|s| s.needs_samples())
    }

    fn errored(&self) -> bool {
        self.sources.iter().any(|s| s.errored())
    }
}

/// Drive `sources` until one key decrypts `disc`. Loops `next_key` and hands
/// each candidate to [`Disc::decrypt_with`] (which validates it against
/// `inputs.samples` and only mutates the disc on success), returning `true` at
/// the first key that decrypts and `false` once every source is exhausted — the
/// genuine "no key for this disc". THE shared key-resolution loop: every
/// application (the `freemkv` CLI, autorip) uses it instead of re-rolling the
/// candidate/retry logic, so the "no key" verdict is identical everywhere.
pub fn resolve_and_apply(
    sources: &mut dyn KeySource,
    inputs: &DiscInputs,
    disc: &mut Disc,
) -> bool {
    while let Some(key) = sources.next_key(inputs) {
        if disc.decrypt_with(key, &inputs.samples).is_ok() {
            return true;
        }
    }
    false
}

/// Read up to `n` ENCRYPTED 6144-byte aligned units from `title`'s body, raw (no
/// decrypt) — the content samples a caller hands to [`resolve_and_apply`] (for
/// `Disc::decrypt_with` to validate a key against) and that a sample-needing
/// source (an online key service) byte-validates against.
///
/// "Encrypted" is decided by `libfreemkv::aacs::is_aacs_scrambled` — the SAME
/// predicate the library's decrypt gate and a key service use — so all sides
/// agree. A clip opens with clear navigation units (PAT/PMT, menus); only the
/// feature body is scrambled, and a clear unit proves nothing, so this collects
/// only scrambled ones, sampling the largest extent at its midpoint forward.
pub fn read_sample_units(
    reader: &mut dyn SectorSource,
    title: &DiscTitle,
    n: usize,
) -> Vec<Vec<u8>> {
    const UNIT_LEN: usize = 6144;
    const UNIT_SECTORS: u32 = 3; // 6144 / 2048
    const CHUNK_UNITS: u32 = 15; // 45 sectors/read — under the drive transfer cap
    const MAX_CHUNKS_PER_EXTENT: u32 = 4; // ~60 units scanned at each extent's midpoint

    let mut out: Vec<Vec<u8>> = Vec::new();
    for ext in &title.extents {
        let total_units = ext.sector_count / UNIT_SECTORS;
        if total_units == 0 {
            continue;
        }
        let mut unit = total_units / 2; // midpoint (past the clear nav at the head)
        for _ in 0..MAX_CHUNKS_PER_EXTENT {
            if unit >= total_units {
                break;
            }
            let units_this = CHUNK_UNITS.min(total_units - unit);
            // Saturate: start_lba comes from attacker-controlled UDF/MPLS
            // extents; a malformed extent near u32::MAX would otherwise panic
            // (debug) or wrap to a wrong LBA (release). Matches the hardened
            // pattern in mux/disc.rs and verify.rs; an over-capacity LBA then
            // fails cleanly via the read_sectors().is_err() break below.
            let lba = ext
                .start_lba
                .saturating_add(unit.saturating_mul(UNIT_SECTORS));
            let count = (units_this * UNIT_SECTORS) as u16;
            let mut buf = vec![0u8; count as usize * 2048];
            // `false` = no recovery retries; the reader is the raw drive/file
            // (no decrypt decorator), so these are the on-disc encrypted bytes.
            if reader.read_sectors(lba, count, &mut buf, false).is_err() {
                break;
            }
            for i in 0..units_this as usize {
                let o = i * UNIT_LEN;
                if o + UNIT_LEN > buf.len() {
                    break;
                }
                let u = &buf[o..o + UNIT_LEN];
                if libfreemkv::aacs::is_aacs_scrambled(u) {
                    out.push(u.to_vec());
                    if out.len() >= n {
                        return out;
                    }
                }
            }
            unit += units_this;
        }
    }
    out
}
