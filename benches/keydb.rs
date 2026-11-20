//! KEYDB load and lookup timings over a synthetic, real-sized keydb.cfg.
//!
//! Run with `cargo bench --bench keydb`. `KEYDB_BENCH_ROWS` overrides the disc
//! row count (default 181 000, the size of the public UHD keydb). Plain
//! `fn main` timing with `std::time::Instant`; no bench framework.

use std::hint::black_box;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use freemkv_keysources::{KeyDb, KeySource, KeydbSource, ResolveCtx};
use libfreemkv::aacs::types::Vid;

/// A disc context carrying only a hash: enough for a keydb lookup.
struct HashCtx {
    hash: String,
}

impl ResolveCtx for HashCtx {
    fn disc_hash(&self) -> &str {
        &self.hash
    }
    fn title(&self) -> Option<&str> {
        None
    }
    fn vid(&self) -> Option<Vid> {
        None
    }
    fn mkb(&self) -> Result<&[u8], libfreemkv::Error> {
        Ok(&[])
    }
    fn enc_title_keys(&self) -> Result<&[[u8; 16]], libfreemkv::Error> {
        Ok(&[])
    }
    fn samples(&self, _n: usize) -> Result<Vec<Vec<u8>>, libfreemkv::Error> {
        Ok(Vec::new())
    }
}

/// xorshift64*: deterministic filler bytes, no `rand` dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn hex(&mut self, bytes: usize) -> String {
        let mut s = String::with_capacity(bytes * 2);
        while s.len() < bytes * 2 {
            s.push_str(&format!("{:016x}", self.next()));
        }
        s.truncate(bytes * 2);
        s
    }
}

/// Write the synthetic keydb and return `(text, a hash that is present)`.
fn synthetic_keydb(rows: usize) -> (String, String) {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut text = String::with_capacity(rows * 360);
    for _ in 0..4 {
        text.push_str(&format!(
            "| HC | HOST_PRIV_KEY 0x{} | HOST_CERT 0x{}\n",
            rng.hex(20),
            rng.hex(92)
        ));
    }
    for _ in 0..8 {
        text.push_str(&format!(
            "| DK | DEVICE_KEY 0x{} | DEVICE_NODE 0x0800 | KEY_UV 0x00000400 | KEY_U_MASK_SHIFT 0x17\n",
            rng.hex(16)
        ));
    }
    for _ in 0..64 {
        text.push_str(&format!("| PK | 0x{}\n", rng.hex(16)));
    }
    let mut hit = String::new();
    for i in 0..rows {
        let hash = rng.hex(20);
        if i == rows / 2 {
            hit = format!("0x{hash}");
        }
        text.push_str(&format!(
            "0x{hash} = Synthetic Disc Title {i} | D | 2020-01-01 | M | 0x{} | I | 0x{} | V | 0x{} | U | 1-0x{} 2-0x{} ; MKBv76/BEE/FindVUK 1.74 - VolumeSize: 81309007872 (UHD)\n",
            rng.hex(16),
            rng.hex(16),
            rng.hex(16),
            rng.hex(16),
            rng.hex(16)
        ));
    }
    (text, hit)
}

/// Write `text` to a temp file with an mtime an hour in the past, so the source's
/// settle window (a cache entry is only trusted once its mtime is old) is already
/// over and warm lookups really are cache hits.
fn write_aged(path: &Path, text: &str) {
    let mut f = std::fs::File::create(path).expect("create bench keydb");
    f.write_all(text.as_bytes()).expect("write bench keydb");
    f.set_modified(SystemTime::now() - Duration::from_secs(3600))
        .expect("age bench keydb");
}

/// Resident set size in KiB, where the platform exposes it (Linux `/proc`).
fn rss_kib() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("VmRSS:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

fn show_rss(label: &str) {
    match rss_kib() {
        Some(kib) => println!("{label:<44} rss {:>8.1} MiB", kib as f64 / 1024.0),
        None => println!("{label:<44} rss n/a"),
    }
}

/// Run `f` `iters` times and print the mean and the slowest run.
fn time<T>(label: &str, iters: u32, mut f: impl FnMut() -> T) {
    let mut total = Duration::ZERO;
    let mut worst = Duration::ZERO;
    for _ in 0..iters {
        let t = Instant::now();
        black_box(f());
        let d = t.elapsed();
        total += d;
        worst = worst.max(d);
    }
    println!(
        "{label:<44} {iters:>6} iters  mean {:>12.3?}  max {:>12.3?}",
        total / iters,
        worst
    );
}

fn main() {
    let rows: usize = std::env::var("KEYDB_BENCH_ROWS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(181_000);
    let dir: PathBuf =
        std::env::temp_dir().join(format!("freemkv-keydb-bench-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("bench temp dir");
    let path = dir.join("keydb.cfg");

    let (text, hit_hash) = synthetic_keydb(rows);
    write_aged(&path, &text);
    println!(
        "synthetic keydb: {rows} disc rows, {:.1} MiB at {}",
        text.len() as f64 / (1024.0 * 1024.0),
        path.display()
    );
    let hit = HashCtx {
        hash: hit_hash.clone(),
    };
    let miss = HashCtx {
        hash: format!("0x{}", "5a".repeat(20)),
    };
    // The odd forms a caller may pass (uppercase, no prefix) take the same path.
    let hit_upper = HashCtx {
        hash: hit_hash.to_uppercase(),
    };

    show_rss("start");

    time("KeyDb::parse (whole text)", 3, || KeyDb::parse(&text));
    time("KeyDb::load (open + read + parse)", 3, || {
        KeyDb::load(&path).expect("load")
    });

    // What the engine does today: a fresh source per acquire, so every first
    // lookup pays the full load.
    time("KeydbSource::new + first lookup (cold)", 3, || {
        KeydbSource::new(&path).get_unit_keys(&hit).expect("lookup")
    });
    time("KeydbSource::new + host_certs (cold)", 3, || {
        KeydbSource::new(&path).host_certs()
    });

    let src = KeydbSource::new(&path);
    assert_eq!(src.get_unit_keys(&hit).expect("hit").len(), 2);
    assert!(src.get_unit_keys(&miss).expect("miss").is_empty());
    show_rss("one warm KeydbSource held");

    time("warm get_unit_keys (hit)", 1000, || {
        src.get_unit_keys(&hit).expect("hit")
    });
    time("warm get_unit_keys (hit, uppercase hash)", 1000, || {
        src.get_unit_keys(&hit_upper).expect("hit")
    });
    time("warm get_unit_keys (miss)", 1000, || {
        src.get_unit_keys(&miss).expect("miss")
    });
    time("warm resolve_unit_keys (hit)", 1000, || {
        src.resolve_unit_keys(&hit).expect("hit")
    });
    time("warm resolve_unit_keys (miss)", 1000, || {
        src.resolve_unit_keys(&miss).expect("miss")
    });
    time("warm host_certs()", 1000, || src.host_certs());
    drop(src);

    std::fs::remove_dir_all(&dir).ok();
}
