use super::*;
use std::path::PathBuf;

fn scratch_file(tag: &str, bytes: &[u8]) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);
    let n = CTR.fetch_add(1, Ordering::Relaxed);
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/test-scratch")
        .join(format!("keydb-index-{}-{}-{}", std::process::id(), tag, n));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("keydb.cfg");
    std::fs::write(&path, bytes).unwrap();
    path
}

fn hx(b: u8, n: usize) -> String {
    format!("{b:02x}").repeat(n)
}

// Every field of a disc entry, for comparison (DiscEntry has no PartialEq).
type EntryFields = (
    String,
    String,
    Option<[u8; 16]>,
    Option<[u8; 16]>,
    Option<[u8; 16]>,
    Vec<(u32, [u8; 16])>,
    Option<u32>,
    Option<u64>,
    bool,
);

fn fields(e: &DiscEntry) -> EntryFields {
    (
        e.disc_hash.to_string(),
        e.title.clone(),
        e.media_key,
        e.vid,
        e.vuk,
        e.unit_keys.clone(),
        e.mkb_version,
        e.volume_size,
        e.is_uhd,
    )
}

type CertFields = (
    [u8; 20],
    Vec<u8>,
    Option<[u8; 32]>,
    Option<Vec<u8>>,
    Option<u32>,
);

fn cert_fields(c: &crate::keydb_format::KeydbHostCert) -> CertFields {
    (
        c.cert.private_key,
        c.cert.certificate.clone(),
        c.cert.private_key_v2,
        c.cert.certificate_v2.clone(),
        c.revoked_at_mkb,
    )
}

fn dk_fields(keys: &GlobalKeys) -> Vec<([u8; 16], u16, u32, u8)> {
    keys.device_keys
        .iter()
        .map(|d| (d.key, d.node, d.uv, d.u_mask_shift))
        .collect()
}

// The odd forms a caller may pass for one stored hash, all of which `find_disc` accepts.
fn query_forms(stored: &str) -> Vec<String> {
    let digits = &stored[2..];
    vec![
        stored.to_string(),
        stored.to_uppercase(),
        format!("0X{}", digits.to_uppercase()),
        format!("0x{}", digits.to_uppercase()),
        digits.to_string(),
        digits.to_uppercase(),
        format!("  {stored}\t"),
        format!("0x0x{digits}"),
        format!("{stored}0"),
        format!("0x{}", &digits[1..]),
    ]
}

// Build the index over `text` and require it to agree with `KeyDb::parse_counted` on
// stats, entry count, global keys, and the answer to every query.
fn assert_parity(tag: &str, text: &str, extra_queries: &[&str]) {
    let path = scratch_file(tag, text.as_bytes());
    let file = File::open(&path).unwrap();
    let index = KeydbIndex::build(&file, &path).expect("index builds");
    let (db, stats) = KeyDb::parse_counted(text);

    assert_eq!(index.stats, stats, "{tag}: parse stats");
    assert_eq!(index.entries(), db.disc_entries.len(), "{tag}: entry count");
    assert_eq!(
        index.keys.processing_keys, db.processing_keys,
        "{tag}: processing keys"
    );
    let db_keys = GlobalKeys {
        device_keys: db.device_keys.clone(),
        processing_keys: Vec::new(),
        host_certs: Vec::new(),
    };
    assert_eq!(dk_fields(&index.keys), dk_fields(&db_keys), "{tag}: DKs");
    assert_eq!(
        index
            .keys
            .host_certs
            .iter()
            .map(cert_fields)
            .collect::<Vec<_>>(),
        db.host_certs.iter().map(cert_fields).collect::<Vec<_>>(),
        "{tag}: host certs"
    );

    let mut queries: Vec<String> = extra_queries.iter().map(|q| q.to_string()).collect();
    for stored in db.disc_entries.keys() {
        queries.extend(query_forms(stored));
    }
    queries.push(format!("0x{}", hx(0x5a, 20)));
    queries.push(String::new());
    queries.push("0x".into());
    for q in &queries {
        let want = db.find_disc(q).map(fields);
        let got = match index.find(&file, q).expect("lookup reads") {
            Lookup::Found(e) => Some(fields(&e)),
            Lookup::Missing => None,
            Lookup::Stale => panic!("{tag}: unchanged file reported stale for {q:?}"),
        };
        assert_eq!(got, want, "{tag}: query {q:?}");
    }
}

fn h40(b: u8) -> String {
    format!("0x{}", hx(b, 20))
}

#[test]
fn duplicates_resolve_to_the_last_row() {
    let text = format!(
        "{a} = First | U | 1-0x{k1}\n\
         0xaabb = Short1 | V | 0x{k1}\n\
         {a} = Second | U | 1-0x{k2}\n\
         0XAABB = Short2 | V | 0x{k2}\n\
         {up} = Third | U | 1-0x{k3}\n\
         0xAaBb = Short3 | V | 0x{k3}\n\
         {b} = Only | M | 0x{k1}\n",
        a = h40(0x11),
        up = h40(0x11).to_uppercase(),
        b = h40(0x22),
        k1 = hx(0x01, 16),
        k2 = hx(0x02, 16),
        k3 = hx(0x03, 16),
    );
    assert_parity("dupes", &text, &[]);
    let (_, stats) = KeyDb::parse_counted(&text);
    assert_eq!(stats.disc_duplicate, 4, "the fixture must hold duplicates");
}

#[test]
fn bom_crlf_comments_and_a_missing_final_newline_match_the_parser() {
    let text = format!(
        "\u{feff}{a} = Bom Row | U | 1-0x{k} ; MKBv76/BEE - VolumeSize: 81309007872 (UHD)\r\n\
         ; a comment line\r\n\
         # another comment\r\n\
         \r\n\
         \t  {b} = Indented | I | 0x{k} | V | 0x{k}   \r\n\
         {c} = Title Only ; MKBv68\r\n\
         \u{feff}{d} = Bom Not On Line One\n\
         {e} = (Paren) Title | D | 2020-01-01 | M | 0x{k} | I | 0x{k} | V | 0x{k} | U | 1-0x{k} 2-0x{k} ; MKBv77\n\
         \r\n\
         {f} = Last Row No Newline | U | 1-0x{k}",
        a = h40(0x31),
        b = h40(0x32),
        c = h40(0x33),
        d = h40(0x34),
        e = h40(0x35),
        f = h40(0x36),
        k = hx(0x07, 16),
    );
    assert_parity("bom-crlf", &text, &[]);
}

#[test]
fn a_bom_before_a_non_disc_first_line_matches_the_parser() {
    let text = format!(
        "\u{feff}| PK | 0x{k}\n{a} = T | U | 1-0x{k}\n",
        a = h40(0x41),
        k = hx(0x08, 16)
    );
    assert_parity("bom-pk", &text, &[]);
}

#[test]
fn non_40_digit_hashes_and_malformed_rows_match_the_parser() {
    let k = hx(0x09, 16);
    let text = format!(
        "0xaabb = Short | U | 1-0x{k}\n\
         0x1 = One Digit | V | 0x{k}\n\
         0x{d41} = Forty One | V | 0x{k}\n\
         0x{d39} = Thirty Nine | V | 0x{k}\n\
         0x = Empty Hash\n\
         0xzz = Not Hex\n\
         0xaabb=NoSpaces\n\
         0x aabb = Space In Hash\n\
         0x{bad40} = Forty Non Hex\n\
         0xccdd\n\
         0X{upper} = Upper Prefix | U | 1-0x{k}\n\
         | PK | 0xnothex\n\
         | PK | 0x{k}\n\
         | DK | DEVICE_KEY 0xZZ | DEVICE_NODE 0x0800 | KEY_UV 0x00000400 | KEY_U_MASK_SHIFT 0x17\n\
         | DK | DEVICE_KEY 0x{k} | DEVICE_NODE 0x0800 | KEY_UV 0x00000400 | KEY_U_MASK_SHIFT 0x17\n\
         | DK | DEVICE_KEY 0x{k}\n\
         | HC2 | HOST_PRIV_KEY 0x{p32} | HOST_CERT 0x{c132} ; Revoked in MKBv70\n\
         | HC | HOST_PRIV_KEY 0x{p20} | HOST_CERT 0x{c92} ; Revoked in MKBv72\n\
         | HC2 | HOST_PRIV_KEY 0x{p32} | HOST_CERT 0x{c132}\n\
         | HC | HOST_PRIV_KEY 0x{p20} | HOST_CERT 0xshort\n\
         | HC2 | HOST_PRIV_KEY 0x00 | HOST_CERT 0x{c132}\n\
         random junk line\n",
        d41 = "a".repeat(41),
        d39 = "b".repeat(39),
        bad40 = "g".repeat(40),
        upper = "C".repeat(40),
        p32 = hx(0x0a, 32),
        c132 = hx(0x0b, 132),
        p20 = hx(0x0c, 20),
        c92 = hx(0x0d, 92),
    );
    let extra = ["0x1", "1", "0xAABB", "aabb", "0x0xaabb", "0x", "0xzz"];
    assert_parity("odd-and-malformed", &text, &extra);
    let (db, stats) = KeyDb::parse_counted(&text);
    assert!(
        stats.disc_rejected >= 5,
        "the fixture must hold rejected rows"
    );
    assert!(stats.pk_rejected == 1 && stats.dk_rejected == 1);
    assert!(stats.hc_rejected == 1 && stats.hc2_rejected == 1);
    assert_eq!(db.host_certs.len(), 2);
}

#[test]
fn an_empty_or_comment_only_keydb_matches_the_parser() {
    assert_parity("empty", "", &["0xaabb"]);
    assert_parity("comments", "; nothing\n# here\n\n", &["0xaabb"]);
}

#[test]
fn a_round_tripped_keydb_matches_the_parser() {
    let rows: String = (0u8..64)
        .map(|i| {
            format!(
                "{} = Disc {i} | M | 0x{} | U | 1-0x{} ; MKBv{i}\n",
                h40(i),
                hx(i, 16),
                hx(i.wrapping_add(1), 16)
            )
        })
        .collect();
    let text = KeyDb::parse(&rows).to_keydb_cfg();
    assert_parity("round-trip", &text, &[]);
}

#[test]
fn hash20_decodes_either_case_and_rejects_the_rest() {
    let lower = hash20(hx(0xab, 20).as_bytes()).unwrap();
    assert_eq!(lower, [0xab; 20]);
    assert_eq!(hash20(hx(0xab, 20).to_uppercase().as_bytes()), Some(lower));
    assert_eq!(hash20(hx(0xab, 19).as_bytes()), None);
    assert_eq!(hash20(format!("{}a", hx(0xab, 20)).as_bytes()), None);
    assert_eq!(hash20("g".repeat(40).as_bytes()), None);
}

#[test]
fn line_text_strips_endings_and_only_a_first_line_bom() {
    assert_eq!(line_text("a\r\n", false), "a");
    assert_eq!(line_text("a\n", false), "a");
    assert_eq!(line_text("a", false), "a");
    assert_eq!(line_text("\u{feff}a\n", true), "a");
    assert_eq!(line_text("\u{feff}a\n", false), "\u{feff}a");
}

// A handle onto DIFFERENT bytes than were indexed: the row at the indexed offset no
// longer holds the hash, so the lookup reports Stale instead of a wrong entry.
#[test]
fn a_row_that_moved_is_reported_stale() {
    let row = |h: &str, k: u8| format!("{h} = T | U | 1-0x{}\n", hx(k, 16));
    let a = format!("{}{}", row("0xaabb", 1), row("0xccdd", 2));
    let b = format!("{}{}", row("0xccdd", 2), row("0xaabb", 1));
    let pa = scratch_file("stale-a", a.as_bytes());
    let pb = scratch_file("stale-b", b.as_bytes());
    let index = KeydbIndex::build(&File::open(&pa).unwrap(), &pa).unwrap();
    let moved = File::open(&pb).unwrap();
    assert!(matches!(
        index.find(&moved, "0xaabb").unwrap(),
        Lookup::Stale
    ));
    assert!(matches!(
        index.find(&moved, "0xccdd").unwrap(),
        Lookup::Stale
    ));
    assert!(matches!(
        index.find(&moved, "0xeeff").unwrap(),
        Lookup::Missing
    ));

    // A row whose bytes are no longer UTF-8 is stale too.
    let mut bad = a.clone().into_bytes();
    bad[0] = 0xff;
    let pc = scratch_file("stale-utf8", &bad);
    assert!(matches!(
        index.find(&File::open(&pc).unwrap(), "0xaabb").unwrap(),
        Lookup::Stale
    ));
}

// Same bytes, same error (kind AND text) as `KeyDb::load_counted`.
fn assert_same_error(path: &Path) {
    let Err(want) = KeyDb::load_counted(File::open(path).unwrap(), path) else {
        panic!("the loader rejects this file");
    };
    let Err(got) = KeydbIndex::build(&File::open(path).unwrap(), path) else {
        panic!("the index rejects this file");
    };
    assert_eq!(got.kind(), want.kind());
    assert_eq!(got.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(got.to_string(), want.to_string());
}

#[test]
fn a_non_utf8_keydb_gives_the_loaders_error() {
    assert_same_error(&scratch_file(
        "utf8-mid",
        b"0xaabb = T\n\xff\xfe\n0xccdd = T\n",
    ));
    assert_same_error(&scratch_file("utf8-last", b"0xaabb = T\n0xccdd = T \xc3"));
    assert_same_error(&scratch_file("utf8-first", b"\xff"));
}

// Over the cap wins over bad UTF-8, as in the loader; exactly at the cap is accepted.
#[test]
fn the_size_cap_matches_the_loader_at_both_edges() {
    let over = scratch_file("cap-over", b"\xff0xaabb = T\n");
    std::fs::OpenOptions::new()
        .write(true)
        .open(&over)
        .unwrap()
        .set_len(MAX_KEYDB_BYTES + 1)
        .unwrap();
    assert_same_error(&over);
    std::fs::remove_file(&over).ok();

    let at = scratch_file("cap-at", b"0xaabb = T\n");
    std::fs::OpenOptions::new()
        .write(true)
        .open(&at)
        .unwrap()
        .set_len(MAX_KEYDB_BYTES)
        .unwrap();
    let index = KeydbIndex::build(&File::open(&at).unwrap(), &at).expect("at the cap loads");
    assert_eq!(index.entries(), 1);
    std::fs::remove_file(&at).ok();
}
