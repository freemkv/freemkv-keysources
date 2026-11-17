#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if data.len() > 65536 {
        return;
    }
    if let Ok(text) = std::str::from_utf8(data) {
        let db = freemkv_keysources::KeyDb::parse(text);
        let serialized = db.to_keydb_cfg();
        let reparsed = freemkv_keysources::KeyDb::parse(&serialized);
        assert_eq!(db.disc_entries.len(), reparsed.disc_entries.len());
    }
});
