use super::*;

/// The expected exe-local keydb path, computed the same way the code does.
/// Under `cargo test`, `current_exe()` is the test binary under `target/…`.
fn expected_local() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("keydb.cfg")))
}

#[test]
fn search_paths_is_exactly_exe_local_keydb() {
    let paths = keydb_search_paths();
    match expected_local() {
        Some(expected) => {
            assert_eq!(
                paths,
                vec![expected],
                "search list must be exactly [<exe dir>/keydb.cfg]"
            );
        }
        None => {
            // No exe dir available → empty, no OS fallback (local only).
            assert!(
                paths.is_empty(),
                "no exe dir means an empty search list, never an OS fallback"
            );
        }
    }
}

#[test]
fn default_path_matches_search_head() {
    // The write default is the single search entry, or None if unavailable.
    assert_eq!(default_keydb_path(), expected_local());
    assert_eq!(
        default_keydb_path(),
        keydb_search_paths().into_iter().next()
    );
}
