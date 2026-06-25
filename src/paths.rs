//! Where the `keydb.cfg` lives: local to the executable, local ONLY.
//!
//! Key-path policy belongs with the key sources (this crate), not the library:
//! libfreemkv is handed a path and reads it. The CLI/app asks here for the
//! list of locations to *search* (first existing wins) and for the single
//! *default* location to write to (e.g. `update-keys`/save).
//!
//! freemkv is a portable, standalone binary: the `keydb.cfg` lives *next to*
//! the executable — `<dir of current exe>/keydb.cfg` — and nowhere else. There
//! is no OS-specific config-dir lookup (`%APPDATA%`, `%USERPROFILE%\.config`,
//! `$XDG_CONFIG_HOME`, `$HOME/.config`). Drop the exe and its `keydb.cfg` in
//! the same folder and it works. Callers needing a custom location pass
//! `--keydb PATH`, which bypasses this module entirely.

use std::path::PathBuf;

/// The single `keydb.cfg` location to search: next to the current executable.
///
/// Returns exactly one path — `<dir of current exe>/keydb.cfg` — on success.
/// Returns an empty list if the executable's own directory can't be determined
/// (`std::env::current_exe()` fails or has no parent); there is deliberately no
/// OS config-dir fallback (portable / local-only).
///
/// The caller picks the first path that exists on disk (see
/// [`existing_keydb_path`]); for writing a freshly-downloaded keydb, use
/// [`default_keydb_path`].
pub fn keydb_search_paths() -> Vec<PathBuf> {
    match std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("keydb.cfg")))
    {
        Some(path) => vec![path],
        None => Vec::new(),
    }
}

/// The first search path that exists on disk, if any.
///
/// Use this to LOCATE an existing keydb for reading. Falls back to `None` when
/// no candidate file exists (the caller then surfaces "no KEYDB.cfg found").
pub fn existing_keydb_path() -> Option<PathBuf> {
    keydb_search_paths().into_iter().find(|p| p.exists())
}

/// The canonical default location to WRITE the keydb to (e.g. after a download).
///
/// This is the sole entry of [`keydb_search_paths`]: `<dir of current exe>/keydb.cfg`.
/// Returns `None` only when the executable's own directory can't be determined.
pub fn default_keydb_path() -> Option<PathBuf> {
    keydb_search_paths().into_iter().next()
}

#[cfg(test)]
mod tests {
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
}
