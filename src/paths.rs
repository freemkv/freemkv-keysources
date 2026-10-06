//! Where the `keydb.cfg` lives: local to the executable, local ONLY.
//!
//! Key-path policy belongs here (key sources), not in libfreemkv, which
//! just reads a handed-in path. This module gives the *search* list (first
//! existing wins) and the single *default* write location.
//!
//! freemkv is portable: `keydb.cfg` lives next to the exe — `<dir of current exe>/keydb.cfg` —
//! with no OS config-dir fallback. `--keydb PATH` bypasses this module.

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
#[path = "paths_tests.rs"]
mod tests;
