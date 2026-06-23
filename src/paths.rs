//! Where the `keydb.cfg` lives, per OS.
//!
//! Key-path policy belongs with the key sources (this crate), not the library:
//! libfreemkv is handed a path and reads it. The CLI/app asks here for the
//! ordered list of locations to *search* (first existing wins) and for the
//! single *default* location to write to (e.g. `update-keys`/save).
//!
//! Resolution order:
//!
//! - **Windows**: `%APPDATA%\freemkv\keydb.cfg` FIRST (the idiomatic per-user
//!   roaming config dir), then the legacy `%USERPROFILE%\.config\freemkv\keydb.cfg`
//!   for back-compat with installs that predate this fix.
//! - **Linux / macOS**: `$XDG_CONFIG_HOME/freemkv/keydb.cfg` (if `XDG_CONFIG_HOME`
//!   is set), then `$HOME/.config/freemkv/keydb.cfg` — the long-standing default,
//!   unchanged so existing users keep working.
//!
//! Pure `std::env` — `%APPDATA%`, `%USERPROFILE%`, `$HOME`, `$XDG_CONFIG_HOME`
//! are all environment variables, so no `dirs`-style crate is pulled in.

use std::path::PathBuf;

/// The keydb filename plus its `freemkv` subdir, joined onto a base dir.
fn keydb_under(base: PathBuf) -> PathBuf {
    base.join("freemkv").join("keydb.cfg")
}

/// The ordered list of `keydb.cfg` locations to search, most-idiomatic first.
///
/// The caller picks the first path that exists on disk (see
/// [`existing_keydb_path`]); for writing a freshly-downloaded keydb, use
/// [`default_keydb_path`] (the first entry — the canonical location).
///
/// Always returns at least one entry on a normally-configured system; returns
/// an empty list only if none of the relevant env vars are set.
pub fn keydb_search_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if cfg!(windows) {
        // Idiomatic Windows location first.
        if let Ok(appdata) = std::env::var("APPDATA") {
            if !appdata.is_empty() {
                paths.push(keydb_under(PathBuf::from(appdata)));
            }
        }
        // Legacy XDG-style dotfolder under the user profile, for back-compat.
        if let Ok(profile) = std::env::var("USERPROFILE") {
            if !profile.is_empty() {
                paths.push(
                    PathBuf::from(profile)
                        .join(".config")
                        .join("freemkv")
                        .join("keydb.cfg"),
                );
            }
        }
    } else {
        // Honour XDG_CONFIG_HOME if the user set it, then the historical default.
        if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
            if !xdg.is_empty() {
                paths.push(keydb_under(PathBuf::from(xdg)));
            }
        }
        if let Ok(home) = std::env::var("HOME") {
            if !home.is_empty() {
                paths.push(
                    PathBuf::from(home)
                        .join(".config")
                        .join("freemkv")
                        .join("keydb.cfg"),
                );
            }
        }
    }

    paths
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
/// This is the first (most idiomatic) entry of [`keydb_search_paths`]:
/// `%APPDATA%\freemkv\keydb.cfg` on Windows, `~/.config/freemkv/keydb.cfg`
/// elsewhere. Returns `None` only when the relevant env vars are unset.
pub fn default_keydb_path() -> Option<PathBuf> {
    keydb_search_paths().into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialize env-mutating tests: they share the process environment.
    fn lock() -> std::sync::MutexGuard<'static, ()> {
        static M: std::sync::Mutex<()> = std::sync::Mutex::new(());
        M.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Build the search list under an explicit env, restoring the prior env
    /// afterwards. Avoids depending on the host's real HOME/APPDATA.
    fn with_env(vars: &[(&str, Option<&str>)], f: impl FnOnce()) {
        let _g = lock();
        let keys = ["APPDATA", "USERPROFILE", "HOME", "XDG_CONFIG_HOME"];
        let saved: Vec<(&str, Option<String>)> =
            keys.iter().map(|k| (*k, std::env::var(k).ok())).collect();
        // Clear all, then apply the requested overrides.
        for k in keys {
            unsafe { std::env::remove_var(k) };
        }
        for (k, v) in vars {
            match v {
                Some(val) => unsafe { std::env::set_var(k, val) },
                None => unsafe { std::env::remove_var(k) },
            }
        }
        f();
        // Restore.
        for (k, v) in saved {
            match v {
                Some(val) => unsafe { std::env::set_var(k, val) },
                None => unsafe { std::env::remove_var(k) },
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_prefers_appdata_then_legacy_userprofile() {
        with_env(
            &[
                ("APPDATA", Some(r"C:\Users\matt\AppData\Roaming")),
                ("USERPROFILE", Some(r"C:\Users\matt")),
            ],
            || {
                let paths = keydb_search_paths();
                assert_eq!(paths.len(), 2, "APPDATA + legacy USERPROFILE");
                assert_eq!(
                    paths[0],
                    PathBuf::from(r"C:\Users\matt\AppData\Roaming")
                        .join("freemkv")
                        .join("keydb.cfg"),
                    "APPDATA location must be searched first on Windows"
                );
                assert_eq!(
                    paths[1],
                    PathBuf::from(r"C:\Users\matt")
                        .join(".config")
                        .join("freemkv")
                        .join("keydb.cfg"),
                    "legacy .config dotfolder is the back-compat fallback"
                );
                assert_eq!(default_keydb_path(), Some(paths[0].clone()));
            },
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_falls_back_to_legacy_when_appdata_unset() {
        with_env(
            &[("APPDATA", None), ("USERPROFILE", Some(r"C:\Users\matt"))],
            || {
                let paths = keydb_search_paths();
                assert_eq!(paths.len(), 1, "only the legacy USERPROFILE path");
                assert_eq!(
                    paths[0],
                    PathBuf::from(r"C:\Users\matt")
                        .join(".config")
                        .join("freemkv")
                        .join("keydb.cfg")
                );
            },
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn unix_default_is_home_dotconfig() {
        with_env(
            &[("HOME", Some("/u/me")), ("XDG_CONFIG_HOME", None)],
            || {
                let paths = keydb_search_paths();
                assert_eq!(paths.len(), 1, "just the $HOME/.config default");
                assert_eq!(
                    paths[0],
                    PathBuf::from("/u/me")
                        .join(".config")
                        .join("freemkv")
                        .join("keydb.cfg"),
                    "Linux/macOS default must remain ~/.config/freemkv/keydb.cfg"
                );
                assert_eq!(default_keydb_path(), Some(paths[0].clone()));
            },
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn unix_honours_xdg_config_home_first() {
        with_env(
            &[
                ("XDG_CONFIG_HOME", Some("/u/me/.cfg")),
                ("HOME", Some("/u/me")),
            ],
            || {
                let paths = keydb_search_paths();
                assert_eq!(paths.len(), 2, "XDG dir + $HOME/.config fallback");
                assert_eq!(
                    paths[0],
                    PathBuf::from("/u/me/.cfg")
                        .join("freemkv")
                        .join("keydb.cfg"),
                    "XDG_CONFIG_HOME, when set, is searched before ~/.config"
                );
            },
        );
    }
}
