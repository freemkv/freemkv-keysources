# `keydb.cfg` path policy (`src/paths.rs`)

Key-path policy belongs with the key sources (this crate), not the library:
libfreemkv is handed a path and reads it. The CLI/app asks here for the
list of locations to *search* (first existing wins) and for the single
*default* location to write to (e.g. `update-keys`/save).

freemkv is a portable, standalone binary: the `keydb.cfg` lives *next to*
the executable — `<dir of current exe>/keydb.cfg` — and nowhere else. There
is no OS-specific config-dir lookup (`%APPDATA%`, `%USERPROFILE%\.config`,
`$XDG_CONFIG_HOME`, `$HOME/.config`). Drop the exe and its `keydb.cfg` in
the same folder and it works. Callers needing a custom location pass
`--keydb PATH`, which bypasses this module entirely.
