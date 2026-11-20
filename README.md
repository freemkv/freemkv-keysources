[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![CI](https://github.com/freemkv/freemkv-keysources/actions/workflows/ci.yml/badge.svg)](https://github.com/freemkv/freemkv-keysources/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/freemkv/freemkv-keysources/branch/dev/graph/badge.svg)](https://codecov.io/gh/freemkv/freemkv-keysources)

# freemkv-keysources

Pluggable AACS key sources for
[libfreemkv](https://github.com/freemkv/libfreemkv). Each source looks a disc up
and hands libfreemkv its terminal Unit Keys via `get_unit_keys`. The library
does all key derivation.

- `KeydbSource` reads a local `keydb.cfg`. It can also save and update the file
  from a downloaded `.zip` or `.gz`.
- `OnlineSource` queries a remote key service over HTTP.
- `MultiSource` tries several sources in order.
- `keydb_format` exposes the `keydb.cfg` parser (`KeyDb`, `DiscEntry`).

It is not published on crates.io. Depend on it by git tag, like the other
freemkv crates. Requires Rust 1.88 or later (`rust-version` in `Cargo.toml`).
The optional `test-hooks` feature is for consumers' tests only.

## Development

Build the API docs with `cargo doc --no-deps --open` for source construction,
keydb paths and online-query contracts. Run `cargo test --tests` for the
parsing, caching and request-guard tests. Tests use synthetic keys and local
fixtures. Never commit real key material or credentials.

## License

MIT. See [LICENSE](LICENSE).
