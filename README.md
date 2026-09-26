[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![CI](https://github.com/freemkv/freemkv-keysources/actions/workflows/ci.yml/badge.svg)](https://github.com/freemkv/freemkv-keysources/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/freemkv/freemkv-keysources/branch/dev/graph/badge.svg)](https://codecov.io/gh/freemkv/freemkv-keysources)

# freemkv-keysources

Pluggable AACS key sources (keydb, online key service) for
[libfreemkv](https://github.com/freemkv/libfreemkv). Each source looks a disc up
and hands libfreemkv its terminal Unit Keys via `get_unit_keys`; the library
does all derivation.

## Development

Build API documentation with `cargo doc --no-deps --open` for source construction,
keydb paths and online-query contracts. Run `cargo test --tests` to validate
parsing, caching and request guards. Tests use synthetic keys and local fixtures;
never commit real key material or credentials.

## License

MIT — see [LICENSE](LICENSE).
