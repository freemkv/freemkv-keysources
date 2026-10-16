[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![CI](https://github.com/freemkv/freemkv-keysources/actions/workflows/ci.yml/badge.svg)](https://github.com/freemkv/freemkv-keysources/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/freemkv/freemkv-keysources/branch/dev/graph/badge.svg)](https://codecov.io/gh/freemkv/freemkv-keysources)

# freemkv-keysources

Pluggable AACS key sources (keydb, online key service) for
[libfreemkv](https://github.com/freemkv/libfreemkv). Each source looks a disc up
and hands libfreemkv its terminal Unit Keys via `get_unit_keys`; the library
does all derivation.

## Development

### Optional BD+ companion records

`OnlineSource` accepts raw primary SVM bytes through `ResolveCtx::svm()`.
It derives the service's 20-byte identity locally and sends only its 40-character
hex encoding as optional JSON `bdp`. Missing or malformed SVM data does not
prevent ordinary unit-key resolution.

Use `resolve_unit_keys()` (or `resolve_fmts_indexes()`) to receive both
`result.keys` and `result.bdp`. The latter is a `Vec<BdPlusRecord>` retaining
each binary `selector` and its ordered `Vec<Option<Vec<u8>>>` responses. The wire
shape is `BDP: [{selector_hex, responses: [{index, data_hex}]}]`: null means
missing, an empty hex string means found but empty; there is no status field.
Indices 0–6 are the fixed `svq-seven-v1` request profile: `[1]`, `[6,0,0]`,
`[6,0,1]`, `[7,4]`, `[7,6]`, `[7,5]`, `[7,0]`, all with empty request blobs.
This profile is not automatic discovery of all requests needed by every disc.
No match yields an empty vector. The legacy key-only methods continue returning only keys. No second
request is made and records are not cached as shared "last response" state.

Ordinary responses retain the 1 MiB cap. Requests carrying a derived BD+ ID
allow up to 16 MiB of JSON, with at most 256 companion records. Malformed
companion data is discarded as a set without discarding valid unit keys.
Interpreting or applying the binary records is the caller's responsibility.

Build API documentation with `cargo doc --no-deps --open` for source construction,
keydb paths and online-query contracts. Run `cargo test --tests` to validate
parsing, caching and request guards. Tests use synthetic keys and local fixtures;
never commit real key material or credentials.

## License

MIT — see [LICENSE](LICENSE).
