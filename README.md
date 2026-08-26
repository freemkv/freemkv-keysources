[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![CI](https://github.com/freemkv/freemkv-keysources/actions/workflows/ci.yml/badge.svg)](https://github.com/freemkv/freemkv-keysources/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/freemkv/freemkv-keysources/branch/dev/graph/badge.svg)](https://codecov.io/gh/freemkv/freemkv-keysources)

# freemkv-keysources

Pluggable AACS key sources (keydb, online key service) for
[libfreemkv](https://github.com/freemkv/libfreemkv). Each source looks a disc up
and hands libfreemkv its terminal Unit Keys via `get_unit_keys`; the library
does all derivation.

## License

MIT — see [LICENSE](LICENSE).
