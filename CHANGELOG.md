# Changelog

## [1.3.0] — 2026-07-08

### Added

- **AACS 2.0 host certs round-trip through `keydb.cfg`.** `to_keydb_cfg` now
  emits the sibling `| HC2 |` line — the inverse of the v2 host-cert parser — so
  writing a keydb back out no longer silently drops AACS 2.0 host certs.

### Changed

- **Resolve runs directly on `libfreemkv::aacs` primitives.** After libfreemkv
  dropped its `aacs::boil` veneer, the resolve path now calls
  `derive_media_key_from_{pk,dk}`, `derive_vuk`, and `decrypt_unit_key` from
  `aacs::derive` with the `aacs::types` newtypes. No behaviour change.
- Inherits **libfreemkv 1.3.0**.

### Fixed

- **keydb save-validation matches the parser exactly.** A `0x` line counts as a
  disc entry only when it also contains ` = `, so validating and persisting
  content that parses to zero usable entries (e.g. a stray `0xDEADBEEF` line) can
  no longer succeed.
- **Disc-entry titles round-trip verbatim** (parentheses and all) — the parse
  path now keeps the title exactly as the emit path writes it.

## [1.2.0] — 2026-06-29

### Changed

- **One hex parser across the toolchain.** Online and keydb hex inputs now parse
  through `libfreemkv::hex`, the same parser the library uses — no separate
  decoder with its own length/nibble rules.
- **`DiscInputs` carries the disc's AACS version**, and the tests derive the
  `Unit_Key_RO` stride from `inputs.version` instead of hardcoding it, so an
  AACS-1.0 (V10, 48-byte) and AACS-2.x (V20/V21, 64-byte) disc are each handled
  at their own stride.
- **Online MKB read cap aligned with libfreemkv (64 MiB)**, and an over-cap MKB
  is logged rather than silently truncated.
