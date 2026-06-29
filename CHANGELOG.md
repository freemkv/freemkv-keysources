# Changelog

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
