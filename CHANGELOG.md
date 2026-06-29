# Changelog

## [1.2.0] — 2026-06-28

### Added

- `KeydbSource` now owns keydb save + update (atomic write to the source's own
  path); honors the caller-supplied location.

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

### Fixed

- **Processing-Key decryption restored.** A keydb Processing Key is again driven
  through the full AACS chain — PK → Media Key (against this disc's own MKB) →
  Volume Unique Key (with the disc Volume ID) → unit keys — so discs that ship
  only a Processing Key decrypt again. Stored Media Keys and Volume Unique Keys
  are still honored directly. (Cross-disc Media-Key reuse remains intentionally
  disabled.)
