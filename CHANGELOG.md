# Changelog

## [1.1.0-beta.1] — UNRELEASED

### Fixed

- **Processing-Key decryption restored.** A keydb Processing Key is again driven
  through the full AACS chain — PK → Media Key (against this disc's own MKB) →
  Volume Unique Key (with the disc Volume ID) → unit keys — so discs that ship
  only a Processing Key decrypt again. Stored Media Keys and Volume Unique Keys
  are still honored directly. (Cross-disc Media-Key reuse remains intentionally
  disabled.)
