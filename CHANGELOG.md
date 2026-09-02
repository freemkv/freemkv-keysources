# Changelog

## [1.6.15] — 2026-09-02

### Changed

- Version aligned to 1.6.15 for the unified release. Internal CI/lint hardening only (stable-clippy MSRV split, cargo-deny dependency-audit gate, audience-based comment-guard); no functional changes.

## [1.6.14] — 2026-08-31

### Changed

- Version aligned to 1.6.14 for the unified release.

## [1.6.13] — 2026-08-28

### Changed

- Version aligned to 1.6.13 for the unified release.

## [1.6.12] — 2026-08-27

### Changed

- Version aligned to 1.6.12 for the unified release; no functional changes.

## [1.6.11] — 2026-08-26

### Changed

- Version aligned to 1.6.11 for the unified release. No functional changes to
  this crate; the release was driven by the libfreemkv main-feature selection
  improvements and the autorip mux-quarantine fix (see the libfreemkv and
  autorip 1.6.11 notes).

### Added

- Codecov coverage reporting and badge.
- Substantially expanded unit-test coverage.

## [1.6.10] — 2026-08-23

### Changed

- Version aligned to 1.6.10 for the unified release. No functional changes to
  this crate; the release was driven by libfreemkv (TrueHD/MLP audio now resyncs
  to the next major-sync access unit after a source transport-stream
  discontinuity, instead of splicing post-gap audio mid-stream — fixing
  decoder-choking seams on discs whose stream carries a continuity-counter gap;
  see the libfreemkv 1.6.10 notes).

## [1.6.9] — 2026-08-22

### Changed

- Version aligned to 1.6.9 for the unified release. No functional changes to
  this crate; the release was driven by autorip (automatic per-episode TV
  ripping — each episode named `S{NN}E{MM}`, with TMDB runtime-aligned episode
  numbering across multi-disc seasons — a Manual Rename option, and a unified
  per-disc staging state file — see the autorip 1.6.9 notes).

## [1.6.8] — 2026-08-21

### Changed

- Version aligned to 1.6.8 for the unified release. No functional changes to
  this crate; the release was driven by autorip (webhooks now fire per pipeline
  stage — Rip / Mux / Move — with the Rip hook firing the moment the drive is
  free again, plus a Ripper-tab activity-banner fix so it also shows during
  moves — see the autorip 1.6.8 notes).

## [1.6.7] — 2026-08-21

### Changed

- Version aligned to 1.6.7 for the unified release. No functional changes to
  this crate; the release was driven by autorip (per-webhook event selection,
  a progress bar per moved artifact, and move-queue / webhook-error fixes —
  see the autorip 1.6.7 notes).

## [1.6.6] — 2026-08-20

### Changed

- Version aligned to 1.6.6 for the unified release. No functional changes
  to this crate; the release was driven by autorip (webhooks may now target
  private/LAN addresses — see the autorip 1.6.6 notes).

## [1.6.5] — 2026-08-20

### Fixed

- **A media, disc-ID, or VUK key at the end of a keydb row is no longer
  lost to the comment beside it.** Many `keydb.cfg` rows end with a
  `; MKBv…` note. When that note sat directly after the row's final
  field and that field was the media key (`M`), disc ID (`I`), or VUK
  (`V`) — rather than a unit key (`U`) — the note was read as part of the
  value, the hex parse failed, and the key was silently dropped, so the
  disc reported no key even though the file held one. The note is now
  stripped from those three fields exactly as it already was from the
  unit-key field (a hex value never contains `;`, so the split is safe).
  A disc that stopped resolving for this reason resolves again.

- **A misconfigured key service is no longer quieter than an outage.** A
  mistyped port, an `http://` URL, or a key-service address the SSRF guard
  refuses all mean the same thing: the service was never asked, so nothing is
  known about the disc. They were reported as an empty result — the same value a
  service returns when it genuinely holds no key — so a standing
  misconfiguration surfaced to the operator as "no key for this disc" and never
  self-corrected, while a transient DNS failure was correctly reported as a
  failure. All three are now failures, logged at error level and separated in
  the log text from an outage: one says fix the URL, the other says wait. A
  later key source's real key still wins, so nothing that used to rip stops
  ripping.
- **A replaced `keydb.cfg` can no longer be missed.** The parsed keydb is cached
  behind the file's identity, and that identity was size plus modification time
  — which are byte-identical when a file is replaced within the same second by
  one of the same length, the common shape of a daily refresh on a filesystem
  that records whole seconds. The old, superseded keys were then served for the
  rest of the process's life while every lookup reported success. The identity
  now includes the file's inode, and a cache entry is not trusted until the file
  has been unmodified long enough for its timestamp to be meaningful.
- **A corrupt keydb keeps saying so.** The summary warning that counts rejected
  and duplicated rows is produced while parsing, and the cache skips parsing —
  so a damaged keydb warned once, at whatever moment it was first read, and was
  then served in silence to every later disc. The summary is now re-emitted on
  every lookup that serves that file. An intact keydb stays silent.
- **A keydb's identity and its contents are read through one file handle.** The
  cache used to stat the path and then separately open it, so a replacement
  landing between the two stored one file's identity beside another file's keys.

### Security

- **`{:?}` on a keydb no longer spells out its keys.** `KeyDb` and
  `DiscEntry` derived their `Debug`, so a single `{:?}` in a log line, a
  tracing field, or a panic message wrote out every processing key and
  every disc's media key, disc ID, VUK, and unit keys in full — on the
  published file, all 184,860 discs' worth. Both are public API, so any
  caller could trip it. Both types now format through a redacting `Debug`
  that names each field without its bytes, matching the AACS types this
  parser was split from, and a test fails if the plain derive ever returns.

- **The host certificate's redaction is now pinned by a test.** `{:?}` on a
  keydb host certificate does not print the AACS host private key, and never
  did — but that depended entirely on libfreemkv's own redacting formatter,
  with nothing in this crate to notice if it changed. The whole-database
  formatter's test did not cover it. It does now, along with device keys.

### Changed

- **Breaking (API):** `KeyDb::disc_entries`' key and `DiscEntry::disc_hash` are
  `Arc<str>` rather than `String` (a ~13 MB saving on the published keydb, which
  is now held in memory). Code that requires an owned `String` from either needs
  `.to_string()`. Unreleased in 1.6.4; recorded here because it shipped to git
  consumers without a note.

## [1.6.4] — 2026-08-15

### Changed

- **No functional change.** This crate ships alongside the rest of freemkv at a
  matching version; its behaviour is untouched.

## [1.6.3] — 2026-08-10

### Changed

- **The key service is reached over a newer HTTP client, with the same
  protections.** Before contacting a key service this crate resolves the host,
  rejects any private or link-local address, and then pins the connection to the
  addresses it just checked, so a hostname cannot be re-pointed at an internal
  machine in the moment between the check and the request. That behaviour is
  unchanged; only the client underneath it moved.

### Security

- **The address pinning is now proven by a test rather than assumed.** The checks
  that reject a bad address were well covered, but nothing verified that the
  approved addresses were the ones actually connected to — and every existing
  test still passed with that wiring removed entirely, because none of them
  opened a connection. A connection made to an unreachable name can only
  succeed if the pinned address is honoured, and that is now asserted. No
  defect is being fixed here: the pinning was correct. It simply had no way of
  telling anyone if it stopped being correct.

## [1.6.2] — 2026-08-08

Version sync with the workspace. No functional change in this crate.

## [1.6.1] — 2026-08-07

Version sync with the workspace. No functional change in this crate.

## [1.6.0] — 2026-08-03

### Fixed

- **Key-service failures are no longer indistinguishable from "no key for this
  disc".** `query` returned an empty vector for a 502, a 401, a 429, a
  transport error and an unparseable body alike — the same value a successful
  lookup with no match returns. It now returns a typed error, and the HTTP
  status is classified into the operator action it implies: 401/403 the token,
  429 back off, any other non-2xx the service. A genuine miss is a 200 with no
  key, so every non-2xx is a failure by definition. A DNS failure or timeout
  now counts as unreachable rather than as a bad URL.

Version sync with the workspace (freemkv-engine split release). No source change
in this crate; it remains a pluggable AACS key-source provider consumed by the
`freemkv` CLI and libfreemkv's key resolver.

## [1.5.2] — 2026-07-22

Version sync with the workspace; inherits libfreemkv 1.5.2 (CSS DVD descramble
fix). No source change in this crate.

## [1.4.5] — 2026-07-18

Version sync; inherits libfreemkv 1.4.5. `KeySource` split into `get_unit_keys` +
`get_fmts_indexes`, and a keydb device-key parse bug on an uppercase `0X` hex
prefix was fixed (case-insensitive hex parsing across the toolchain).

## [1.4.4] — 2026-07-17

Version sync; inherits libfreemkv 1.4.4. The online `/decode` request is built from
a `DecodeSampleSet` proven sufficient by type rather than a runtime length check.

## [1.4.3] — 2026-07-17

Version sync; inherits libfreemkv 1.4.3. The online unit-key reply is parsed as a
list (one key for an ordinary disc, the ordered set for a forensic-variant disc),
and `MIN_SAMPLE_UNITS` is re-exported from libfreemkv.

## [1.4.2] — 2026-07-15

Version sync with the workspace; inherits libfreemkv 1.4.2. The keydb test that
feeds real key material into the AACS crypto was adapted to the segregated
`decrypt_unit` + `is_clean` primitives (behaviour unchanged).

## [1.4.1] — 2026-07-14

Version sync with the workspace; inherits libfreemkv 1.4.1.

## [1.4.0] — 2026-07-13

Version sync with the workspace; inherits libfreemkv 1.4.0.

## [1.3.2] — 2026-07-10

### Changed

- Unit keys carry libfreemkv's new `UnitKey.variant_number`; every source
  (keydb, online, VUK-derived) emits `0` — ordinary, non-forensic content —
  via the `UnitKey::new` constructor. No behaviour change. Inherits
  **libfreemkv 1.3.2**.

## [1.3.1] — 2026-07-10

### Licensing

- **Relicensed to the MIT License, from 1.3.1 onwards** (releases up to and
  including 1.3.0 remain under AGPL-3.0).

Version sync with the workspace; inherits libfreemkv 1.3.1.

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
