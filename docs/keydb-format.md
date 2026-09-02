# keydb_format.rs — design notes

## Full parser API retained on purpose

The parser is copied verbatim, so it carries the full KeyDb/DiscEntry API
even though this crate's consumer (`keydb.rs`) only exercises a subset
(`load`, `find_disc`, `iter_disc_entries`, and the public fields read by
`KeydbSource::unit_keys_from` / `KeydbSource::host_certs`). NOTE: an earlier
revision of this comment cited a `candidates_from` function — no such
function has ever existed in this crate; the real consumer is
`KeydbSource::unit_keys_from` (keydb.rs), which reads `unit_keys`, `vuk`,
`media_key` AND `vid` (`vid` is load-bearing for the MK+VID derivation the
kat_c / kat_d KATs pin — it is NOT unused). The genuinely unused items —
`empty`, `find_vuk`, `DiscEntry::title` — are part of the faithful copy and
are retained rather than pruned; allow dead_code so the byte-for-byte copy
compiles clean without diverging from the libfreemkv original.

## ParseStats — what `KeyDb::parse` threw away

The parser is fed a THIRD-PARTY file: a mirror can serve a truncated or
byte-shifted download that is still valid UTF-8, still contains enough
recognisable rows to pass `KeydbSource::save`'s "at least one entry" check,
and is then atomically committed as the new keydb — after which every disc
past the corruption point silently resolves nothing. Before this counter,
each malformed `| DK` / `| PK` / `| HC` / `| HC2` / `0x…` row was dropped by
an `if let Some(..) = .. { }` with no `else`, no counter and no log, so that
file was indistinguishable from a healthy one at every layer above.

The counts are logged ONCE per parse (a per-line log would be 181k lines on
a real keydb, which is why the rate limit is "one summary", never "hide the
count").

## `KeyDb::load_counted` — same-descriptor stamp + parse

Two callers need this seam, both in `crate::KeydbSource`:

* The identity stamp and the bytes must come from the SAME descriptor.
  Stat-the-path-then-load-the-path is two independent resolutions of one
  name, so an atomic rename landing between them stored a stamp
  describing one file next to the parsed contents of another — and the
  cache then served that pairing until the stamp changed again. `fstat`
  on the open handle cannot be pointed at a different inode.
* The rejection counts have to be RETAINED, not just logged, so a cache
  hit can re-emit them.

## `to_keydb_cfg` — trailing-comment placement

The trailing `; <comment>` (MKB version / volume size / UHD) is emitted
ONLY after a `U` (unit-keys) field — that is the one place the parser
splits the value on `;`. Gluing a comment onto an `M`/`I`/`V` value would
make `parse_hex16` reject the whole field, so a comment-bearing entry that
has no unit keys drops its comment (keys always survive; the metadata is a
derivable hint). Real per-disc rows that carry metadata also carry keys.

## `parse_disc_entry` title handling

Title = everything between `= ` and the first ` | ` field (or the trailing
`;` comment), kept VERBATIM (trimmed). This is a FAITHFUL copy of the keydb
title, so it must round-trip exactly: a previous version extracted a `(...)`
substring as a "display title", but that TRUNCATED real titles that
legitimately contain parentheses ("Lawrence of Arabia (Restored Version) –
Disc 2 …" → "Restored Version") and broke serialize→parse idempotence.
Display prettification, if wanted, belongs in the title-display layer, NOT
this codec.

## Real-data test notes

`to_keydb_cfg_is_idempotent_on_real_keydb`: parse the full keydb -> serialize
(S1) -> parse S1 -> serialize again (S2). S1 MUST equal S2 byte-for-byte.
This is the right invariant: a raw keydb.cfg has formatting variance
(whitespace, optional fields, comment style) that our CANONICAL serializer
normalizes, so `text == to_keydb_cfg` is NOT expected — but once normalized,
a re-load+re-serialize must be stable. Idempotence here proves `parse` is
lossless on its own output and `to_keydb_cfg` is deterministic. Also asserts
no rows are dropped. It used to carry no `#[ignore]` and `return` early when
`KEYDB_PATH` was unset — so CI ran it, asserted NOTHING about 181k-entry
behaviour, and reported green. A skip has to be visible in the test output
to mean anything, and an ignored test that is RUN without its fixture must
fail loudly rather than silently pass.

`real_keydb_path`: the old pattern (`match keydb_path() { Some(p) => p, None
=> return }`) on a non-ignored test is the worst of both worlds: CI ran the
test, asserted nothing, and reported success. These tests are `#[ignore]`d,
so running one at all is an explicit request — and an explicit request with
no fixture must fail, not quietly pass.

## `load_counted_reads_the_handle_not_the_path` test

`load_counted` must read the HANDLE it was given, never re-resolve the
path. `KeydbSource::cached_db` stamps the open file with `fstat` and then
parses from that same descriptor precisely so the recorded identity and
the parsed bytes cannot describe two different files; the moment this
function re-opens the path, that guarantee is gone and an atomic rename
landing in between stores one file's stamp beside another file's keys —
a mismatch the cache then serves as if it were valid.

The race itself cannot be scheduled deterministically in-process, so the
SEAM is what is pinned: with the path already replaced, the handle's
contents must still win. Catches the mutation that restores an internal
`File::open(path)`.

## `host_cert_debug_is_redacted_including_the_sibling_wrapper` test

The SIBLING type. `KeyDb`'s hand-written `Debug` prints `host_certs_len`, so
it protects the whole-db rendering and nothing else — `KeyDb::host_certs` is
a public field, and `{:?}` on ONE element of it walks a completely different
code path: `KeydbHostCert`'s derive, then `HostCert`'s impl. That path
carries the AACS host PRIVATE key, the only key material in the crate that
authenticates US rather than opening a disc.

It is safe today only because `libfreemkv::HostCert` hand-writes a redacting
`Debug` (`aacs::types`, `private_key: "<redacted>"` + `certificate_len`) —
an EXTERNAL guarantee this crate silently inherits through the derive, with
nothing on this side pinning it. This test pins it: it catches a libfreemkv
upgrade that swaps that impl for `#[derive(Debug)]`, which would leak the
host private key out of this crate's public API with no diff in this
repository at all.

Rendered three ways because callers reach the cert three ways: the whole
`Vec` (`db.host_certs`), one element, and the inner `HostCert` a caller
gets back from `KeyDb::host_certs(mkb)`.

## KEYDB-parser integration tests relocated from libfreemkv

These exercise the parser (`KeyDb::load`) end-to-end against a real
keydb.cfg and feed its material into libfreemkv's AACS crypto
(`derive_vuk`, then `decrypt_unit` + `is_clean_ts`). They live here now
that the parser lives here. All are `KEYDB_PATH`-env-gated and no-op in CI
when the env is unset; they must still COMPILE.

## `test_decrypt_real_unit` — no-decrypt outcome

Reaching the fallback path is the EXPECTED outcome for the AACS 2.0 (BEE)
sample this test was written against: the unit is still bus-encrypted, so
no unit key alone can open it. That makes "no key worked" an unusable
assertion on its own — which is exactly why this test used to end in an
`eprintln!` and fall off the end, i.e. pass unconditionally. A no-op
`decrypt_unit`, an `is_clean` stuck at `false`, or a parser that yielded
zero keys would all have produced this same clean exit.

What CAN be asserted regardless of the sample: the pipeline actually ran,
and the decrypt primitive actually transformed the bytes.

## Hand-written redacting `Debug`

Key material must never reach a log, a panic message, or a bug report. Both
`KeyDb` and `DiscEntry` carry raw AACS key bytes, and both are public API, so
a `#[derive(Debug)]` on either is a leak of the crown jewels: `{:?}` on a
loaded `KeyDb` printed every processing key plus every disc's Media Key,
VID, VUK and Unit Keys. libfreemkv's equivalent types (`aacs::types`:
`DeviceKey`, `HostCert`, `Vid`, `MediaKey`, `Vuk`, `ProcessingKey`,
`UnitKey`, its own `DiscEntry`) all hand-write a redacting `Debug` for
exactly this reason; this crate's copy of the parser dropped that
convention when it was relocated. These restore it, field-for-field in the
same style (`<redacted>` for key bytes, a `_len` for key-bearing
collections). Pinned by `keydb_debug_is_redacted` /
`disc_entry_debug_is_redacted`.
