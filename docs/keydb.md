# `keydb.rs` design notes

Long-form rationale moved out of `src/keydb.rs` doc comments to satisfy the
repo's comment-guard line caps. Each section is pointed to from the file by a
one-line `// See docs/keydb.md#<anchor>` comment.

## candidate-order

Full derivation path this source walks, cheapest-first:

1. per-disc **Unit Keys** (hash hit) → returned terminal, no derivation.
2. per-disc **VUK** (hash hit) → `uks_from_vuk` over the disc's encrypted
   title keys.
3. a **Media Key**, then `derive_vuk` → `uks_from_vuk`. The MK comes from, in
   order: the disc's stored MK (hash hit); the keydb's **Processing Key**
   pool walked against THIS disc's MKB via `derive_media_key_from_pk`; or the
   device-key pool via `derive_media_key_from_dk`. The PK and DK pools
   resolve the Media Key WITHOUT a VID; the final `derive_vuk` still needs
   one. The VID is the unlocker's physical VID (`ResolveCtx::vid`) when
   present, else the keydb entry's OWN stored VID (the `I` field, `vid`) for
   the non-physical / ISO path. With no VID from either source the MK path
   cannot complete — return nothing.

The cross-disc MK-pool brute (trying OTHER discs' stored media keys against
this disc) stays RETIRED: every MK path here is anchored to the matched
disc's own MKB or stored material.

The library still OWNS the crypto; this source owns only which primitive to
call with which material. Returning an empty `Vec` is a genuine "no key for
this disc here".

## file-identity

`(len, modified)` ALONE IS NOT AN IDENTITY. mtime is stored at whole-second
resolution on HFS+, on many container overlays and on most network
filesystems, so a writer that replaces `keydb.cfg` within the same second
with a file of the same byte length leaves `(len, modified)` bit-identical —
and the cache then serves the superseded parse for the rest of the process's
life. For a key database that is not a stale page: it is serving retired or
since-corrected keys while reporting success. The writers that hit this are
real and named in this crate's own docs: the daily-refresh job, a second
freemkv process, an operator's editor, a sync tool.

Two independent discriminators close it:

1. `dev` + `ino`. Every writer that publishes ATOMICALLY (temp file, fsync,
   rename — what `KeydbSource::save` does, and what any correct publisher
   does) creates a NEW inode, so the stamp differs immediately and
   unconditionally, whatever the clock or the mtime resolution did. Zero on
   platforms without them (see `FileStamp::of`), which costs nothing: rule 2
   stands alone.
2. A freshness rule on the cache entry — `CacheEntry::is_settled` — which
   covers the residual in-place rewrite that reuses the inode.

What this still does NOT catch: a writer that FORGES the timestamp, i.e.
restores an mtime equal to the cached one (`touch -t`, `rsync --times`, a
tar/backup restore) into the SAME inode with the SAME length. Nothing short
of hashing the content can see that, and hashing 62 MiB per lookup is
precisely the cost the cache exists to remove (~141 ms × ≥3 loads per rip).
`KeydbSource::save` therefore keeps invalidating the cache directly, so the
one write path this crate owns never depends on any of the above.

## settle-proof

Whether a cache entry's stamp can be TRUSTED to change if the file changes.

The proof, for a filesystem storing mtime at granularity `G`: suppose this
entry was stamped at `stamped_at` with `stamped_at - modified >= G`, and some
writer later rewrites the file in place at wall time `T > stamped_at`. The
recorded mtime `m'` of that write is within one granule of `T`, so
`m' >= T - G > stamped_at - G >= modified`. Hence `m' != modified` and the
stamp DOES change. The ambiguous window is therefore exactly the one where
the cached entry was stamped less than `G` after the file's own mtime — i.e.
we looked at the file while it was still "hot" — and in that window the
entry is refused and the file is re-read. Once the file has been quiet for
`G`, its entry settles and the cache is fully effective again.

Cost: after every keydb write, lookups re-parse for up to `G` (2 s). The
published keydb is rewritten daily, so that is ~2 s of re-parsing per day
against a cache that saves ~420 ms per rip.

`modified: None` (a filesystem that reports no mtime) never settles: the only
two discriminators left would be size and inode, so the entry is re-read
every time rather than being trusted on a weaker basis.

CLOCK CAVEAT: `stamped_at` is the local clock and `modified` is the
filesystem's. On a network share whose server clock runs AHEAD of the
client's by more than `G`, entries never settle (safe: more re-parsing). A
server clock BEHIND the client's makes an entry settle early, which re-opens
the same-second window it closes — the inode rule (1) is what covers the
realistic writers there.

## keydbsource-cache

`KeydbSource` caches the parsed database behind the file's identity stamp.
The published keydb is ~62 MiB / ~181k entries and a single AACS-cert rip
parses it repeatedly — `host_certs()` for the drive handshake (freemkv's
`pipe.rs`/`engine.rs`, autorip's `keysource.rs` each build their own source),
then the trait `host_certs(mkb)` during resolution, then `get_unit_keys` —
and every one of those calls used to re-read all 62 MiB from disk and
re-parse it from scratch, because the struct held nothing but a `PathBuf`.

A keydb replaced underneath this source is picked up on the next call, with
ONE stated exception: a writer that rewrites the file in place, into the
same inode, at the same byte length, having restored the previous mtime
exactly (`touch -t` / `rsync --times` / a backup restore). Everything else —
any atomic rename, any length change, any real clock advance — changes the
stamp. `FileStamp` and `CacheEntry::is_settled` carry the full argument and
the clock caveats; do not weaken either without re-reading them. (The
earlier wording here — "an externally replaced keydb is still picked up" —
was simply false for a same-second, same-length replacement, which is the
common shape of a daily-refresh job on a whole-second-mtime filesystem.)

MEMORY RESIDENCY (accepted, and deliberately recorded rather than fixed
here): a hit keeps the entire parsed keydb — every disc's Media Key / VID /
VUK / Unit Keys, the processing- and device-key pools, and the host-cert
PRIVATE keys — resident for the process's life, where the pre-cache code
held one parse transiently. Nothing in this crate zeroizes on drop, so that
material was always exposed to a core dump or a swapped page; the cache
widens the WINDOW, it does not create the class. Closing it properly means
zeroize-on-drop across `KeyDb`, `DiscEntry` and libfreemkv's `aacs::types`
(which owns most of the buffers) — a cross-crate change, tracked separately,
NOT smuggled in behind a cache fix.

## cached-db-one-open

Errors are the same ones `KeyDb::load` produces, unchanged: a missing file
is `NotFound` (the documented benign case), an over-cap or non-UTF-8 file is
`InvalidData`. The stamp costs an `fstat`, not a 62 MiB read.

ONE OPEN, ONE IDENTITY. The file is opened once and both the stamp (`fstat`
on that handle) and, on a miss, the bytes come from it. The previous shape —
`std::fs::metadata(path)` and then a separate `KeyDb::load(path)` — resolved
the path TWICE with no atomicity between them, so a rename landing in the
gap cached the new file's stamp beside the old file's contents (or the
reverse); the pairing was then served, looking perfectly valid, until the
stamp changed again. The stamp is read BEFORE the bytes on purpose: a write
racing the read then leaves the OLD stamp cached, which the next call
detects, whereas stamping afterwards would file torn content under a
fresh-looking identity and pin it.

## cached-db-reemit

Re-emit the parser's rejection summary on EVERY hit, not just on the parse
that produced it. `KeyDb::parse` is what logs it, and a hit skips `parse`
entirely — so a daemon that cached a corrupt keydb logged its rejected-row
counts exactly once, at whatever moment it first read the file, and then
served that same damaged database to every later rip in silence. Repetition
is the correct failure mode here: the line is emitted only when the file
really does have rejected or duplicate rows, and a warning an operator can
still see on the tenth rip is worth more than one they had to catch on the
first.

## load-failure

A MISSING keydb is the documented benign case: the app may simply not have
one, another source may hold the key, and "no keydb" is genuinely "no key
here". Everything else is NOT that: `InvalidData` is a keydb over the
128 MiB cap or one that is not valid UTF-8 — i.e. corrupt, truncated, or a
half-finished download — and a permission/IO failure means the file could
not be read at all. Reporting either as an empty result made a broken keydb
indistinguishable from "this disc has no key" (the same conflation as the
seven-hour 502), with no log to notice it by. Both are now logged AND
surfaced as errors so the resolver reports a source failure instead of
`E7022`.

## save-mirror-parse

Mirror `KeyDb::parse`'s disc-entry rule EXACTLY by CALLING it
(`is_disc_entry_line`), so `save()` never validates + persists content that
parses to zero usable entries (e.g. a stray "0xDEADBEEF" comment line) and
the two can no longer drift — they did drift once already, on the `0X` case
rule.

## unit-keys-from

CPS-unit numbering: a returned `UnitKey::idx` is the POSITIONAL index
libfreemkv's `resolve_and_apply` turns into the canonical CPS-unit number
`idx + 1`. For the terminal per-disc unit-key path we therefore map the
keydb's stored CPS number `num` to `idx = num - 1`, so the committed number
is byte-identical to the keydb's `num` (and to what the OLD
`Key::Unit(entry.unit_keys)` path committed). For the VUK / MK paths the
boil primitive already yields 0-based positional indices, matching
`parse_unit_key_ro`'s `(i + 1)` after the resolver's `+ 1`.

## unit-keys-per-disc-hit

Per-disc hit (most specific). `find_disc` normalizes the hash form. Without
a matched entry this keydb has no per-disc material (Unit Keys / VUK / Media
Key / stored VID) to anchor a derivation for the disc, so it resolves
nothing. (The PK and DK pools are global, but the cross-disc MK-pool brute —
trying OTHER discs' media keys against this disc — stays retired; a PK/DK
pool only ever resolves a disc reached through its own matched entry below.)

## unit-keys-union

UNION every source of terminal keys, then dedup — never first-hit. A stored
`unit_keys` list can be PARTIAL (the key-import tool only ever sampled the
CPS units reachable from a playlist, so an orphan unit's key may be
missing), while the per-disc VUK boils EVERY declared CPS unit. Taking the
stored list alone (the old return-at-first-path) would shadow the VUK and
silently drop the orphan unit's key. So gather both and keep a unique-by-key
list: the read path tries every key per unit, so an extra or stale key is
harmless — only a MISSING key hurts.

## unit-keys-vuk-or-mk

2. Per-disc VUK — one step, no VID needed; boils ALL declared units.
3. Else a Media Key path (stored MK / PK pool / DK pool) → VUK → all
   declared units. The MK itself carries no VID, but the final `vuk_from_mk`
   needs one: physical (unlocker) VID first, else the entry's stored VID
   (`I` field), else cannot derive. Either branch yields the COMPLETE
   declared set, so we take the first that resolves (VUK preferred —
   cheapest).

## write-atomic

keydb.cfg is the single source of AACS truth, and save/update run
unattended (first-boot download + daily-refresh thread, with a container
restart on every release). A bare in-place `fs::write` truncates the file
before writing, so a SIGKILL (docker stop's grace window), OOM-kill, power
loss, or ENOSPC mid-write would leave the keydb half-written — the prior
good copy already gone. A truncated keydb doesn't error at write time; it
silently breaks key resolution on every later AACS rip. Writing to a temp
file then renaming (POSIX rename is atomic within a filesystem) means an
interrupted update leaves the previous keydb fully intact.

The fsync MUST succeed before the rename: a `sync_all` failure (ENOSPC,
ESTALE on the bind-mounted volume) means the kernel never guaranteed the
bytes reached stable storage, so publishing them via rename would defeat
crash-safety. The temp name is unique per call (pid + monotonic counter) so
a concurrent update can't share a fixed temp path and rename a mangled file
over the keydb.

## get-unit-keys-trait

A MISSING keydb is not an error — it simply yields no keys (another source
may have them), the same as the library's own loader. A keydb that exists
but cannot be USED (over the size cap, not UTF-8, unreadable) is a source
failure and returns `Err`: it says nothing about whether this disc has a
key, and reporting it as an empty result is the same looks-like-success
failure as a 502 reported as `E7022`.

The keydb carries no AACS 2.1 forensic index keys today, so it does not
override `get_fmts_indexes` — the default (empty) opts it out, and an FMTS
disc's forensic set comes from the online source.

## host-certs-trait

Expose the keydb's host certs through the trait — the OEM/AACS cert-auth
route collects them across every source via this method. Wires the disc's
MKB generation through for revocation filtering (the keydb parser's
`; Revoked in MKBv<N>` annotation): a cert revoked at generation `R` is
withheld once the disc's generation reaches `R`.

## test-pinned-mtime

Force a file's mtime to `PINNED_MTIME`, so two different files can be made
bit-identical to a `(len, mtime)` stamp on purpose. The cache tests that
matter all depend on FORCING the indistinguishable case rather than hoping
the filesystem produces it: on APFS (nanosecond mtimes) a same-second
replacement is otherwise detected by mtime alone, and a test that relies on
that passes with the fix reverted — which is worth nothing.

## test-committed

The committed `(cps, key)` pairs libfreemkv's `resolve_and_apply` derives
from a source's Unit Keys: positional `idx` → canonical CPS number
`idx + 1`. The KATs compare against THIS to prove byte-identical parity with
the OLD `Key::Unit` / resolver-derived commit.

## test-mock-ctx-stub

`MockCtx` implements the full `ResolveCtx` trait so it can stand in for a
real disc, but `KeydbSource` itself never calls `title()`/`samples()` (those
matter to the online source, not the local keydb). Exercise them directly
so the mock's trait surface is proven correct too.

## test-kat-a

Here `enc_title_keys` is empty, so the VUK can't derive anything — only the
stored list contributes, and it commits byte-identically to the stored
`(cps, key)` pairs.

## test-orphan-union

Orphan-unit completeness (the real keydb bug): an entry stores only `uk1`
(the key-import tool sampled one reachable CPS unit) but ALSO carries the
VUK, which boils BOTH declared units. The old return-at-first-path handed
back just `[uk1]`, shadowing the VUK and silently dropping the orphan unit.
The union must return BOTH — the stored uk1 AND the VUK-derived second unit.

## test-kat-c

A hash hit with a Media Key and a physical VID (from the unlocker) derives
`MK → VUK → UK`. The PHYSICAL VID must be used in preference to the keydb's
stored VID — proven by giving the entry a DIFFERENT stored VID and showing
the result tracks the physical one.

## test-kat-f

Owner decision #1 (AACS): a keydb Processing Key must be walked against the
matched disc's own MKB to recover the Media Key, then driven down the full
chain `PK → MK → VUK → UK`. The disc entry carries NO stored MK/VUK/UK — the
only key material is a global `PK` row — and the result must be the real
Unit Keys, byte-identical to deriving from the recovered MK.

The MKB + PK use a known-answer construction (a planted PK whose derived MK
satisfies the synthetic verify record); the constants are precomputed AES
vectors so this crate needs no AES primitive of its own. They mirror
libfreemkv's `boil::mk_from_pk_drives_full_chain_to_uks` KAT.

## test-repeated-lookups

A single AACS-cert rip drives this source at least three times — the
scan-options builder's inherent `host_certs()`, the trait `host_certs(mkb)`
during the handshake, then `get_unit_keys` — and each call used to re-read
and re-parse the WHOLE file, because `KeydbSource` held nothing but a
`PathBuf`. Measured on the real 62 MiB / 184,860-entry keydb: ~140 ms per
parse in `--release`, i.e. ~420 ms and ~186 MiB of file reads per rip,
against ~1 µs for a cache hit.

Catches the mutation that drops the cache (every call re-parses: count 3)
and the mutation that makes the cache unconditional (see the invalidation
tests below).

The mtime is pinned into the PAST first, because a cache entry is only
trusted once the file has been quiet for the mtime granularity
(`CacheEntry::is_settled`) — a keydb written microseconds ago is
deliberately re-read. Unix-only: pinning an mtime needs `touch -t` (no
`filetime` dependency for a test).

## test-changed-keydb

The cache must not go stale: a keydb replaced UNDERNEATH the source (the
daily-refresh thread writing through a different `KeydbSource`, or an
operator dropping in a new file) has a different size/mtime stamp and must
be re-read. Catches the mutation that caches on first load and never
re-stats — which would pin a rip to a keydb deleted hours earlier.

## test-two-discriminators

The defect both of the inode/settle tests below pin: `(len, mtime)` is not a
file identity. An external writer — the daily-refresh job, a second freemkv
process, an editor, a sync tool — that replaces `keydb.cfg` inside one mtime
granule with a file of the SAME length leaves that pair bit-identical, and
the source then serves the superseded parse for the rest of the process's
life: retired or since-corrected keys, reported as success.

Each test disables the OTHER discriminator through `mtime_granularity`, so
neither can pass on the strength of the one it is not testing, and neither
depends on the host filesystem's real mtime resolution (on APFS the naive
scenario is not reproducible at all).

## test-inode-rename

A keydb replaced by ATOMIC RENAME — how every correct publisher, including
this crate's own `save()`, installs a new file — must be re-read even when
length and mtime are identical. `mtime_granularity: 0` makes every entry
settle, so ONLY dev+ino can distinguish the two files here.

Catches the mutation that drops `dev`/`ino` from `FileStamp` (the original
`(len, modified)` stamp): the source then keeps answering with the previous
keydb's keys.

## test-inplace-rewrite

A keydb rewritten IN PLACE — same inode, same length, mtime forced back to
the same value — must still be re-read while the cached entry is too young
to trust. `mtime_granularity` is set to a decade so nothing ever settles,
which is the same condition a real same-second, whole-second-mtime
replacement creates and the only way to reproduce it deterministically on a
nanosecond-mtime filesystem.

Catches the mutation that deletes the `is_settled` check from `cached_db`
(every stamp match trusted unconditionally, which is what the original code
did): dev, ino, len and mtime are ALL identical here, so without the
freshness rule the source serves the old keys forever.

## test-corrupt-warns

`ParseStats::log` runs inside `KeyDb::parse`, and a cache hit skips `parse`
— so once the cache landed, the rejected-row summary for a given file was
emitted exactly ONCE for the entire life of the process, while that same
damaged file went on being served to every subsequent rip. A long-running
daemon (autorip) logs it at startup, the operator misses it in the startup
noise or loses it to log rotation, and there is no second chance for as long
as the process runs.

Catches the mutation that deletes the `emit_parse_stats` call from the
cache-HIT arm of `cached_db`: warnings would drop to 1 while the file is
still served three times.

## test-healthy-silent

Catches the mutation that makes `emit_parse_stats` unconditional (drops
`ParseStats::log`'s empty-counts early return).

## test-fresh-not-trusted

Catches the mutation that widens the window to something unbounded (a
granularity of hours would re-parse 62 MiB on every lookup all day) by
pairing with `repeated_lookups_parse_the_keydb_once`, which proves the entry
DOES settle once the mtime is in the past.

## test-save-invalidates

`save()` replaces the very file this source reads, so it drops the cached
parse ITSELF rather than trusting the (size, mtime) stamp: a same-size
rewrite that lands inside the filesystem's timestamp granularity is the one
change the stamp cannot see — and it is exactly the change this crate
performs (the daily-refresh thread re-saving a keydb through the source it
then reads from).

The test forces that indistinguishable case rather than hoping for it: the
file is written, stamped to a FIXED mtime, cached, re-saved with different
keys of the SAME length, and stamped back to the same mtime. To the stamp
the two files are identical, so only the explicit invalidation can produce
the new key. Unix-only because pinning an mtime needs `touch -t` (no
`filetime` dependency for one test).

## test-corrupt-is-error

`KeyDb::load` fails distinguishably for a keydb that is over the 128 MiB cap
or not valid UTF-8 — a truncated download, a half-written file, a binary
blob dropped in by mistake. Both used to collapse into `Ok(Vec::new())` with
ZERO tracing, i.e. into the benign "no key for this disc" the resolver
reports as `E7022` — the same looks-like-success failure as the seven-hour
502. Only a MISSING file is genuinely benign.

Catches the mutation that restores `Err(_) => Ok(Vec::new())`.
</content>
