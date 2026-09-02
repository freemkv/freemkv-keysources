# freemkv-keysources: scope and design notes

## Mechanism vs. policy

Applications (autorip, the `freemkv` CLI) choose and order the key sources
from their own config — the local-vs-online policy is just which impls they
plug in — then resolve and hand the resulting key to `Disc::decrypt_with`.

Each source resolves a disc's terminal **Unit Keys** in one shot via
`KeySource::get_unit_keys`, driving libfreemkv's boil-down crypto primitives
for whatever level of material it holds. Compose several with `MultiSource`
in the caller's chosen order.

Reading the encrypted content-sample units a key server validates on, and
applying the resolved keys against a disc, is decryption *mechanism* — it
lives in the library (`libfreemkv::resolve_and_apply`,
`libfreemkv::read_encrypted_units`), not here.

## `MultiSource` failure semantics

`MultiSource::get_unit_keys` tries each inner source in order and returns the
first non-empty Unit Key set (and `get_fmts_indexes` does the same for the
forensic set). The caller supplies the list AND the order — local-first
`[Keydb, Online]`, online-first `[Online, Keydb]`, etc. — so the "which
sources, in what order" policy lives entirely with the application, not the
library. `MultiSource` is itself a `KeySource`, so it nests and composes.

**A source that could not ANSWER is not a source that answered "no key".**
When no inner source produces keys, the composition returns `Err` if any
inner source failed, and `Ok(empty)` only when every source genuinely
answered and none held a key. This mirrors libfreemkv's own resolver
(`keysource::drive_unit_keys`, which tracks an `errored` flag, and
`source_failure`, which stamps the first failure onto the disc) — a
composition that swallowed the `Err` would hand the resolver a clean
`Ok(empty)`, and an outage would once again be reported to the operator as
`E7022 No key source has a decryption key for this disc`.

## `first_non_empty` ordering rule

A source failure never blocks the chain (a later source is still tried, and
a later success still wins outright, error or no error), but it is not
forgotten either: with no keys anywhere, the FIRST failure is returned.
First (not last) matches libfreemkv's `source_failure` rule, so the
most-preferred source's reason is the one the operator is told about, in the
same order the caller expressed a preference for successes.

`get` selects which trait method to drive, so the base and forensic paths
share ONE implementation of this rule and cannot drift apart — the forensic
half carried the identical bug.
