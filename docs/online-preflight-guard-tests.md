# `src/online.rs` tests — pre-flight guards in `query`

Each of the three guards (cleartext scheme, over-cap MKB, under-sampled)
fires BEFORE any address is resolved and before anything is sent. None was
exercised before these tests: a reordering that let the cleartext POST
through would have shipped green, and that POST carries the bearer token
plus base64 key material.

Their VERDICTS differ on purpose (see docs/online-query-guards.md): the
cleartext-scheme guard is an operator fault and yields `Err`, while the two
input-shaped guards yield `Ok(empty)` — this source has nothing for THIS
disc, permanently, and calling that an outage would send the operator
waiting for nothing.

The discriminator in all three: the configured host is `.test`, which RFC
6761 guarantees never resolves. On the guarded path nothing resolves it, so
the test touches no network and returns `Ok(empty)`. Remove the guard and
control reaches `resolve_and_guard`, which fails as `Unreachable` ->
`Err(KeyServiceUnavailable)` — a different Result, so the mutation cannot
pass.
