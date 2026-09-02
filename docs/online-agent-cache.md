# `src/online.rs` — `OnlineSource::agent` caching

## Why cache at all

`query` used to build a FRESH `ureq::Agent` every call, and an FMTS disc
makes two calls per rip (`get_unit_keys` + `get_fmts_indexes`), so it paid
two TLS handshakes to the same host for no reason — an agent owns the
connection pool, and a discarded agent discards the pooled, already
negotiated TLS connection with it.

## Security invariant

The agent is reused ONLY when the freshly resolved + guarded address SET is
identical to the one the cached agent is pinned to. Every query still
re-resolves and re-runs the SSRF guard — that is the whole anti-rebinding
defence and is deliberately not cached; what is reused is the connection,
and only to addresses just re-validated this call.

## Why the cache key is a sorted, deduped SET, not an ordered sequence

`to_socket_addrs` hands back whatever order the resolver felt like, and a
round-robin keyserver reorders its A/AAAA records on essentially every
lookup — an ordered `==` therefore missed the cache every single time
against exactly the deployment that most needs it, silently degrading to
the per-query TLS handshake this field exists to avoid.

Set equality is also the honest predicate: the security property being
asserted is "these are the same validated addresses", which says nothing
about their order. The agent itself stays pinned to the order it was BUILT
with; that is safe because an equal set means every address it holds was
re-resolved and re-guarded this call.

## `a_reordered_but_identical_address_set_reuses_the_agent`

Catches the mutation that drops the sort/dedup from `agent_for`'s key (the
reversed order would then build a second agent) and, via the second half of
the test, the mutation that "fixes" order-sensitivity by comparing only
lengths or the first element — which would wrongly reuse an agent pinned to
a DIFFERENT address.
