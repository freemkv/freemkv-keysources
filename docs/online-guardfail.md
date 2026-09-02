# `src/online.rs` — `GuardFail` classification details

## Malformed-port authority

A `host:port` authority whose port is not a u16 is a TYPO in the operator's
config — `https://example.com:notaport/keys`. This used to fall back to the
WHOLE authority as the hostname (port text included), which of course never
resolves, so the URL surfaced as `GuardFail::Unreachable` →
`Err(KeyServiceUnavailable)`: a standing misconfiguration reported as a
transient outage, the exact collapse `GuardFail`'s own doc says must not
happen, because the two halves demand OPPOSITE operator actions (fix the URL
vs. wait).

Reject it as `Config`, identical to the bracketed-IPv6 branch a few lines
above, which already returns `Config` for an unparseable port. Silently
substituting `default_port` would be worse still — it would ship the bearer
token and key material to a port the operator never configured.

## Guard-blocked address (`Config` arm, `resolve_and_guard`)

Log THAT the URL was rejected, never WHY: the guard's message names the
resolved address, and an internal address must not reach a log an operator
may paste into a bug report. The static label is enough to separate
"misconfigured/blocked key-service URL" from "this disc has no key", which
is the only distinction the operator needs here.

`error!`, not `warn!`, and `Err`, not `Ok(empty)`. This arm used to return
`Ok(Vec::new())`, which made the PERMANENT fault quieter than the transient
one directly above it: the service was never asked, yet the composition was
handed a clean empty and — with no other source holding the key — told the
operator `E7022 no key for this disc`. Same lie as the seven-hour 502, from
a config typo that never self-heals. A failure to ask is never evidence
about the disc, so it leaves as `Err`; `MultiSource::first_non_empty` still
lets a later source's real key win outright, so this cannot fail a rip that
the local keydb could have served.

NOTE (reported upstream): libfreemkv has no `KeyServiceMisconfigured` code,
so the permanent fault borrows the transient E7028. E7028's contract — "the
source never got as far as answering the question" — is exactly true here;
only its "transient, retry later" hint is wrong, and the `error!` log
carries the correcting detail until a 70xx config code exists.
