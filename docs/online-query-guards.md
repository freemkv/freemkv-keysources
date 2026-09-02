# `src/online.rs` — `OnlineSource::query` pre-flight guards

## Refusing cleartext (`http://`)

The request body always carries base64 AACS key material
(inf/mkb/units/vid) and, when configured, a bearer token in a header — so an
`http://` POST hands both to any on-path observer, and the token is
replayable.

There is no legitimate plaintext deployment to preserve here: the address
guard rejects loopback, RFC1918, ULA and link-local, so an `http://` URL can
only ever reach the PUBLIC internet — the single worst case for cleartext. A
self-hosted keyserver on a LAN is already impossible by that guard, whatever
its scheme.

Still falls THROUGH to the next key source (a local keydb) — an `Err` here
does not block the chain, because `MultiSource::first_non_empty` returns any
later source's non-empty key set outright and only surfaces the failure
when nothing anywhere resolved. What it does stop is the silent case: a
cleartext URL is the same permanent operator fault as the address-guard
rejection (see `GuardFail`), so it gets the same verdict. Returning
`Ok(empty)` here made "we refused to ask" indistinguishable from "the
service answered and has no key".

## The three-way skip/fault/miss line (MKB cap, sample count)

Written out after the `Config`-was-quieter-than-`Unreachable` bug, in three
parts:

* NO URL AT ALL is not a fault: the operator did not configure an online
  source, so there is nothing to report. `Ok(empty)`, silently (the first
  guard in `query`).
* A bad URL — wrong scheme, mistyped port, guard-blocked address — is an
  OPERATOR FAULT. Every disc is affected, nothing was asked, and the fix is
  to edit the config. That is `Err`.
* An over-cap MKB or too few content samples is a property of THIS DISC's
  inputs, not a fault: the request cannot be *formed* for this disc, so this
  source has nothing for it and never will, whatever the operator does and
  however long they wait. Reporting that as `KeyServiceUnavailable` would
  send the operator waiting out an outage that does not exist — the same
  mislabelling in the opposite direction. These stay `Ok(empty)`, and stay
  logged.

Logging on the MKB-cap skip matters: a silent empty return there is
indistinguishable from "no key", so the real cause is surfaced (the cap is
64 MiB, far above any real trimmed MKB).

## `cleartext_http_url_is_refused_before_anything_is_sent`

Catches two mutations: sending the request anyway (the host is `.test` and
would surface as `Unreachable`, but the assertion would still hold, which is
why `too_few_samples_skips_the_request` guards the send-path ordering
separately) and — the one this test was rewritten for — returning
`Ok(Vec::new())`, which made a permanent cleartext misconfiguration
indistinguishable from a genuine miss. A later source's real key still wins
(`MultiSource::first_non_empty`), so refusing does not fail a rip the local
keydb can serve.
