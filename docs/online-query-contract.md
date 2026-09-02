# `src/online.rs` — `OnlineSource::query` return contract

The return type draws THE distinction this source exists to draw:

* `Ok(non-empty)` — the service answered with a key.
* `Ok(empty)` — the service ANSWERED and holds no key for this disc, or this
  source had nothing to ask with (no service configured, a misconfigured
  URL, an over-cap MKB, too few samples). A genuine miss; the resolver moves
  to the next source and `E7022` is the right verdict.
* `Err(..)` — the service could not answer: unreachable, timed out, DNS
  failed, returned 5xx, rejected the token (401/403), rate-limited (429), or
  replied with something unreadable. NOTHING is known about whether a key
  exists. Collapsing this into `Ok(empty)` is the bug this signature fixes:
  a seven-hour run of HTTP 502s was reported to operators as
  `E7022 No key source has a decryption key for this disc`, and they went
  hunting for a VUK when the correct action was to wait.

`&self`: one-shot is the resolver's contract (each source's
`get_unit_keys` is called once), so no per-call latch is needed.
