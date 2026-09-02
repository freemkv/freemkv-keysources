# `src/online.rs` — SSRF guard

## Threat model

The keyserver URL is operator-supplied and the bearer token is confidential.
After `validate_keyserver_url` checked the host at config time, an attacker
who controls the keyserver's DNS can rebind it to 169.254.169.254 (cloud
metadata) or an RFC1918 host in the window between validation and the actual
POST, exfiltrating the key material and the Authorization token.

## Defence

Resolve the host once just before the POST, reject any blocked IP, and pin
the ureq connection to those validated addresses so a subsequent DNS flip
cannot redirect the request. Use `redirects(0)` so a public URL can't
30x-redirect to an internal host.

## Resolver wiring pitfall (`PinnedResolver`)

ureq 3 replaced v2's resolver closure with the `Resolver` trait. The agent
MUST be built through `Agent::with_parts` to take a custom one:
`Agent::new_with_config` silently keeps the default resolver, which would
send the request to live DNS and quietly reopen the rebinding window this
module exists to close. That failure is invisible — it has no symptom short
of an actual attack — so it is pinned by the test
`hardened_agent_connects_to_the_pinned_address_not_dns`.

## Why that test is structured the way it is

`resolve_and_guard` VALIDATES addresses; `hardened_agent` PINS them, so a
hostname cannot re-resolve to an internal address between validation and
connection. The validation half is well covered by other tests — but every
one of those still passes if the pinned resolver is never consulted, because
none of them makes a connection. Nothing else in the file proves the agent
honours the pin, and a mis-wired resolver fails OPEN: the connection quietly
falls back to live DNS and the rebinding window this module exists to close
is reopened, with no visible symptom.

The discriminator: pin the agent to a loopback listener the test owns, then
ask it for a host that CANNOT resolve — `.test` is reserved by RFC 6761 and
never resolves in the public DNS. Only a consulted resolver can turn that
name into a connection; a fallback to live DNS fails instead. No network is
touched, and `query` (whose guard blocks loopback by design) is not
involved — this drives `hardened_agent` directly.
