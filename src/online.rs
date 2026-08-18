//! Online key-service source.

use std::io::Read;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::uks_from_vuk;
use base64::Engine;
use libfreemkv::aacs::types::UnitKey;
use libfreemkv::keysource::{DecodeSampleSet, ResolveCtx};
use libfreemkv::{Error, KeySource};
use ureq::config::Config;
use ureq::http::Uri;
use ureq::unversioned::resolver::{ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::{DefaultConnector, NextTimeout};

// Upper bound on the MKB forwarded to the key service — kept in lockstep with
// libfreemkv's `read_mkb_content` MAX_BYTES (64 MiB) so an MKB the library is
// willing to capture is never silently un-forwardable here (a trimmed MKB
// record stream is normally a few MiB; this is headroom, not an expected size).
const MAX_MKB_BYTES: usize = 64 * 1024 * 1024;
const TIMEOUT_SECS: u64 = 180;
/// Minimum encrypted-content samples the online source will send in one key
/// request — re-exported from the base crate ([`libfreemkv::keysource::MIN_SAMPLE_UNITS`])
/// so this crate and libfreemkv's own FMTS forensic query share ONE value.
///
/// The service identifies the key by which of the submitted units it decrypts,
/// so too few samples — especially on FMTS, where a segment interleaves several
/// variants at the unit level — can return a key that matches an incidental unit
/// rather than the one asked about (a false positive). A request carrying fewer
/// is refused (empty result → the resolver moves to the next source) rather than
/// sent and trusted. Kept public so callers that GATHER the samples (the CLI,
/// autorip) sample at least this many — sampling fewer guarantees the request is
/// skipped and the online source never consulted.
pub use libfreemkv::keysource::MIN_SAMPLE_UNITS;
/// Hard cap on the key-service response body. A real unit-key reply is a few
/// hundred bytes; bound the read so a malicious/compromised server can't drive
/// the client to OOM with an unbounded body.
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

// ── SSRF guard ──────────────────────────────────────────────────────────────
//
// The keyserver URL is operator-supplied and the bearer token is confidential.
// After validate_keyserver_url checked the host at config time, an attacker
// who controls the keyserver's DNS can rebind it to 169.254.169.254 (cloud
// metadata) or an RFC1918 host in the window between validation and the
// actual POST, exfiltrating the key material and the Authorization token.
//
// Defence: resolve the host once just before the POST, reject any blocked IP,
// and pin the ureq connection to those validated addresses so a subsequent DNS
// flip cannot redirect the request. Use redirects(0) so a public URL can't
// 30x-redirect to an internal host.

/// True when `ip` must never be the target of an outbound key-service POST.
/// Blocks loopback, link-local (incl. 169.254.0.0/16 cloud metadata), all
/// RFC1918 private ranges, carrier-grade NAT, multicast, unspecified, and
/// IPv4-mapped equivalents for all of the above.
fn is_blocked_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local() // 169.254.0.0/16, incl. 169.254.169.254
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                // Carrier-grade NAT 100.64.0.0/10.
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 0x40)
                // "This network" 0.0.0.0/8.
                || v4.octets()[0] == 0
                // Class E reserved 240.0.0.0/4.
                || v4.octets()[0] >= 240
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // Unique-local fc00::/7.
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // Link-local fe80::/10.
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                // IPv4-mapped (::ffff:x.x.x.x) and IPv4-compatible (::x.x.x.x,
                // deprecated by RFC 4291 §2.5.5.1) — to_ipv4() returns Some for
                // both forms; re-check the embedded address as IPv4.
                || v6
                    .to_ipv4()
                    .map(|m| is_blocked_ip(&IpAddr::V4(m)))
                    == Some(true)
        }
    }
}

/// Why [`resolve_and_guard`] rejected a URL. The two halves demand OPPOSITE
/// operator actions, so they must not be collapsed: a `Config` rejection is a
/// standing misconfiguration that will never fix itself, while `Unreachable` is
/// the key service being down right now — exactly the condition this module's
/// callers must not report as "this disc has no key".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GuardFail {
    /// Malformed URL, bad scheme, or a host that is (or resolves to) a
    /// non-public address. Operator configuration; retrying changes nothing.
    Config,
    /// The host did not resolve — DNS failure or DNS timeout. The service is
    /// unreachable; nothing is known about this disc's key. Transient.
    Unreachable,
}

/// Resolve `url`'s host and validate every resulting address against the SSRF
/// guard. Returns the pinned socket addresses (for use with a custom ureq
/// resolver) on success, or the rejection reason plus an explanatory message.
///
/// SECURITY: the message names the resolved address on an SSRF rejection and is
/// for the CONFIG-time caller only — never log it (see the call site in
/// [`OnlineSource::query`]).
fn resolve_and_guard(url: &str) -> Result<Vec<SocketAddr>, (GuardFail, String)> {
    let rest = if let Some(r) = url.strip_prefix("https://") {
        (r, 443u16)
    } else if let Some(r) = url.strip_prefix("http://") {
        (r, 80u16)
    } else {
        return Err((
            GuardFail::Config,
            "URL must start with http:// or https://".into(),
        ));
    };
    let (authority, default_port) = rest;
    let authority = authority.split(['/', '?', '#']).next().unwrap_or(authority);
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    if authority.is_empty() {
        return Err((GuardFail::Config, "URL has no host".into()));
    }
    let (host, port): (String, u16) = if let Some(stripped) = authority.strip_prefix('[') {
        match stripped.split_once(']') {
            Some((h, after)) => {
                let p = after
                    .strip_prefix(':')
                    .map(|s| {
                        s.parse::<u16>()
                            .map_err(|_| (GuardFail::Config, "invalid port".to_string()))
                    })
                    .transpose()?
                    .unwrap_or(default_port);
                (h.to_string(), p)
            }
            None => return Err((GuardFail::Config, "malformed IPv6 host".into())),
        }
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        match p.parse::<u16>() {
            Ok(p) => (h.to_string(), p),
            // A `host:port` authority whose port is not a u16 is a TYPO in the
            // operator's config — `https://example.com:notaport/keys`. This used
            // to fall back to the WHOLE authority as the hostname (port text
            // included), which of course never resolves, so the URL surfaced as
            // `GuardFail::Unreachable` → `Err(KeyServiceUnavailable)`: a standing
            // misconfiguration reported as a transient outage, the exact
            // collapse `GuardFail`'s own doc says must not happen, because the
            // two halves demand OPPOSITE operator actions (fix the URL vs. wait).
            // Reject it as `Config`, identical to the bracketed-IPv6 branch a few
            // lines above, which already returns `Config` for an unparseable
            // port. Silently substituting `default_port` would be worse still —
            // it would ship the bearer token and key material to a port the
            // operator never configured.
            Err(_) => return Err((GuardFail::Config, "invalid port".into())),
        }
    } else {
        (authority.to_string(), default_port)
    };
    if host.is_empty() {
        return Err((GuardFail::Config, "URL has no host".into()));
    }
    // `to_socket_addrs` is a BLOCKING DNS lookup that can hang for the OS
    // resolver timeout (tens of seconds) and freeze the rip thread that called
    // query(). Run it on a spawned thread and join with a bounded deadline;
    // on timeout return Err so query() yields None and the rip proceeds
    // (mirrors the bounded-resolve in autorip/libfreemkv).
    let addrs: Vec<SocketAddr> = {
        use std::sync::mpsc;
        const DNS_TIMEOUT: Duration = Duration::from_secs(10);
        let host = host.clone();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let res = (host.as_str(), port)
                .to_socket_addrs()
                .map(|it| it.collect::<Vec<SocketAddr>>());
            // Receiver may be gone after the timeout — ignore the send error.
            let _ = tx.send(res);
        });
        match rx.recv_timeout(DNS_TIMEOUT) {
            Ok(Ok(addrs)) => addrs,
            Ok(Err(e)) => {
                return Err((
                    GuardFail::Unreachable,
                    format!("could not resolve host: {e}"),
                ));
            }
            Err(_) => return Err((GuardFail::Unreachable, "DNS resolution timed out".into())),
        }
    };
    if addrs.is_empty() {
        return Err((
            GuardFail::Unreachable,
            "host did not resolve to any address".into(),
        ));
    }
    for a in &addrs {
        if is_blocked_ip(&a.ip()) {
            return Err((
                GuardFail::Config,
                format!(
                    "refusing to connect to non-public address {} (SSRF guard)",
                    a.ip()
                ),
            ));
        }
    }
    Ok(addrs)
}

/// Validate a key-service base URL before it is handed to [`OnlineSource`].
/// Requires an `http(s)` scheme, extracts the host, and rejects any host that
/// is — or resolves to — a loopback / link-local (incl. the 169.254.169.254
/// cloud-metadata endpoint) / RFC1918 / ULA / other non-public address (SSRF /
/// metadata-exfiltration guard). Returns `Ok(())` on success so a caller can
/// gate `OnlineSource` construction; the error string explains the rejection.
///
/// This is the *config-time* check. [`OnlineSource`] independently re-resolves
/// and re-guards the host immediately before each POST (and pins the validated
/// addresses), so a DNS rebind between this check and the request can't redirect
/// the key material. The two share the SAME `is_blocked_ip` classifier and the
/// SAME bounded-resolve, so their verdicts never diverge — the reason this lives
/// here, in the key-source crate, rather than being re-rolled per application.
pub fn validate_keyserver_url(url: &str) -> Result<(), String> {
    resolve_and_guard(url).map(|_| ()).map_err(|(_, msg)| msg)
}

/// ureq's `ResolvedSocketAddrs` is a fixed 16-slot array and its `push` writes
/// straight into that array, so handing it a 17th address is an out-of-bounds
/// panic — in the rip thread, on a host that merely publishes a lot of A
/// records. Keep the first 16; every one of them was validated by
/// [`resolve_and_guard`], so a subset is still safe, just less redundant.
const MAX_PINNED_ADDRS: usize = 16;

/// The pinned-address resolver behind [`hardened_agent`].
///
/// ureq 3 replaced v2's resolver closure with this trait. The agent MUST be
/// built through `Agent::with_parts` to take one: `Agent::new_with_config`
/// silently keeps the default resolver, which would send the request to live
/// DNS and quietly reopen the rebinding window this module exists to close.
/// That failure is invisible — it has no symptom short of an actual attack —
/// so it is pinned by `hardened_agent_connects_to_the_pinned_address_not_dns`.
#[derive(Debug)]
struct PinnedResolver(Vec<SocketAddr>);

impl Resolver for PinnedResolver {
    fn resolve(
        &self,
        _uri: &Uri,
        _config: &Config,
        _timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        let mut out = self.empty();
        for addr in self.0.iter().take(MAX_PINNED_ADDRS) {
            out.push(*addr);
        }
        if out.is_empty() {
            // The trait's contract: at least one address, or this error.
            return Err(ureq::Error::HostNotFound);
        }
        Ok(out)
    }
}

/// Build a ureq agent that follows zero redirects (so a public URL can't
/// 30x-redirect to an internal host) and pins DNS resolution to `pinned`
/// (the addresses already validated by [`resolve_and_guard`]).
fn hardened_agent(pinned: Vec<SocketAddr>) -> ureq::Agent {
    let config = Config::builder()
        .max_redirects(0)
        .timeout_connect(Some(Duration::from_secs(10)))
        .timeout_recv_response(Some(Duration::from_secs(TIMEOUT_SECS)))
        .build();
    // `with_parts`, never `new_with_config` — see [`PinnedResolver`].
    ureq::Agent::with_parts(config, DefaultConnector::new(), PinnedResolver(pinned))
}

pub struct OnlineSource {
    base_url: String,
    secret: String,
    /// The last agent built, with the address set it was pinned to.
    ///
    /// A `query` used to build a FRESH `ureq::Agent` every call, and an FMTS disc
    /// makes two calls per rip (`get_unit_keys` + `get_fmts_indexes`), so it paid
    /// two TLS handshakes to the same host for no reason — an agent owns the
    /// connection pool, and a discarded agent discards the pooled, already
    /// negotiated TLS connection with it.
    ///
    /// SECURITY: the agent is reused ONLY when the freshly resolved + guarded
    /// address set is IDENTICAL to the one the cached agent is pinned to. Every
    /// query still re-resolves and re-runs the SSRF guard — that is the whole
    /// anti-rebinding defence and is deliberately not cached; what is reused is
    /// the connection, and only to addresses just re-validated this call.
    agent: Mutex<Option<(Vec<SocketAddr>, Arc<ureq::Agent>)>>,
}

impl OnlineSource {
    pub fn new(base_url: impl Into<String>, secret: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            secret: secret.into(),
            agent: Mutex::new(None),
        }
    }

    /// The agent pinned to `pinned` — the cached one when the address set is
    /// unchanged, a fresh one otherwise (which then becomes the cached one).
    /// Poisoning is recovered from: a panic elsewhere must not make every later
    /// key request panic.
    fn agent_for(&self, pinned: Vec<SocketAddr>) -> Arc<ureq::Agent> {
        let mut guard = self.agent.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((addrs, agent)) = guard.as_ref()
            && *addrs == pinned
        {
            return agent.clone();
        }
        let agent = Arc::new(hardened_agent(pinned.clone()));
        *guard = Some((pinned, agent.clone()));
        agent
    }

    /// The server-resolved Unit Keys for this disc. Runs exactly one network
    /// round-trip. The service returns either a terminal `UK` (used directly) or
    /// a `VUK` (derived to Unit Keys locally via the disc's encrypted title keys
    /// from `ctx`).
    ///
    /// The return type draws THE distinction this source exists to draw:
    ///
    /// * `Ok(non-empty)` — the service answered with a key.
    /// * `Ok(empty)` — the service ANSWERED and holds no key for this disc, or
    ///   this source had nothing to ask with (no service configured, a
    ///   misconfigured URL, an over-cap MKB, too few samples). A genuine miss;
    ///   the resolver moves to the next source and `E7022` is the right verdict.
    /// * `Err(..)` — the service could not answer: unreachable, timed out, DNS
    ///   failed, returned 5xx, rejected the token (401/403), rate-limited (429),
    ///   or replied with something unreadable. NOTHING is known about whether a
    ///   key exists. Collapsing this into `Ok(empty)` is the bug this signature
    ///   fixes: a seven-hour run of HTTP 502s was reported to operators as
    ///   `E7022 No key source has a decryption key for this disc`, and they went
    ///   hunting for a VUK when the correct action was to wait.
    ///
    /// `&self`: one-shot is the resolver's contract (each source's
    /// `get_unit_keys` is called once), so no per-call latch is needed.
    fn query(&self, ctx: &dyn ResolveCtx) -> Result<Vec<UnitKey>, Error> {
        // No configured service: nothing to resolve.
        if self.base_url.is_empty() {
            return Ok(Vec::new());
        }
        // Refuse to transmit over plaintext. The request body always carries
        // base64 AACS key material (inf/mkb/units/vid) and, when configured, a
        // bearer token in a header — so an `http://` POST hands both to any
        // on-path observer, and the token is replayable.
        //
        // There is no legitimate plaintext deployment to preserve here: the
        // address guard below rejects loopback, RFC1918, ULA and link-local, so
        // an `http://` URL can only ever reach the PUBLIC internet — the single
        // worst case for cleartext. A self-hosted keyserver on a LAN is already
        // impossible by that guard, whatever its scheme.
        //
        // Falls through to the next key source (a local keydb) rather than
        // failing the rip, and says why — misconfiguration should be visible,
        // not silently indistinguishable from "this disc has no key".
        if !self.base_url.starts_with("https://") {
            tracing::warn!(
                target: "freemkv::keysource",
                "key-service URL is not https:// — refusing to send key material \
                 and credentials in cleartext; skipping the online source"
            );
            return Ok(Vec::new());
        }
        let mkb = ctx.mkb().unwrap_or(&[]);
        // An over-cap MKB cannot be forwarded — bound the body. Log it: a silent
        // empty return here is indistinguishable from "no key", so surface the
        // real cause (the cap is 64 MiB, far above any real trimmed MKB).
        if mkb.len() > MAX_MKB_BYTES {
            tracing::warn!(
                target: "freemkv::keysource",
                mkb_len = mkb.len(),
                cap = MAX_MKB_BYTES,
                "MKB exceeds the key-service forward cap; skipping the online source for this disc (no key from online)"
            );
            return Ok(Vec::new());
        }
        // Gather encrypted-content samples and prove the minimum by TYPE: a
        // `DecodeSampleSet` only exists with >= MIN_SAMPLE_UNITS units, so from here
        // on the request cannot be built under-sized. The service resolves a key by
        // which submitted unit it decrypts, so a request carrying too few can return
        // a key matching an incidental unit (a false positive, seen on FMTS variant
        // units) — too few → skip this source and fall through to the next.
        let gathered = ctx.samples(64).unwrap_or_default();
        let n = gathered.len();
        let Some(samples) = DecodeSampleSet::new(gathered) else {
            tracing::info!(
                target: "freemkv::keysource",
                samples = n,
                min = MIN_SAMPLE_UNITS,
                "too few content samples for a reliable online key request; skipping the online source"
            );
            return Ok(Vec::new());
        };
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut body = serde_json::json!({
            // Raw Unit_Key_RO.inf, verbatim — the server does its own parse /
            // derivation, so it needs the unparsed blob (not enc_title_keys).
            "inf_b64": b64.encode(ctx.unit_key_ro()),
            "mkb_b64": b64.encode(mkb),
        });
        if let Some(vid) = ctx.vid() {
            body["vid_b64"] = serde_json::Value::String(b64.encode(vid.0));
        }
        // Encrypted-content samples for server-side ciphertext validation (already
        // gathered + minimum-checked above).
        body["units_b64"] = serde_json::Value::Array(
            samples
                .units()
                .iter()
                .map(|u| serde_json::Value::String(b64.encode(u)))
                .collect(),
        );
        // The disc's own title (UDF/ISO volume id), plain text. The key service
        // catalogs it by disc_hash (its disc-titles.json) — independent of keydb.
        if let Some(label) = ctx.title().map(str::trim)
            && !label.is_empty()
        {
            body["title"] = serde_json::Value::String(label.to_string());
        }
        // Resolve + SSRF-guard the host just before the POST; pin the
        // validated addresses into a redirect-disabled agent so a DNS
        // rebind between config time and fetch time can't redirect the
        // request (and the bearer token) to an internal/metadata host.
        let pinned = match resolve_and_guard(&self.base_url) {
            Ok(addrs) => addrs,
            // A host that did not RESOLVE is the service being unreachable, not a
            // bad URL — DNS failure and DNS timeout are exactly what a key-service
            // outage looks like from here, and reporting them as a genuine miss is
            // the same conflation as reporting a 502 that way.
            Err((GuardFail::Unreachable, _)) => {
                tracing::warn!(
                    target: "freemkv::keysource",
                    phase = "keyserver_post",
                    "key-service host did not resolve (DNS failure or timeout); \
                     the service is unreachable, not out of keys"
                );
                return Err(Error::KeyServiceUnavailable);
            }
            Err((GuardFail::Config, _)) => {
                // Log THAT the URL was rejected, never WHY: the guard's message
                // names the resolved address, and an internal address must not
                // reach a log an operator may paste into a bug report. The
                // static label is enough to separate "misconfigured/blocked
                // key-service URL" from "this disc has no key", which is the
                // only distinction the operator needs here.
                tracing::warn!(
                    target: "freemkv::keysource",
                    phase = "keyserver_post",
                    "key-service URL failed the address guard; skipping the online source"
                );
                return Ok(Vec::new());
            }
        };
        let agent = self.agent_for(pinned);
        let mut req = agent.post(&self.base_url);
        if let Some(value) = bearer_header(&self.secret) {
            req = req.header("Authorization", &value);
        }
        // Begin/end around the keyserver round-trip — a slow or unresponsive
        // service is the suspected DVD-scan hang. The agent is built with a
        // 10s connect + bounded read timeout (see `hardened_agent`), so this
        // call can never block forever; we log the timing so a slow round-trip
        // is visible. SECURITY: never log `body` — it carries base64 key
        // material.
        tracing::info!(target: "freemkv::keysource", phase = "keyserver_post", "begin");
        let post_t0 = std::time::Instant::now();
        let sent = req.send_json(body);
        interpret_reply(sent, ctx, post_t0.elapsed().as_millis() as u64)
    }
}

/// Map a key-service HTTP status the client never asked for into the operator
/// action it implies. THE table this fix exists for — each arm is a different
/// thing for a person to do, and none of them is "your disc has no key":
///
/// * 401 / 403 → the token is wrong or expired. Fix the credentials.
/// * 429 → rate limited. Back off and retry more slowly.
/// * 5xx → the service is down. Wait; this is the seven-hour-502 case.
/// * anything else non-2xx → the service is misbehaving in a way this client
///   cannot interpret. Treated as unavailable, deliberately: the genuine miss is
///   a **200 with no key in the body**, so a non-2xx status is never evidence
///   about this disc, and guessing "no key" from one is the original bug.
fn classify_http_status(code: u16) -> Error {
    match code {
        401 | 403 => Error::KeyServiceUnauthorized,
        429 => Error::KeyServiceRateLimited,
        _ => Error::KeyServiceUnavailable,
    }
}

/// Turn the raw outcome of the key-service POST into this source's answer.
///
/// Split out of [`OnlineSource::query`] so the reply → verdict mapping is
/// testable WITHOUT a network: the SSRF guard in `resolve_and_guard` blocks
/// loopback by design, so a stub HTTP server on 127.0.0.1 can never be reached
/// through `query`, and this seam is the only honest way to drive "the service
/// returned 502" and "the service returned 200 with no entry" through the same
/// code the rip uses.
///
/// `elapsed_ms` is the round-trip time, for the timing logs only.
///
/// SECURITY: logs status codes, byte counts and static labels only. The request
/// body carries base64 AACS key material and the reply carries keys — neither is
/// ever logged, and nor is a serde parse error (it quotes the offending input).
fn interpret_reply(
    sent: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
    ctx: &dyn ResolveCtx,
    elapsed_ms: u64,
) -> Result<Vec<UnitKey>, Error> {
    let mut resp = match sent {
        Ok(r) => r,
        Err(e) => {
            // Record the HTTP status when the service actually answered:
            // 401/403 (bad or expired token), 429 (rate limited) and
            // 5xx (service down) are completely different operator actions,
            // and collapsing them into one line is why a 502 was read as
            // "this disc has no key". The status is the service's own
            // response code — it carries no key material and no address.
            // A transport error has no status; report it as such rather
            // than inventing one.
            //
            // Each arm now RETURNS the classified error instead of an empty
            // vec, so the distinction survives past this function.
            return Err(match e {
                ureq::Error::StatusCode(code) => {
                    let err = classify_http_status(code);
                    tracing::warn!(
                        target: "freemkv::keysource",
                        phase = "keyserver_post",
                        http_status = code,
                        error_code = err.code(),
                        elapsed_ms,
                        "key service returned an HTTP error; no ANSWER from online (not a missing key)"
                    );
                    err
                }
                // ureq 3 fans v2's single `Transport` variant out into `Io`,
                // `Timeout`, `Tls`, `Protocol`, `HostNotFound` and more, and the
                // enum is non_exhaustive. Every one of them means the same thing
                // here — nothing answered, so nothing is known about this disc —
                // and a catch-all is the only shape that stays correct as the
                // enum grows. The status arm above is the sole case where the
                // service actually replied.
                _ => {
                    tracing::warn!(
                        target: "freemkv::keysource",
                        phase = "keyserver_post",
                        elapsed_ms,
                        "key service unreachable (connect/timeout/TLS); no ANSWER from online (not a missing key)"
                    );
                    Error::KeyServiceUnavailable
                }
            });
        }
    };
    tracing::info!(
        target: "freemkv::keysource",
        phase = "keyserver_post",
        elapsed_ms,
        "end"
    );
    // Bounded read: cap the body so a hostile server can't OOM the client.
    // Reading MAX_RESPONSE_BYTES+1 lets us detect (and reject) an over-cap body.
    let mut buf = Vec::new();
    if resp
        .body_mut()
        .as_reader()
        .take(MAX_RESPONSE_BYTES as u64 + 1)
        .read_to_end(&mut buf)
        .is_err()
        || buf.len() > MAX_RESPONSE_BYTES
    {
        // Length only — never the body, which carries base64 key material.
        // A truncated / over-cap body is the service failing mid-answer: the
        // question went unanswered, so this is a source failure, not a miss.
        tracing::warn!(
            target: "freemkv::keysource",
            phase = "keyserver_post",
            cap = MAX_RESPONSE_BYTES,
            "key-service reply was unreadable or over the size cap; no ANSWER from online"
        );
        return Err(Error::KeyServiceUnavailable);
    }
    let json: serde_json::Value = match serde_json::from_slice(&buf) {
        Ok(j) => j,
        Err(_) => {
            // Never log the parse error or the payload: a serde message
            // quotes the offending input, which here is key material.
            // Unparseable is not "no key" — it is the service answering in a
            // language this client does not speak. Transient / a service bug.
            tracing::warn!(
                target: "freemkv::keysource",
                phase = "keyserver_post",
                "key-service reply was not valid JSON; no ANSWER from online"
            );
            return Err(Error::KeyServiceUnavailable);
        }
    };
    // `UK` is an ARRAY of hex keys (the service always returns an array now,
    // even of one). A single element is the base Unit Key. A full set (one per
    // forensic index, ordered index 1..N) is returned for a forensic sample.
    // Preserve array order and tag each key with its array position, so the
    // caller can map position → index (element i = index i+1). A bare string is
    // still accepted for backward compatibility.
    if let Some(uk) = json.get("UK") {
        let mut out = Vec::new();
        if let Some(s) = uk.as_str() {
            if let Some(k) = parse_uk(s) {
                out.push(UnitKey::new(0, k));
            }
        } else if let Some(arr) = uk.as_array() {
            // A forensic set is only usable COMPLETE: the mux trusts any
            // non-empty result as the whole set and never assumes 32 (see
            // `get_fmts_indexes`). Skipping an unparseable element would
            // hand back a short set that silently omits an index, so a
            // malformed element rejects the whole reply — that is a service
            // bug, not a usable answer, and therefore a source FAILURE.
            let mut bad = false;
            for (i, v) in arr.iter().enumerate() {
                match v.as_str().and_then(parse_uk) {
                    Some(k) => out.push(UnitKey::new(i as u32, k)),
                    None => {
                        bad = true;
                        break;
                    }
                }
            }
            if bad {
                tracing::warn!(
                    target: "freemkv::keysource",
                    phase = "keyserver_post",
                    keys = arr.len(),
                    "key-service returned a malformed key in the UK set; rejecting the whole reply"
                );
                return Err(Error::KeyServiceUnavailable);
            }
        }
        if !out.is_empty() {
            return Ok(out);
        }
    }
    // A VUK is derived to the terminal keys locally, via the disc's
    // encrypted title keys from the context — the library owns the crypto.
    if let Some(vuk) = json.get("VUK").and_then(|u| u.as_str()).and_then(parse_uk) {
        match ctx.enc_title_keys() {
            Ok(enc) => return Ok(uks_from_vuk(&vuk, enc)),
            Err(_) => {
                // The SERVICE answered correctly; the DISC's encrypted title keys
                // are what could not be read. Not a service failure, so not an
                // `Err` from this source — the disc-side reason is the library's
                // to report.
                tracing::warn!(
                    target: "freemkv::keysource",
                    phase = "keyserver_post",
                    "key-service returned a VUK but the disc's encrypted title keys \
                     are unreadable; cannot derive unit keys"
                );
                return Ok(Vec::new());
            }
        }
    }
    // The genuine miss — and the ONLY path that returns `Ok(empty)` from a
    // completed round-trip. Logged distinctly from every failure above so an
    // operator can tell "the service has no key for this disc" from "the
    // service did not answer"; collapsing the two is what made a 502 look like
    // a missing key. This is the one case where `E7022` is the truth.
    tracing::info!(
        target: "freemkv::keysource",
        phase = "keyserver_post",
        "key service has no key for this disc"
    );
    Ok(Vec::new())
}

impl KeySource for OnlineSource {
    /// Base per-CPS-unit Unit Keys: submit the ctx's content samples and take the
    /// service's reply (a terminal `UK`, or a `VUK` derived locally). One network
    /// round-trip. An empty `Ok` means the service ANSWERED and holds no key; an
    /// `Err` means it could not answer (see [`OnlineSource::query`]). Both let the
    /// resolver try the next source — the difference is what the operator is told
    /// when no source has one.
    fn get_unit_keys(&self, ctx: &dyn ResolveCtx) -> Result<Vec<UnitKey>, Error> {
        self.query(ctx)
    }

    /// AACS 2.1 forensic index set: the mux injects an index-1 single-phase anchor
    /// batch as the ctx's samples; the service maps it to the full ordered set of
    /// forensic index keys, tagged by array position (element `i` → forensic index
    /// `i + 1`). Same one round-trip as [`get_unit_keys`](Self::get_unit_keys) —
    /// the difference is purely which samples the mux gathered and how the caller
    /// reads the reply. The count is whatever the service returns; the mux trusts
    /// any non-empty result as the complete set and never assumes 32.
    fn get_fmts_indexes(&self, ctx: &dyn ResolveCtx) -> Result<Vec<UnitKey>, Error> {
        self.query(ctx)
    }

    fn label(&self) -> &'static str {
        "online"
    }

    // host_certs: the no-op default. The online service does not serve host
    // certs today (no client-side fetch, no server-side endpoint), so the OEM
    // cert route falls back to whatever other source (e.g. the keydb) supplies.
    // No network is touched. (Future task: online host-cert serving.)
}

/// The `Authorization` header value for a key-service request, or `None` when no
/// secret/token is configured (the request then goes out unauthenticated). The
/// token — passed as `--key-auth` on the CLI or `keyserver_secret` in autorip —
/// is sent verbatim as an HTTP Bearer credential.
fn bearer_header(secret: &str) -> Option<String> {
    if secret.is_empty() {
        None
    } else {
        Some(format!("Bearer {secret}"))
    }
}

fn parse_uk(hex: &str) -> Option<[u8; 16]> {
    // The one workspace hex parser: byte-based (rejects sign chars / multi-byte),
    // 32 hex digits → [u8; 16], with an optional 0x/0X prefix tolerated.
    libfreemkv::hex::parse_hex_fixed::<16>(hex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // ── is_blocked_ip ──────────────────────────────────────────────────────

    #[test]
    fn ssrf_guard_blocks_loopback_private_and_metadata() {
        // Loopback.
        assert!(is_blocked_ip(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        // RFC1918 private ranges.
        assert!(is_blocked_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_blocked_ip(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))));
        assert!(is_blocked_ip(&IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        // Cloud-metadata anycast (link-local 169.254.0.0/16).
        assert!(is_blocked_ip(&IpAddr::V4(Ipv4Addr::new(
            169, 254, 169, 254
        ))));
        // Carrier-grade NAT 100.64.0.0/10 and "this network" 0.0.0.0/8.
        assert!(is_blocked_ip(&IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(is_blocked_ip(&IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))));
        // IPv6 loopback, ULA fc00::/7, link-local fe80::/10.
        assert!(is_blocked_ip(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(is_blocked_ip(&IpAddr::V6(Ipv6Addr::new(
            0xfd00, 0, 0, 0, 0, 0, 0, 1
        ))));
        assert!(is_blocked_ip(&IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1
        ))));
        // IPv4-mapped loopback ::ffff:127.0.0.1 must also be blocked.
        assert!(is_blocked_ip(&IpAddr::V6(
            Ipv4Addr::new(127, 0, 0, 1).to_ipv6_mapped()
        )));
        // IPv4-compatible loopback ::127.0.0.1 (= ::7f00:1, deprecated RFC
        // 4291 §2.5.5.1) — to_ipv4_mapped() misses this form; to_ipv4() catches
        // both mapped and compatible.
        assert!(is_blocked_ip(&IpAddr::V6(Ipv6Addr::new(
            0, 0, 0, 0, 0, 0, 0x7f00, 0x0001
        ))));
        // Class E reserved 240.0.0.0/4.
        assert!(is_blocked_ip(&IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1))));
        assert!(is_blocked_ip(&IpAddr::V4(Ipv4Addr::new(
            255, 255, 255, 254
        ))));
    }

    #[test]
    fn ssrf_guard_allows_public_ips() {
        assert!(!is_blocked_ip(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_blocked_ip(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        // Public IPv6 (Cloudflare DNS 2606:4700:4700::1111).
        assert!(!is_blocked_ip(&IpAddr::V6(Ipv6Addr::new(
            0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111
        ))));
    }

    /// The online source serves NO host certs today (no fetch, no endpoint).
    /// `host_certs()` must return empty WITHOUT touching the network, so the OEM
    /// route falls back to whatever else (the keydb) supplies. Uses a non-empty
    /// base URL to prove the empty result isn't merely "no service configured" —
    /// it's the deliberate no-op stub.
    #[test]
    fn host_certs_is_noop_empty_no_network() {
        let src = OnlineSource::new("http://example.test/keys", "secret");
        assert!(
            KeySource::host_certs(&src, None).is_empty(),
            "online host_certs must be an empty no-op (no network)"
        );
        assert!(
            KeySource::host_certs(&src, Some(68)).is_empty(),
            "still empty regardless of the MKB generation"
        );
    }

    // ── resolve_and_guard ──────────────────────────────────────────────────

    #[test]
    fn resolve_and_guard_rejects_internal_literals() {
        // Numeric literals resolve without DNS — must still be rejected.
        assert!(resolve_and_guard("http://127.0.0.1/keys").is_err());
        assert!(resolve_and_guard("http://169.254.169.254/latest/meta-data/").is_err());
        assert!(resolve_and_guard(&format!("http://{}.{}.{}.{}:8080/keys", 10, 0, 0, 5)).is_err());
        assert!(resolve_and_guard(&format!("https://{}.{}.{}.{}/keys", 192, 168, 0, 1)).is_err());
        assert!(resolve_and_guard("http://[::1]:9000/keys").is_err());
    }

    #[test]
    fn resolve_and_guard_rejects_bad_scheme() {
        assert!(resolve_and_guard("ftp://example.com/keys").is_err());
        assert!(resolve_and_guard("file:///etc/passwd").is_err());
        assert!(resolve_and_guard("not a url").is_err());
        assert!(resolve_and_guard("").is_err());
    }

    #[test]
    fn resolve_and_guard_accepts_public_literal() {
        // Public numeric hosts resolve without DNS — must be accepted.
        let addrs = resolve_and_guard("https://8.8.8.8/keys").expect("public IP must be accepted");
        assert!(!addrs.is_empty());
        assert_eq!(addrs[0].port(), 443);

        let addrs =
            resolve_and_guard("http://1.1.1.1:8080/keys").expect("public IP with port accepted");
        assert!(!addrs.is_empty());
        assert_eq!(addrs[0].port(), 8080);
    }

    // ── the pin is actually consulted ──────────────────────────────────────
    //
    // `resolve_and_guard` VALIDATES addresses; `hardened_agent` PINS them, so a
    // hostname cannot re-resolve to an internal address between validation and
    // connection. The validation half is well covered above — but every one of
    // those tests still passes if the pinned resolver is never consulted,
    // because none of them makes a connection. Nothing else in this file proves
    // the agent honours the pin, and a mis-wired resolver fails OPEN: the
    // connection quietly falls back to live DNS and the rebinding window this
    // module exists to close is reopened, with no visible symptom.
    //
    // The discriminator: pin the agent to a loopback listener this test owns,
    // then ask it for a host that CANNOT resolve — `.test` is reserved by
    // RFC 6761 and never resolves in the public DNS. Only a consulted resolver
    // can turn that
    // name into a connection; a fallback to live DNS fails instead. No network
    // is touched, and `query` (whose guard blocks loopback by design) is not
    // involved — this drives `hardened_agent` directly.
    #[test]
    fn hardened_agent_connects_to_the_pinned_address_not_dns() {
        use std::io::Write as _;
        use std::net::TcpListener;
        use std::sync::mpsc;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind stub listener");
        let pinned = listener.local_addr().expect("stub listener address");
        let (tx, rx) = mpsc::channel();

        let server = std::thread::spawn(move || {
            let (mut sock, _peer) = listener.accept().expect("stub listener accept failed");
            // Signal that a connection ARRIVED before doing anything else: that
            // arrival, on this exact socket, is the fact under test.
            let _ = tx.send(());
            // Drain the request head, then answer with the smallest valid reply.
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                match sock.read(&mut byte) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => head.push(byte[0]),
                }
            }
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
            let _ = sock.flush();
            head
        });

        let sent = hardened_agent(vec![pinned])
            .post("http://keyserver.test/keys")
            .send("{}");

        // 1. The connection reached the pinned socket at all. Checked FIRST so
        //    a mis-wired resolver reports the resolver, not a confusing
        //    downstream symptom.
        rx.recv_timeout(Duration::from_secs(10)).expect(
            "hardened_agent never connected to the pinned address — the custom \
             resolver is not being consulted, so a DNS rebind between the guard \
             and the POST can still redirect the key material",
        );
        // 2. The whole round-trip completed through it. Had the agent fallen
        //    back to live DNS, an unresolvable host is an error, never a 200.
        let resp = sent.expect("the pinned round-trip must complete");
        assert_eq!(resp.status(), 200, "the stub server's reply must come back");
        // 3. The pin redirected the CONNECTION without rewriting the request:
        //    the original host still travels in the Host header.
        let head = server.join().expect("stub server panicked");
        let head = String::from_utf8_lossy(&head);
        assert!(
            head.contains("keyserver.test"),
            "the pinned agent must still address the original host; got: {head}"
        );
    }

    // ── bearer_header ──────────────────────────────────────────────────────

    #[test]
    fn bearer_header_formats_token_and_omits_when_empty() {
        // A configured token becomes a Bearer credential, sent verbatim.
        assert_eq!(
            bearer_header("s3cr3t-token"),
            Some("Bearer s3cr3t-token".to_string())
        );
        // No token → no Authorization header (request goes out unauthenticated).
        assert_eq!(bearer_header(""), None);
    }

    // ── validate_keyserver_url ─────────────────────────────────────────────

    #[test]
    fn validate_keyserver_url_rejects_internal_and_bad_scheme() {
        // Mirrors resolve_and_guard: the public wrapper rejects the same hosts.
        assert!(validate_keyserver_url("http://127.0.0.1/keys").is_err());
        assert!(validate_keyserver_url("http://169.254.169.254/latest/meta-data/").is_err());
        assert!(validate_keyserver_url(&format!("http://{}.{}.{}.{}/k", 10, 0, 0, 5)).is_err());
        assert!(validate_keyserver_url("http://[::1]:9000/keys").is_err());
        assert!(validate_keyserver_url("ftp://example.com/keys").is_err());
        assert!(validate_keyserver_url("").is_err());
        // A public literal IP passes (no DNS needed, deterministic).
        assert!(validate_keyserver_url("https://8.8.8.8/keys").is_ok());
    }

    // ── the reply → verdict mapping (THE defect) ───────────────────────────
    //
    // Driven through `interpret_reply`, the seam `query` hands its round-trip
    // to. A stub HTTP server is NOT usable here: `resolve_and_guard` blocks
    // loopback by design (SSRF guard), so 127.0.0.1 can never be reached through
    // `query`, and pointing the test at a public host would make it a network
    // test. Everything from the response onward is this function.

    /// A `ResolveCtx` that carries nothing — enough for the reply paths that do
    /// not derive from a VUK.
    struct BareCtx;
    impl ResolveCtx for BareCtx {
        fn disc_hash(&self) -> &str {
            "0x422EB"
        }
        fn title(&self) -> Option<&str> {
            None
        }
        fn vid(&self) -> Option<libfreemkv::aacs::types::Vid> {
            None
        }
        fn mkb(&self) -> Result<&[u8], Error> {
            Ok(&[])
        }
        fn enc_title_keys(&self) -> Result<&[[u8; 16]], Error> {
            Ok(&[])
        }
        fn samples(&self, _n: usize) -> Result<Vec<Vec<u8>>, Error> {
            Ok(Vec::new())
        }
    }

    /// A stub reply. ureq 3 has no `Response::new`; a response is just an
    /// `http::Response` carrying a `ureq::Body`, which is constructible
    /// directly — so these stay honest unit tests with no server involved.
    fn reply(status: u16, body: &str) -> ureq::http::Response<ureq::Body> {
        ureq::http::Response::builder()
            .status(status)
            .body(ureq::Body::builder().data(body))
            .expect("stub response")
    }

    /// THE regression. The key service returned HTTP 502 for ~seven hours and
    /// the CLI told operators the disc had no key, so they went hunting for a
    /// VUK that was never missing. A 5xx must be a source FAILURE, and it must
    /// be distinguishable from the service answering 200 with no entry.
    #[test]
    fn http_5xx_is_a_source_failure_not_a_missing_key() {
        for status in [500u16, 502, 503, 504] {
            let out = interpret_reply(Err(ureq::Error::StatusCode(status)), &BareCtx, 7);
            assert_eq!(
                out.expect_err("a 5xx must not look like an answer").code(),
                libfreemkv::error::E_KEY_SERVICE_UNAVAILABLE,
                "HTTP {status} must report the service as unavailable"
            );
        }

        // The contrast case, through the SAME function: the service answered,
        // and genuinely holds nothing for this disc.
        let miss = interpret_reply(Ok(reply(200, "{}")), &BareCtx, 7)
            .expect("a 200 with no key is an ANSWER, not a failure");
        assert!(miss.is_empty(), "no key in the body → no keys out");

        // And the two must not be the same outcome — the whole point.
        let down = interpret_reply(Err(ureq::Error::StatusCode(502)), &BareCtx, 7);
        assert!(
            down.is_err(),
            "502 and 200-with-no-entry must not collapse to the same result"
        );
    }

    /// Each status the service can return maps to a DIFFERENT operator action:
    /// fix the token (401/403), back off (429), wait (5xx). A non-2xx status is
    /// never evidence about this disc, so anything else is "unavailable" too —
    /// guessing "no key" from a status code is the original bug.
    #[test]
    fn http_status_maps_to_the_operator_action() {
        let cases: &[(u16, u16)] = &[
            (401, libfreemkv::error::E_KEY_SERVICE_UNAUTHORIZED),
            (403, libfreemkv::error::E_KEY_SERVICE_UNAUTHORIZED),
            (429, libfreemkv::error::E_KEY_SERVICE_RATE_LIMITED),
            (500, libfreemkv::error::E_KEY_SERVICE_UNAVAILABLE),
            (502, libfreemkv::error::E_KEY_SERVICE_UNAVAILABLE),
            (400, libfreemkv::error::E_KEY_SERVICE_UNAVAILABLE),
            (404, libfreemkv::error::E_KEY_SERVICE_UNAVAILABLE),
        ];
        for (status, want) in cases {
            assert_eq!(
                classify_http_status(*status).code(),
                *want,
                "HTTP {status} classified wrongly"
            );
            assert_ne!(
                classify_http_status(*status).code(),
                libfreemkv::error::E_NO_DISC_KEY,
                "no HTTP status may ever mean \"this disc has no key\""
            );
        }
    }

    /// A transport failure — nothing answered at all — is the same verdict as a
    /// 5xx and equally not a missing key. Uses a refused connection to
    /// 127.0.0.1:1 to obtain a REAL transport-class error; this touches no
    /// network and never reaches `query`, so the SSRF guard is not involved.
    #[test]
    fn transport_failure_is_a_source_failure() {
        let config = Config::builder()
            .timeout_connect(Some(Duration::from_secs(2)))
            .build();
        let sent = ureq::Agent::new_with_config(config)
            .post("http://127.0.0.1:1/")
            .send("{}");
        // ureq 3 split v2's single `Transport` variant across `Io`,
        // `ConnectionFailed`, `Timeout` and friends, and which one a refused
        // connection produces is a platform detail. The claim that matters is
        // unchanged and is what this asserts: it failed, and NOT with a status
        // code — nothing on the other end ever answered.
        assert!(
            !matches!(sent, Ok(_) | Err(ureq::Error::StatusCode(_))),
            "a refused connection must fail as transport, never as an HTTP status"
        );
        assert_eq!(
            interpret_reply(sent, &BareCtx, 3)
                .expect_err("an unreachable service must not look like an answer")
                .code(),
            libfreemkv::error::E_KEY_SERVICE_UNAVAILABLE,
        );
    }

    /// A reply the client cannot read is the service failing mid-answer, not an
    /// answer of "no key".
    #[test]
    fn unparseable_reply_is_a_source_failure() {
        assert_eq!(
            interpret_reply(Ok(reply(200, "<html>gateway error</html>")), &BareCtx, 1)
                .expect_err("non-JSON is not an answer")
                .code(),
            libfreemkv::error::E_KEY_SERVICE_UNAVAILABLE,
        );
        // A malformed element in the UK set rejects the whole reply (a partial
        // forensic set silently omits an index) — also a service fault.
        assert_eq!(
            interpret_reply(
                Ok(reply(
                    200,
                    r#"{"UK":["000102030405060708090a0b0c0d0e0f","zz"]}"#
                )),
                &BareCtx,
                1
            )
            .expect_err("a malformed key in the set is not an answer")
            .code(),
            libfreemkv::error::E_KEY_SERVICE_UNAVAILABLE,
        );
    }

    /// Regression pin (passes before and after): a service that DOES hold the
    /// key still resolves it, and array order is preserved as the forensic index
    /// order. The Result-returning signature must not have changed the happy path.
    #[test]
    fn service_with_a_key_still_resolves_it_in_order() {
        let keys = interpret_reply(
            Ok(reply(
                200,
                r#"{"UK":["000102030405060708090a0b0c0d0e0f","0f0e0d0c0b0a09080706050403020100"]}"#,
            )),
            &BareCtx,
            1,
        )
        .expect("a 200 carrying keys resolves");
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].idx, 0);
        assert_eq!(keys[1].idx, 1);
        assert_eq!(keys[0].key[0], 0x00);
        assert_eq!(keys[1].key[0], 0x0f);
    }

    /// A URL that fails the ADDRESS guard is operator configuration, not the
    /// service being down — the two must stay separable, since only one of them
    /// is worth retrying.
    #[test]
    fn address_guard_rejections_are_config_not_unreachable() {
        for url in [
            "http://127.0.0.1/keys",
            "http://169.254.169.254/latest/meta-data/",
            "ftp://example.com/keys",
            "not a url",
            "",
        ] {
            assert_eq!(
                resolve_and_guard(url).expect_err("must be rejected").0,
                GuardFail::Config,
                "{url} is a configuration fault, not an outage"
            );
        }
    }

    // ── The pre-flight guards in `query` (nothing leaves the process) ───────
    //
    // Each of the three guards below returns `Ok(empty)` BEFORE any address is
    // resolved and before anything is sent. None was exercised: a reordering
    // that let the cleartext POST through would have shipped green, and that
    // POST carries the bearer token plus base64 key material.
    //
    // The discriminator in all three: the configured host is `.invalid`, which
    // RFC 6761 guarantees never resolves. On the guarded path nothing resolves
    // it, so the test touches no network and returns `Ok(empty)`. Remove the
    // guard and control reaches `resolve_and_guard`, which fails as
    // `Unreachable` → `Err(KeyServiceUnavailable)` — a different Result, so the
    // mutation cannot pass.

    /// A `ResolveCtx` whose MKB size and sample COUNT are dialled per guard.
    struct GuardCtx {
        mkb: Vec<u8>,
        samples: usize,
    }
    impl ResolveCtx for GuardCtx {
        fn disc_hash(&self) -> &str {
            "0x422EB"
        }
        fn title(&self) -> Option<&str> {
            None
        }
        fn vid(&self) -> Option<libfreemkv::aacs::types::Vid> {
            None
        }
        fn mkb(&self) -> Result<&[u8], Error> {
            Ok(&self.mkb)
        }
        fn enc_title_keys(&self) -> Result<&[[u8; 16]], Error> {
            Ok(&[])
        }
        fn samples(&self, _n: usize) -> Result<Vec<Vec<u8>>, Error> {
            Ok(vec![vec![0u8; 16]; self.samples])
        }
    }

    /// An `http://` key-service URL must never be POSTed to: the body carries
    /// base64 AACS key material and the header carries a replayable bearer
    /// token. The source refuses and falls through to the next source.
    #[test]
    fn cleartext_http_url_is_refused_before_anything_is_sent() {
        let src = OnlineSource::new("http://keyserver.invalid/keys", "s3cr3t");
        let ctx = GuardCtx {
            mkb: Vec::new(),
            // Enough samples that ONLY the scheme guard can stop the request.
            samples: MIN_SAMPLE_UNITS,
        };
        assert!(
            src.get_unit_keys(&ctx)
                .expect("a cleartext URL is a config skip, not a service failure")
                .is_empty(),
            "an http:// key-service URL must be refused, not sent"
        );
    }

    /// An MKB larger than the forward cap cannot be sent; the source skips
    /// rather than truncating the MKB (which would ask about a different disc).
    #[test]
    fn over_cap_mkb_skips_the_request() {
        let src = OnlineSource::new("https://keyserver.invalid/keys", "s3cr3t");
        let ctx = GuardCtx {
            mkb: vec![0u8; MAX_MKB_BYTES + 1],
            samples: MIN_SAMPLE_UNITS,
        };
        assert!(
            src.get_unit_keys(&ctx)
                .expect("an un-forwardable MKB is a skip, not a service failure")
                .is_empty(),
            "an over-cap MKB must skip the online source"
        );
    }

    /// Too few content samples make the service's answer ambiguous (it
    /// identifies the key by which submitted unit decrypts), so the request is
    /// never built. Proven at the boundary: `MIN_SAMPLE_UNITS - 1` skips.
    #[test]
    fn too_few_samples_skips_the_request() {
        let src = OnlineSource::new("https://keyserver.invalid/keys", "s3cr3t");
        let ctx = GuardCtx {
            mkb: Vec::new(),
            samples: MIN_SAMPLE_UNITS - 1,
        };
        assert!(
            src.get_unit_keys(&ctx)
                .expect("under-sampling is a skip, not a service failure")
                .is_empty(),
            "fewer than MIN_SAMPLE_UNITS samples must skip the online source"
        );
    }

    // ── MAX_RESPONSE_BYTES: the stated anti-OOM defence ─────────────────────

    /// The reply cap is the crate's only defence against a hostile or broken
    /// key service driving the client to OOM with an unbounded body, and it had
    /// never been exercised. Both edges are asserted so the `+1` read cannot
    /// quietly become a truncating read (which would hand a half-body to the
    /// JSON parser) or an off-by-one that rejects a legal reply.
    #[test]
    fn over_cap_reply_is_rejected_and_an_at_cap_reply_still_parses() {
        // The over-cap body is deliberately VALID, key-bearing JSON. A body of
        // junk would be rejected by the JSON parser whether or not the cap
        // exists, so the test would pass with the cap deleted — worthless. This
        // one is only rejectable BY the cap: remove the bounded read and it
        // parses into a key.
        let head = r#"{"UK":["000102030405060708090a0b0c0d0e0f"],"pad":""#;
        let tail = r#""}"#;
        let over = format!(
            "{head}{}{tail}",
            "p".repeat(MAX_RESPONSE_BYTES + 1 - head.len() - tail.len())
        );
        assert_eq!(over.len(), MAX_RESPONSE_BYTES + 1);
        assert_eq!(
            interpret_reply(Ok(reply(200, &over)), &BareCtx, 1)
                .expect_err("an over-cap body must not be treated as an answer")
                .code(),
            libfreemkv::error::E_KEY_SERVICE_UNAVAILABLE,
        );

        // EXACTLY at the cap, and valid: still read and still answered. Padded
        // with a JSON string so the length is exact and the key is real.
        let pad = MAX_RESPONSE_BYTES - head.len() - tail.len();
        let at_cap = format!("{head}{}{tail}", "p".repeat(pad));
        assert_eq!(at_cap.len(), MAX_RESPONSE_BYTES);
        let keys = interpret_reply(Ok(reply(200, &at_cap)), &BareCtx, 1)
            .expect("a reply exactly at the cap is legal and must be read");
        assert_eq!(keys.len(), 1, "the key in an at-cap reply must survive");
    }

    // ── A bad port is CONFIG, not an outage ────────────────────────────────

    /// `https://example.com:notaport/keys` is a typo in the operator's config.
    /// The unparseable port used to make the WHOLE authority (port text
    /// included) the hostname, which of course never resolved — so a standing
    /// misconfiguration was reported as `Unreachable`, i.e. as the key service
    /// being down. The two demand OPPOSITE actions (fix the URL vs. wait), which
    /// is precisely what `GuardFail`'s doc says must not be collapsed.
    #[test]
    fn unparseable_port_is_a_config_fault_not_an_outage() {
        for url in [
            "https://example.com:notaport/keys",
            "http://example.com:99999/keys", // out of u16 range
            "https://example.com:/keys",     // empty port
        ] {
            assert_eq!(
                resolve_and_guard(url).expect_err("must be rejected").0,
                GuardFail::Config,
                "{url} is a configuration typo, not a service outage"
            );
        }
        // A WELL-FORMED port is still split off the host and honoured.
        let addrs = resolve_and_guard("https://8.8.8.8:8443/keys").expect("valid port accepted");
        assert_eq!(addrs[0].port(), 8443);
    }

    /// The same distinction as seen by a caller: a mistyped port makes the
    /// online source SKIP (`Ok(empty)`, the next source is tried and a genuine
    /// `E7022` is honest), where an unreachable service returns `Err`. Before
    /// the fix this URL returned `Err(KeyServiceUnavailable)` and sent the
    /// operator waiting for an outage that would never end.
    #[test]
    fn query_with_a_mistyped_port_skips_rather_than_reporting_an_outage() {
        let src = OnlineSource::new("https://example.com:notaport/keys", "s3cr3t");
        let ctx = GuardCtx {
            mkb: Vec::new(),
            samples: MIN_SAMPLE_UNITS,
        };
        assert!(
            src.get_unit_keys(&ctx)
                .expect("a mistyped port is configuration, not an outage")
                .is_empty()
        );
    }

    // ── One agent per address set, not one per query ────────────────────────

    /// An FMTS disc calls `query` twice per rip (`get_unit_keys` +
    /// `get_fmts_indexes`), and a fresh `ureq::Agent` per call throws away the
    /// connection pool with it — a second full TLS handshake to the same host
    /// for nothing. The agent is reused only while the freshly guarded address
    /// set is IDENTICAL, so the anti-rebinding guarantee is untouched: a
    /// different address set builds (and re-pins) a new agent.
    #[test]
    fn the_agent_is_reused_per_address_set_only() {
        let src = OnlineSource::new("https://keyserver.invalid/keys", "");
        let a: Vec<SocketAddr> = vec!["8.8.8.8:443".parse().unwrap()];
        let b: Vec<SocketAddr> = vec!["1.1.1.1:443".parse().unwrap()];

        let first = src.agent_for(a.clone());
        let second = src.agent_for(a.clone());
        assert!(
            Arc::ptr_eq(&first, &second),
            "the same pinned address set must reuse the agent (and its pooled TLS connection)"
        );

        let other = src.agent_for(b);
        assert!(
            !Arc::ptr_eq(&first, &other),
            "a DIFFERENT address set must never reuse an agent pinned elsewhere"
        );
        // And the address set is re-pinned, so going back re-builds.
        let back = src.agent_for(a);
        assert!(!Arc::ptr_eq(&first, &back));
    }

    /// Finding #9 regression: parse_uk must reject any non-hex byte up front so
    /// sign prefixes / whitespace can't slip through the windowed 2-char parse
    /// (`u8::from_str_radix` accepts "+5", "-A", etc.).
    #[test]
    fn parse_uk_rejects_non_hex_bytes() {
        // Valid 32-char hex parses.
        assert_eq!(
            parse_uk("000102030405060708090a0b0c0d0e0f"),
            Some([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
        );
        // Sign-prefixed window: "+5" / "-A" would parse via from_str_radix.
        assert!(parse_uk("+5000102030405060708090a0b0c0d0e").is_none());
        assert!(parse_uk("-A000102030405060708090a0b0c0d0e").is_none());
        // Embedded whitespace.
        assert!(parse_uk("00 0102030405060708090a0b0c0d0e0f").is_none());
        // Wrong length is still rejected.
        assert!(parse_uk("00").is_none());
    }
}
