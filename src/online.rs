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
// libfreemkv's `read_mkb_content` MAX_BYTES (64 MiB), so a capturable MKB is
// never silently un-forwardable here (headroom, not an expected size).
const MAX_MKB_BYTES: usize = 64 * 1024 * 1024;
const TIMEOUT_SECS: u64 = 180;
/// Minimum encrypted-content samples the online source will send in one key
/// request — re-exported from the base crate
/// ([`libfreemkv::keysource::MIN_SAMPLE_UNITS`]) so this crate and
/// libfreemkv's own FMTS forensic query share ONE value.
///
/// A request carrying fewer samples is refused (empty result, never sent)
/// since the service identifies the key by which submitted unit it decrypts
/// and too few risks a false-positive match. Kept public so gathering
/// callers (the CLI, autorip) sample at least this many.
pub use libfreemkv::keysource::MIN_SAMPLE_UNITS;
/// Hard cap on the key-service response body. A real unit-key reply is a few
/// hundred bytes; bound the read so a malicious/compromised server can't drive
/// the client to OOM with an unbounded body.
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

// ── SSRF guard — see docs/online-ssrf-guard.md ───────────────────────────────
// is_blocked_ip: true when `ip` must never be an outbound key-service POST
// target (loopback, link-local incl. cloud metadata, RFC1918, IPv4-mapped).
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
            let seg = v6.segments();
            // 6to4 (2002::/16) embeds an IPv4 in segments[1..3]; Teredo
            // (2001:0000::/32) embeds the client IPv4 in the last two segments,
            // each XOR 0xffff. Both must be re-checked as their embedded IPv4.
            let sixtofour = (seg[0] == 0x2002)
                .then(|| std::net::Ipv4Addr::from(((seg[1] as u32) << 16) | (seg[2] as u32)));
            let teredo = (seg[0] == 0x2001 && seg[1] == 0x0000).then(|| {
                std::net::Ipv4Addr::from(
                    (((seg[6] ^ 0xffff) as u32) << 16) | ((seg[7] ^ 0xffff) as u32),
                )
            });
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // Unique-local fc00::/7.
                || (seg[0] & 0xfe00) == 0xfc00
                // Link-local fe80::/10.
                || (seg[0] & 0xffc0) == 0xfe80
                // IPv4-mapped (::ffff:x.x.x.x) and IPv4-compatible (::x.x.x.x,
                // deprecated by RFC 4291 §2.5.5.1) — to_ipv4() returns Some for
                // both forms; re-check the embedded address as IPv4.
                || v6
                    .to_ipv4()
                    .map(|m| is_blocked_ip(&IpAddr::V4(m)))
                    == Some(true)
                || sixtofour.is_some_and(|v4| is_blocked_ip(&IpAddr::V4(v4)))
                || teredo.is_some_and(|v4| is_blocked_ip(&IpAddr::V4(v4)))
        }
    }
}

// Why resolve_and_guard rejected a URL, split by the operator action each
// demands: Config is a standing misconfiguration (never self-heals),
// Unreachable is the service down now. Both are Err from query, never Ok(empty).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GuardFail {
    // Malformed URL, bad scheme, or a host that resolves to a non-public
    // address. Operator configuration; retrying changes nothing.
    Config,
    // Host did not resolve — DNS failure or timeout. Service unreachable;
    // nothing known about this disc's key. Transient.
    Unreachable,
}

// Resolve `url`'s host, validating every address against the SSRF guard;
// returns pinned socket addrs or a rejection reason + message. SECURITY: the
// message names the address — log only at config time, never in `query`.
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
            // A malformed port (e.g. `:notaport`) is an operator config typo,
            // not a service outage — reject as `Config`, same as the
            // bracketed-IPv6 branch above. See docs/online-guardfail.md.
            Err(_) => return Err((GuardFail::Config, "invalid port".into())),
        }
    } else {
        (authority.to_string(), default_port)
    };
    if host.is_empty() {
        return Err((GuardFail::Config, "URL has no host".into()));
    }
    // `to_socket_addrs` is a BLOCKING DNS lookup that can hang for the OS
    // resolver timeout and freeze the calling rip thread, so run it on a
    // spawned thread with a bounded deadline (mirrors autorip/libfreemkv).
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
/// This is the *config-time* check; [`OnlineSource`] re-resolves and
/// re-guards the host again before each POST, closing the DNS-rebind window.
pub fn validate_keyserver_url(url: &str) -> Result<(), String> {
    resolve_and_guard(url).map(|_| ()).map_err(|(_, msg)| msg)
}

// ureq's `ResolvedSocketAddrs` is a fixed 16-slot array; `push`ing a 17th
// address panics (out of bounds) on a host with many A records. Keep the
// first 16 — each already validated by `resolve_and_guard`.
const MAX_PINNED_ADDRS: usize = 16;

// The pinned-address resolver behind `hardened_agent`. Must be wired via
// `Agent::with_parts` — `new_with_config` silently keeps live DNS and
// reopens the rebind window. See docs/online-ssrf-guard.md.
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
    /// The last agent built, with the address set (sorted, deduped — an
    /// order-insensitive SET KEY) it was pinned to. Reused only when a fresh
    /// resolve + SSRF-guard of the host yields the identical address set, so
    /// the anti-rebinding guarantee is untouched: only the pooled TLS
    /// connection is reused, never a stale, un-reguarded address. See
    /// docs/online-agent-cache.md for why this exists and why the key is a
    /// set rather than an ordered sequence.
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

    // The agent pinned to `pinned` — the cached one when the address set is
    // unchanged, a fresh one otherwise. Poisoning is recovered from: a panic
    // elsewhere must not make every later key request panic.
    fn agent_for(&self, pinned: Vec<SocketAddr>) -> Arc<ureq::Agent> {
        // Compare SETS, not sequences — see the `agent` field's doc.
        let key = {
            let mut k = pinned.clone();
            k.sort();
            k.dedup();
            k
        };
        let mut guard = self.agent.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((cached_key, agent)) = guard.as_ref()
            && *cached_key == key
        {
            return agent.clone();
        }
        let agent = Arc::new(hardened_agent(pinned));
        *guard = Some((key, agent.clone()));
        agent
    }

    // The server-resolved Unit Keys for this disc: one round-trip, returning
    // a terminal `UK` or a `VUK` derived locally. `Ok`/`Err` draw the
    // miss-vs-outage distinction — see docs/online-query-contract.md.
    fn query(&self, ctx: &dyn ResolveCtx) -> Result<Vec<UnitKey>, Error> {
        // No configured service: nothing to resolve.
        if self.base_url.is_empty() {
            return Ok(Vec::new());
        }
        // Refuse to transmit over plaintext: the body carries base64 key
        // material and, when configured, a replayable bearer token. `Err`,
        // not `Ok(empty)` — see docs/online-query-guards.md.
        if !self.base_url.starts_with("https://") {
            tracing::error!(
                target: "freemkv::keysource",
                "key-service URL is not https:// — refusing to send key material \
                 and credentials in cleartext; the service was NOT asked about this disc \
                 (fix the URL scheme), which is not the same as this disc having no key"
            );
            return Err(Error::KeyServiceUnavailable);
        }
        let mkb = ctx.mkb().unwrap_or(&[]);
        // No-URL / bad-URL / over-cap-or-under-sampled draw three different
        // verdicts — see docs/online-query-guards.md. Logged: a silent empty
        // here reads as "no key", so the real cause (64 MiB cap) is surfaced.
        if mkb.len() > MAX_MKB_BYTES {
            tracing::warn!(
                target: "freemkv::keysource",
                mkb_len = mkb.len(),
                cap = MAX_MKB_BYTES,
                "MKB exceeds the key-service forward cap; skipping the online source for this disc (no key from online)"
            );
            return Ok(Vec::new());
        }
        // Prove the minimum by TYPE: `DecodeSampleSet` only exists with >=
        // MIN_SAMPLE_UNITS units, so the request can't be built under-sized
        // (too few risks the service matching an incidental unit — FMTS).
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
        // validated addresses so a DNS rebind between config time and fetch
        // time can't redirect the request to an internal/metadata host.
        let pinned = match resolve_and_guard(&self.base_url) {
            Ok(addrs) => addrs,
            // Did-not-RESOLVE is the service unreachable, not a bad URL — see
            // docs/online-guardfail.md.
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
                // Log THAT the URL was rejected, never WHY (the message names
                // the address). `error!` + `Err`, not `Ok(empty)` — see
                // docs/online-guardfail.md for the full rationale.
                tracing::error!(
                    target: "freemkv::keysource",
                    phase = "keyserver_post",
                    "key-service URL failed the address guard — the service was NOT asked about this disc; \
                     this is a standing misconfiguration (fix the URL), not a disc without a key"
                );
                // Borrows transient E7028 pending a 70xx config code upstream.
                return Err(Error::KeyServiceUnavailable);
            }
        };
        let agent = self.agent_for(pinned);
        let mut req = agent.post(&self.base_url);
        if let Some(value) = bearer_header(&self.secret) {
            req = req.header("Authorization", &value);
        }
        // Begin/end around the keyserver round-trip: bounded by
        // `hardened_agent`'s connect/read timeouts, so this can never block
        // forever. SECURITY: never log `body` — it carries base64 key material.
        tracing::info!(target: "freemkv::keysource", phase = "keyserver_post", "begin");
        let post_t0 = std::time::Instant::now();
        let sent = req.send_json(body);
        interpret_reply(sent, ctx, post_t0.elapsed().as_millis() as u64)
    }
}

// Map a key-service HTTP status into the operator action it implies: 401/403
// fix credentials, 429 back off, 5xx wait — none of them is "no key" (the
// genuine miss is a 200 with an empty body), the original bug this fixes.
fn classify_http_status(code: u16) -> Error {
    match code {
        401 | 403 => Error::KeyServiceUnauthorized,
        429 => Error::KeyServiceRateLimited,
        _ => Error::KeyServiceUnavailable,
    }
}

// Turn the raw key-service POST outcome into this source's answer. Split
// out of `query` so the reply -> verdict mapping is testable WITHOUT a
// network. SECURITY: logs status/byte-count/labels only — never `body`.
fn interpret_reply(
    sent: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
    ctx: &dyn ResolveCtx,
    elapsed_ms: u64,
) -> Result<Vec<UnitKey>, Error> {
    let mut resp = match sent {
        Ok(r) => r,
        Err(e) => {
            // 401/403/429/5xx demand different operator actions; collapsing
            // them is why a 502 was read as "no key". Each arm RETURNS the
            // classified error, never an empty vec, so it survives past here.
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
                // ureq 3's non_exhaustive transport-error enum (`Io`, `Timeout`,
                // `Tls`, ...) all mean the same thing here — nothing answered —
                // so a catch-all stays correct as the enum grows.
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
            // Never log the parse error or payload (a serde message quotes
            // the offending input, i.e. key material). Unparseable is a
            // service bug, not "no key".
            tracing::warn!(
                target: "freemkv::keysource",
                phase = "keyserver_post",
                "key-service reply was not valid JSON; no ANSWER from online"
            );
            return Err(Error::KeyServiceUnavailable);
        }
    };
    // `UK` is an ARRAY of hex keys — one for the base Unit Key, or an
    // ordered forensic-index set. Array position tags each key (i -> index
    // i+1). A bare string is still accepted for backward compatibility.
    if let Some(uk) = json.get("UK") {
        let mut out = Vec::new();
        if let Some(s) = uk.as_str() {
            if let Some(k) = parse_uk(s) {
                out.push(UnitKey::new(0, k));
            }
        } else if let Some(arr) = uk.as_array() {
            // A forensic set is only usable COMPLETE (the mux trusts any
            // non-empty result as the whole set). Skipping a bad element
            // would silently omit an index, so reject the whole reply.
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
                // The SERVICE answered; the DISC's encrypted title keys are
                // what could not be read — a disc-side reason, not `Err` here.
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
    // The genuine miss — the ONLY path returning `Ok(empty)` from a completed
    // round-trip, logged distinctly from every failure above so a 502 can
    // never again look like a missing key. `E7022` is the truth here.
    tracing::info!(
        target: "freemkv::keysource",
        phase = "keyserver_post",
        "key service has no key for this disc"
    );
    Ok(Vec::new())
}

impl KeySource for OnlineSource {
    // Base per-CPS-unit Unit Keys via `query`: `Ok(empty)` means the service
    // answered with no key, `Err` means it could not answer — see
    // docs/online-query-contract.md.
    fn get_unit_keys(&self, ctx: &dyn ResolveCtx) -> Result<Vec<UnitKey>, Error> {
        self.query(ctx)
    }

    // AACS 2.1 forensic index set: same `query` round-trip as
    // `get_unit_keys`, but the mux's samples are a single-phase anchor batch
    // and the service's array position tags each forensic index.
    fn get_fmts_indexes(&self, ctx: &dyn ResolveCtx) -> Result<Vec<UnitKey>, Error> {
        self.query(ctx)
    }

    fn label(&self) -> &'static str {
        "online"
    }

    // host_certs: no-op default. No online cert fetch/endpoint today, so
    // OEM certs fall back to another source (e.g. keydb); no network touched.
}

// The `Authorization` header value, or `None` when no secret is configured
// (request goes out unauthenticated). Sent verbatim as an HTTP Bearer
// credential — the token comes from `--key-auth` (CLI) / `keyserver_secret`.
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

    // 6to4 (2002::/16) and Teredo (2001:0000::/32) tunnel an IPv4 inside an
    // IPv6 address; the guard must decode and re-check that embedded IPv4 or an
    // internal target slips through the tunnel.
    #[test]
    fn ssrf_guard_blocks_embedded_ipv4_via_6to4_and_teredo() {
        // 6to4 for 127.0.0.1: 2002:7f00:0001:: (embedded in segments[1..3]).
        assert!(is_blocked_ip(&IpAddr::V6(Ipv6Addr::new(
            0x2002, 0x7f00, 0x0001, 0, 0, 0, 0, 0
        ))));
        // 6to4 for 169.254.169.254 (cloud metadata): 2002:a9fe:a9fe::.
        assert!(is_blocked_ip(&IpAddr::V6(Ipv6Addr::new(
            0x2002, 0xa9fe, 0xa9fe, 0, 0, 0, 0, 0
        ))));
        // Teredo for 127.0.0.1: client IPv4 lives in the last two segments XOR
        // 0xffff, so 0x7f00^0xffff=0x80ff and 0x0001^0xffff=0xfffe.
        assert!(is_blocked_ip(&IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x0000, 0, 0, 0, 0, 0x80ff, 0xfffe
        ))));
        // A 6to4 wrapping a PUBLIC IPv4 (8.8.8.8 → 2002:0808:0808::) is allowed.
        assert!(!is_blocked_ip(&IpAddr::V6(Ipv6Addr::new(
            0x2002, 0x0808, 0x0808, 0, 0, 0, 0, 0
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

    // host_certs() must return empty WITHOUT touching the network. Uses a
    // non-empty base URL to prove the empty result is the deliberate no-op
    // stub, not merely "no service configured".
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

    // Malformed-authority edges rejected BEFORE touching DNS: empty host,
    // unterminated IPv6 literal, and a bare `host:` with an empty host part.
    #[test]
    fn resolve_and_guard_rejects_malformed_authorities() {
        // Scheme with nothing after it at all.
        assert!(resolve_and_guard("https://").is_err());
        // Scheme immediately followed by a path — empty authority.
        assert!(resolve_and_guard("https:///keys").is_err());
        // Bracketed IPv6 host missing its closing `]`.
        assert!(resolve_and_guard("http://[::1/keys").is_err());
        // `host:port` split with an empty host before the colon.
        assert!(resolve_and_guard("https://:8080/keys").is_err());
    }

    // A host that genuinely does not resolve (RFC 6761 `.test`) must report
    // `GuardFail::Unreachable` ("service is down"), not `Config`.
    #[test]
    fn resolve_and_guard_reports_unreachable_for_a_host_that_never_resolves() {
        let (kind, msg) = resolve_and_guard("https://this-host-does-not-exist.test/keys")
            .expect_err(
                "a .test host must never resolve — if this passes, treat it as a fixture bug",
            );
        assert_eq!(kind, GuardFail::Unreachable);
        assert!(msg.contains("resolve"), "message should explain: {msg}");
    }

    // An EMPTY pinned address set must fail the resolve step with
    // `HostNotFound` rather than silently falling back to live DNS.
    #[test]
    fn pinned_resolver_with_no_addresses_fails_the_connection() {
        let result = hardened_agent(Vec::new())
            .post("http://keyserver.test/keys")
            .send("{}");
        assert!(
            result.is_err(),
            "an empty pin must fail the connection, not silently resolve some other way"
        );
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

    // The pin is actually consulted (a mis-wired resolver fails OPEN to
    // live DNS with no symptom — see docs/online-ssrf-guard.md): pin to a
    // loopback listener, then ask for a `.test` host that CANNOT resolve.
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

    // ── the reply → verdict mapping (THE defect) ──────────────────────────
    // Driven through `interpret_reply` directly: a stub HTTP server is NOT
    // usable here since `resolve_and_guard` blocks loopback by design.

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

    // THE regression: a 5xx for ~seven hours was reported as "no key" and
    // sent operators hunting a VUK that was never missing. A 5xx must be a
    // source FAILURE, distinguishable from a 200 with no entry.
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

    // Each status maps to a DIFFERENT operator action: fix the token
    // (401/403), back off (429), wait (5xx) — never "no key" from a status.
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

    // A transport failure is the same verdict as a 5xx. Uses a refused
    // connection to 127.0.0.1:1 for a REAL transport-class error; never
    // reaches `query`, so the SSRF guard is not involved.
    #[test]
    fn transport_failure_is_a_source_failure() {
        let config = Config::builder()
            .timeout_connect(Some(Duration::from_secs(2)))
            .build();
        let sent = ureq::Agent::new_with_config(config)
            .post("http://127.0.0.1:1/")
            .send("{}");
        // Which transport variant a refused connection produces is a
        // platform detail; what matters (asserted below) is that it failed,
        // and NOT with a status code — nothing on the other end answered.
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

    /// Backward-compatible form: `"UK"` as a bare hex STRING (not an array)
    /// is still the single base Unit Key at index 0.
    #[test]
    fn uk_as_a_bare_string_is_still_accepted() {
        let keys = interpret_reply(
            Ok(reply(200, r#"{"UK":"000102030405060708090a0b0c0d0e0f"}"#)),
            &BareCtx,
            1,
        )
        .expect("a string UK must still resolve");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].idx, 0);
        assert_eq!(keys[0].key[0], 0x00);
    }

    // A malformed `"UK"` STRING falls through to the genuine-miss path,
    // distinct from the array form's "reject the whole reply" behaviour.
    #[test]
    fn uk_as_an_unparseable_string_falls_through_to_a_miss() {
        let keys = interpret_reply(Ok(reply(200, r#"{"UK":"not hex"}"#)), &BareCtx, 1)
            .expect("an unparseable scalar UK is a miss, not a transport failure");
        assert!(keys.is_empty());
    }

    /// A `"VUK"` reply is derived LOCALLY into terminal unit keys via the
    /// disc's encrypted title keys — the service never sees or returns them
    /// directly.
    #[test]
    fn vuk_reply_is_derived_locally_into_unit_keys() {
        struct EncCtx;
        impl ResolveCtx for EncCtx {
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
                Ok(&[[0x11u8; 16], [0x22u8; 16]])
            }
            fn samples(&self, _n: usize) -> Result<Vec<Vec<u8>>, Error> {
                Ok(Vec::new())
            }
        }
        let vuk_hex = "0f0e0d0c0b0a09080706050403020100";
        let keys = interpret_reply(
            Ok(reply(200, &format!(r#"{{"VUK":"{vuk_hex}"}}"#))),
            &EncCtx,
            1,
        )
        .expect("a VUK reply must resolve");
        assert_eq!(
            keys.len(),
            2,
            "one derived unit key per encrypted title key"
        );
        assert_eq!(keys[0].idx, 0);
        assert_eq!(keys[1].idx, 1);
    }

    /// The service answered correctly with a VUK, but the DISC's encrypted
    /// title keys could not be read — that is a disc-side condition, not a
    /// service failure, so it is `Ok(empty)`, never `Err`.
    #[test]
    fn vuk_reply_with_unreadable_enc_title_keys_is_an_empty_ok_not_an_error() {
        struct BrokenEncCtx;
        impl ResolveCtx for BrokenEncCtx {
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
                Err(Error::KeydbInvalid)
            }
            fn samples(&self, _n: usize) -> Result<Vec<Vec<u8>>, Error> {
                Ok(Vec::new())
            }
        }
        let vuk_hex = "0f0e0d0c0b0a09080706050403020100";
        let keys = interpret_reply(
            Ok(reply(200, &format!(r#"{{"VUK":"{vuk_hex}"}}"#))),
            &BrokenEncCtx,
            1,
        )
        .expect("an unreadable disc-side input must not be a source failure");
        assert!(keys.is_empty());
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

    // ── The pre-flight guards in `query` (nothing leaves the process) ──────
    // See docs/online-preflight-guard-tests.md — why each guard's verdict
    // differs and why `.test` is the discriminator host used below.

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

    // An `http://` key-service URL must never be POSTed to; the source
    // refuses with `Err`, not an empty that reads as "no key" — see
    // docs/online-query-guards.md.
    #[test]
    fn cleartext_http_url_is_refused_before_anything_is_sent() {
        let src = OnlineSource::new("http://keyserver.test/keys", "s3cr3t");
        let ctx = GuardCtx {
            mkb: Vec::new(),
            // Enough samples that ONLY the scheme guard can stop the request.
            samples: MIN_SAMPLE_UNITS,
        };
        assert_eq!(
            src.get_unit_keys(&ctx)
                .expect_err("refusing to ask is a source failure, never a miss")
                .code(),
            libfreemkv::error::E_KEY_SERVICE_UNAVAILABLE,
            "an http:// key-service URL must be refused, not sent — and reported"
        );
    }

    /// An MKB larger than the forward cap cannot be sent; the source skips
    /// rather than truncating the MKB (which would ask about a different disc).
    #[test]
    fn over_cap_mkb_skips_the_request() {
        let src = OnlineSource::new("https://keyserver.test/keys", "s3cr3t");
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
        let src = OnlineSource::new("https://keyserver.test/keys", "s3cr3t");
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

    // ── MAX_RESPONSE_BYTES: the anti-OOM defence, both edges asserted so
    // `+1` can't quietly truncate, nor an off-by-one reject a legal reply.
    #[test]
    fn over_cap_reply_is_rejected_and_an_at_cap_reply_still_parses() {
        // The over-cap body is deliberately VALID, key-bearing JSON — junk
        // would be rejected by the parser regardless of the cap. This one is
        // only rejectable BY the cap.
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

    // A typo'd port must be `Config`, not `Unreachable` — see
    // docs/online-guardfail.md for why collapsing the two is the bug.
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

    // The caller-visible half: a mistyped port must get `Err`, exactly like
    // an outage (only the log text differs) — catches the `Ok(Vec::new())`
    // regression from `GuardFail::Config` (docs/online-guardfail.md).
    #[test]
    fn query_with_a_mistyped_port_reports_a_failure_not_a_miss() {
        let src = OnlineSource::new("https://example.com:notaport/keys", "s3cr3t");
        let ctx = GuardCtx {
            mkb: Vec::new(),
            samples: MIN_SAMPLE_UNITS,
        };
        assert_eq!(
            src.get_unit_keys(&ctx)
                .expect_err("a config fault means the service was never asked — never Ok(empty)")
                .code(),
            libfreemkv::error::E_KEY_SERVICE_UNAVAILABLE,
        );
    }

    // A guard-BLOCKED address travels the same `GuardFail::Config` arm and
    // must be just as loud — distinct from the mistyped port above because
    // it fails AFTER resolution, on the address check.
    #[test]
    fn query_against_a_guard_blocked_address_reports_a_failure_not_a_miss() {
        // 127.0.0.1 needs no DNS and is unconditionally rejected by is_blocked_ip.
        let src = OnlineSource::new("https://127.0.0.1/keys", "s3cr3t");
        let ctx = GuardCtx {
            mkb: Vec::new(),
            samples: MIN_SAMPLE_UNITS,
        };
        assert_eq!(
            src.get_unit_keys(&ctx)
                .expect_err("a blocked address means the service was never asked")
                .code(),
            libfreemkv::error::E_KEY_SERVICE_UNAVAILABLE,
        );
    }

    // `get_fmts_indexes` shares `query` with `get_unit_keys` — same
    // guard-blocked, no-network path proves it is wired up.
    #[test]
    fn get_fmts_indexes_shares_the_same_query_path() {
        let src = OnlineSource::new("https://127.0.0.1/keys", "s3cr3t");
        let ctx = GuardCtx {
            mkb: Vec::new(),
            samples: MIN_SAMPLE_UNITS,
        };
        assert_eq!(
            src.get_fmts_indexes(&ctx)
                .expect_err("a blocked address means the service was never asked")
                .code(),
            libfreemkv::error::E_KEY_SERVICE_UNAVAILABLE,
        );
    }

    // A host that does not resolve travels `query`'s OWN `Unreachable` arm
    // (distinct from `Config` above) — still `Err`, never a genuine miss.
    #[test]
    fn query_against_an_unresolvable_host_reports_unreachable_as_a_failure() {
        let src = OnlineSource::new("https://this-host-does-not-exist.test/keys", "s3cr3t");
        let ctx = GuardCtx {
            mkb: Vec::new(),
            samples: MIN_SAMPLE_UNITS,
        };
        assert_eq!(
            src.get_unit_keys(&ctx)
                .expect_err("an unresolvable host means the service was never asked")
                .code(),
            libfreemkv::error::E_KEY_SERVICE_UNAVAILABLE,
        );
    }

    // `vid_b64`/`title` are assembled BEFORE the address guard runs, so a
    // VID+title ctx still exercises that assembly even when the guard then
    // rejects the address (same deterministic guard-blocked path, no network).
    #[test]
    fn query_assembles_vid_and_title_before_the_address_guard_runs() {
        struct VidTitleCtx;
        impl ResolveCtx for VidTitleCtx {
            fn disc_hash(&self) -> &str {
                "0x422EB"
            }
            fn title(&self) -> Option<&str> {
                Some("  My Disc Title  ")
            }
            fn vid(&self) -> Option<libfreemkv::aacs::types::Vid> {
                Some(libfreemkv::aacs::types::Vid([0x42u8; 16]))
            }
            fn mkb(&self) -> Result<&[u8], Error> {
                Ok(&[])
            }
            fn enc_title_keys(&self) -> Result<&[[u8; 16]], Error> {
                Ok(&[])
            }
            fn samples(&self, _n: usize) -> Result<Vec<Vec<u8>>, Error> {
                Ok(vec![vec![0u8; 16]; MIN_SAMPLE_UNITS])
            }
        }
        // 127.0.0.1 needs no DNS and is unconditionally rejected — the guard
        // fires AFTER the body (incl. vid/title) is already built.
        let src = OnlineSource::new("https://127.0.0.1/keys", "s3cr3t");
        assert_eq!(
            src.get_unit_keys(&VidTitleCtx)
                .expect_err("a blocked address means the service was never asked")
                .code(),
            libfreemkv::error::E_KEY_SERVICE_UNAVAILABLE,
        );
    }

    /// A title that is present but ALL WHITESPACE must not be sent — `query`
    /// trims then checks `is_empty()` before adding the `title` field.
    #[test]
    fn query_skips_a_whitespace_only_title() {
        struct WhitespaceTitleCtx;
        impl ResolveCtx for WhitespaceTitleCtx {
            fn disc_hash(&self) -> &str {
                "0x422EB"
            }
            fn title(&self) -> Option<&str> {
                Some("   ")
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
                Ok(vec![vec![0u8; 16]; MIN_SAMPLE_UNITS])
            }
        }
        let src = OnlineSource::new("https://127.0.0.1/keys", "s3cr3t");
        // Reaches the same guard-blocked failure either way; this test's
        // value is in exercising the whitespace-title branch without panic.
        assert!(src.get_unit_keys(&WhitespaceTitleCtx).is_err());
    }

    // ── One agent per address set, not one per query ──────────────────────
    // A round-robin keyserver reorders the SAME addresses; still the same
    // set, so it must reuse the agent — see docs/online-agent-cache.md.
    #[test]
    fn a_reordered_but_identical_address_set_reuses_the_agent() {
        let src = OnlineSource::new("https://keyserver.test/keys", "");
        let forward: Vec<SocketAddr> = vec![
            "8.8.8.8:443".parse().unwrap(),
            "8.8.4.4:443".parse().unwrap(),
        ];
        let reversed: Vec<SocketAddr> = forward.iter().rev().copied().collect();
        assert_ne!(forward, reversed, "the two orders must really differ");

        let first = src.agent_for(forward);
        let again = src.agent_for(reversed);
        assert!(
            Arc::ptr_eq(&first, &again),
            "a reordered but identical address SET must reuse the pinned agent"
        );

        // Same cardinality, one address swapped: a genuinely different set, so
        // never the same agent.
        let changed: Vec<SocketAddr> = vec![
            "8.8.8.8:443".parse().unwrap(),
            "1.1.1.1:443".parse().unwrap(),
        ];
        assert!(
            !Arc::ptr_eq(&first, &src.agent_for(changed)),
            "a different address set must never reuse an agent pinned elsewhere"
        );
    }

    // An FMTS disc calls `query` twice per rip; the agent is reused only
    // while the freshly guarded address set is IDENTICAL — see
    // docs/online-agent-cache.md.
    #[test]
    fn the_agent_is_reused_per_address_set_only() {
        let src = OnlineSource::new("https://keyserver.test/keys", "");
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
