//! Online key-service source.

use std::io::Read;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

use crate::uks_from_vuk;
use base64::Engine;
use libfreemkv::aacs::types::UnitKey;
use libfreemkv::keysource::ResolveCtx;
use libfreemkv::{Error, KeySource};

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

/// Resolve `url`'s host and validate every resulting address against the SSRF
/// guard. Returns the pinned socket addresses (for use with a custom ureq
/// resolver) on success, or an error message on rejection.
fn resolve_and_guard(url: &str) -> Result<Vec<SocketAddr>, String> {
    let rest = if let Some(r) = url.strip_prefix("https://") {
        (r, 443u16)
    } else if let Some(r) = url.strip_prefix("http://") {
        (r, 80u16)
    } else {
        return Err("URL must start with http:// or https://".into());
    };
    let (authority, default_port) = rest;
    let authority = authority.split(['/', '?', '#']).next().unwrap_or(authority);
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    if authority.is_empty() {
        return Err("URL has no host".into());
    }
    let (host, port): (String, u16) = if let Some(stripped) = authority.strip_prefix('[') {
        match stripped.split_once(']') {
            Some((h, after)) => {
                let p = after
                    .strip_prefix(':')
                    .map(|s| s.parse::<u16>().map_err(|_| "invalid port".to_string()))
                    .transpose()?
                    .unwrap_or(default_port);
                (h.to_string(), p)
            }
            None => return Err("malformed IPv6 host".into()),
        }
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        match p.parse::<u16>() {
            Ok(p) => (h.to_string(), p),
            Err(_) => (authority.to_string(), default_port),
        }
    } else {
        (authority.to_string(), default_port)
    };
    if host.is_empty() {
        return Err("URL has no host".into());
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
            Ok(Err(e)) => return Err(format!("could not resolve host: {e}")),
            Err(_) => return Err("DNS resolution timed out".into()),
        }
    };
    if addrs.is_empty() {
        return Err("host did not resolve to any address".into());
    }
    for a in &addrs {
        if is_blocked_ip(&a.ip()) {
            return Err(format!(
                "refusing to connect to non-public address {} (SSRF guard)",
                a.ip()
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
    resolve_and_guard(url).map(|_| ())
}

/// Build a ureq agent that follows zero redirects (so a public URL can't
/// 30x-redirect to an internal host) and pins DNS resolution to `pinned`
/// (the addresses already validated by [`resolve_and_guard`]).
fn hardened_agent(pinned: Vec<SocketAddr>) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .redirects(0)
        .timeout_connect(Duration::from_secs(10))
        .timeout_read(Duration::from_secs(TIMEOUT_SECS))
        .resolver(move |_netloc: &str| Ok(pinned.clone()))
        .build()
}

pub struct OnlineSource {
    base_url: String,
    secret: String,
}

impl OnlineSource {
    pub fn new(base_url: impl Into<String>, secret: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            secret: secret.into(),
        }
    }

    /// The server-resolved Unit Keys for this disc, or an empty `Vec`. Runs
    /// exactly one network round-trip. The service returns either a terminal
    /// `UK` (used directly) or a `VUK` (derived to Unit Keys locally via the
    /// disc's encrypted title keys from `ctx`). Any failure — no service,
    /// over-cap MKB, network/parse error, or no key for this disc — yields an
    /// empty `Vec` (the resolver tries the next source). `&self`: one-shot is
    /// the resolver's contract (each source's `get_uk` is called once), so no
    /// per-call latch is needed.
    fn query(&self, ctx: &dyn ResolveCtx) -> Vec<UnitKey> {
        // No configured service: nothing to resolve.
        if self.base_url.is_empty() {
            return Vec::new();
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
            return Vec::new();
        }
        // Gather encrypted-content samples FIRST and enforce the minimum: the
        // service resolves a key by which submitted unit it decrypts, so a
        // request carrying fewer than `MIN_SAMPLE_UNITS` can return a key matching
        // an incidental unit (a false positive, seen on FMTS variant units). Refuse
        // to send an under-sampled request — return empty so the resolver falls
        // through to the next source rather than trusting an ambiguous key.
        let samples = ctx.samples(64).unwrap_or_default();
        if samples.len() < MIN_SAMPLE_UNITS {
            tracing::info!(
                target: "freemkv::keysource",
                samples = samples.len(),
                min = MIN_SAMPLE_UNITS,
                "too few content samples for a reliable online key request; skipping the online source"
            );
            return Vec::new();
        }
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
                .iter()
                .map(|u| serde_json::Value::String(b64.encode(u)))
                .collect(),
        );
        // The disc's own title (UDF/ISO volume id), plain text. The key service
        // catalogs it by disc_hash (its disc-titles.json) — independent of keydb.
        if let Some(label) = ctx.title().map(str::trim) {
            if !label.is_empty() {
                body["title"] = serde_json::Value::String(label.to_string());
            }
        }
        // Resolve + SSRF-guard the host just before the POST; pin the
        // validated addresses into a redirect-disabled agent so a DNS
        // rebind between config time and fetch time can't redirect the
        // request (and the bearer token) to an internal/metadata host.
        let pinned = match resolve_and_guard(&self.base_url) {
            Ok(addrs) => addrs,
            Err(_) => return Vec::new(),
        };
        let agent = hardened_agent(pinned);
        let mut req = agent.post(&self.base_url);
        if let Some(value) = bearer_header(&self.secret) {
            req = req.set("Authorization", &value);
        }
        // Begin/end around the keyserver round-trip — a slow or unresponsive
        // service is the suspected DVD-scan hang. The agent is built with a
        // 10s connect + bounded read timeout (see `hardened_agent`), so this
        // call can never block forever; we log the timing so a slow round-trip
        // is visible. SECURITY: never log `body` — it carries base64 key
        // material.
        tracing::info!(target: "freemkv::keysource", phase = "keyserver_post", "begin");
        let post_t0 = std::time::Instant::now();
        let resp = match req.send_json(body) {
            Ok(r) => r,
            Err(_) => {
                tracing::warn!(
                    target: "freemkv::keysource",
                    phase = "keyserver_post",
                    elapsed_ms = post_t0.elapsed().as_millis() as u64,
                    "keyserver request failed (timeout, network, or HTTP error)"
                );
                return Vec::new();
            }
        };
        tracing::info!(
            target: "freemkv::keysource",
            phase = "keyserver_post",
            elapsed_ms = post_t0.elapsed().as_millis() as u64,
            "end"
        );
        // Bounded read: cap the body so a hostile server can't OOM the client.
        // Reading MAX_RESPONSE_BYTES+1 lets us detect (and reject) an over-cap body.
        let mut buf = Vec::new();
        if resp
            .into_reader()
            .take(MAX_RESPONSE_BYTES as u64 + 1)
            .read_to_end(&mut buf)
            .is_err()
            || buf.len() > MAX_RESPONSE_BYTES
        {
            return Vec::new();
        }
        let json: serde_json::Value = match serde_json::from_slice(&buf) {
            Ok(j) => j,
            Err(_) => return Vec::new(),
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
                for (i, v) in arr.iter().enumerate() {
                    if let Some(k) = v.as_str().and_then(parse_uk) {
                        out.push(UnitKey::new(i as u32, k));
                    }
                }
            }
            if !out.is_empty() {
                return out;
            }
        }
        // A VUK is derived to the terminal keys locally, via the disc's
        // encrypted title keys from the context — the library owns the crypto.
        if let Some(vuk) = json.get("VUK").and_then(|u| u.as_str()).and_then(parse_uk) {
            if let Ok(enc) = ctx.enc_title_keys() {
                return uks_from_vuk(&vuk, enc);
            }
        }
        Vec::new()
    }
}

impl KeySource for OnlineSource {
    fn get_uk(&self, ctx: &dyn ResolveCtx) -> Result<Vec<UnitKey>, Error> {
        Ok(self.query(ctx))
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
