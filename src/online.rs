//! Online key-service source.

use std::io::Read;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

use base64::Engine;
use libfreemkv::{DiscInputs, Key, KeySource};

const MAX_MKB_BYTES: usize = 10 * 1024 * 1024;
const TIMEOUT_SECS: u64 = 180;
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
    /// The key service pre-validates server-side and returns a single UK, so it
    /// is asked **at most once** — this flips true after the first `next_key`,
    /// and every later ask returns `None` without re-hitting the network.
    asked: bool,
    /// Set when the round-trip itself failed (network down, bad response) — as
    /// opposed to the service simply having no key. Lets the caller report
    /// "key service unreachable" distinctly from "no key for this disc".
    errored: bool,
}

impl OnlineSource {
    pub fn new(base_url: impl Into<String>, secret: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            secret: secret.into(),
            asked: false,
            errored: false,
        }
    }

    /// The single server-resolved UK for this disc, or `None`. Runs exactly the
    /// one network round-trip; `next_key` gates it to one call per session.
    fn query(&mut self, inputs: &DiscInputs) -> Option<Key> {
        // No configured service: a clean None ("no service"), not an error.
        if self.base_url.is_empty() {
            return None;
        }
        // An over-cap MKB is a real failure to resolve THIS disc, not "no
        // service" — flag it so the caller reports it distinctly (and a later
        // ask doesn't conflate it with a missing key).
        if inputs.mkb.len() > MAX_MKB_BYTES {
            self.errored = true;
            return None;
        }
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut body = serde_json::json!({
            "inf_b64": b64.encode(&inputs.unit_key_ro),
            "mkb_b64": b64.encode(&inputs.mkb),
        });
        if inputs.volume_id != [0u8; 16] {
            body["vid_b64"] = serde_json::Value::String(b64.encode(inputs.volume_id));
        }
        if !inputs.samples.is_empty() {
            body["units_b64"] = serde_json::Value::Array(
                inputs
                    .samples
                    .iter()
                    .map(|u| serde_json::Value::String(b64.encode(u)))
                    .collect(),
            );
        }
        // The disc's own title (UDF/ISO volume id), plain text. The key service
        // catalogs it by disc_hash (its disc-titles.json) — independent of keydb.
        if let Some(label) = inputs.volume_label.as_deref().map(str::trim) {
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
            Err(_) => {
                self.errored = true;
                return None;
            }
        };
        let agent = hardened_agent(pinned);
        let mut req = agent.post(&self.base_url);
        if !self.secret.is_empty() {
            req = req.set("Authorization", &format!("Bearer {}", self.secret));
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
                self.errored = true;
                return None;
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
            self.errored = true;
            return None;
        }
        let json: serde_json::Value = match serde_json::from_slice(&buf) {
            Ok(j) => j,
            Err(_) => {
                self.errored = true;
                return None;
            }
        };
        json.get("UK")
            .and_then(|u| u.as_str())
            .and_then(parse_uk)
            .map(|uk| Key::Unit(vec![(1, uk)]))
    }
}

impl KeySource for OnlineSource {
    fn next_key(&mut self, inputs: &DiscInputs) -> Option<Key> {
        // One shot: the service pre-validates and returns a single UK, so a
        // second ask has nothing new to offer — don't re-hit the network.
        if self.asked {
            return None;
        }
        self.asked = true;
        self.query(inputs)
    }

    fn needs_samples(&self) -> bool {
        true
    }

    fn errored(&self) -> bool {
        self.errored
    }
}

fn parse_uk(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 32 {
        return None;
    }
    // Reject any non-hex byte up front. `u8::from_str_radix` on a 2-char
    // window otherwise accepts sign prefixes (e.g. "+5", "-A"), letting a
    // signed/whitespace-tainted string slip through as a valid key.
    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
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
