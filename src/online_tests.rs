use super::*;
use std::net::Ipv4Addr;

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
fn resolve_and_guard_allows_lan_literals_and_rejects_invalid_ones() {
    // Numeric literals resolve without DNS. https:// so a rejection is the
    // address guard, not the scheme check (http:// has its own test below).
    let lan = format!("{}.{}.{}.{}:8080", 192, 168, 0, 1);
    for ok in ["127.0.0.1", "169.254.169.254", "[::1]:9000", lan.as_str()] {
        assert!(
            resolve_and_guard(&format!("https://{ok}/keys")).is_ok(),
            "{ok}"
        );
    }
    for bad in [
        "0.0.0.0",
        "224.0.0.1",
        "255.255.255.255",
        "240.0.0.1",
        "[::]",
        "[ff02::1]",
    ] {
        assert!(
            resolve_and_guard(&format!("https://{bad}/keys")).is_err(),
            "{bad}"
        );
    }
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
    assert!(resolve_and_guard("https://[::1/keys").is_err());
    // `host:port` split with an empty host before the colon.
    assert!(resolve_and_guard("https://:8080/keys").is_err());
}

// A host that genuinely does not resolve (RFC 6761 `.test`) must report
// `GuardFail::Unreachable` ("service is down"), not `Config`.
#[test]
fn resolve_and_guard_reports_unreachable_for_a_host_that_never_resolves() {
    let (kind, msg) = resolve_and_guard("https://this-host-does-not-exist.test/keys")
        .expect_err("a .test host must never resolve — if this passes, treat it as a fixture bug");
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

// KT9 (replaces the 180 s totals test). Per spec, stop-design-v5 §2.7: "There is
// **no total cap.**" Every phase bound is a stall bound owned by the idle connector.
// Guard: do not change without a spec citation proving otherwise.
#[test]
fn agent_timeouts_are_idle_not_totals() {
    let agent = hardened_agent(Vec::new());
    let t = agent.config().timeouts();
    assert_eq!(t.global, None, "no whole-request total");
    assert_eq!(t.per_call, None, "no per-call total");
    assert_eq!(t.send_request, None, "request headers: idle only");
    assert_eq!(t.send_body, None, "request body: idle only");
    assert_eq!(
        t.recv_response, None,
        "first byte: the T17 budget, not a total"
    );
    assert_eq!(t.recv_body, None, "reply body: idle only");
    // T15: "Connect | 10 s with no answer (existing)".
    assert_eq!(t.connect, Some(Duration::from_secs(10)));
    // T16: "**60 s (D3)**. This replaces the 180 s totals".
    assert_eq!(IDLE_TIMEOUT, Duration::from_secs(60));
}

#[test]
fn resolve_and_guard_accepts_public_literal() {
    // Public numeric hosts resolve without DNS — must be accepted.
    let addrs = resolve_and_guard("https://8.8.8.8/keys").expect("public IP must be accepted");
    assert!(!addrs.is_empty());
    assert_eq!(addrs[0].port(), 443);

    let addrs =
        resolve_and_guard("https://1.1.1.1:8080/keys").expect("public IP with port accepted");
    assert!(!addrs.is_empty());
    assert_eq!(addrs[0].port(), 8080);
}

// The pin is actually consulted: pin to a loopback listener, then ask for a `.test` host
// that CANNOT resolve.
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
        let _ =
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
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

// ureq 3 defaults to `Proxy::try_from_env()`; PinnedResolver would send the proxy connection to
// the key service's address, failing every lookup. Checked in a child so no test mutates env.
#[test]
fn the_key_service_agent_never_uses_an_environment_proxy() {
    const CHILD: &str = "FMKV_KS_PROXY_CHILD";
    const NAME: &str = "online::tests::the_key_service_agent_never_uses_an_environment_proxy";
    if std::env::var_os(CHILD).is_some() {
        assert!(
            hardened_agent(Vec::new()).config().proxy().is_none(),
            "the pinned agent picked up a proxy from the environment"
        );
        return;
    }
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([NAME, "--exact", "--test-threads=1"])
        .env(CHILD, "1")
        .env("ALL_PROXY", "http://proxy.example:3128")
        .env("HTTPS_PROXY", "http://proxy.example:3128")
        .env("HTTP_PROXY", "http://proxy.example:3128")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("1 passed"),
        "child run failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// Stop rule (stall-based only, Stop can interrupt every wait): a factory build has no
// Halt, so its URL check does no DNS. It rejects what is wrong without a lookup and
// leaves the host lookup to the first query, which is Stop-aware (ST-K1b, J10).
#[test]
fn the_static_check_rejects_config_faults_without_a_lookup() {
    for url in [
        "http://8.8.8.8/keys",
        "ftp://example.com/keys",
        "https:///keys",
        "https://8.8.8.8:notaport/keys",
        "https://[::1/keys",
        "https://0.0.0.0/keys",
        "https://224.0.0.1/keys",
        "https://[ff02::1]:8443/keys",
    ] {
        let r = check_keyserver_url_static(url).expect_err(url);
        assert_eq!(r.fault, KeyserverUrlFault::Permanent, "{url}");
    }
    // A host name is not looked up: `.test` (RFC 2606) never resolves, yet it passes here.
    assert_eq!(
        check_keyserver_url_static("https://keys.ku-e1.test/keys"),
        Ok(())
    );
    assert_eq!(check_keyserver_url_static("https://8.8.8.8/keys"), Ok(()));
    let dns_before = DNS_LOOKUPS.load(Ordering::SeqCst);
    let _ = check_keyserver_url_static("https://keys.example.com/keys");
    assert_eq!(
        DNS_LOOKUPS.load(Ordering::SeqCst),
        dns_before,
        "no DNS lookup"
    );
}

// The typed verdict autorip needs instead of matching message text: a standing fault
// (scheme, host, port, blocked address) is Permanent; only a failed lookup is Temporary.
#[test]
fn check_keyserver_url_types_permanent_rejections() {
    for url in [
        "http://8.8.8.8/keys",
        "ftp://example.com/keys",
        "https:///keys",
        "https://8.8.8.8:notaport/keys",
        "https://[::1/keys",
        "https://0.0.0.0/keys",
        "https://240.0.0.1/latest/meta-data",
    ] {
        let r = check_keyserver_url(url).expect_err(url);
        assert_eq!(r.fault, KeyserverUrlFault::Permanent, "{url}");
        assert!(!r.is_temporary(), "{url}");
        assert_eq!(Err(r.message.clone()), validate_keyserver_url(url), "{url}");
        assert_eq!(r.to_string(), r.message);
    }
    assert_eq!(check_keyserver_url("https://8.8.8.8/keys"), Ok(()));
}

#[test]
fn a_failed_lookup_is_a_temporary_rejection() {
    // Offline: every GuardFail::Unreachable reason resolve_and_guard produces.
    for msg in [
        "DNS resolution timed out",
        "could not resolve host: failed to lookup address information",
        "host did not resolve to any address",
        "too many concurrent DNS resolutions in flight for this host",
    ] {
        let r = KeyserverUrlRejection::from((GuardFail::Unreachable, msg.to_string()));
        assert_eq!(r.fault, KeyserverUrlFault::Temporary, "{msg}");
        assert!(r.is_temporary());
        assert_eq!(r.message, msg);
    }
    let c = KeyserverUrlRejection::from((GuardFail::Config, "URL has no host".into()));
    assert_eq!(c.fault, KeyserverUrlFault::Permanent);
}

// Callers test their verdict mapping with the hook instead of a real DNS lookup.
#[test]
fn the_decode_reachability_hook_plants_what_take_reads() {
    set_last_decode_reachability(Some(DecodeReachability::Status(422)));
    assert_eq!(
        take_last_decode_reachability(),
        Some(DecodeReachability::Status(422))
    );
    assert_eq!(take_last_decode_reachability(), None);
    set_last_decode_reachability(Some(DecodeReachability::Transport));
    set_last_decode_reachability(None);
    assert_eq!(take_last_decode_reachability(), None);
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
fn validate_keyserver_url_allows_lan_and_rejects_invalid_and_bad_scheme() {
    // A home app: loopback, RFC1918 and link-local key services are valid.
    assert!(validate_keyserver_url("https://127.0.0.1/keys").is_ok());
    assert!(validate_keyserver_url("https://169.254.169.254/keys").is_ok());
    assert!(validate_keyserver_url(&format!("https://{}.{}.{}.{}/k", 10, 0, 0, 5)).is_ok());
    assert!(validate_keyserver_url("https://[::1]:9000/keys").is_ok());
    assert!(validate_keyserver_url("https://0.0.0.0/keys").is_err());
    assert!(validate_keyserver_url("https://[ff02::1]/keys").is_err());
    assert!(validate_keyserver_url("ftp://example.com/keys").is_err());
    assert!(validate_keyserver_url("").is_err());
    // A public literal IP passes (no DNS needed, deterministic).
    assert!(validate_keyserver_url("https://8.8.8.8/keys").is_ok());
}

// Cleartext http:// must be refused at CONFIG time (validate_keyserver_url),
// not per-rip — the body carries key material + a replayable token. A public
// host proves it's the SCHEME being rejected, not the address guard.
#[test]
fn non_https_scheme_is_rejected_at_config_time() {
    // A perfectly reachable public host — only the http:// scheme is wrong.
    assert!(validate_keyserver_url("http://8.8.8.8/keys").is_err());
    assert!(resolve_and_guard("http://8.8.8.8/keys").is_err());
    // The rejection is a standing Config fault, never a transient outage.
    let (kind, _msg) =
        resolve_and_guard("http://8.8.8.8/keys").expect_err("cleartext http:// must be refused");
    assert_eq!(kind, GuardFail::Config);
    // https:// for the same public host is accepted.
    assert!(validate_keyserver_url("https://8.8.8.8/keys").is_ok());
}

// A non-empty, non-`:port` tail after a bracketed IPv6 authority (e.g.
// `[::1]extra`) must be rejected as a Config fault, not silently dropped
// with a fall back to the default port.
#[test]
fn resolve_and_guard_rejects_garbage_after_bracketed_ipv6() {
    // `[::1]junk` — junk after the closing bracket.
    let (kind, _) =
        resolve_and_guard("https://[::1]junk/keys").expect_err("garbage after ] must be rejected");
    assert_eq!(kind, GuardFail::Config);
    // A public v6 literal with a trailing garbage tail is likewise rejected
    // (so the garbage can't slip a request out on the default port).
    assert!(resolve_and_guard("https://[2606:4700:4700::1111]extra/keys").is_err());
    // Sanity: the same public v6 literal WITHOUT the tail is accepted.
    assert!(resolve_and_guard("https://[2606:4700:4700::1111]/keys").is_ok());
    // And an explicit :port after ] still parses.
    let addrs = resolve_and_guard("https://[2606:4700:4700::1111]:8443/keys")
        .expect("bracketed v6 with :port must parse");
    assert_eq!(addrs[0].port(), 8443);
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
// (401/403), back off (429), wait (5xx). Definitive misses bypass this mapping.
#[test]
fn http_status_maps_to_the_operator_action() {
    let cases: &[(u16, u16)] = &[
        (401, libfreemkv::error::E_KEY_SERVICE_UNAUTHORIZED),
        (403, libfreemkv::error::E_KEY_SERVICE_UNAUTHORIZED),
        (429, libfreemkv::error::E_KEY_SERVICE_RATE_LIMITED),
        (500, libfreemkv::error::E_KEY_SERVICE_UNAVAILABLE),
        (502, libfreemkv::error::E_KEY_SERVICE_UNAVAILABLE),
        (400, libfreemkv::error::E_KEY_SERVICE_UNAVAILABLE),
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
            "service failures must not mean \"this disc has no key\""
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

// The decode POST records its reachability so the caller classifies a
// no-key from the REAL answer, not a second empty probe: an HTTP answer
// (200/404/422) → `Status(code)`, a transport failure → `Transport`.
#[test]
fn interpret_reply_records_the_decode_reachability() {
    // A 200 with no entry — the service answered; record its status.
    let _ = interpret_reply(Ok(reply(200, "{}")), &BareCtx, 1);
    assert_eq!(
        take_last_decode_reachability(),
        Some(DecodeReachability::Status(200)),
        "a 200 answer must record Status(200)"
    );
    // take clears the slot — a second take sees nothing.
    assert_eq!(
        take_last_decode_reachability(),
        None,
        "take must clear the slot"
    );

    // A definitive 422 ("licensed but unresolved") / 404 is still an ANSWER:
    // record the status so the caller reads it as reachable (genuine no-key).
    for status in [422u16, 404] {
        let keys = interpret_reply(Err(ureq::Error::StatusCode(status)), &BareCtx, 1)
            .expect("a definitive miss must allow the resolver to try the other FMTS phase");
        assert!(keys.is_empty());
        assert_eq!(
            take_last_decode_reachability(),
            Some(DecodeReachability::Status(status)),
            "HTTP {status} must record Status({status}) — a reachable answer"
        );
    }

    // A 5xx is an answer too — Status(502); the caller maps 5xx to down.
    let _ = interpret_reply(Err(ureq::Error::StatusCode(502)), &BareCtx, 1);
    assert_eq!(
        take_last_decode_reachability(),
        Some(DecodeReachability::Status(502)),
        "a 5xx must record its status, not Transport"
    );

    // A transport failure (refused connection) records `Transport` — no
    // HTTP answer, so the caller treats it as a transient outage.
    let config = Config::builder()
        .timeout_connect(Some(Duration::from_secs(2)))
        .build();
    let sent = ureq::Agent::new_with_config(config)
        .post("http://127.0.0.1:1/")
        .send("{}");
    assert!(
        !matches!(sent, Ok(_) | Err(ureq::Error::StatusCode(_))),
        "a refused connection must be a transport error"
    );
    let _ = interpret_reply(sent, &BareCtx, 1);
    assert_eq!(
        take_last_decode_reachability(),
        Some(DecodeReachability::Transport),
        "a transport failure must record Transport, never a Status"
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
    // Full 16 bytes of each key, not just byte 0 — a byte-transposition bug
    // would pass a first-byte-only check.
    assert_eq!(
        keys[0].key,
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    );
    assert_eq!(
        keys[1].key,
        [15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
    );
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
    // Full 16-byte key, not just byte 0.
    assert_eq!(
        keys[0].key,
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    );
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
    // Full-byte KAT: the derived keys must equal the local VUK boil over
    // the disc's encrypted title keys (the same primitive the code calls).
    let vuk = parse_uk(vuk_hex).unwrap();
    let expected = crate::uks_from_vuk(&vuk, &[[0x11u8; 16], [0x22u8; 16]]);
    assert_eq!(keys[0].key, expected[0].key);
    assert_eq!(keys[1].key, expected[1].key);
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
        "http://0.0.0.0/keys",
        "http://240.0.0.1/latest/meta-data/",
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

// ── The pre-flight guards in `query` (nothing leaves the process) ──────.

/// A `ResolveCtx` whose MKB size and sample COUNT are dialled per guard.
#[derive(Default)]
struct GuardCtx {
    mkb: Vec<u8>,
    samples: usize,
    halt: Option<Halt>,
    progress: Option<Liveness>,
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
    fn halt(&self) -> Option<&Halt> {
        self.halt.as_ref()
    }
    fn progress(&self) -> Option<&Liveness> {
        self.progress.as_ref()
    }
}

// An `http://` key-service URL must never be POSTed to; the source refuses with `Err`, not
// an empty that reads as "no key".
#[test]
fn cleartext_http_url_is_refused_before_anything_is_sent() {
    let src = OnlineSource::new("http://keyserver.test/keys", "s3cr3t");
    let ctx = GuardCtx {
        mkb: Vec::new(),
        // Enough samples that ONLY the scheme guard can stop the request.
        samples: MIN_SAMPLE_UNITS,

        ..Default::default()
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

        ..Default::default()
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

        ..Default::default()
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
    // The surviving key must be the planted UK bytes, not merely present.
    assert_eq!(
        keys[0].key,
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        "the at-cap key must be the exact planted UK"
    );
}

// ── A bad port is CONFIG, not an outage ────────────────────────────────

// A typo'd port must be `Config`, not `Unreachable`
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

// The caller-visible half: a mistyped port must get `Err`, exactly like an outage (only the
// log text differs) — catches the `Ok(Vec::new())` regression from `GuardFail::Config`.
#[test]
fn query_with_a_mistyped_port_reports_a_failure_not_a_miss() {
    let src = OnlineSource::new("https://example.com:notaport/keys", "s3cr3t");
    let ctx = GuardCtx {
        mkb: Vec::new(),
        samples: MIN_SAMPLE_UNITS,
        ..Default::default()
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
    // 0.0.0.0 needs no DNS and is unconditionally rejected by is_blocked_ip.
    let src = OnlineSource::new("https://0.0.0.0/keys", "s3cr3t");
    let ctx = GuardCtx {
        mkb: Vec::new(),
        samples: MIN_SAMPLE_UNITS,
        ..Default::default()
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
    let src = OnlineSource::new("https://0.0.0.0/keys", "s3cr3t");
    let ctx = GuardCtx {
        mkb: Vec::new(),
        samples: MIN_SAMPLE_UNITS,
        ..Default::default()
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
        ..Default::default()
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
    // 0.0.0.0 needs no DNS and is unconditionally rejected — the guard
    // fires AFTER the body (incl. vid/title) is already built.
    let src = OnlineSource::new("https://0.0.0.0/keys", "s3cr3t");
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
    let src = OnlineSource::new("https://0.0.0.0/keys", "s3cr3t");
    // Reaches the same guard-blocked failure either way; this test's
    // value is in exercising the whitespace-title branch without panic.
    assert!(src.get_unit_keys(&WhitespaceTitleCtx).is_err());
}

// ── One agent per address set, not one per query ────────────────────── A round-robin
// keyserver reorders the SAME addresses; still the same set, so it must reuse the agent.
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

// An FMTS disc calls `query` twice per rip; the agent is reused only while the freshly
// guarded address set is IDENTICAL.
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

// ── ST-K1a: stall-only key-service timeouts, mid-flight Stop (stop-design-v5 §2.7, §5.3)

/// Scaled T16 idle bound for the loopback tests (60 s in production).
const T_IDLE: Duration = Duration::from_secs(1);
/// Idle bound for a Stop test against a silent stub: well past the Stop, so only the Stop
/// can end the query, and short enough for the abandoned worker to drain within the test.
const T_STOP_IDLE: Duration = Duration::from_secs(2);
/// How long a stub holds a stalled connection; far past every bound under test.
const STUB_HOLD: Duration = Duration::from_secs(20);

fn source_via(
    host: &str,
    idle: Duration,
    resolve: impl Fn() -> Result<Vec<SocketAddr>, (GuardFail, String)> + Send + Sync + 'static,
) -> OnlineSource {
    let mut src = OnlineSource::new(format!("https://{host}/keys"), "s3cr3t");
    src.test_net = Some(TestNet {
        resolve: Arc::new(resolve),
        post_url: format!("http://{host}/keys"),
        idle,
    });
    src
}

fn ctx_with_mkb(len: usize) -> GuardCtx {
    GuardCtx {
        mkb: vec![0x5a; len],
        samples: MIN_SAMPLE_UNITS,
        ..Default::default()
    }
}

/// What the loopback stub does with its one connection.
#[derive(Clone, Copy)]
enum Stub {
    /// Read the whole request, then answer with this status and `{}`.
    Answer(u16),
    /// Read the whole request, then never answer.
    NeverAnswer,
    /// Read the request head only, then stop reading.
    StallUpload,
    /// Answer 200 with a 100-byte body, send 5 bytes of it, then stall.
    StallBody,
    /// Answer 200, then send an `n`-byte JSON body one byte per `gap`.
    TrickleBody { n: usize, gap: Duration },
    /// Read the body `chunk` bytes per `gap`, then answer 200 with `{}`.
    SlowReader { chunk: usize, gap: Duration },
}

fn read_head(sock: &mut std::net::TcpStream) -> usize {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match sock.read(&mut byte) {
            Ok(0) | Err(_) => return 0,
            Ok(_) => head.push(byte[0]),
        }
    }
    let head = String::from_utf8_lossy(&head).to_ascii_lowercase();
    head.lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0)
}

fn read_body(sock: &mut std::net::TcpStream, mut left: usize, chunk: usize, gap: Duration) {
    let mut buf = vec![0u8; chunk.max(1)];
    while left > 0 {
        let want = left.min(buf.len());
        match sock.read(&mut buf[..want]) {
            Ok(0) | Err(_) => return,
            Ok(n) => left -= n,
        }
        if !gap.is_zero() {
            std::thread::sleep(gap);
        }
    }
}

/// A one-connection HTTP/1.1 stub on loopback, playing the key service.
fn stub_server(kind: Stub) -> SocketAddr {
    use std::io::Write as _;
    let listener =
        std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind stub listener");
    let addr = listener.local_addr().expect("stub address");
    std::thread::spawn(move || {
        let Ok((mut sock, _)) = listener.accept() else {
            return;
        };
        let len = read_head(&mut sock);
        let ok = |code: u16, body_len: usize| {
            format!("HTTP/1.1 {code} X\r\nContent-Length: {body_len}\r\nConnection: close\r\n\r\n")
        };
        match kind {
            Stub::Answer(code) => {
                read_body(&mut sock, len, 64 * 1024, Duration::ZERO);
                let _ = sock.write_all(format!("{}{{}}", ok(code, 2)).as_bytes());
            }
            Stub::NeverAnswer => {
                read_body(&mut sock, len, 64 * 1024, Duration::ZERO);
                std::thread::sleep(STUB_HOLD);
            }
            Stub::StallUpload => std::thread::sleep(STUB_HOLD),
            Stub::StallBody => {
                read_body(&mut sock, len, 64 * 1024, Duration::ZERO);
                let _ = sock.write_all(format!("{}{{\"UK\"", ok(200, 100)).as_bytes());
                std::thread::sleep(STUB_HOLD);
            }
            Stub::TrickleBody { n, gap } => {
                read_body(&mut sock, len, 64 * 1024, Duration::ZERO);
                let _ = sock.write_all(ok(200, n).as_bytes());
                let body = format!("{{{}}}", " ".repeat(n - 2));
                for b in body.bytes() {
                    std::thread::sleep(gap);
                    if sock.write_all(&[b]).is_err() {
                        return;
                    }
                }
            }
            Stub::SlowReader { chunk, gap } => {
                read_body(&mut sock, len, chunk, gap);
                let _ = sock.write_all(format!("{}{{}}", ok(200, 2)).as_bytes());
            }
        }
        let _ = sock.flush();
    });
    addr
}

/// Polls `cond` every 10 ms until it holds or `within` passes.
fn eventually(within: Duration, cond: impl Fn() -> bool) -> bool {
    let t0 = std::time::Instant::now();
    while t0.elapsed() < within {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    cond()
}

/// Runs `query_with` on this thread and cancels `halt` after `after`; returns the
/// result and how long after the cancel it came back.
fn query_cancelled_after(
    src: &OnlineSource,
    ctx: &GuardCtx,
    after: Duration,
) -> (Result<Vec<UnitKey>, Error>, Duration) {
    let halt = Halt::new();
    let canceller = {
        let halt = halt.clone();
        std::thread::spawn(move || {
            std::thread::sleep(after);
            halt.cancel();
            std::time::Instant::now()
        })
    };
    let out = src.query_with(ctx, &halt);
    let returned = std::time::Instant::now();
    let cancelled = canceller.join().expect("canceller");
    (out, returned.saturating_duration_since(cancelled))
}

// KT1. Per spec, stop-design-v5 §2.7: "On Stop, the call returns `Halted` and
// records nothing." A hung host lookup must not hold the caller.
#[test]
fn query_halted_during_dns() {
    let host = "kt1.test";
    let src = source_via(host, T_IDLE, || {
        std::thread::sleep(Duration::from_secs(3));
        Err((GuardFail::Unreachable, "DNS resolution timed out".into()))
    });
    let (out, after_cancel) =
        query_cancelled_after(&src, &ctx_with_mkb(0), Duration::from_millis(100));
    assert_eq!(
        out.expect_err("a Stop is never an answer").code(),
        libfreemkv::error::E_HALTED
    );
    assert!(
        after_cancel <= Duration::from_secs(1),
        "Halted took {after_cancel:?}"
    );
    assert_eq!(
        take_last_decode_reachability(),
        None,
        "a Stop records nothing"
    );
    assert!(
        eventually(Duration::from_secs(8), || query_slots_in_flight(host) == 0),
        "the abandoned worker frees its slot when its lookup returns"
    );
}

// KT2. Per spec, stop-design-v5 §2.7: "The worker is abandoned. It ends on its own
// at the next T15–T17 bound, and its slot is freed then."
#[test]
fn query_halted_during_post() {
    let host = "kt2.test";
    let addr = stub_server(Stub::NeverAnswer);
    let src = source_via(host, T_STOP_IDLE, move || Ok(vec![addr]));
    let (out, after_cancel) =
        query_cancelled_after(&src, &ctx_with_mkb(0), Duration::from_millis(150));
    assert_eq!(
        out.expect_err("a Stop is never an answer").code(),
        libfreemkv::error::E_HALTED
    );
    assert!(
        after_cancel <= Duration::from_secs(1),
        "Halted took {after_cancel:?}"
    );
    assert_eq!(
        take_last_decode_reachability(),
        None,
        "a Stop records nothing"
    );
    assert!(
        eventually(Duration::from_secs(10), || query_slots_in_flight(host) == 0),
        "the worker ends at its own first-byte bound and frees its slot"
    );
}

// KT3. Per spec, stop-design-v5 §2.7 (D4): "When the cap is full, the caller waits
// halt-aware for a slot." The cap is "4 per host".
#[test]
fn slot_cap_waits_halt_aware() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let host = "kt3.test";
    let entered = Arc::new(AtomicUsize::new(0));
    let (release, gate) = std::sync::mpsc::channel::<()>();
    let gate = Arc::new(Mutex::new(gate));
    let src = Arc::new({
        let entered = entered.clone();
        source_via(host, T_IDLE, move || {
            entered.fetch_add(1, Ordering::SeqCst);
            let _ = gate.lock().unwrap().recv_timeout(Duration::from_secs(10));
            Err((GuardFail::Unreachable, "released".into()))
        })
    });
    let spawn_query = |halt: Halt| {
        let src = src.clone();
        std::thread::spawn(move || src.query_with(&ctx_with_mkb(0), &halt))
    };
    let first_four: Vec<_> = (0..4).map(|_| spawn_query(Halt::new())).collect();
    assert!(eventually(Duration::from_secs(2), || entered
        .load(Ordering::SeqCst)
        == 4));

    let fifth = spawn_query(Halt::new());
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        entered.load(Ordering::SeqCst),
        4,
        "the 5th query must wait for a slot"
    );
    assert_eq!(query_slots_in_flight(host), MAX_QUERY_WORKERS_PER_HOST);

    // A cancel while waiting for a slot returns Halted and starts nothing.
    let waiting = Halt::new();
    let sixth = spawn_query(waiting.clone());
    std::thread::sleep(Duration::from_millis(100));
    waiting.cancel();
    let sixth = sixth.join().expect("sixth query");
    assert_eq!(
        sixth.expect_err("cancelled while waiting").code(),
        libfreemkv::error::E_HALTED
    );

    // One slot frees, so exactly the waiting 5th proceeds.
    release.send(()).unwrap();
    assert!(eventually(Duration::from_secs(2), || entered
        .load(Ordering::SeqCst)
        == 5));
    for _ in 0..4 {
        release.send(()).unwrap();
    }
    for q in first_four.into_iter().chain([fifth]) {
        assert_eq!(
            q.join().expect("query").expect_err("unreachable").code(),
            libfreemkv::error::E_KEY_SERVICE_UNAVAILABLE
        );
    }
    assert_eq!(
        entered.load(Ordering::SeqCst),
        5,
        "the cancelled 6th never started"
    );
}

// KT4 (T16 a). Per spec, stop-design-v5 §2.7: "Receive headers and body | **60 s with
// no bytes read** | every read that returns bytes". A slow reply that keeps moving lives.
#[test]
fn slow_trickle_response_not_timed_out() {
    let n = 8;
    let gap = T_IDLE / 2;
    assert!(gap * n as u32 > 3 * T_IDLE, "total must exceed 3 × idle");
    let addr = stub_server(Stub::TrickleBody { n, gap });
    let src = source_via("kt4.test", T_IDLE, move || Ok(vec![addr]));
    let out = src.query_with(&ctx_with_mkb(0), &Halt::new());
    assert_eq!(out.expect("a moving reply is never timed out"), Vec::new());
}

// KT5 (T16 b). Per spec, stop-design-v5 T16: "no bytes moved" for 60 s → "`Transport`
// reachability". A reply that stops mid-body fails at idle, as a transport failure.
#[test]
fn stalled_response_body_times_out_on_idle() {
    let addr = stub_server(Stub::StallBody);
    let src = source_via("kt5.test", T_IDLE, move || Ok(vec![addr]));
    let t0 = std::time::Instant::now();
    let out = src.query_with(&ctx_with_mkb(0), &Halt::new());
    let took = t0.elapsed();
    assert_eq!(
        out.expect_err("a stalled reply is no answer").code(),
        libfreemkv::error::E_KEY_SERVICE_UNAVAILABLE
    );
    assert!(
        took <= T_IDLE + Duration::from_secs(1),
        "stall cut after {took:?}"
    );
    assert_eq!(
        take_last_decode_reachability(),
        Some(DecodeReachability::Transport)
    );
}

// KT6 (T16 a, send side). Per spec, stop-design-v5 §2.7: "Send request and body |
// **60 s with no bytes written** | every write that moves bytes".
#[test]
fn slow_upload_not_timed_out() {
    let gap = T_IDLE / 2;
    let chunk = 1024 * 1024;
    let mkb = 8 * 1024 * 1024;
    let addr = stub_server(Stub::SlowReader { chunk, gap });
    let src = source_via("kt6.test", T_IDLE, move || Ok(vec![addr]));
    let t0 = std::time::Instant::now();
    let out = src.query_with(&ctx_with_mkb(mkb), &Halt::new());
    assert!(
        t0.elapsed() > 3 * T_IDLE,
        "the upload must outlast 3 × idle to prove anything"
    );
    assert_eq!(out.expect("a moving upload is never timed out"), Vec::new());
}

// KT7a. Per spec, stop-design-v5 T17: "**60 s + body / 256 KiB/s (D3)**" — the one
// phase with no byte signal while the server processes the upload.
#[test]
fn await_first_byte_budget_scales_with_body() {
    let idle = Duration::from_secs(60);
    assert_eq!(FIRST_BYTE_RATE, 256 * 1024);
    assert_eq!(first_byte_budget(idle, 0), idle);
    assert_eq!(first_byte_budget(idle, 256 * 1024), Duration::from_secs(61));
    assert_eq!(
        first_byte_budget(idle, 128 * 1024),
        Duration::from_millis(60_500)
    );
    // The largest forwardable MKB (64 MiB) buys 256 s of server processing.
    assert_eq!(
        first_byte_budget(idle, 64 * 1024 * 1024),
        Duration::from_secs(316)
    );
    // The largest request saturates instead of overflowing, and never undercuts idle.
    let huge = first_byte_budget(idle, u64::MAX);
    assert!(huge >= idle && huge > first_byte_budget(idle, 64 * 1024 * 1024));
}

// KT7b. Per spec, stop-design-v5 T17: a server that never answers after the body fails
// at "60 s + body / 256 KiB/s" as `Transport` — not at the bare idle bound.
#[test]
fn await_first_byte_budget_expires_without_first_byte() {
    let mkb = 96 * 1024;
    // A lower bound on the bytes written: the base64 MKB alone.
    let floor = first_byte_budget(T_IDLE, (mkb as u64).div_ceil(3) * 4);
    assert!(
        floor >= T_IDLE + Duration::from_millis(400),
        "the body must matter"
    );
    let addr = stub_server(Stub::NeverAnswer);
    let src = source_via("kt7.test", T_IDLE, move || Ok(vec![addr]));
    let t0 = std::time::Instant::now();
    let out = src.query_with(&ctx_with_mkb(mkb), &Halt::new());
    let took = t0.elapsed();
    assert_eq!(
        out.expect_err("no first byte is no answer").code(),
        libfreemkv::error::E_KEY_SERVICE_UNAVAILABLE
    );
    assert!(
        took >= floor,
        "fired at {took:?}, before the {floor:?} first-byte budget"
    );
    assert!(
        took <= floor + Duration::from_secs(1),
        "fired late: {took:?}"
    );
    assert_eq!(
        take_last_decode_reachability(),
        Some(DecodeReachability::Transport)
    );
}

// KT8. Per spec, stop-design-v5 §2.7: "Reachability is recorded on the caller's thread,
// and only when the worker's result arrives." RFC 9110 §15.6 (SS-20): "The 5xx (Server
// Error) class of status code indicates that the server is aware that it has erred".
#[test]
fn reachability_recorded_on_caller_thread_only_on_result() {
    for (host, code) in [("kt8a.test", 200u16), ("kt8b.test", 503)] {
        let addr = stub_server(Stub::Answer(code));
        let src = source_via(host, T_IDLE, move || Ok(vec![addr]));
        let _ = src.query_with(&ctx_with_mkb(0), &Halt::new());
        assert_eq!(
            take_last_decode_reachability(),
            Some(DecodeReachability::Status(code)),
            "an answer ({code}) is recorded on the calling thread"
        );
    }
    // A Stop records nothing, then or later: the late worker result reaches no caller.
    let host = "kt8c.test";
    let addr = stub_server(Stub::NeverAnswer);
    let src = source_via(host, T_STOP_IDLE, move || Ok(vec![addr]));
    let (out, _) = query_cancelled_after(&src, &ctx_with_mkb(0), Duration::from_millis(100));
    assert_eq!(
        out.expect_err("stopped").code(),
        libfreemkv::error::E_HALTED
    );
    assert!(eventually(
        Duration::from_secs(10),
        || query_slots_in_flight(host) == 0
    ));
    assert_eq!(
        take_last_decode_reachability(),
        None,
        "a stopped query records nothing"
    );
}

// KT10. Per spec, stop-design-v5 §2.7: "a Stop … lands within one slice even while DNS,
// connect, upload or download is in progress." Each stall is cancelled at its stage.
#[test]
fn stop_mid_flight_returns_within_a_slice() {
    let idle = Duration::from_secs(2);
    for (host, stub, mkb) in [
        ("kt10a.test", Stub::NeverAnswer, 0),
        ("kt10b.test", Stub::StallUpload, 8 * 1024 * 1024),
        ("kt10c.test", Stub::StallBody, 0),
    ] {
        let addr = stub_server(stub);
        let src = source_via(host, idle, move || Ok(vec![addr]));
        let (out, after_cancel) =
            query_cancelled_after(&src, &ctx_with_mkb(mkb), Duration::from_millis(300));
        assert_eq!(
            out.expect_err(host).code(),
            libfreemkv::error::E_HALTED,
            "{host}"
        );
        assert!(
            after_cancel <= Duration::from_secs(1),
            "{host}: Halted took {after_cancel:?}"
        );
        assert_eq!(
            take_last_decode_reachability(),
            None,
            "{host}: a Stop records nothing"
        );
        // The abandoned worker ends at its own T16/T17 bound, which frees its slot.
        let bound = first_byte_budget(idle, (mkb as u64).div_ceil(3) * 4 + 4096);
        assert!(
            eventually(bound + Duration::from_secs(2), || query_slots_in_flight(
                host
            ) == 0),
            "{host}: the worker's slot was never freed"
        );
    }
}

// G12. Per spec, RFC 9110 §15.4 (SS-20): "The 3xx (Redirection) class of status code
// indicates that further action needs to be taken by the user agent". Never followed.
// Guard: do not change without a spec citation proving otherwise.
#[test]
fn the_agent_keeps_zero_redirects_and_no_proxy_after_the_timeout_change() {
    for agent in [
        hardened_agent(Vec::new()),
        hardened_agent_with(Vec::new(), T_IDLE),
    ] {
        assert_eq!(agent.config().max_redirects(), 0);
        assert!(agent.config().proxy().is_none());
    }
}

// G13. Per stop-design-v5 §5.9 G13: "the byte caps are unchanged: keysources
// `MAX_RESPONSE_BYTES`". Guard: do not change without a spec citation proving otherwise.
#[test]
fn the_reply_byte_cap_is_unchanged() {
    assert_eq!(MAX_RESPONSE_BYTES, 1024 * 1024);
}

// Per keys-upfront-design §2.1 invariant 4 ("No lookups after K exists") and the user
// rule "never call the key service twice": a Stop during the host lookup must send
// nothing, so a reopen's query is the only one the service ever sees.
#[test]
fn a_stop_during_the_lookup_never_reaches_the_service() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let host = "kt1b.test";
    let listener =
        std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind stub listener");
    let addr = listener.local_addr().expect("stub address");
    listener.set_nonblocking(true).expect("nonblocking stub");
    let connections = Arc::new(AtomicUsize::new(0));
    {
        let connections = connections.clone();
        std::thread::spawn(move || {
            let t0 = std::time::Instant::now();
            while t0.elapsed() < Duration::from_secs(5) {
                if listener.accept().is_ok() {
                    connections.fetch_add(1, Ordering::SeqCst);
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        });
    }
    let src = source_via(host, T_IDLE, move || {
        std::thread::sleep(Duration::from_millis(500));
        Ok(vec![addr])
    });
    let (out, _) = query_cancelled_after(&src, &ctx_with_mkb(0), Duration::from_millis(100));
    assert_eq!(
        out.expect_err("stopped").code(),
        libfreemkv::error::E_HALTED
    );
    assert!(eventually(
        Duration::from_secs(3),
        || query_slots_in_flight(host) == 0
    ));
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        connections.load(Ordering::SeqCst),
        0,
        "a stopped query must send nothing"
    );
}

// A Stop that is already pending costs nothing: no samples gathered, no MKB encoded.
#[test]
fn a_pending_stop_returns_before_the_body_is_built() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct CountingCtx(AtomicUsize);
    impl ResolveCtx for CountingCtx {
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
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(&[])
        }
        fn enc_title_keys(&self) -> Result<&[[u8; 16]], Error> {
            Ok(&[])
        }
        fn samples(&self, _n: usize) -> Result<Vec<Vec<u8>>, Error> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(vec![vec![0u8; 16]; MIN_SAMPLE_UNITS])
        }
    }
    let src = source_via("kt1c.test", T_IDLE, || Ok(Vec::new()));
    let halt = Halt::new();
    halt.cancel();
    let ctx = CountingCtx(AtomicUsize::new(0));
    let out = src.query_with(&ctx, &halt);
    assert_eq!(
        out.expect_err("stopped").code(),
        libfreemkv::error::E_HALTED
    );
    assert_eq!(
        ctx.0.load(Ordering::SeqCst),
        0,
        "no disc material read after a Stop"
    );
    assert_eq!(take_last_decode_reachability(), None);
}

// ── KU-K1: `last_failure_was_transport` (J13, J15) ──────────────────────

// KU J23: the service derives keys from the VID it is sent (`vid_b64`; KS-16 "Kvu =
// AES-G(Km, IDv)"), so a Missing piece might open with the disc's VID in hand (E7034).
#[test]
fn online_source_uses_the_vid() {
    assert!(OnlineSource::new("https://keyserver.test/keys", "s3cr3t").uses_vid());
}

#[test]
fn last_failure_was_transport_is_false_before_any_query() {
    let src = OnlineSource::new("https://keyserver.test/keys", "s3cr3t");
    assert!(!src.last_failure_was_transport());
}

// Per J15/J13: a DNS failure never answers, so it is transport-class and gets retried.
#[test]
fn last_failure_was_transport_true_after_dns_failure() {
    let src = source_via("kuk1a.test", T_IDLE, || {
        Err((GuardFail::Unreachable, "did not resolve".into()))
    });
    assert!(src.get_unit_keys(&ctx_with_mkb(0)).is_err());
    assert!(
        src.last_failure_was_transport(),
        "a DNS failure is transport-class"
    );
}

// A refused connection never answers either — transport-class (J13's "connect").
#[test]
fn last_failure_was_transport_true_after_connect_refused() {
    let refused: SocketAddr = ([127, 0, 0, 1], 1).into();
    let src = source_via("kuk1b.test", T_IDLE, move || Ok(vec![refused]));
    assert!(src.get_unit_keys(&ctx_with_mkb(0)).is_err());
    assert!(
        src.last_failure_was_transport(),
        "a refused connection is transport-class"
    );
}

// Stop-design-v5 T16: "no bytes moved" for the idle bound is a transport-class timeout.
#[test]
fn last_failure_was_transport_true_after_idle_timeout() {
    let addr = stub_server(Stub::NeverAnswer);
    let src = source_via("kuk1c.test", T_IDLE, move || Ok(vec![addr]));
    assert!(src.get_unit_keys(&ctx_with_mkb(0)).is_err());
    assert!(
        src.last_failure_was_transport(),
        "an idle stall is transport-class"
    );
}

// J15: a 5xx (or any decode reply) IS an answer, so it must never look transport-class —
// that would re-ask a source the service already answered ("never call it twice").
#[test]
fn last_failure_was_transport_false_after_5xx() {
    let addr = stub_server(Stub::Answer(503));
    let src = source_via("kuk1d.test", T_IDLE, move || Ok(vec![addr]));
    assert!(src.get_unit_keys(&ctx_with_mkb(0)).is_err());
    assert!(
        !src.last_failure_was_transport(),
        "the service answered (5xx) — never re-asked"
    );
}

// J15: "reset it on success" — a later answer must clear a prior transport verdict.
#[test]
fn last_failure_was_transport_resets_on_success() {
    let ok_addr = stub_server(Stub::Answer(200));
    let refused: SocketAddr = ([127, 0, 0, 1], 1).into();
    let target = Arc::new(Mutex::new(refused));
    let for_resolve = target.clone();
    let src = source_via("kuk1e.test", T_IDLE, move || {
        Ok(vec![*for_resolve.lock().unwrap()])
    });
    assert!(src.get_unit_keys(&ctx_with_mkb(0)).is_err());
    assert!(src.last_failure_was_transport());
    *target.lock().unwrap() = ok_addr;
    assert!(src.get_unit_keys(&ctx_with_mkb(0)).is_ok());
    assert!(
        !src.last_failure_was_transport(),
        "a success must reset the flag"
    );
}

// Regression: freemkv-library's server takes the reachability slot itself
// after `resolve`, to classify a no-key without a second probe.
// `last_failure_was_transport` must PEEK it, not TAKE it (never ask twice).
#[test]
fn recording_last_failure_does_not_erase_the_reachability_slot() {
    let addr = stub_server(Stub::Answer(422));
    let src = source_via("kuk1f.test", T_IDLE, move || Ok(vec![addr]));
    assert!(src.get_unit_keys(&ctx_with_mkb(0)).unwrap().is_empty());
    assert_eq!(
        take_last_decode_reachability(),
        Some(DecodeReachability::Status(422)),
        "get_unit_keys must leave the slot for a later caller (e.g. the server) to read"
    );

    let addr = stub_server(Stub::Answer(422));
    let src = source_via("kuk1g.test", T_IDLE, move || Ok(vec![addr]));
    assert!(src.get_fmts_indexes(&ctx_with_mkb(0)).unwrap().is_empty());
    assert_eq!(
        take_last_decode_reachability(),
        Some(DecodeReachability::Status(422)),
        "get_fmts_indexes must leave the slot too"
    );
}

// The base and forensic paths share `query_with`, so the flag must update
// through `get_fmts_indexes` exactly as it does through `get_unit_keys`.
#[test]
fn last_failure_was_transport_true_through_get_fmts_indexes() {
    let addr = stub_server(Stub::NeverAnswer);
    let src = source_via("kuk1h.test", T_IDLE, move || Ok(vec![addr]));
    assert!(src.get_fmts_indexes(&ctx_with_mkb(0)).is_err());
    assert!(
        src.last_failure_was_transport(),
        "get_fmts_indexes must classify the failure too"
    );
}

// Stop-design-v5 T16: a reply that stalls mid-BODY (not just before the
// first byte) is still "no bytes moved" past idle — transport-class.
#[test]
fn last_failure_was_transport_true_after_mid_body_stall() {
    let addr = stub_server(Stub::StallBody);
    let src = source_via("kuk1i.test", T_IDLE, move || Ok(vec![addr]));
    assert!(src.get_unit_keys(&ctx_with_mkb(0)).is_err());
    assert!(
        src.last_failure_was_transport(),
        "a mid-body stall is transport-class"
    );
}

// J15: a definite answer after a transport failure must clear the flag — the
// NEXT verdict always wins, so a stale `true` never survives past one query.
#[test]
fn last_failure_was_transport_resets_from_true_on_5xx() {
    let refused: SocketAddr = ([127, 0, 0, 1], 1).into();
    let answering = stub_server(Stub::Answer(503));
    let target = Arc::new(Mutex::new(refused));
    let for_resolve = target.clone();
    let src = source_via("kuk1j.test", T_IDLE, move || {
        Ok(vec![*for_resolve.lock().unwrap()])
    });
    assert!(src.get_unit_keys(&ctx_with_mkb(0)).is_err());
    assert!(src.last_failure_was_transport());
    *target.lock().unwrap() = answering;
    assert!(src.get_unit_keys(&ctx_with_mkb(0)).is_err());
    assert!(
        !src.last_failure_was_transport(),
        "a 5xx answer must clear a prior transport verdict"
    );
}
// ── ST-K1b: `ctx.halt()` / `ctx.progress()` wired to KU's ctx (stop-design-v5 §2.7) ──

// `get_unit_keys` must wait on `ctx.halt()`, not a fresh `Halt::new()` — a Stop
// reaching only the KU ctx must still land within one slice.
#[test]
fn stop_during_stalled_post_returns_halted_via_ctx_halt() {
    let addr = stub_server(Stub::NeverAnswer);
    let src = source_via("stk1b1.test", T_IDLE, move || Ok(vec![addr]));
    let halt = Halt::new();
    let ctx = GuardCtx {
        mkb: Vec::new(),
        samples: MIN_SAMPLE_UNITS,
        halt: Some(halt.clone()),
        progress: None,
    };
    let canceller = {
        let halt = halt.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            halt.cancel();
        })
    };
    let out = src.get_unit_keys(&ctx);
    canceller.join().expect("canceller");
    assert_eq!(
        out.expect_err("a ctx.halt() Stop is never an answer")
            .code(),
        libfreemkv::error::E_HALTED
    );
}

// T29: `ctx.progress()` must bump on body bytes moved, WHILE the call is
// still running — not only once, after it ends.
#[test]
fn progress_bumps_during_a_slow_body() {
    let n = 6;
    let gap = T_IDLE / 2;
    let addr = stub_server(Stub::TrickleBody { n, gap });
    let src = Arc::new(source_via("stk1b2.test", T_IDLE, move || Ok(vec![addr])));
    let progress = Liveness::new();
    let ctx = GuardCtx {
        mkb: Vec::new(),
        samples: MIN_SAMPLE_UNITS,
        halt: None,
        progress: Some(progress.clone()),
    };
    let handle = {
        let src = src.clone();
        std::thread::spawn(move || src.get_unit_keys(&ctx))
    };
    let seen_mid_flight = eventually(gap * n as u32 + T_IDLE, || progress.get() > 0);
    let out = handle.join().expect("query thread");
    assert!(
        seen_mid_flight,
        "progress must bump before the trickle finishes"
    );
    assert_eq!(
        out.expect("a trickled {} body is a genuine miss"),
        Vec::new()
    );
    assert!(
        progress.get() > 1,
        "a multi-byte trickle must bump more than once, got {}",
        progress.get()
    );
}

// §2.1 bullet 3: "The K1 worker holds `busy()` while a key-service call is in
// flight." An `idle_only` `StallTimer` on the same `Liveness` must never see
// `Expired` while the call runs, even though a `NeverAnswer` stub sends nothing.
#[test]
fn busy_is_held_during_the_call() {
    let addr = stub_server(Stub::NeverAnswer);
    let src = Arc::new(source_via("stk1b3.test", T_IDLE, move || Ok(vec![addr])));
    let progress = Liveness::new();
    let ctx = GuardCtx {
        mkb: Vec::new(),
        samples: MIN_SAMPLE_UNITS,
        halt: None,
        progress: Some(progress.clone()),
    };
    let mut timer = libfreemkv::halt::StallTimer::idle_only(T_IDLE / 4, &progress);
    let handle = {
        let src = src.clone();
        std::thread::spawn(move || src.get_unit_keys(&ctx))
    };
    std::thread::sleep(T_IDLE / 2);
    let stall = timer.poll(&progress);
    let _ = handle.join();
    assert!(
        !matches!(stall, libfreemkv::halt::Stall::Expired),
        "busy() must hold off the idle timer while the call is in flight: got {stall:?}"
    );
}
