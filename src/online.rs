//! Online key-service source.

use std::collections::BTreeMap;
use std::io::Read;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use crate::uks_from_vuk;
use base64::Engine;
use libfreemkv::aacs::types::UnitKey;
use libfreemkv::halt::Liveness;
use libfreemkv::keysource::{DecodeSampleSet, ResolveCtx};
use libfreemkv::{Error, Halt, KeySource};
use ureq::config::Config;
use ureq::http::Uri;
use ureq::unversioned::resolver::{ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::time::Duration as UreqDuration;
use ureq::unversioned::transport::{
    Buffers, ConnectionDetails, Connector, DefaultConnector, NextTimeout, Transport,
};

// Upper bound on the MKB forwarded to the key service — kept in lockstep with
// libfreemkv's `read_mkb_content` MAX_BYTES (64 MiB), so a capturable MKB is
// never silently un-forwardable here (headroom, not an expected size).
const MAX_MKB_BYTES: usize = 64 * 1024 * 1024;
/// Connect bound, TLS handshake included (stop-design-v5 T15: "10 s with no answer").
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Stall bound for the key-service send and receive phases (stop-design-v5 T16, D3).
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Server-side upload processing allowance in the first-byte budget, bytes per second (T17, D3).
const FIRST_BYTE_RATE: u64 = 256 * 1024;
/// Queries in flight per key-service host (stop-design-v5 §2.7).
const MAX_QUERY_WORKERS_PER_HOST: usize = 4;
/// How often a waiting caller re-checks its halt (the Stop design's `WAIT_SLICE`).
const WORKER_POLL_SLICE: Duration = Duration::from_millis(20);
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

// Addresses no connection can reach (unspecified, multicast, broadcast, Class E); LAN,
// loopback and link-local are valid home-network targets. One rule shared with libfreemkv.
use libfreemkv::mux::is_blocked_ip;

// Why resolve_and_guard rejected a URL, split by the operator action each
// demands: Config is a standing misconfiguration (never self-heals),
// Unreachable is the service down now. Both are Err from query, never Ok(empty).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GuardFail {
    // Malformed URL, bad scheme, or a host that resolves to an invalid
    // address. Operator configuration; retrying changes nothing.
    Config,
    // Host did not resolve — DNS failure or timeout. Service unreachable;
    // nothing known about this disc's key. Transient.
    Unreachable,
}

// The `(host, port)` a key-service URL names; `Config` when it is not an https URL with a host.
fn split_authority(url: &str) -> Result<(String, u16), (GuardFail, String)> {
    // ONLY https: the POST body carries base64 key material and a replayable
    // bearer token, so cleartext `http://` is refused here in the shared guard —
    // a standing operator fault (`Config`) caught once at config time, not per rip.
    let Some(authority) = url.strip_prefix("https://") else {
        return Err((
            GuardFail::Config,
            "URL scheme must be https:// (cleartext http:// is refused)".into(),
        ));
    };
    let default_port = 443u16;
    let authority = authority.split(['/', '?', '#']).next().unwrap_or(authority);
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    if authority.is_empty() {
        return Err((GuardFail::Config, "URL has no host".into()));
    }
    let (host, port): (String, u16) = if let Some(stripped) = authority.strip_prefix('[') {
        match stripped.split_once(']') {
            Some((h, after)) => {
                // The only thing allowed after `]` is an optional `:port`. A non-empty
                // tail that isn't `:port` (e.g. `[::1]extra`) is garbage — reject as
                // `Config` rather than silently drop it and connect on the default port.
                let p = if after.is_empty() {
                    default_port
                } else if let Some(port_str) = after.strip_prefix(':') {
                    port_str
                        .parse::<u16>()
                        .map_err(|_| (GuardFail::Config, "invalid port".to_string()))?
                } else {
                    return Err((GuardFail::Config, "malformed IPv6 authority".into()));
                };
                (h.to_string(), p)
            }
            None => return Err((GuardFail::Config, "malformed IPv6 host".into())),
        }
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        match p.parse::<u16>() {
            Ok(p) => (h.to_string(), p),
            // A malformed port (e.g. `:notaport`) is an operator config typo, not a service
            // outage — reject as `Config`, same as the bracketed-IPv6 branch above.
            Err(_) => return Err((GuardFail::Config, "invalid port".into())),
        }
    } else {
        (authority.to_string(), default_port)
    };
    if host.is_empty() {
        return Err((GuardFail::Config, "URL has no host".into()));
    }
    Ok((host, port))
}

// Host lookups started, for the tests that prove a check made none.
#[cfg(test)]
static DNS_LOOKUPS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

// Resolve `url`'s host, validating every address against the SSRF guard;
// returns pinned socket addrs or a rejection reason + message. SECURITY: the
// message names the address — log only at config time, never in `query`.
fn resolve_and_guard(url: &str) -> Result<Vec<SocketAddr>, (GuardFail, String)> {
    let (host, port) = split_authority(url)?;
    // `to_socket_addrs` is a BLOCKING DNS lookup that can hang for the OS
    // resolver timeout and freeze the calling rip thread, so run it on a
    // spawned thread with a bounded deadline (mirrors autorip/libfreemkv).
    let addrs: Vec<SocketAddr> = {
        use std::sync::mpsc;
        const DNS_TIMEOUT: Duration = Duration::from_secs(10);
        // Resolver threads can hang for the OS timeout and are never joined, leaking
        // a thread+stack per attempt — so cap outstanding ones PER HOST (a global cap
        // lets one dead keyserver starve a healthy different one). Const-init map.
        const MAX_DNS_THREADS_PER_HOST: usize = 4;
        static DNS_INFLIGHT: Mutex<std::collections::BTreeMap<String, usize>> =
            Mutex::new(std::collections::BTreeMap::new());
        {
            let mut inflight = DNS_INFLIGHT.lock().unwrap_or_else(|e| e.into_inner());
            let n = inflight.entry(host.clone()).or_insert(0);
            if *n >= MAX_DNS_THREADS_PER_HOST {
                return Err((
                    GuardFail::Unreachable,
                    "too many concurrent DNS resolutions in flight for this host".into(),
                ));
            }
            *n += 1;
        }
        let host = host.clone();
        let (tx, rx) = mpsc::channel();
        #[cfg(test)]
        DNS_LOOKUPS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        std::thread::spawn(move || {
            let res = (host.as_str(), port)
                .to_socket_addrs()
                .map(|it| it.collect::<Vec<SocketAddr>>());
            // Receiver may be gone after the timeout — ignore the send error.
            let _ = tx.send(res);
            // Release this host's slot only when the (possibly long-hung) lookup
            // actually returns, so the cap reflects lookups truly in flight.
            let mut inflight = DNS_INFLIGHT.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(n) = inflight.get_mut(&host) {
                *n -= 1;
                if *n == 0 {
                    inflight.remove(&host);
                }
            }
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
        if is_blocked_ip(a.ip()) {
            return Err((
                GuardFail::Config,
                format!("refusing to connect to invalid address {}", a.ip()),
            ));
        }
    }
    Ok(addrs)
}

/// Validate a key-service base URL before it is handed to [`OnlineSource`].
/// Requires `https` (cleartext `http` is rejected as a `Config` fault — see
/// `resolve_and_guard`), extracts the host, and rejects any host that is — or
/// resolves to — an unspecified / multicast / broadcast / reserved address. Returns `Ok(())`
/// so a caller can gate `OnlineSource`; the error string says why.
///
/// The *config-time* check; [`OnlineSource`] re-guards before each POST, closing the DNS-rebind window.
pub fn validate_keyserver_url(url: &str) -> Result<(), String> {
    check_keyserver_url(url).map_err(|r| r.message)
}

/// Whether a rejected key-service URL can start working without a config change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyserverUrlFault {
    /// Bad scheme, host or port, or an invalid address: retrying changes nothing.
    Permanent,
    /// The host did not resolve (DNS failure, timeout, lookup cap): may succeed later.
    Temporary,
}

/// Why [`check_keyserver_url`] rejected a URL; `message` is [`validate_keyserver_url`]'s text.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct KeyserverUrlRejection {
    pub fault: KeyserverUrlFault,
    pub message: String,
}

impl KeyserverUrlRejection {
    pub fn is_temporary(&self) -> bool {
        self.fault == KeyserverUrlFault::Temporary
    }
}

impl std::fmt::Display for KeyserverUrlRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for KeyserverUrlRejection {}

impl From<(GuardFail, String)> for KeyserverUrlRejection {
    fn from((fail, message): (GuardFail, String)) -> Self {
        let fault = match fail {
            GuardFail::Config => KeyserverUrlFault::Permanent,
            GuardFail::Unreachable => KeyserverUrlFault::Temporary,
        };
        Self { fault, message }
    }
}

/// The key-service URL checks that need no DNS lookup: `https`, a host, a valid port, and
/// no literal invalid address (unspecified, multicast, broadcast, Class E). Every rejection is
/// [`KeyserverUrlFault::Permanent`]. For a factory build, which no Stop can reach: the host
/// lookup (and its guard) runs at the first query, on the source's worker. That query is
/// Stop-aware (`ctx.halt()`, ST-K1b, J10); this static check itself opens no socket.
pub fn check_keyserver_url_static(url: &str) -> Result<(), KeyserverUrlRejection> {
    let (host, _) = split_authority(url).map_err(KeyserverUrlRejection::from)?;
    let literal = host.trim_start_matches('[').trim_end_matches(']');
    match literal.parse::<IpAddr>() {
        Ok(ip) if is_blocked_ip(ip) => Err(KeyserverUrlRejection::from((
            GuardFail::Config,
            format!("refusing to connect to invalid address {ip}"),
        ))),
        _ => Ok(()),
    }
}

/// [`validate_keyserver_url`] with a typed verdict: [`KeyserverUrlFault::Temporary`] only when
/// the host lookup failed, so a caller can keep the source and retry at request time.
pub fn check_keyserver_url(url: &str) -> Result<(), KeyserverUrlRejection> {
    resolve_and_guard(url).map(|_| ()).map_err(Into::into)
}

// ureq's `ResolvedSocketAddrs` is a fixed 16-slot array; `push`ing a 17th
// address panics (out of bounds) on a host with many A records. Keep the
// first 16 — each already validated by `resolve_and_guard`.
const MAX_PINNED_ADDRS: usize = 16;

// The pinned-address resolver behind `hardened_agent`. Must be wired via `Agent::with_parts` —
// `new_with_config` silently keeps live DNS and reopens the rebind window.
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

// Per spec, stop-design-v5 T17: "**60 s + body / 256 KiB/s (D3)**". `request_bytes` is all
// that was written for the request: the body plus a few hundred header bytes.
fn first_byte_budget(idle: Duration, request_bytes: u64) -> Duration {
    let micros = u128::from(request_bytes) * 1_000_000 / u128::from(FIRST_BYTE_RATE);
    idle.saturating_add(Duration::from_micros(
        u64::try_from(micros).unwrap_or(u64::MAX),
    ))
}

// Per spec, stop-design-v5 §2.7: "a ureq connector chained after `DefaultConnector` that
// re-arms a rolling per-read and per-write idle bound". It owns every bound after connect.
#[derive(Debug)]
struct IdleConnector {
    idle: Duration,
}

impl<In: Transport> Connector<In> for IdleConnector {
    type Out = IdleTransport<In>;

    fn connect(
        &self,
        _details: &ConnectionDetails,
        chained: Option<In>,
    ) -> Result<Option<Self::Out>, ureq::Error> {
        Ok(chained.map(|inner| IdleTransport {
            inner,
            idle: self.idle,
            request_bytes: 0,
            awaiting_reply: false,
        }))
    }
}

/// A transport whose every write and read gets a fresh stall bound (T16), except the wait
/// for a reply's first byte, which gets the upload-scaled budget (T17).
#[derive(Debug)]
struct IdleTransport<In> {
    inner: In,
    idle: Duration,
    /// Bytes written for the request now awaiting its reply.
    request_bytes: u64,
    /// A request was written and no reply byte has arrived yet.
    awaiting_reply: bool,
}

thread_local! {
    // Liveness for the query in flight on THIS thread (§2.7, T29), bumped by
    // IdleTransport on every byte moved. Thread-local: ureq's cached Agent
    // reuses one connector across queries whose ctx.progress() differs.
    static ACTIVE_QUERY_PROGRESS: std::cell::RefCell<Option<Liveness>> =
        const { std::cell::RefCell::new(None) };
}

// Bump this thread's active query Liveness, if `PostJob::post` set one; a no-op
// off a worker thread (or with no ctx.progress()).
fn bump_active_progress() {
    ACTIVE_QUERY_PROGRESS.with(|p| {
        if let Some(progress) = p.borrow().as_ref() {
            progress.bump();
        }
    });
}

// ureq hands an unconfigured phase `NotHappening`; the tighter of that and `bound` wins.
fn within(timeout: NextTimeout, bound: Duration) -> NextTimeout {
    let bound = UreqDuration::Exact(bound);
    NextTimeout {
        after: if timeout.after < bound {
            timeout.after
        } else {
            bound
        },
        reason: timeout.reason,
    }
}

impl<In: Transport> Transport for IdleTransport<In> {
    fn buffers(&mut self) -> &mut dyn Buffers {
        self.inner.buffers()
    }

    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), ureq::Error> {
        // T16: "60 s with no bytes written"; the first write after a reply starts a request.
        if !self.awaiting_reply {
            self.awaiting_reply = true;
            self.request_bytes = 0;
        }
        self.request_bytes = self.request_bytes.saturating_add(amount as u64);
        let result = self
            .inner
            .transmit_output(amount, within(timeout, self.idle));
        // §2.7, T29: "bumps it on every byte moved."
        if result.is_ok() && amount > 0 {
            bump_active_progress();
        }
        result
    }

    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        // T17 until the reply's first byte, then T16: "60 s with no bytes read".
        let bound = if self.awaiting_reply {
            first_byte_budget(self.idle, self.request_bytes)
        } else {
            self.idle
        };
        let progressed = self.inner.await_input(within(timeout, bound))?;
        if progressed {
            self.awaiting_reply = false;
            // §2.7, T29: "bumps it on every byte moved."
            bump_active_progress();
        }
        Ok(progressed)
    }

    fn is_open(&mut self) -> bool {
        self.inner.is_open()
    }

    fn is_tls(&self) -> bool {
        self.inner.is_tls()
    }
}

/// Build a ureq agent that follows zero redirects (so a public URL can't
/// 30x-redirect to an internal host) and pins DNS resolution to `pinned`
/// (the addresses already validated by [`resolve_and_guard`]).
fn hardened_agent(pinned: Vec<SocketAddr>) -> ureq::Agent {
    hardened_agent_with(pinned, IDLE_TIMEOUT)
}

// `hardened_agent` with a caller-chosen idle bound, so the stall rules are testable at scale.
// Per spec, stop-design-v5 §2.7: "There is **no total cap.**" — no phase total is configured.
fn hardened_agent_with(pinned: Vec<SocketAddr>, idle: Duration) -> ureq::Agent {
    let config = Config::builder()
        .max_redirects(0)
        .timeout_connect(Some(CONNECT_TIMEOUT))
        // Never the env proxy: PinnedResolver would also answer the proxy's lookup with the key
        // service's address, so with HTTP(S)_PROXY/ALL_PROXY set every key lookup failed.
        .proxy(None)
        .build();
    // `with_parts`, never `new_with_config` — see [`PinnedResolver`].
    ureq::Agent::with_parts(
        config,
        DefaultConnector::new().chain(IdleConnector { idle }),
        PinnedResolver(pinned),
    )
}

#[cfg(test)]
type TestResolve = Arc<dyn Fn() -> Result<Vec<SocketAddr>, (GuardFail, String)> + Send + Sync>;

// Test seam: replaces the host lookup and the POST target, so a loopback stub can play the service.
#[cfg(test)]
#[derive(Clone)]
struct TestNet {
    resolve: TestResolve,
    post_url: String,
    idle: Duration,
}

// Per spec, stop-design-v5 §2.7: "a worker capped at 4 per host … When the cap is full, the
// caller waits halt-aware for a slot (D4)." A slot is freed only when its worker ends.
static QUERY_INFLIGHT: Mutex<BTreeMap<String, usize>> = Mutex::new(BTreeMap::new());

/// One of a host's [`MAX_QUERY_WORKERS_PER_HOST`] worker slots, released on drop.
struct QuerySlot(String);

impl Drop for QuerySlot {
    fn drop(&mut self) {
        let mut inflight = QUERY_INFLIGHT.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = inflight.get_mut(&self.0) {
            *n -= 1;
            if *n == 0 {
                inflight.remove(&self.0);
            }
        }
    }
}

fn acquire_query_slot(host: &str, halt: &Halt) -> Result<QuerySlot, Error> {
    loop {
        if halt.is_cancelled() {
            return Err(Error::Halted);
        }
        {
            let mut inflight = QUERY_INFLIGHT.lock().unwrap_or_else(|e| e.into_inner());
            let n = inflight.entry(host.to_owned()).or_insert(0);
            if *n < MAX_QUERY_WORKERS_PER_HOST {
                *n += 1;
                return Ok(QuerySlot(host.to_owned()));
            }
        }
        std::thread::sleep(WORKER_POLL_SLICE);
    }
}

// Queries holding a worker slot for `host` right now.
#[cfg(test)]
fn query_slots_in_flight(host: &str) -> usize {
    let inflight = QUERY_INFLIGHT.lock().unwrap_or_else(|e| e.into_inner());
    inflight.get(host).copied().unwrap_or(0)
}

/// What a worker hands back: the source's answer and the reachability of its POST, if any.
type WorkerOutcome = (Result<Vec<UnitKey>, Error>, Option<DecodeReachability>);

// Runs `work` (DNS + POST) on a worker in one of `host`'s slots. Per spec, stop-design-v5
// §2.7: "The caller never blocks inside ureq"; on Stop it returns `Halted` within a slice.
fn run_on_worker(
    host: &str,
    halt: &Halt,
    work: impl FnOnce() -> WorkerOutcome + Send + 'static,
) -> Result<Vec<UnitKey>, Error> {
    let slot = acquire_query_slot(host, halt)?;
    let (tx, rx) = mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name("keysource-online".into())
        .spawn(move || {
            // Held until the worker ends on its own, even after the caller has gone.
            let _slot = slot;
            let _ = tx.send(work());
        });
    if spawned.is_err() {
        tracing::warn!(
            target: "freemkv::keysource",
            phase = "keyserver_post",
            "could not start the key-service worker; the service was not asked"
        );
        return Err(Error::KeyServiceUnavailable);
    }
    loop {
        if halt.is_cancelled() {
            // Per spec, stop-design-v5 §2.7: "On Stop, the call returns `Halted` and records
            // nothing." The worker is abandoned; its answer is dropped with the channel.
            return Err(Error::Halted);
        }
        match rx.recv_timeout(WORKER_POLL_SLICE) {
            Ok((answer, reachability)) => {
                // "Reachability is recorded on the caller's thread, and only when the
                // worker's result arrives" (stop-design-v5 §2.7).
                if let Some(outcome) = reachability {
                    record_decode_reachability(outcome);
                }
                return answer;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                tracing::warn!(
                    target: "freemkv::keysource",
                    phase = "keyserver_post",
                    "the key-service worker ended without an answer"
                );
                return Err(Error::KeyServiceUnavailable);
            }
        }
    }
}

/// The disc's encrypted title keys, read on the caller's thread for the worker's VUK path.
struct TitleKeysCtx(Option<Vec<[u8; 16]>>);

impl ResolveCtx for TitleKeysCtx {
    fn disc_hash(&self) -> &str {
        ""
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
        self.0.as_deref().ok_or(Error::AacsKeyRead)
    }
    fn samples(&self, _n: usize) -> Result<Vec<Vec<u8>>, Error> {
        Ok(Vec::new())
    }
}

type AgentCache = Arc<Mutex<Option<(Vec<SocketAddr>, Arc<ureq::Agent>)>>>;

pub struct OnlineSource {
    base_url: String,
    secret: String,
    /// The last agent built, with the address set (sorted, deduped — an order-insensitive SET
    /// KEY) it was pinned to. Reused only when a fresh resolve + SSRF-guard of the host yields
    /// the identical address set, so the anti-rebinding guarantee is untouched: only the pooled
    /// TLS connection is reused, never a stale, un-reguarded address.
    agent: AgentCache,
    /// KU-K1 (J15): whether the most recent `query` failure was transport-class
    /// (`DecodeReachability::Transport`). Reset on every success.
    last_failure_transport: AtomicBool,
    #[cfg(test)]
    test_net: Option<TestNet>,
}

// The agent pinned to `pinned`: the cached one when the address SET is unchanged, else a fresh
// one. Poisoning is recovered from, so one panic cannot fail every later key request.
fn pinned_agent(
    cache: &Mutex<Option<(Vec<SocketAddr>, Arc<ureq::Agent>)>>,
    pinned: Vec<SocketAddr>,
) -> Arc<ureq::Agent> {
    let key = {
        let mut k = pinned.clone();
        k.sort();
        k.dedup();
        k
    };
    let mut guard = cache.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((cached_key, agent)) = guard.as_ref()
        && *cached_key == key
    {
        return agent.clone();
    }
    let agent = Arc::new(hardened_agent(pinned));
    *guard = Some((key, agent.clone()));
    agent
}

impl OnlineSource {
    pub fn new(base_url: impl Into<String>, secret: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            secret: secret.into(),
            agent: Arc::new(Mutex::new(None)),
            last_failure_transport: AtomicBool::new(false),
            #[cfg(test)]
            test_net: None,
        }
    }

    #[cfg(test)]
    fn agent_for(&self, pinned: Vec<SocketAddr>) -> Arc<ureq::Agent> {
        pinned_agent(&self.agent, pinned)
    }

    // The server-resolved Unit Keys for this disc: one round-trip, returning a terminal `UK` or
    // a `VUK` derived locally. `Ok`/`Err` draw the miss-vs-outage distinction; `halt` stops it.
    fn query_with(&self, ctx: &dyn ResolveCtx, halt: &Halt) -> Result<Vec<UnitKey>, Error> {
        // Reset the per-thread decode-reachability slot so it reflects ONLY this
        // query afterwards: `Some(..)` once a POST answers/transport-fails, `None`
        // if we short-circuit before the network. See `take_last_decode_reachability`.
        clear_decode_reachability();
        // No configured service: nothing to resolve.
        if self.base_url.is_empty() {
            return Ok(Vec::new());
        }
        // Refuse to transmit over plaintext: the body carries base64 key material and, when
        // configured, a replayable bearer token. `Err`, not `Ok(empty)`
        if !self.base_url.starts_with("https://") {
            tracing::error!(
                target: "freemkv::keysource",
                "key-service URL is not https:// — refusing to send key material \
                 and credentials in cleartext; the service was NOT asked about this disc \
                 (fix the URL scheme), which is not the same as this disc having no key"
            );
            return Err(Error::KeyServiceUnavailable);
        }
        // A pending Stop returns before any disc material is read or encoded (up to 64 MiB).
        if halt.is_cancelled() {
            return Err(Error::Halted);
        }
        let mkb = ctx.mkb().unwrap_or(&[]);
        // No-URL / bad-URL / over-cap-or-under-sampled draw three different verdicts.
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
        // Everything below touches the network, so it runs on a worker; the body and the
        // title keys (for a VUK reply) are read here, on the caller's thread.
        let job = PostJob {
            url: self.base_url.clone(),
            secret: self.secret.clone(),
            body,
            title_keys: TitleKeysCtx(ctx.enc_title_keys().ok().map(<[_]>::to_vec)),
            agents: self.agent.clone(),
            halt: halt.clone(),
            progress: ctx.progress().cloned(),
            #[cfg(test)]
            test_net: self.test_net.clone(),
        };
        // A URL with no parsable host still takes a slot (keyed by the URL); its worker then
        // fails the address guard at once.
        let host = split_authority(&self.base_url)
            .map(|(host, _)| host)
            .unwrap_or_else(|_| self.base_url.clone());
        run_on_worker(&host, halt, move || job.run())
    }

    // KU-K1 (J15): classify the query just finished, from a PEEK (never a
    // `take`) at the slot — a caller downstream of `resolve` (freemkv-library's
    // server) still needs to read the same verdict once (`query_with` clears it).
    fn record_last_failure_transport(&self, result: &Result<Vec<UnitKey>, Error>) {
        let transport = result.is_err()
            && LAST_DECODE_REACHABILITY.with(|c| c.get()) == Some(DecodeReachability::Transport);
        self.last_failure_transport
            .store(transport, Ordering::Relaxed);
    }
}

/// One key-service round-trip, owned so it can run on a worker thread.
struct PostJob {
    url: String,
    secret: String,
    body: serde_json::Value,
    title_keys: TitleKeysCtx,
    agents: AgentCache,
    /// The caller's Stop, re-checked after the lookup, before anything is sent.
    halt: Halt,
    /// §2.7, T29: bumped on every body byte moved and at answer; held `busy()`
    /// for the call's duration. `None` when the ctx carries no `Liveness`.
    progress: Option<Liveness>,
    #[cfg(test)]
    test_net: Option<TestNet>,
}

impl PostJob {
    // DNS + address guard + POST + reply, on the worker. The reachability it records lands in
    // this thread's slot and is handed back for the caller to record on its own.
    fn run(self) -> WorkerOutcome {
        // §2.1 bullet 3: "The K1 worker holds busy() while a key-service call is
        // in flight" — held for the worker's whole run, including past a Stop
        // the caller already gave up on (the worker still runs to its own bound).
        let _busy = self.progress.as_ref().map(Liveness::busy);
        ACTIVE_QUERY_PROGRESS.with(|p| *p.borrow_mut() = self.progress.clone());
        let answer = self.post();
        (answer, take_last_decode_reachability())
    }

    fn post(self) -> Result<Vec<UnitKey>, Error> {
        #[cfg(test)]
        let guarded = match &self.test_net {
            Some(t) => (t.resolve)(),
            None => resolve_and_guard(&self.url),
        };
        #[cfg(not(test))]
        let guarded = resolve_and_guard(&self.url);
        // Resolve + SSRF-guard the host just before the POST and pin the validated addresses,
        // so a DNS rebind after config time can't redirect the request to an internal host.
        let pinned = match guarded {
            Ok(addrs) => addrs,
            // Did-not-RESOLVE is the service unreachable, not a bad URL.
            Err((GuardFail::Unreachable, _)) => {
                // Never answered, so a transport-class outcome, like a refused connection.
                record_decode_reachability(DecodeReachability::Transport);
                tracing::warn!(
                    target: "freemkv::keysource",
                    phase = "keyserver_post",
                    "key-service host did not resolve (DNS failure or timeout); \
                     the service is unreachable, not out of keys"
                );
                return Err(Error::KeyServiceUnavailable);
            }
            Err((GuardFail::Config, _)) => {
                // Log THAT the URL was rejected, never WHY (the message names the address).
                // `error!` + `Err`, not `Ok(empty)`
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
        #[cfg(test)]
        let (agent, url) = match &self.test_net {
            Some(t) => (
                Arc::new(hardened_agent_with(pinned, t.idle)),
                t.post_url.clone(),
            ),
            None => (pinned_agent(&self.agents, pinned), self.url.clone()),
        };
        #[cfg(not(test))]
        let (agent, url) = (pinned_agent(&self.agents, pinned), self.url.clone());
        let mut req = agent.post(&url);
        if let Some(value) = bearer_header(&self.secret) {
            req = req.header("Authorization", &value);
        }
        // A caller stopped during the lookup has gone: never connect or send the key material
        // and token, so a reopen's query is the only one the service ever sees.
        if self.halt.is_cancelled() {
            return Err(Error::Halted);
        }
        // Begin/end around the round-trip, bounded only by the stall bounds of
        // `hardened_agent`. SECURITY: never log `body` — it carries base64 key material.
        tracing::info!(target: "freemkv::keysource", phase = "keyserver_post", "begin");
        let post_t0 = std::time::Instant::now();
        let sent = req.send_json(self.body);
        interpret_reply(sent, &self.title_keys, post_t0.elapsed().as_millis() as u64)
    }
}

/// The reachability outcome of a single online `/decode` POST — the raw signal
/// a caller needs to tell a *genuine no-key* (the service answered, e.g. a 200
/// with no entry or a definitive 422/404) from a *transient outage* (it did not
/// — transport failure or a 5xx) WITHOUT firing a second probe. Recorded per
/// thread by [`OnlineSource`] on every decode attempt; read (and cleared) with
/// [`take_last_decode_reachability`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeReachability {
    /// The service answered with this HTTP status — any 2xx/3xx/4xx/5xx,
    /// including a 200 no-key, a 404/422 ("licensed but unresolved"), a 429, or
    /// a 502. The caller maps the code to a verdict.
    Status(u16),
    /// No HTTP answer at all — connection refused, timeout, DNS/TLS failure, so
    /// the request was sent (or attempted) but nothing on the other end replied.
    Transport,
}

thread_local! {
    // The reachability of the most recent decode POST on THIS thread. A
    // thread-local (not a struct field) because resolution runs synchronously on
    // the caller's thread while `OnlineSource` is boxed behind `dyn KeySource`.
    static LAST_DECODE_REACHABILITY: std::cell::Cell<Option<DecodeReachability>> =
        const { std::cell::Cell::new(None) };
}

fn clear_decode_reachability() {
    LAST_DECODE_REACHABILITY.with(|c| c.set(None));
}

fn record_decode_reachability(outcome: DecodeReachability) {
    LAST_DECODE_REACHABILITY.with(|c| c.set(Some(outcome)));
}

/// Take — read and clear — the reachability outcome of the most recent online
/// `/decode` POST made ON THIS THREAD, or `None` if no decode reached the
/// network since the last take (the online source was not attempted, or a
/// short-circuit path that never POSTed). Lets a caller classify a no-key result
/// from the REAL decode's HTTP outcome instead of a second, redundant probe.
pub fn take_last_decode_reachability() -> Option<DecodeReachability> {
    LAST_DECODE_REACHABILITY.with(std::cell::Cell::take)
}

/// Set this thread's decode-reachability slot, as a real decode POST would. Test hook (feature
/// `test-hooks`): lets a caller test its [`take_last_decode_reachability`] handling offline.
#[cfg(any(test, feature = "test-hooks"))]
pub fn set_last_decode_reachability(outcome: Option<DecodeReachability>) {
    LAST_DECODE_REACHABILITY.with(|c| c.set(outcome));
}

// Map a key-service HTTP status into the operator action it implies: 401/403
// fix credentials, 429 back off, 5xx wait — none of them is "no key" (the
// definitive 404/422 misses are handled before this function).
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
        Ok(r) => {
            // The service answered — record its status for the reachability slot
            // (a 200/404/422 is "up"; a 5xx is "down"), read by the caller so a
            // no-key needs no second probe.
            record_decode_reachability(DecodeReachability::Status(r.status().as_u16()));
            // §2.7, T29: "bumps it ... at answer" — this IS the answer.
            bump_active_progress();
            r
        }
        Err(e) => {
            // A 4xx/5xx is still an ANSWER (record its status); a transport
            // error is not (record `Transport`).
            let outcome = match &e {
                ureq::Error::StatusCode(code) => DecodeReachability::Status(*code),
                _ => DecodeReachability::Transport,
            };
            // An HTTP error status is still an answer (§2.7, T29); a transport
            // failure never got one, so it never bumps.
            if matches!(outcome, DecodeReachability::Status(_)) {
                bump_active_progress();
            }
            record_decode_reachability(outcome);
            // A definitive miss is an answer for these samples, not a dead source.
            // In particular, FMTS 422 means this phase is not held: the resolver
            // must still be able to ask the same source about the other phase.
            if let ureq::Error::StatusCode(code @ (404 | 422)) = e {
                tracing::info!(
                    target: "freemkv::keysource",
                    phase = "keyserver_post",
                    http_status = code,
                    elapsed_ms,
                    "key service has no key for these samples"
                );
                return Ok(Vec::new());
            }
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
    let read = resp
        .body_mut()
        .as_reader()
        .take(MAX_RESPONSE_BYTES as u64 + 1)
        .read_to_end(&mut buf);
    if read.is_err() {
        // Per spec, stop-design-v5 T16: "no bytes moved" for 60 s → "`Transport` reachability".
        // A reply that stops mid-body never finished answering.
        record_decode_reachability(DecodeReachability::Transport);
    }
    if read.is_err() || buf.len() > MAX_RESPONSE_BYTES {
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
    // A successful JSON reply with no key is also a definitive miss, like
    // 404/422 above. Keep it distinct from service failures such as a 502.
    tracing::info!(
        target: "freemkv::keysource",
        phase = "keyserver_post",
        "key service has no key for this disc"
    );
    Ok(Vec::new())
}

// ST-K1b (stop-design-v5 §2.7): the KU ctx's own token, or an uncancellable
// stand-in for a caller (autorip, a test) that built its ctx with none.
fn ctx_halt(ctx: &dyn ResolveCtx) -> Halt {
    ctx.halt().cloned().unwrap_or_default()
}

impl KeySource for OnlineSource {
    // Base per-CPS-unit Unit Keys via `query`: `Ok(empty)` means the service answered with no
    // key, `Err` means it could not answer.
    fn get_unit_keys(&self, ctx: &dyn ResolveCtx) -> Result<Vec<UnitKey>, Error> {
        let result = self.query_with(ctx, &ctx_halt(ctx));
        self.record_last_failure_transport(&result);
        result
    }

    // AACS 2.1 forensic index set: same `query` round-trip as
    // `get_unit_keys`, but the mux's samples are a single-phase anchor batch
    // and the service's array position tags each forensic index.
    fn get_fmts_indexes(&self, ctx: &dyn ResolveCtx) -> Result<Vec<UnitKey>, Error> {
        let result = self.query_with(ctx, &ctx_halt(ctx));
        self.record_last_failure_transport(&result);
        result
    }

    fn label(&self) -> &'static str {
        "online"
    }

    // host_certs: no-op default. No online cert fetch/endpoint today, so
    // OEM certs fall back to another source (e.g. keydb); no network touched.

    // KU-K1 (J15): only a transport-class failure (no answer at all) is retried by `resolve`.
    fn last_failure_was_transport(&self) -> bool {
        self.last_failure_transport.load(Ordering::Relaxed)
    }

    // KU J23: the service derives keys from the VID it is sent (`vid_b64`), so a Missing
    // piece might open with the disc's VID in hand.
    fn uses_vid(&self) -> bool {
        true
    }
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
        let (kind, _msg) = resolve_and_guard("http://8.8.8.8/keys")
            .expect_err("cleartext http:// must be refused");
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
        let (kind, _) = resolve_and_guard("https://[::1]junk/keys")
            .expect_err("garbage after ] must be rejected");
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
    const T_IDLE: Duration = Duration::from_millis(300);
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
                format!(
                    "HTTP/1.1 {code} X\r\nContent-Length: {body_len}\r\nConnection: close\r\n\r\n"
                )
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
        let src = source_via(host, T_IDLE, move || Ok(vec![addr]));
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
            eventually(Duration::from_secs(5), || query_slots_in_flight(host) == 0),
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
        let src = source_via(host, T_IDLE, move || Ok(vec![addr]));
        let (out, _) = query_cancelled_after(&src, &ctx_with_mkb(0), Duration::from_millis(100));
        assert_eq!(
            out.expect_err("stopped").code(),
            libfreemkv::error::E_HALTED
        );
        assert!(eventually(
            Duration::from_secs(5),
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
}
