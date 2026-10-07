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
    let waited = std::time::Instant::now();
    let slot = acquire_query_slot(host, halt)?;
    tracing::info!(target: "freemkv::keysource", phase = "keyserver_slot", waited_ms = waited.elapsed().as_millis() as u64, "key-service connection slot acquired");
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
        let guarded = {
            let t0 = std::time::Instant::now();
            let g = resolve_and_guard(&self.url);
            // Count only: the addresses themselves are never logged.
            tracing::info!(
                target: "freemkv::keysource",
                phase = "keyserver_dns",
                ok = g.is_ok(),
                addrs = g.as_ref().map(|a| a.len()).unwrap_or(0),
                elapsed_ms = t0.elapsed().as_millis() as u64,
                "key-service host resolved"
            );
            g
        };
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
#[path = "online_tests.rs"]
mod tests;
