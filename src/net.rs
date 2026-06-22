// AUTHORED-BY Claude Opus 4.8
//! The DNS-pinned, SSRF-guarded HTTP fetch primitive shared by the network adapters.
//!
//! This is the **single load-bearing security plumbing** of M2. Both the OIDC-discovery / JWKS fetch
//! ([`crate::config::NetworkJwksProvider`]) and the WebID-profile fetch
//! ([`crate::webid::NetworkWebIdResolver`]) go through [`SafeFetcher::get`], so the SSRF discipline is
//! implemented exactly once and cannot drift between the two surfaces.
//!
//! The discipline (a faithful port of `packages/guarded-fetch` + `webidResolver.ts`, spike risk R5):
//!   1. **Per-URL static gate** — scheme allowlist (https only, http only under `allow_loopback`),
//!      userinfo refusal, and IP-literal classification. (Reuses [`crate::webid::ssrf_gate_static`].)
//!   2. **Resolve the host ourselves** (`hickory-resolver`) to the FULL record set.
//!   3. **Classify EVERY resolved record** through the M1 [`crate::ssrf`] classifier; if ANY record is
//!      non-public the request is refused — the DNS-rebinding mitigation (an attacker who returns one
//!      public + one private A record cannot smuggle the private one past us).
//!   4. **Pin the connection to the validated IP(s)** via reqwest `resolve_to_addrs`, so the socket
//!      connects to exactly the address we classified — closing the resolve-then-connect TOCTOU
//!      window (reqwest pins NO DNS by default).
//!   5. **No auto-redirect.** `redirect(Policy::none())`; a 3xx is followed MANUALLY, re-running the
//!      WHOLE gate (1–4) on each `Location` — so a 302 from a public host to `169.254.169.254` /
//!      `127.0.0.1` / an RFC-1918 address fails closed. A bounded hop count stops redirect loops.
//!   6. **Bounded body + timeout.** The response body is read with a hard byte cap (DoS guard against
//!      an oversized JWKS / profile) and the whole request has a wall-clock timeout.
//!
//! Errors are deliberately COARSE (`SafeFetchError`) — the caller turns them into the constant,
//! non-leaky client-facing message (the reconnaissance-oracle guard). We never echo the resolved IP or
//! the redirect target to the client.
//!
//! (The whole module is `network`-feature-gated at its declaration in `lib.rs`.)

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use url::Url;

use crate::ssrf::Nat64Policy;
use crate::webid::{
    classify_resolved_address_with_nat64, ssrf_gate_static_with_nat64, WebIdProfileError,
};

/// Hard cap on a fetched body (discovery doc / JWKS / WebID profile). 1 MiB is far above any real
/// JWKS or profile document and bounds the DoS surface of an attacker-controlled (or
/// compromised-IdP) endpoint streaming an unbounded body.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Default per-request wall-clock timeout. Covers connect + TLS + the (bounded) body read.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum number of redirect hops to follow MANUALLY (each fully re-gated). A small bound — real
/// discovery / JWKS / WebID endpoints redirect 0–1 times; this stops a redirect loop / chain DoS.
pub const MAX_REDIRECTS: usize = 5;

/// A coarse fetch failure. Intentionally carries only a short internal-logging reason — never the
/// resolved IP, the redirect target, or response bytes (the SSRF reconnaissance-oracle guard).
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct SafeFetchError(pub String);

impl From<WebIdProfileError> for SafeFetchError {
    fn from(e: WebIdProfileError) -> Self {
        SafeFetchError(e.0)
    }
}

/// A successfully-fetched, size-bounded response body + the final (already-gated) URL it came from.
pub struct SafeResponse {
    pub body: Vec<u8>,
    /// The URL the body was actually fetched from (after any followed, re-gated redirects). Useful for
    /// resolving a relative `jwks_uri` against the discovery doc's effective location.
    pub final_url: String,
}

/// Configuration for [`SafeFetcher`].
#[derive(Clone)]
pub struct SafeFetchConfig {
    /// Permit `http:` to a loopback address (dev / IT only). Production leaves this `false`.
    pub allow_loopback: bool,
    /// Per-request wall-clock timeout.
    pub timeout: Duration,
    /// Hard body-size cap in bytes.
    pub max_body_bytes: usize,
    /// Max manual (re-gated) redirect hops.
    pub max_redirects: usize,
    /// Operator-configured NAT64 NSP allowlist (opt-in, default-OFF / empty). When non-empty, an
    /// IPv6 resolved-record (or IP-literal host) that falls under a configured NSP has its embedded
    /// IPv4 decoded and re-classified, so an embedded private/loopback/link-local v4 is refused. The
    /// IANA well-known `64:ff9b::/96` is ALWAYS decoded regardless of this list (strict baseline).
    /// Mirrors the `allow_loopback` seam: default-OFF, opt-in only.
    pub nat64: Nat64Policy,
}

impl Default for SafeFetchConfig {
    fn default() -> Self {
        Self {
            allow_loopback: false,
            timeout: DEFAULT_TIMEOUT,
            max_body_bytes: MAX_BODY_BYTES,
            max_redirects: MAX_REDIRECTS,
            nat64: Nat64Policy::strict(),
        }
    }
}

/// Resolves a hostname to its A/AAAA records. Abstracted so tests can inject a deterministic resolver
/// (including the adversarial "one public + one private record" / "rebind-to-private" cases) WITHOUT a
/// live network, while production uses the system resolver via `hickory-resolver`.
pub trait HostResolver: Send + Sync {
    /// Resolve `host` to zero+ IP addresses. An empty result (or an `Err`) makes the fetch fail closed.
    fn resolve_host(&self, host: &str) -> Result<Vec<IpAddr>, SafeFetchError>;
}

/// A single DNS-resolution request handed to the resolver thread: the host to look up + a one-shot
/// channel for the (full) record set or the coarse error.
///
/// The reply channel is a plain `std::sync::mpsc::Sender` so the (synchronous) caller in
/// [`HostResolver::resolve_host`] can block on the reply with an ordinary `recv()` — no Tokio runtime
/// entry on the caller's thread. The *job* channel (host → resolver thread) is an async tokio channel
/// (see [`SystemResolver`]) so the dispatch loop can `tokio::spawn` each lookup CONCURRENTLY.
type ResolveJob = (
    String,
    std::sync::mpsc::Sender<Result<Vec<IpAddr>, SafeFetchError>>,
);

/// The production resolver: `hickory-resolver` reading the system config. Returns the FULL record set
/// (every A + AAAA) so the per-record classification sees all of them.
///
/// ## Why a dedicated resolver thread + an ASYNC resolver (the runtime-panic fix)
/// [`HostResolver::resolve_host`] is a **synchronous** trait method (so the whole sync `SafeFetcher`
/// chain — and the sync `JwksProvider`/`WebIdResolver` seams the verifier drives — stay sync, and the
/// blocking `reqwest::blocking` HTTP path, which spawns its OWN runtime thread, keeps working from
/// inside a caller's runtime). But hickory's *synchronous* `Resolver::lookup_ip` internally does
/// `Runtime::block_on`, which **panics** ("Cannot start a runtime from within a runtime") when it is
/// invoked from inside an existing Tokio runtime — exactly what happens when a Tokio/axum handler (e.g.
/// `solid-server-rs`) calls `Verifier::verify` directly (not via `spawn_blocking`).
///
/// The fix: own a dedicated background thread that runs a *current-thread* Tokio runtime and a
/// [`hickory_resolver::TokioAsyncResolver`] (genuinely async `lookup_ip`). `resolve_host` ships the
/// host to that thread over a channel and blocks on the reply. The `block_on` now happens on a thread
/// that has NO ambient runtime, so it is legal — no panic — and the caller's runtime is never touched.
///
/// ## Concurrent lookups (the head-of-line-blocking fix)
/// The resolver thread drives lookups CONCURRENTLY rather than one-at-a-time. A `TokioAsyncResolver` is
/// cheaply cloneable (`Arc`-shared internals), so the dispatch loop — a single `block_on` of an async
/// task that drains the (async) job channel — `tokio::spawn`s each `lookup_ip` onto the thread's runtime
/// with its own clone of the resolver and replies on that job's own oneshot channel. A slow lookup
/// therefore CANNOT head-of-line-block a fast one sharing the same `SystemResolver`: N concurrent
/// `resolve_host` calls run in parallel. (The thread's runtime is current-thread, so the spawned tasks
/// are cooperatively multiplexed on the one resolver thread — which is exactly right for I/O-bound DNS
/// waits: a task awaiting a slow nameserver yields, letting a fast lookup complete and reply first.)
///
/// **SSRF guarantees are unchanged:** `resolve_host` still returns the FULL A+AAAA record set; every
/// record is classified by [`SafeFetcher::get`] (the per-record public-address check, DNS-rebinding
/// refusal, NAT64 decode), and the connection is still pinned to the validated IP(s). This thread does
/// resolution only; it changes nothing about *which* addresses are accepted.
pub struct SystemResolver {
    /// Send a job to the resolver thread over an ASYNC tokio channel (so the dispatch loop can await it
    /// and spawn each lookup concurrently). Cloneable + `Send`/`Sync`, so it is used directly from
    /// `&self` across threads — no `Mutex` needed.
    tx: tokio::sync::mpsc::UnboundedSender<ResolveJob>,
}

impl SystemResolver {
    /// Build the resolver: spawn the dedicated thread that owns a current-thread Tokio runtime + an
    /// async `TokioAsyncResolver` (system `/etc/resolv.conf`, falling back to a sane default). The
    /// runtime + resolver are built ON that thread (so no ambient-runtime requirement at construction),
    /// and the thread loops serving resolution jobs until the `SystemResolver` (and thus the sender) is
    /// dropped.
    pub fn new() -> Result<Self, SafeFetchError> {
        // ASYNC job channel: the dispatch loop awaits it inside `block_on` and `tokio::spawn`s each
        // lookup, so a slow lookup cannot head-of-line-block a fast one.
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<ResolveJob>();
        // A oneshot channel for the thread to report whether resolver init succeeded, so `new()` can
        // surface an init failure synchronously (fail-closed) rather than only at first lookup.
        let (init_tx, init_rx) = std::sync::mpsc::channel::<Result<(), String>>();

        std::thread::Builder::new()
            .name("solid-oidc-dns-resolver".to_string())
            .spawn(move || {
                // A current-thread runtime owned by THIS thread — `block_on` here is legal because the
                // thread has no other runtime. (We never enter this runtime from the caller's thread.)
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        let _ = init_tx.send(Err(format!("DNS runtime init failed: {e}")));
                        return;
                    }
                };

                // Build the ASYNC resolver. `tokio_from_system_conf` reads /etc/resolv.conf; fall back
                // to the default config on a platform/host without one (mirrors the prior behaviour).
                // Cloneable (`Arc`-shared internals) so each spawned lookup gets its own cheap clone.
                let resolver = hickory_resolver::TokioAsyncResolver::tokio_from_system_conf()
                    .unwrap_or_else(|_| {
                        hickory_resolver::TokioAsyncResolver::tokio(
                            hickory_resolver::config::ResolverConfig::default(),
                            hickory_resolver::config::ResolverOpts::default(),
                        )
                    });
                // Resolver construction is infallible here (the fallback can't fail), so signal ready.
                let _ = init_tx.send(Ok(()));

                // Drive the shared concurrent dispatch loop with the production hickory lookup. Each job
                // clones the (`Arc`-shared) resolver into its own spawned task — see `run_resolver_loop`.
                runtime.block_on(run_resolver_loop(rx, move |host| {
                    let resolver = resolver.clone();
                    async move {
                        resolver
                            .lookup_ip(host.as_str())
                            .await
                            .map(|lookup| lookup.iter().collect::<Vec<IpAddr>>())
                            .map_err(|e| SafeFetchError(format!("DNS lookup failed: {e}")))
                    }
                }));
            })
            .map_err(|e| SafeFetchError(format!("DNS resolver thread spawn failed: {e}")))?;

        // Wait for the thread to report resolver-init status (fail-closed if it couldn't even start).
        match init_rx.recv() {
            Ok(Ok(())) => Ok(Self { tx }),
            Ok(Err(msg)) => Err(SafeFetchError(msg)),
            Err(_) => Err(SafeFetchError(
                "DNS resolver thread exited before initialising.".to_string(),
            )),
        }
    }
}

/// The CONCURRENT dispatch loop shared by production and the concurrency regression test. Drains the
/// async job channel and `tokio::spawn`s `lookup(host)` for each job onto the ambient (current-thread)
/// runtime, so a slow lookup never head-of-line-blocks a fast one — each spawned task replies on its
/// OWN reply channel, fully independently. The loop ends when the last sender is dropped and the channel
/// closes (then awaiting in-flight tasks finish via their own spawned futures).
///
/// `lookup` is the per-host async resolution; production passes the hickory `lookup_ip` closure, the
/// test passes a controllable stub (one host slow, one fast). Driving BOTH through this one function is
/// what makes the test prove the REAL dispatch path is concurrent, not a hand-rolled copy of it.
async fn run_resolver_loop<F, Fut>(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<ResolveJob>,
    lookup: F,
) where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<IpAddr>, SafeFetchError>> + Send + 'static,
{
    while let Some((host, reply)) = rx.recv().await {
        // Build the per-job future BEFORE spawning (so the closure's captured clone is moved into this
        // job's future), then spawn it — each job runs independently.
        let fut = lookup(host);
        tokio::spawn(async move {
            // If the requester has gone away, just drop the result.
            let _ = reply.send(fut.await);
        });
    }
}

impl HostResolver for SystemResolver {
    fn resolve_host(&self, host: &str) -> Result<Vec<IpAddr>, SafeFetchError> {
        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        // The async job sender is cloneable + thread-safe, so no lock is needed; sending is
        // non-blocking (unbounded channel). The reply travels back on a plain std channel.
        self.tx
            .send((host.to_string(), reply_tx))
            .map_err(|_| SafeFetchError("DNS resolver thread is not available.".to_string()))?;
        // Block on the reply. This is a plain channel recv (NOT a Tokio runtime entry), so it is safe to
        // call from inside a caller's async runtime — the async resolution itself runs on the dedicated
        // resolver thread's own current-thread runtime, never on the caller's. Because each lookup is
        // spawned independently on that runtime, a slow lookup does not block this (or any other) reply.
        reply_rx
            .recv()
            .map_err(|_| SafeFetchError("DNS resolver thread dropped the request.".to_string()))?
    }
}

/// The DNS-pinned, SSRF-guarded fetcher. Generic over the [`HostResolver`] so tests inject adversarial
/// DNS without a live network; production uses [`SystemResolver`].
pub struct SafeFetcher<R: HostResolver> {
    resolver: R,
    config: SafeFetchConfig,
}

impl SafeFetcher<SystemResolver> {
    /// The production fetcher: system DNS + the given config.
    pub fn system(config: SafeFetchConfig) -> Result<Self, SafeFetchError> {
        Ok(Self {
            resolver: SystemResolver::new()?,
            config,
        })
    }
}

impl<R: HostResolver> SafeFetcher<R> {
    /// Build a fetcher with an explicit resolver (the test seam).
    pub fn with_resolver(resolver: R, config: SafeFetchConfig) -> Self {
        Self { resolver, config }
    }

    /// GET `url`, applying the full SSRF discipline at every hop, bounding the body, and following up
    /// to `max_redirects` manually-re-gated redirects. Returns the (bounded) body + the final URL.
    ///
    /// `accept` is the `Accept` header value (e.g. `application/json` for discovery/JWKS, the RDF
    /// content types for a WebID profile).
    pub fn get(&self, url: &str, accept: &str) -> Result<SafeResponse, SafeFetchError> {
        let mut current = url.to_string();
        // 0..=max_redirects: the initial request plus up to `max_redirects` followed hops.
        for _hop in 0..=self.config.max_redirects {
            // (1) static gate (scheme/userinfo/IP-literal) on THIS hop's URL.
            ssrf_gate_static_with_nat64(&current, self.config.allow_loopback, &self.config.nat64)?;
            let parsed = Url::parse(&current)
                .map_err(|_| SafeFetchError("URL is malformed.".to_string()))?;
            let host = parsed
                .host_str()
                .ok_or_else(|| SafeFetchError("URL has no host.".to_string()))?
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_string();

            // (2)+(3) resolve + classify EVERY record. If the host is an IP literal, the static gate
            // already classified it; skip the resolver (and pin to that literal). Otherwise resolve and
            // require ALL records public (rebinding mitigation), then pin to them.
            let pinned: Vec<IpAddr> = if let Ok(ip) = host.parse::<IpAddr>() {
                vec![ip]
            } else {
                let records = self.resolver.resolve_host(&host)?;
                if records.is_empty() {
                    return Err(SafeFetchError(
                        "host did not resolve to any address.".to_string(),
                    ));
                }
                for ip in &records {
                    // classify_resolved_address enforces: http+allow_loopback ⇒ must be loopback; and
                    // every record must be public (or loopback when allowed). ANY non-public record
                    // fails the WHOLE request — the attacker cannot mix a public + private record.
                    classify_resolved_address_with_nat64(
                        &ip.to_string(),
                        &parsed,
                        self.config.allow_loopback,
                        &self.config.nat64,
                    )?;
                }
                records
            };

            // (4) pin reqwest's DNS for this host to exactly the validated IP(s), connect, no
            //     auto-redirect, bounded timeout. A fresh client per hop keeps the pin host-scoped.
            let port = parsed
                .port_or_known_default()
                .ok_or_else(|| SafeFetchError("URL has no usable port.".to_string()))?;
            let pinned_addrs: Vec<SocketAddr> =
                pinned.iter().map(|ip| SocketAddr::new(*ip, port)).collect();

            // (4)+(5)+(6) The reqwest::blocking HTTP exchange runs on a DEDICATED OS THREAD (see
            // `http_hop_off_runtime`). reqwest's blocking client owns an internal Tokio runtime whose
            // `Drop` JOINS its runtime thread — which PANICS ("Cannot drop a runtime ... from within an
            // asynchronous context") if the client is constructed/dropped while a Tokio runtime is
            // active on the calling thread (the conformance-blocking case: the verifier called directly
            // from an axum handler). Doing the whole exchange on a plain `std::thread` keeps that
            // runtime lifecycle entirely off the caller's async context. The host string + pinned
            // addresses are the only inputs, so the SSRF pin/classification (done above) is unchanged.
            let outcome = http_hop_off_runtime(HopRequest {
                url: parsed.to_string(),
                host: host.clone(),
                accept: accept.to_string(),
                pinned_addrs,
                timeout: self.config.timeout,
                max_body_bytes: self.config.max_body_bytes,
            })?;

            match outcome {
                HopOutcome::Redirect(location) => {
                    // (5) manual redirect: resolve relative to the current URL, loop to re-gate it from
                    // scratch. We do NOT trust reqwest to follow it.
                    let next = parsed.join(&location).map_err(|_| {
                        SafeFetchError("redirect Location is malformed.".to_string())
                    })?;
                    current = next.to_string();
                    continue;
                }
                HopOutcome::Body(body) => {
                    return Ok(SafeResponse {
                        body,
                        final_url: parsed.to_string(),
                    });
                }
            }
        }
        Err(SafeFetchError("too many redirects.".to_string()))
    }
}

/// The inputs for a single (already SSRF-gated + DNS-pinned) HTTP hop, sent to the off-runtime worker
/// thread. Everything is owned (`String`/`Vec`) so it can cross the thread boundary.
struct HopRequest {
    url: String,
    host: String,
    accept: String,
    pinned_addrs: Vec<SocketAddr>,
    timeout: Duration,
    max_body_bytes: usize,
}

/// The result of one HTTP hop: either a redirect Location to re-gate, or the (bounded) success body.
enum HopOutcome {
    Redirect(String),
    Body(Vec<u8>),
}

/// Perform one reqwest::blocking HTTP hop on a DEDICATED OS THREAD, so the blocking client's internal
/// Tokio-runtime lifecycle (construct + `Drop`-joins-its-thread) never runs on the caller's async
/// context. This is what makes the whole sync fetch path safe to invoke from inside a Tokio runtime
/// (an axum handler calling `Verifier::verify` directly). The thread has no ambient runtime, so the
/// reqwest blocking client builds, sends, reads, and drops without tripping Tokio's "drop a runtime
/// from within an asynchronous context" guard.
fn http_hop_off_runtime(req: HopRequest) -> Result<HopOutcome, SafeFetchError> {
    let handle = std::thread::Builder::new()
        .name("solid-oidc-http-hop".to_string())
        .spawn(move || run_http_hop(req))
        .map_err(|e| SafeFetchError(format!("HTTP worker thread spawn failed: {e}")))?;
    // Joining a plain OS thread is a normal blocking call (not a Tokio runtime drop), so it is safe
    // from within an async context. The reqwest runtime was created AND dropped inside the closure on
    // that thread.
    handle
        .join()
        .map_err(|_| SafeFetchError("HTTP worker thread panicked.".to_string()))?
}

/// The body of one HTTP hop, executed on the dedicated worker thread (no ambient runtime). Builds the
/// pinned, no-proxy, no-auto-redirect blocking client, sends the GET, and returns either the redirect
/// Location or the bounded success body. Identical request semantics to the previous inline code.
fn run_http_hop(req: HopRequest) -> Result<HopOutcome, SafeFetchError> {
    let mut builder = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(req.timeout)
        // CRITICAL SSRF invariant: disable ambient proxy config. reqwest defaults to honouring
        // HTTP_PROXY/HTTPS_PROXY/ALL_PROXY env vars; with a proxy set, reqwest connects to the
        // PROXY and sends `CONNECT <target>`, so the proxy (not us) resolves the target — which
        // bypasses our DNS-pin + per-record SSRF classification entirely. This fetcher controls
        // its own egress; it must NOT inherit ambient proxy config. (Without this, a single
        // HTTPS_PROXY env var turns the whole guard into a no-op.)
        .no_proxy()
        // Defence-in-depth: even though we pin, also forbid reqwest from following redirects on
        // its own and cap the connect time within the overall timeout.
        .connect_timeout(req.timeout);
    builder = builder.resolve_to_addrs(&req.host, &req.pinned_addrs);
    let client = builder
        .build()
        .map_err(|e| SafeFetchError(format!("HTTP client build failed: {e}")))?;

    let resp = client
        .get(req.url.as_str())
        .header(reqwest::header::ACCEPT, req.accept.as_str())
        .send()
        .map_err(|e| SafeFetchError(format!("request failed: {e}")))?;

    let status = resp.status();
    if status.is_redirection() {
        let location = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| SafeFetchError("redirect without a Location header.".to_string()))?
            .to_string();
        return Ok(HopOutcome::Redirect(location));
    }
    if !status.is_success() {
        return Err(SafeFetchError(format!("upstream returned HTTP {status}.")));
    }

    // (6) bounded body read. Honour Content-Length as an early reject, but ALSO cap the actual
    // bytes read so a lying / chunked oversize body is still bounded. Compare in u64 space so a
    // 32-bit `usize` cannot truncate a large advertised length into a small one.
    if let Some(len) = resp.content_length() {
        if len > req.max_body_bytes as u64 {
            return Err(SafeFetchError(
                "response body exceeds the size cap.".to_string(),
            ));
        }
    }
    let body = read_bounded(resp, req.max_body_bytes)?;
    Ok(HopOutcome::Body(body))
}

/// Read a response body with a hard byte cap. Reads in chunks and aborts the moment the cap is
/// exceeded, so an attacker-controlled endpoint cannot exhaust memory even with a lying / absent
/// Content-Length (chunked transfer).
fn read_bounded(
    mut resp: reqwest::blocking::Response,
    max: usize,
) -> Result<Vec<u8>, SafeFetchError> {
    use std::io::Read as _;
    let mut buf = Vec::new();
    // Read one byte past the cap so we can DETECT an over-cap body (>= max+1 means too big).
    let limit = (max as u64).saturating_add(1);
    resp.by_ref()
        .take(limit)
        .read_to_end(&mut buf)
        .map_err(|e| SafeFetchError(format!("body read failed: {e}")))?;
    if buf.len() > max {
        return Err(SafeFetchError(
            "response body exceeds the size cap.".to_string(),
        ));
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// A deterministic resolver mapping host → records (the adversarial DNS seam).
    struct MapResolver {
        map: HashMap<String, Vec<IpAddr>>,
    }
    impl MapResolver {
        fn new(entries: &[(&str, &[&str])]) -> Self {
            let mut map = HashMap::new();
            for (host, ips) in entries {
                map.insert(
                    host.to_string(),
                    ips.iter().map(|s| s.parse().unwrap()).collect(),
                );
            }
            Self { map }
        }
    }
    impl HostResolver for MapResolver {
        fn resolve_host(&self, host: &str) -> Result<Vec<IpAddr>, SafeFetchError> {
            self.map
                .get(host)
                .cloned()
                .ok_or_else(|| SafeFetchError("NXDOMAIN".into()))
        }
    }

    fn fetcher(entries: &[(&str, &[&str])]) -> SafeFetcher<MapResolver> {
        SafeFetcher::with_resolver(MapResolver::new(entries), SafeFetchConfig::default())
    }

    // NB: these tests exercise the PRE-CONNECT gate (resolve + classify). They assert the request is
    // refused BEFORE any socket is opened — so they need no live network. A host whose records are all
    // public would proceed to a real connect (which has no server in a unit test); we therefore only
    // assert the *refusal* cases here. The live end-to-end happy path is covered by the Keycloak IT.

    #[test]
    fn refuses_when_a_record_is_private() {
        // DNS-rebinding: one public + one private record ⇒ the whole request is refused.
        let f = fetcher(&[("evil.example", &["8.8.8.8", "10.0.0.1"])]);
        let e = f.get(
            "https://evil.example/.well-known/openid-configuration",
            "application/json",
        );
        assert!(e.is_err());
    }

    #[test]
    fn refuses_when_all_records_private() {
        let f = fetcher(&[("intra.example", &["192.168.1.1"])]);
        assert!(f
            .get("https://intra.example/jwks", "application/json")
            .is_err());
    }

    #[test]
    fn refuses_metadata_service_literal() {
        // IP-literal host hitting the cloud metadata service — caught by the static gate, no resolve.
        let f = fetcher(&[]);
        assert!(f
            .get(
                "https://169.254.169.254/latest/meta-data/",
                "application/json"
            )
            .is_err());
    }

    #[test]
    fn refuses_loopback_literal_by_default() {
        let f = fetcher(&[]);
        assert!(f.get("https://127.0.0.1/jwks", "application/json").is_err());
    }

    #[test]
    fn refuses_http_scheme_by_default() {
        let f = fetcher(&[("pod.example", &["8.8.8.8"])]);
        assert!(f
            .get("http://pod.example/jwks", "application/json")
            .is_err());
    }

    #[test]
    fn refuses_userinfo_url() {
        let f = fetcher(&[("pod.example", &["8.8.8.8"])]);
        assert!(f
            .get("https://user:pass@pod.example/jwks", "application/json")
            .is_err());
    }

    #[test]
    fn refuses_non_http_scheme() {
        let f = fetcher(&[]);
        assert!(f.get("file:///etc/passwd", "application/json").is_err());
    }

    #[test]
    fn refuses_nxdomain() {
        let f = fetcher(&[]);
        assert!(f
            .get("https://does-not-resolve.example/jwks", "application/json")
            .is_err());
    }

    // =================================================================================================
    // CONCURRENCY regression (the Medium fix): the resolver dispatch loop must NOT serialise lookups —
    // a slow lookup must not head-of-line-block a fast one sharing the same resolver thread/runtime.
    //
    // This drives the REAL production dispatch loop (`run_resolver_loop`) on a dedicated thread with its
    // own current-thread runtime — exactly as `SystemResolver::new` wires it — but injects a
    // CONTROLLABLE async lookup stub: host "slow" awaits a long delay, host "fast" returns immediately.
    // Two jobs are submitted back-to-back (slow first, so a serial loop would make the fast one wait
    // behind it); the test asserts the FAST reply arrives well BEFORE the slow one could have. A serial
    // (await-each-inline) loop FAILS this; the concurrent (`tokio::spawn`-per-job) loop PASSES it.
    // =================================================================================================
    #[test]
    fn resolver_loop_does_not_serialize_a_slow_lookup_ahead_of_a_fast_one() {
        use std::sync::mpsc::{channel, RecvTimeoutError};
        use std::time::{Duration, Instant};

        // The injected concurrent dispatch loop runs the SAME `run_resolver_loop` production uses.
        let (job_tx, job_rx) = tokio::sync::mpsc::unbounded_channel::<ResolveJob>();
        let handle = std::thread::Builder::new()
            .name("test-dns-loop".to_string())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("test runtime");
                rt.block_on(run_resolver_loop(job_rx, |host: String| async move {
                    if host == "slow" {
                        // A long delay relative to the fast path: a serial loop would block the fast
                        // lookup for this entire duration.
                        tokio::time::sleep(Duration::from_millis(800)).await;
                        Ok(vec!["10.0.0.1".parse().unwrap()])
                    } else {
                        // Fast path: resolves essentially instantly.
                        Ok(vec!["8.8.8.8".parse().unwrap()])
                    }
                }));
            })
            .expect("spawn test dns loop");

        // Submit the SLOW job first, then the FAST job immediately after — so a head-of-line-blocking
        // (serial) loop would force the fast reply to wait for the slow one.
        let (slow_reply_tx, slow_reply_rx) = channel();
        job_tx.send(("slow".to_string(), slow_reply_tx)).unwrap();
        let (fast_reply_tx, fast_reply_rx) = channel();
        job_tx.send(("fast".to_string(), fast_reply_tx)).unwrap();

        let start = Instant::now();
        // The fast reply MUST arrive promptly — far sooner than the slow lookup's 800ms. We give it a
        // generous 300ms ceiling (well under 800ms) to stay robust on a loaded CI box while still
        // proving non-serialisation.
        let fast = fast_reply_rx
            .recv_timeout(Duration::from_millis(300))
            .expect("fast lookup must return without waiting for the slow one (NOT serialised)");
        let fast_elapsed = start.elapsed();
        assert!(
            fast.is_ok(),
            "fast lookup should succeed, got {:?}",
            fast.err()
        );
        assert_eq!(fast.unwrap(), vec!["8.8.8.8".parse::<IpAddr>().unwrap()]);
        assert!(
            fast_elapsed < Duration::from_millis(700),
            "fast lookup returned in {fast_elapsed:?} — that is ~the slow lookup's duration, so the \
             loop SERIALISED (head-of-line blocked) instead of running concurrently"
        );

        // Sanity: the slow lookup is still in flight (it should NOT have completed by now) and does
        // eventually return correctly — proving both ran, just concurrently rather than serially.
        match slow_reply_rx.recv_timeout(Duration::from_millis(50)) {
            Err(RecvTimeoutError::Timeout) => {} // expected: slow lookup hasn't finished yet
            other => panic!("slow lookup should still be in flight, got {other:?}"),
        }
        let slow = slow_reply_rx
            .recv_timeout(Duration::from_millis(1500))
            .expect("slow lookup must eventually return")
            .expect("slow lookup result");
        assert_eq!(slow, vec!["10.0.0.1".parse::<IpAddr>().unwrap()]);

        // Dropping the sender closes the channel → the loop ends → the thread joins cleanly.
        drop(job_tx);
        handle.join().expect("test dns loop thread should join");
    }
}
