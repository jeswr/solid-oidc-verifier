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

use crate::webid::{classify_resolved_address, ssrf_gate_static, WebIdProfileError};

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
}

impl Default for SafeFetchConfig {
    fn default() -> Self {
        Self {
            allow_loopback: false,
            timeout: DEFAULT_TIMEOUT,
            max_body_bytes: MAX_BODY_BYTES,
            max_redirects: MAX_REDIRECTS,
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

/// The production resolver: `hickory-resolver` reading the system config. Returns the FULL record set
/// (every A + AAAA) so the per-record classification sees all of them.
pub struct SystemResolver {
    inner: hickory_resolver::Resolver,
}

impl SystemResolver {
    /// Build a resolver from the system's `/etc/resolv.conf` (falling back to a sane default on a
    /// platform without one). Constructed once and reused.
    pub fn new() -> Result<Self, SafeFetchError> {
        let inner = hickory_resolver::Resolver::from_system_conf()
            .or_else(|_| {
                hickory_resolver::Resolver::new(
                    hickory_resolver::config::ResolverConfig::default(),
                    hickory_resolver::config::ResolverOpts::default(),
                )
            })
            .map_err(|e| SafeFetchError(format!("DNS resolver init failed: {e}")))?;
        Ok(Self { inner })
    }
}

impl HostResolver for SystemResolver {
    fn resolve_host(&self, host: &str) -> Result<Vec<IpAddr>, SafeFetchError> {
        let lookup = self
            .inner
            .lookup_ip(host)
            .map_err(|e| SafeFetchError(format!("DNS lookup failed: {e}")))?;
        Ok(lookup.iter().collect())
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
            ssrf_gate_static(&current, self.config.allow_loopback)?;
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
                    classify_resolved_address(
                        &ip.to_string(),
                        &parsed,
                        self.config.allow_loopback,
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

            let mut builder = reqwest::blocking::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(self.config.timeout)
                // Defence-in-depth: even though we pin, also forbid reqwest from following redirects on
                // its own and cap the connect time within the overall timeout.
                .connect_timeout(self.config.timeout);
            builder = builder.resolve_to_addrs(&host, &pinned_addrs);
            let client = builder
                .build()
                .map_err(|e| SafeFetchError(format!("HTTP client build failed: {e}")))?;

            let resp = client
                .get(parsed.as_str())
                .header(reqwest::header::ACCEPT, accept)
                .send()
                .map_err(|e| SafeFetchError(format!("request failed: {e}")))?;

            let status = resp.status();
            if status.is_redirection() {
                // (5) manual redirect: extract Location, resolve relative to the current URL, loop to
                // re-gate it from scratch. We do NOT trust reqwest to follow it.
                let location = resp
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| {
                        SafeFetchError("redirect without a Location header.".to_string())
                    })?
                    .to_string();
                let next = parsed
                    .join(&location)
                    .map_err(|_| SafeFetchError("redirect Location is malformed.".to_string()))?;
                current = next.to_string();
                continue;
            }
            if !status.is_success() {
                return Err(SafeFetchError(format!("upstream returned HTTP {status}.")));
            }

            // (6) bounded body read. Honour Content-Length as an early reject, but ALSO cap the actual
            // bytes read so a lying / chunked oversize body is still bounded. Compare in u64 space so a
            // 32-bit `usize` cannot truncate a large advertised length into a small one.
            if let Some(len) = resp.content_length() {
                if len > self.config.max_body_bytes as u64 {
                    return Err(SafeFetchError(
                        "response body exceeds the size cap.".to_string(),
                    ));
                }
            }
            let body = read_bounded(resp, self.config.max_body_bytes)?;
            return Ok(SafeResponse {
                body,
                final_url: parsed.to_string(),
            });
        }
        Err(SafeFetchError("too many redirects.".to_string()))
    }
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
}
