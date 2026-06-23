// AUTHORED-BY Claude Opus 4.8
//! Verifier configuration + the JWKS-provider seam.
//!
//! Mirrors the TS `VerifierOptions` + the issuer-config resolver. The M2 network OIDC discovery + JWKS
//! fetch (cached, over the DNS-pinned SSRF-guarded [`crate::net::SafeFetcher`]) lives in
//! [`NetworkJwksProvider`] behind the [`JwksProvider`] seam; the static in-memory [`StaticJwksProvider`]
//! keeps the security core testable with no network. (We hand-roll the minimal discovery + JWKS parse
//! we need over the SSRF-guarded fetcher rather than pull `openidconnect`, which is ID-token-oriented
//! and would route around our DNS-pinned connector — spike §4 noted it as a discovery/JWKS-only option.)

use std::sync::Arc;
use std::time::Duration;

use crate::jwk::Jwk;
use crate::webid::{BidirectionalMode, WebIdResolver};

/// The DPoP-proof `iat` freshness half-width (seconds) the verifier enforces (TS
/// `DPOP_PROOF_MAX_AGE_SEC`). The freshness check is SYMMETRIC — `|now - iat| <= max_age + tolerance`
/// — so a proof is accepted whether its `iat` is up to `max_age + tolerance` in the PAST or the
/// FUTURE. The replay-cache TTL must therefore cover the FULL symmetric window (see [`VerifierConfig::replay_ttl`]).
pub const DPOP_PROOF_MAX_AGE_SECS: u64 = 300;

/// Default clock tolerance (seconds) for temporal claims (TS default `clockToleranceSec: 5`).
pub const DEFAULT_CLOCK_TOLERANCE_SECS: u64 = 5;

/// Supplies the verification keys (JWKS) for a trusted issuer. The network implementation performs
/// OIDC discovery + JWKS fetch (cached, SSRF-guarded) — M2. A static implementation returns a
/// pre-seeded keyset (tests; an embedded deployment). Mirrors the TS `resolveIssuer`/`IssuerConfig`.
pub trait JwksProvider: Send + Sync {
    /// Return the candidate verification keys for `issuer`. The verifier has already confirmed
    /// `issuer` is in the trusted list before calling this, so a provider may assume trust. An error
    /// (e.g. discovery/JWKS fetch failure) maps to a 401 challenge, never a 500 (TS semantics).
    ///
    /// Returns an `Arc<[Jwk]>` so a caching provider can hand out the cached set with a cheap
    /// reference-count bump (`Arc::clone`) rather than deep-cloning the key `Vec` on every verify (the
    /// per-request hot path). The returned slice derefs to `&[Jwk]` for the signature primitive.
    fn keys_for(&self, issuer: &str) -> Result<Arc<[Jwk]>, JwksError>;
}

/// A JWKS-resolution failure (discovery unreachable, no jwks_uri, fetch failed, …). Surfaced to the
/// client as a generic `invalid_token` 401 (no internal detail leaks).
#[derive(Debug, thiserror::Error)]
#[error("JWKS resolution failed: {0}")]
pub struct JwksError(pub String);

/// A static, in-memory [`JwksProvider`] mapping issuer → keys. Used by tests and embedded deployments
/// that pre-provision the IdP's keys. The verifier still enforces the trusted-issuer allowlist, so an
/// untrusted issuer never reaches this provider.
pub struct StaticJwksProvider {
    entries: std::collections::HashMap<String, Arc<[Jwk]>>,
}

impl StaticJwksProvider {
    pub fn new() -> Self {
        Self {
            entries: std::collections::HashMap::new(),
        }
    }

    pub fn with_issuer(mut self, issuer: impl Into<String>, keys: Vec<Jwk>) -> Self {
        // Store as a shared slice so `keys_for` is an `Arc::clone` (refcount bump), not a deep clone.
        self.entries.insert(issuer.into(), Arc::from(keys));
        self
    }
}

impl Default for StaticJwksProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl JwksProvider for StaticJwksProvider {
    fn keys_for(&self, issuer: &str) -> Result<Arc<[Jwk]>, JwksError> {
        self.entries
            .get(issuer)
            .map(Arc::clone)
            .ok_or_else(|| JwksError(format!("no JWKS configured for issuer {issuer}")))
    }
}

/// Verifier configuration. Mirrors `VerifierOptions`.
pub struct VerifierConfig {
    /// Issuers trusted to mint access tokens. An `iss` outside this set is rejected *before* any key
    /// resolution (so an untrusted issuer never drives discovery of an attacker-controlled document).
    pub trusted_issuers: Vec<String>,
    /// The claim name carrying the agent's WebID (Keycloak protocol-mapper output, e.g. `webid`).
    pub webid_claim: String,
    /// When `true`, a DPoP proof is required and a bare Bearer token is rejected.
    pub require_dpop: bool,
    /// ADR-0007 opt-in (default `false`): accept an otherwise-valid DPoP proof that omits `ath`. A
    /// *present-but-wrong* `ath` is still rejected. Only the *absence* is tolerated.
    pub allow_missing_ath: bool,
    /// Allowed clock skew (seconds) for token + proof temporal claims.
    pub clock_tolerance_secs: u64,
    /// The audience (this RS's identity) required in a token's `aud` (RFC 9068 — mandatory).
    pub audience: String,
    /// Authorized-party allowlist (ADR-0004 #2). Empty = accept any. Checks `azp`, then `client_id`.
    pub authorized_parties: Vec<String>,
    /// Bidirectional WebID↔issuer check mode (ADR-0004 #3). Requires `webid_resolver` to be set.
    pub bidirectional_mode: BidirectionalMode,
    /// The resolver used by the bidirectional check. `None` ⇒ the check is skipped.
    pub webid_resolver: Option<Arc<dyn WebIdResolver>>,
    /// Fail-closed (default `true`): a replay-store backend error → 503. `false` ⇒ dev fail-open
    /// fallback to an in-memory store (refused in production by the TS config validator).
    pub replay_fail_closed: bool,
}

impl VerifierConfig {
    /// A minimal config: one+ trusted issuers, an audience, DPoP required, strict bidirectional off
    /// (no resolver). Use the builder-style setters to refine.
    pub fn new(trusted_issuers: Vec<String>, audience: impl Into<String>) -> Self {
        Self {
            trusted_issuers,
            webid_claim: "webid".to_string(),
            require_dpop: true,
            allow_missing_ath: false,
            clock_tolerance_secs: DEFAULT_CLOCK_TOLERANCE_SECS,
            audience: audience.into(),
            authorized_parties: Vec::new(),
            bidirectional_mode: BidirectionalMode::Off,
            webid_resolver: None,
            replay_fail_closed: true,
        }
    }

    /// The replay-cache TTL window: it MUST cover the FULL span over which a given DPoP proof's `iat`
    /// would still pass the freshness check, otherwise the store could forget a `jti` while the proof
    /// is still acceptable — reopening a replay window.
    ///
    /// The freshness check is SYMMETRIC: `|now - iat| <= max_age + tolerance`. A proof minted with an
    /// `iat` skewed up to `(max_age + tolerance)` into the FUTURE is therefore accepted *now* AND stays
    /// acceptable until `now ≈ iat + (max_age + tolerance) ≈ initial_now + 2 × (max_age + tolerance)`.
    /// So the *nominal* window is `2 × (max_age + tolerance)` — twice the one-sided window.
    ///
    /// **The +1s safety margin.** The freshness check runs on INTEGER seconds (`now_secs()` truncated)
    /// with an INCLUSIVE `<=` boundary, while the replay entry expires at `mark_instant + ttl` measured
    /// on the sub-second monotonic `Instant` clock. A proof first marked partway through integer second
    /// `N` (so its `Instant` is already past the start of second `N`) stays *acceptable* for the WHOLE
    /// of integer second `N + 2×(max_age+tolerance)` (the `<=` boundary is inclusive of the entire final
    /// second), i.e. until wall-clock ≈ `start_of_second(N) + 2×window + 1`. The entry, however, would
    /// expire at `mark_instant + 2×window < start_of_second(N) + 2×window + 1`, leaving up to ~1s where
    /// the proof is still ACCEPTED but its `jti` is already FORGOTTEN — a replay slips through. Adding a
    /// **+1 second** margin makes the TTL cover the full inclusive integer-second acceptance window with
    /// no gap (the entry now outlives the last acceptable instant for any sub-second mark offset).
    ///
    /// (A tighter fix would clamp the `iat` FUTURE bound to `tolerance`, but the Solid CTH sends a
    /// future-skewed proof the symmetric window must accept, so we widen the TTL — the
    /// conformance-preserving fix — rather than tighten the acceptance window.)
    pub fn replay_ttl(&self) -> Duration {
        Duration::from_secs(2 * (DPOP_PROOF_MAX_AGE_SECS + self.clock_tolerance_secs) + 1)
    }

    /// Validate the configuration at construction (TS constructor invariants): ≥1 trusted issuer and a
    /// non-empty audience.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.trusted_issuers.is_empty() {
            return Err(ConfigError(
                "at least one trusted issuer is required".into(),
            ));
        }
        if self.audience.is_empty() {
            return Err(ConfigError(
                "an audience (the resource server's identity) is required".into(),
            ));
        }
        // (Finding #4, roborev Medium) A strict/warn bidirectional mode without a resolver would
        // SILENTLY skip the WebID↔issuer check — a security policy disabled by misconfiguration.
        // Refuse it: if the operator asked for the check, a resolver MUST be wired (use
        // `BidirectionalMode::Off` to deliberately disable it).
        if matches!(
            self.bidirectional_mode,
            BidirectionalMode::Strict | BidirectionalMode::Warn
        ) && self.webid_resolver.is_none()
        {
            return Err(ConfigError(
                "bidirectional mode strict/warn requires a webid_resolver (use Off to disable the check)".into(),
            ));
        }
        Ok(())
    }

    // --- builder-style setters (ergonomic, optional) ---
    pub fn webid_claim(mut self, claim: impl Into<String>) -> Self {
        self.webid_claim = claim.into();
        self
    }
    pub fn require_dpop(mut self, v: bool) -> Self {
        self.require_dpop = v;
        self
    }
    pub fn allow_missing_ath(mut self, v: bool) -> Self {
        self.allow_missing_ath = v;
        self
    }
    pub fn clock_tolerance_secs(mut self, v: u64) -> Self {
        self.clock_tolerance_secs = v;
        self
    }
    pub fn authorized_parties(mut self, v: Vec<String>) -> Self {
        self.authorized_parties = v;
        self
    }
    pub fn bidirectional(
        mut self,
        mode: BidirectionalMode,
        resolver: Arc<dyn WebIdResolver>,
    ) -> Self {
        self.bidirectional_mode = mode;
        self.webid_resolver = Some(resolver);
        self
    }
    pub fn replay_fail_closed(mut self, v: bool) -> Self {
        self.replay_fail_closed = v;
        self
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid verifier configuration: {0}")]
pub struct ConfigError(pub String);

// =====================================================================================================
// M2 network adapter — the real JwksProvider (OIDC discovery + JWKS fetch, cached, SSRF-guarded).
// =====================================================================================================

/// The real, network-backed [`JwksProvider`] (M2). For each trusted issuer it performs OIDC discovery
/// (`<issuer>/.well-known/openid-configuration`), reads `jwks_uri`, fetches + parses the JWKS, and
/// caches the result. **Every** fetch (discovery AND jwks) goes through the DNS-pinned, SSRF-guarded
/// [`crate::net::SafeFetcher`] (resolve → classify every record → pin to the validated IP → no
/// auto-redirect → bounded body). A `jwks_uri` pointing at a private host is therefore refused exactly
/// like any other SSRF target.
///
/// The verifier only calls [`JwksProvider::keys_for`] for an *already-trusted* issuer (the allowlist is
/// checked first), so discovery is never driven for an attacker-named issuer.
/// A cached JWKS entry: the shared key slice + when it was fetched (for `cache_ttl` expiry). An
/// `Arc<[Jwk]>` so a cache hit hands the keys out with a refcount bump, never a deep `Vec` clone.
#[cfg(feature = "network")]
type JwksCacheEntry = (Arc<[Jwk]>, std::time::Instant);

#[cfg(feature = "network")]
pub struct NetworkJwksProvider<R: crate::net::HostResolver = crate::net::SystemResolver> {
    fetcher: crate::net::SafeFetcher<R>,
    /// issuer → cached entry. A successful resolution is cached for `cache_ttl`.
    cache: Mutex<std::collections::HashMap<String, JwksCacheEntry>>,
    cache_ttl: Duration,
}

#[cfg(feature = "network")]
use std::sync::Mutex;

#[cfg(feature = "network")]
impl NetworkJwksProvider<crate::net::SystemResolver> {
    /// Build a production provider: the system-DNS SSRF-guarded fetcher + the given JWKS cache TTL.
    /// `allow_loopback` (dev/IT only) permits an `http:`/loopback IdP.
    pub fn new(cache_ttl: Duration, allow_loopback: bool) -> Result<Self, JwksError> {
        let cfg = crate::net::SafeFetchConfig {
            allow_loopback,
            ..Default::default()
        };
        let fetcher = crate::net::SafeFetcher::system(cfg)
            .map_err(|e| JwksError(format!("JWKS fetcher init failed: {e}")))?;
        Ok(Self {
            fetcher,
            cache: Mutex::new(std::collections::HashMap::new()),
            cache_ttl,
        })
    }
}

#[cfg(feature = "network")]
impl<R: crate::net::HostResolver> NetworkJwksProvider<R> {
    /// Build a provider over an explicit fetcher (the test seam — inject adversarial DNS).
    pub fn with_fetcher(fetcher: crate::net::SafeFetcher<R>, cache_ttl: Duration) -> Self {
        Self {
            fetcher,
            cache: Mutex::new(std::collections::HashMap::new()),
            cache_ttl,
        }
    }

    /// Discover + fetch the issuer's JWKS over the SSRF-guarded path. Not cached (the caller caches).
    fn fetch_keys(&self, issuer: &str) -> Result<Arc<[Jwk]>, JwksError> {
        // OIDC discovery URL: <issuer>/.well-known/openid-configuration. We join carefully so an issuer
        // with or without a trailing slash both resolve to the sibling well-known path under the issuer
        // origin+path (matching how IdPs publish it). RFC 8414 also defines a host-rooted variant, but
        // Keycloak/Solid IdPs use the issuer-suffixed form, which the harness env also uses.
        let discovery_url = join_well_known(issuer)
            .ok_or_else(|| JwksError(format!("issuer is not a valid URL: {issuer}")))?;
        let disc = self
            .fetcher
            .get(&discovery_url, "application/json")
            .map_err(|e| JwksError(format!("OIDC discovery failed: {e}")))?;
        let doc: serde_json::Value = serde_json::from_slice(&disc.body)
            .map_err(|_| JwksError("OIDC discovery document is not valid JSON.".into()))?;

        // RFC 8414: the discovery doc's `issuer` MUST equal the requested issuer (prevents a
        // mix-up / open-redirect substituting a different issuer's metadata).
        match doc.get("issuer").and_then(|v| v.as_str()) {
            Some(i) if i == issuer => {}
            _ => return Err(JwksError("OIDC discovery issuer mismatch.".into())),
        }

        let jwks_uri = doc
            .get("jwks_uri")
            .and_then(|v| v.as_str())
            .ok_or_else(|| JwksError("OIDC discovery document has no jwks_uri.".into()))?;
        // The jwks_uri is fetched through the SAME SSRF-guarded path — a jwks_uri at a private host
        // (or one that 302s to one) fails closed in `SafeFetcher::get`.
        let jwks_resp = self
            .fetcher
            .get(jwks_uri, "application/json")
            .map_err(|e| JwksError(format!("JWKS fetch failed: {e}")))?;
        parse_jwks(&jwks_resp.body)
    }
}

#[cfg(feature = "network")]
impl<R: crate::net::HostResolver> JwksProvider for NetworkJwksProvider<R> {
    fn keys_for(&self, issuer: &str) -> Result<Arc<[Jwk]>, JwksError> {
        // Serve from cache when fresh. `Arc::clone` is a refcount bump — the shared key slice is NOT
        // deep-copied on the per-request hot path.
        {
            let cache = self
                .cache
                .lock()
                .map_err(|_| JwksError("JWKS cache mutex poisoned".into()))?;
            if let Some((keys, at)) = cache.get(issuer) {
                if at.elapsed() < self.cache_ttl {
                    return Ok(Arc::clone(keys));
                }
            }
        }
        // Miss / stale → fetch over the SSRF-guarded path, then cache. Caching the `Arc` clone is again
        // a refcount bump (the keys are shared, not copied, between the cache and the returned handle).
        let keys = self.fetch_keys(issuer)?;
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(
                issuer.to_string(),
                (Arc::clone(&keys), std::time::Instant::now()),
            );
        }
        Ok(keys)
    }
}

/// Build `<issuer>/.well-known/openid-configuration`, treating the issuer as an origin+path base. An
/// issuer with a trailing slash keeps its full path; without one, the well-known is appended under it.
#[cfg(feature = "network")]
fn join_well_known(issuer: &str) -> Option<String> {
    let mut base = url::Url::parse(issuer).ok()?;
    if base.scheme() != "https" && base.scheme() != "http" {
        return None;
    }
    // Ensure the path ends with `/` so `.join` appends rather than replaces the last segment.
    if !base.path().ends_with('/') {
        let p = format!("{}/", base.path());
        base.set_path(&p);
    }
    base.join(".well-known/openid-configuration")
        .ok()
        .map(|u| u.to_string())
}

/// Parse a JWKS JSON document into the crate's [`Jwk`] list. Tolerant of unknown/extra keys; skips an
/// entry that is not a usable asymmetric key shape rather than failing the whole set. Bounds the key
/// count (DoS guard against an enormous JWKS that passed the byte cap with tiny keys).
#[cfg(feature = "network")]
fn parse_jwks(body: &[u8]) -> Result<Arc<[Jwk]>, JwksError> {
    /// Upper bound on keys in a JWKS — far above any real IdP (Keycloak rotates 2–3).
    const MAX_KEYS: usize = 64;
    let doc: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| JwksError("JWKS is not valid JSON.".into()))?;
    let arr = doc
        .get("keys")
        .and_then(|v| v.as_array())
        .ok_or_else(|| JwksError("JWKS has no `keys` array.".into()))?;
    if arr.len() > MAX_KEYS {
        return Err(JwksError("JWKS contains too many keys.".into()));
    }
    let mut keys = Vec::new();
    for entry in arr {
        // A JWKS entry that fails to deserialise into our Jwk shape (or carries private material /
        // symmetric kty) is SKIPPED, not fatal — a usable key elsewhere in the set still works, and a
        // poisoned entry can never become a verification key (verify_signature/decoding_key_from_jwk
        // re-reject symmetric + private material defensively).
        if let Ok(jwk) = serde_json::from_value::<Jwk>(entry.clone()) {
            if jwk.is_symmetric() || jwk.has_private_material() {
                continue;
            }
            keys.push(jwk);
        }
    }
    if keys.is_empty() {
        return Err(JwksError("JWKS contained no usable public keys.".into()));
    }
    Ok(Arc::from(keys))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_rejects_empty_issuers() {
        let c = VerifierConfig::new(vec![], "https://pod.example");
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_empty_audience() {
        let c = VerifierConfig::new(vec!["https://idp".into()], "");
        assert!(c.validate().is_err());
    }

    #[test]
    fn replay_ttl_covers_full_symmetric_window() {
        // The replay TTL must cover the FULL span a proof's `iat` is acceptable. The freshness check is
        // symmetric (`|now - iat| <= max_age + tolerance`), so a future-skewed-but-accepted proof stays
        // replayable for `2 × (max_age + tolerance)` = `2 × 305` = 610s, PLUS a +1s margin for the
        // integer-second/inclusive-boundary residual gap (see `replay_ttl` docs) → 611s.
        let c = VerifierConfig::new(vec!["https://idp".into()], "https://pod.example");
        assert_eq!(c.replay_ttl(), Duration::from_secs(611));
    }

    #[test]
    fn replay_ttl_tracks_clock_tolerance() {
        // The TTL is `2 × (max_age + tolerance) + 1` — it must scale with the configured tolerance so a
        // larger skew allowance does NOT leave a forgotten-but-replayable window. tolerance=20 ⇒
        // `2 × (300 + 20) + 1` = 641s.
        let c = VerifierConfig::new(vec!["https://idp".into()], "https://pod.example")
            .clock_tolerance_secs(20);
        assert_eq!(c.replay_ttl(), Duration::from_secs(641));
    }

    #[test]
    fn replay_ttl_includes_the_one_second_inclusive_boundary_margin() {
        // Pin the +1s margin EXPLICITLY: the TTL is strictly GREATER than the nominal
        // `2 × (max_age + tolerance)`, by exactly one second. This guards against a regression that
        // drops the margin back to the bare doubled window (reopening the residual ~1s replay gap).
        for tol in [0u64, 5, 20, 100] {
            let nominal = 2 * (DPOP_PROOF_MAX_AGE_SECS + tol);
            let c = VerifierConfig::new(vec!["https://idp".into()], "https://pod.example")
                .clock_tolerance_secs(tol);
            assert_eq!(
                c.replay_ttl(),
                Duration::from_secs(nominal + 1),
                "replay_ttl must be 2×(max_age+tolerance)+1 (the inclusive-boundary safety margin)"
            );
            assert!(
                c.replay_ttl() > Duration::from_secs(nominal),
                "the TTL must strictly exceed the nominal doubled window"
            );
        }
    }

    #[test]
    fn replay_ttl_leaves_no_gap_at_the_latest_acceptable_instant() {
        // BOUNDARY PROOF (Finding #1, no-gap): a proof accepted at the LATEST acceptable instant must
        // have its `jti` remembered for the ENTIRE time it remains acceptable. We model the two clocks
        // the live code actually uses:
        //   * freshness check — INTEGER seconds, INCLUSIVE `<=`: accepted iff |now_secs - iat| <= window
        //     (verifier.rs). `now_secs` is truncated to whole seconds.
        //   * replay entry    — sub-second monotonic Instant, expires at `mark_instant + ttl`
        //     (replay.rs). `mark_instant` falls somewhere inside the integer second of marking.
        //
        // Worst case for the gap: a MAX-future-skewed proof (`iat = mark_second + window`) marked at the
        // very START of its integer second (sub-second offset → 0). It stays acceptable through the WHOLE
        // of integer second `mark_second + 2*window` (the inclusive `<=` includes every fractional
        // instant of that final second), i.e. up to wall-clock `mark_second_start + (2*window + 1)`. The
        // replay entry must not expire before then.
        for tol in [0u64, 5, 20] {
            let c = VerifierConfig::new(vec!["https://idp".into()], "https://pod.example")
                .clock_tolerance_secs(tol);
            let window = (DPOP_PROOF_MAX_AGE_SECS + tol) as f64;
            let ttl = c.replay_ttl().as_secs_f64();

            // The latest wall-clock instant (relative to the start of the marking second) at which the
            // freshness check still accepts the proof: the END of integer second `2*window` = `2*window + 1`.
            let last_acceptable_offset = 2.0 * window + 1.0;

            // The replay entry expires at `sub_second_mark_offset + ttl`. Sweep every realistic
            // sub-second mark offset in [0, 1); the smallest expiry (offset → 0) is the tightest case.
            for &mark_offset in &[0.0_f64, 0.001, 0.25, 0.5, 0.999_999] {
                let expiry_offset = mark_offset + ttl;
                assert!(
                    expiry_offset >= last_acceptable_offset,
                    "replay entry would expire (at +{expiry_offset}s) BEFORE the proof stops being \
                     acceptable (at +{last_acceptable_offset}s) for mark_offset={mark_offset}, \
                     tol={tol} — a replay gap. ttl={ttl}",
                );
            }
        }
    }

    #[test]
    fn static_provider_returns_keys_or_err() {
        let p = StaticJwksProvider::new();
        assert!(p.keys_for("https://x").is_err());
    }

    #[test]
    fn static_provider_shares_one_arc_allocation_across_calls() {
        // The perf change: `keys_for` hands out an `Arc<[Jwk]>` from the shared cache via `Arc::clone`
        // (a refcount bump), NOT a deep clone of the key `Vec`. Two calls for the same issuer must
        // therefore return Arcs pointing at the SAME allocation. A mutation that deep-clones (e.g.
        // `Arc::from(keys.to_vec())` per call) makes `Arc::ptr_eq` false and fails this.
        let key: Jwk = serde_json::from_value(serde_json::json!({
            "kty": "EC", "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
        }))
        .unwrap();
        let p = StaticJwksProvider::new().with_issuer("https://idp", vec![key]);
        let a = p.keys_for("https://idp").unwrap();
        let b = p.keys_for("https://idp").unwrap();
        assert_eq!(a.len(), 1);
        assert!(
            Arc::ptr_eq(&a, &b),
            "keys_for must share one Arc, not deep-clone"
        );
    }

    #[cfg(feature = "network")]
    #[test]
    fn join_well_known_handles_trailing_slash_either_way() {
        // With a trailing slash the issuer path is preserved + the well-known appended under it.
        assert_eq!(
            join_well_known("https://idp.example/realms/solid/").unwrap(),
            "https://idp.example/realms/solid/.well-known/openid-configuration"
        );
        // Without a trailing slash we must NOT drop the last path segment (the harness-env footgun).
        assert_eq!(
            join_well_known("https://idp.example/realms/solid").unwrap(),
            "https://idp.example/realms/solid/.well-known/openid-configuration"
        );
        // A bare-origin issuer.
        assert_eq!(
            join_well_known("https://idp.example").unwrap(),
            "https://idp.example/.well-known/openid-configuration"
        );
    }

    #[cfg(feature = "network")]
    #[test]
    fn join_well_known_preserves_userinfo_so_the_ssrf_gate_can_reject_it() {
        // We must NOT silently strip userinfo from the issuer — the discovery URL must carry it through
        // to the SafeFetcher's static gate, which REFUSES userinfo (so a misconfigured userinfo issuer
        // fails closed at fetch time rather than shipping Basic creds to the IdP host).
        let url = join_well_known("https://user:pass@idp.example/realms/solid/").unwrap();
        assert!(
            url.contains("user:pass@"),
            "userinfo must be preserved: {url}"
        );
        // And the static SSRF gate refuses exactly that URL.
        assert!(crate::webid::ssrf_gate_static(&url, false).is_err());
    }

    #[cfg(feature = "network")]
    #[test]
    fn join_well_known_rejects_non_http() {
        assert!(join_well_known("ftp://idp.example").is_none());
        assert!(join_well_known("not a url").is_none());
    }

    #[cfg(feature = "network")]
    #[test]
    fn parse_jwks_reads_keys_and_skips_bad_entries() {
        let body = br#"{
            "keys": [
                { "kty": "EC", "crv": "P-256", "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0" },
                { "kty": "oct", "k": "c2VjcmV0" },
                { "kty": "EC", "crv": "P-256", "x": "a", "y": "b", "d": "private-scalar" }
            ]
        }"#;
        let keys = parse_jwks(body).unwrap();
        // The oct (symmetric) entry and the private-material entry are skipped; only the public EC key.
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].kty, "EC");
    }

    #[cfg(feature = "network")]
    #[test]
    fn parse_jwks_rejects_no_usable_keys() {
        // A JWKS with only an unusable (symmetric) key → error, never an empty accept-anything set.
        let body = br#"{ "keys": [ { "kty": "oct", "k": "c2VjcmV0" } ] }"#;
        assert!(parse_jwks(body).is_err());
    }

    #[cfg(feature = "network")]
    #[test]
    fn parse_jwks_rejects_missing_keys_array_and_bad_json() {
        assert!(parse_jwks(br#"{ "not_keys": [] }"#).is_err());
        assert!(parse_jwks(b"<<<not json>>>").is_err());
    }

    #[cfg(feature = "network")]
    #[test]
    fn parse_jwks_rejects_oversized_keyset() {
        // > MAX_KEYS (64) entries → refused (DoS guard).
        let mut s = String::from("{ \"keys\": [");
        for i in 0..65 {
            if i > 0 {
                s.push(',');
            }
            s.push_str(r#"{ "kty": "EC", "crv": "P-256", "x": "a", "y": "b" }"#);
        }
        s.push_str("] }");
        assert!(parse_jwks(s.as_bytes()).is_err());
    }
}
