// AUTHORED-BY Claude Opus 4.8
//! Verifier configuration + the JWKS-provider seam.
//!
//! Mirrors the TS `VerifierOptions` + the issuer-config resolver. Network OIDC discovery + JWKS fetch
//! (via `openidconnect` + the SSRF-guarded client) is the M2 adapter behind [`JwksProvider`]; M1
//! ships the trait + a static in-memory provider so the security core is testable with no network.

use std::sync::Arc;
use std::time::Duration;

use crate::jwk::Jwk;
use crate::webid::{BidirectionalMode, WebIdResolver};

/// The DPoP-proof `iat` freshness window the verifier enforces (TS `DPOP_PROOF_MAX_AGE_SEC`). The
/// replay-cache TTL must cover this + the clock tolerance.
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
    fn keys_for(&self, issuer: &str) -> Result<Vec<Jwk>, JwksError>;
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
    entries: std::collections::HashMap<String, Vec<Jwk>>,
}

impl StaticJwksProvider {
    pub fn new() -> Self {
        Self {
            entries: std::collections::HashMap::new(),
        }
    }

    pub fn with_issuer(mut self, issuer: impl Into<String>, keys: Vec<Jwk>) -> Self {
        self.entries.insert(issuer.into(), keys);
        self
    }
}

impl Default for StaticJwksProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl JwksProvider for StaticJwksProvider {
    fn keys_for(&self, issuer: &str) -> Result<Vec<Jwk>, JwksError> {
        self.entries
            .get(issuer)
            .cloned()
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

    /// The replay-cache TTL window: max proof age + clock tolerance (TS invariant). Entries must live
    /// at least this long so the replay window cannot reopen.
    pub fn replay_ttl(&self) -> Duration {
        Duration::from_secs(DPOP_PROOF_MAX_AGE_SECS + self.clock_tolerance_secs)
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
    fn replay_ttl_covers_window() {
        let c = VerifierConfig::new(vec!["https://idp".into()], "https://pod.example");
        assert_eq!(c.replay_ttl(), Duration::from_secs(305));
    }

    #[test]
    fn static_provider_returns_keys_or_err() {
        let p = StaticJwksProvider::new();
        assert!(p.keys_for("https://x").is_err());
    }
}
