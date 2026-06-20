// AUTHORED-BY Claude Opus 4.8
//! WebID bidirectional check + SSRF guard tests — the Rust port of the security-relevant slices of
//! `webidResolver.test.ts` and `bidirectional.test.ts`.
//!
//! Covers: strict mode rejects when the profile does NOT list the issuer (constant client message, no
//! oracle), strict accepts when it does, warn accepts on mismatch, off skips; and the SSRF gate
//! refuses private-IP / rebinding / redirect-to-private / non-public-record WebID profile URLs (the
//! address classifier + the per-record loop ported from `assertNotSsrf`).

mod common;

use std::collections::HashSet;
use std::sync::Arc;

use common::*;
use solid_oidc_verifier::config::VerifierConfig;
use solid_oidc_verifier::replay::InMemoryReplayStore;
use solid_oidc_verifier::verifier::{AuthRequest, Verifier};
use solid_oidc_verifier::webid::{
    classify_resolved_address, ssrf_gate_static, BidirectionalMode, WebIdProfile,
    WebIdProfileError, WebIdResolver,
};

const URL: &str = "https://pod.example/alice/data";
const METHOD: &str = "GET";

/// A fixture resolver: returns a fixed issuer set for the WebID, or a failure to simulate an
/// unreachable / SSRF-refused profile.
struct FixtureResolver {
    issuers: Option<HashSet<String>>,
}
impl FixtureResolver {
    fn listing(issuers: &[&str]) -> Self {
        Self {
            issuers: Some(issuers.iter().map(|s| s.to_string()).collect()),
        }
    }
    fn failing() -> Self {
        Self { issuers: None }
    }
}
impl WebIdResolver for FixtureResolver {
    fn resolve(&self, _web_id: &str) -> Result<WebIdProfile, WebIdProfileError> {
        match &self.issuers {
            Some(s) => Ok(WebIdProfile { issuers: s.clone() }),
            None => Err(WebIdProfileError(
                "profile unreachable (simulated SSRF refusal)".into(),
            )),
        }
    }
}

fn build(
    issuer_key: &KeyKit,
    mode: BidirectionalMode,
    resolver: Arc<dyn WebIdResolver>,
) -> Verifier<solid_oidc_verifier::config::StaticJwksProvider, InMemoryReplayStore> {
    let cfg = VerifierConfig::new(vec![ISSUER.to_string()], AUDIENCE)
        .require_dpop(true)
        .bidirectional(mode, resolver);
    let replay = InMemoryReplayStore::with_window(cfg.replay_ttl());
    Verifier::new(cfg, jwks_provider(ISSUER, issuer_key), replay).unwrap()
}

fn dpop_request(issuer: &KeyKit, client: &KeyKit) -> AuthRequest {
    let token = mint_access_token(
        issuer,
        &TokenOpts {
            cnf_jkt: Some(client.thumbprint.clone()),
            ..Default::default()
        },
    );
    let proof = mint_dpop_proof(
        client,
        METHOD,
        URL,
        &ProofOpts {
            access_token: Some(token.clone()),
            ..Default::default()
        },
    );
    AuthRequest {
        authorization: Some(format!("DPoP {token}")),
        dpop: Some(proof),
        method: METHOD.into(),
        url: URL.into(),
    }
}

#[test]
fn strict_accepts_when_profile_lists_issuer() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build(
        &issuer,
        BidirectionalMode::Strict,
        Arc::new(FixtureResolver::listing(&[ISSUER])),
    );
    let creds = v.verify(&dpop_request(&issuer, &client)).unwrap();
    assert_eq!(creds.web_id.as_deref(), Some(WEBID));
}

#[test]
fn strict_rejects_when_profile_omits_issuer() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build(
        &issuer,
        BidirectionalMode::Strict,
        Arc::new(FixtureResolver::listing(&["https://someone-else.example"])),
    );
    let err = v.verify(&dpop_request(&issuer, &client)).unwrap_err();
    assert_eq!(err.status(), 401);
    // Constant, non-leaky message (reconnaissance-oracle guard).
    assert_eq!(err.message(), "WebID issuer check failed.");
}

#[test]
fn strict_rejects_on_resolution_failure_constant_message() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build(
        &issuer,
        BidirectionalMode::Strict,
        Arc::new(FixtureResolver::failing()),
    );
    let err = v.verify(&dpop_request(&issuer, &client)).unwrap_err();
    assert_eq!(err.status(), 401);
    // The simulated SSRF detail MUST NOT leak — constant client message only.
    assert_eq!(err.message(), "WebID issuer check failed.");
    assert!(!err.message().to_lowercase().contains("ssrf"));
    assert!(!err.message().to_lowercase().contains("unreachable"));
}

#[test]
fn warn_accepts_on_mismatch() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build(
        &issuer,
        BidirectionalMode::Warn,
        Arc::new(FixtureResolver::listing(&["https://other.example"])),
    );
    let creds = v.verify(&dpop_request(&issuer, &client)).unwrap();
    assert_eq!(creds.web_id.as_deref(), Some(WEBID));
}

#[test]
fn off_skips_check() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build(
        &issuer,
        BidirectionalMode::Off,
        Arc::new(FixtureResolver::failing()),
    );
    let creds = v.verify(&dpop_request(&issuer, &client)).unwrap();
    assert_eq!(creds.web_id.as_deref(), Some(WEBID));
}

// --- SSRF gate (the resolver's security core) --------------------------------------------------

#[test]
fn ssrf_refuses_private_ip_literals() {
    for u in [
        "https://10.0.0.1/profile",
        "https://192.168.1.1/profile",
        "https://172.20.0.1/profile",
        "https://169.254.1.1/profile",       // link-local
        "https://100.64.0.1/profile",        // CGNAT
        "https://[fd00::1]/profile",         // ULA
        "https://[fe80::1]/profile",         // link-local
        "https://[::1]/profile",             // loopback
        "https://[::ffff:10.0.0.1]/profile", // mapped private
    ] {
        assert!(ssrf_gate_static(u, false).is_err(), "should refuse {u}");
    }
}

#[test]
fn ssrf_allows_public_ip_literal() {
    assert!(ssrf_gate_static("https://8.8.8.8/profile", false).is_ok());
    assert!(ssrf_gate_static("https://[2606:4700:4700::1111]/profile", false).is_ok());
}

#[test]
fn ssrf_refuses_non_https_by_default() {
    assert!(ssrf_gate_static("http://pod.example/profile", false).is_err());
}

#[test]
fn ssrf_refuses_non_http_schemes() {
    assert!(ssrf_gate_static("file:///etc/passwd", false).is_err());
    assert!(ssrf_gate_static("gopher://pod.example/x", false).is_err());
}

#[test]
fn ssrf_refuses_userinfo() {
    assert!(ssrf_gate_static("https://user:pass@pod.example/profile", false).is_err());
}

#[test]
fn ssrf_allows_loopback_http_in_dev() {
    assert!(ssrf_gate_static("http://127.0.0.1:3000/profile", true).is_ok());
    // ...but http: to a public host even in dev is refused.
    assert!(ssrf_gate_static("http://8.8.8.8/profile", true).is_err());
}

#[test]
fn classify_rebinding_record_loop_refuses_any_private() {
    // Simulates the per-DNS-record check (`assertNotSsrf`'s loop): a hostname that resolves to BOTH a
    // public and a private record must be refused because ANY private record fails.
    let url = url::Url::parse("https://pod.example/profile").unwrap();
    assert!(classify_resolved_address("8.8.8.8", &url, false).is_ok());
    assert!(classify_resolved_address("10.0.0.1", &url, false).is_err());
}

#[test]
fn classify_redirect_to_private_refused() {
    // A redirect Location re-validated against the gate: a redirect to a private literal is refused.
    assert!(ssrf_gate_static("https://10.1.2.3/redirected", false).is_err());
}

/// Finding #4 (Medium): strict/warn bidirectional mode WITHOUT a resolver must FAIL at construction —
/// it must not silently skip the WebID↔issuer check. (Use `Off` to deliberately disable it.)
#[test]
fn strict_without_resolver_fails_construction() {
    let issuer = KeyKit::generate();
    // A config with strict mode but no resolver wired (bypassing the `bidirectional()` setter).
    let mut cfg = VerifierConfig::new(vec![ISSUER.to_string()], AUDIENCE).require_dpop(true);
    cfg.bidirectional_mode = BidirectionalMode::Strict;
    // webid_resolver stays None.
    let replay = InMemoryReplayStore::with_window(cfg.replay_ttl());
    let result = Verifier::new(cfg, jwks_provider(ISSUER, &issuer), replay);
    assert!(
        result.is_err(),
        "strict mode without a resolver must be rejected"
    );
}

#[test]
fn warn_without_resolver_fails_construction() {
    let issuer = KeyKit::generate();
    let mut cfg = VerifierConfig::new(vec![ISSUER.to_string()], AUDIENCE).require_dpop(true);
    cfg.bidirectional_mode = BidirectionalMode::Warn;
    let replay = InMemoryReplayStore::with_window(cfg.replay_ttl());
    let result = Verifier::new(cfg, jwks_provider(ISSUER, &issuer), replay);
    assert!(
        result.is_err(),
        "warn mode without a resolver must be rejected"
    );
}

#[test]
fn off_without_resolver_is_fine() {
    let issuer = KeyKit::generate();
    let cfg = VerifierConfig::new(vec![ISSUER.to_string()], AUDIENCE).require_dpop(true);
    // bidirectional_mode defaults to Off, no resolver — construction succeeds.
    let replay = InMemoryReplayStore::with_window(cfg.replay_ttl());
    assert!(Verifier::new(cfg, jwks_provider(ISSUER, &issuer), replay).is_ok());
}
