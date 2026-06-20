// AUTHORED-BY Claude Opus 4.8
//! End-to-end verifier tests — the Rust port of `prod-solid-server`'s
//! `test/unit/auth/verifier.test.ts`. Exercises the full public API with real ES256 tokens + proofs
//! and covers the complete negative/attack space: forged signature, wrong issuer, missing/non-https
//! webid, expired/future token, HS256/none/alg-confusion, DPoP htm/htu/iat/typ mismatch, replayed
//! jti, cnf.jkt mismatch, private-key embed, Bearer-when-DPoP-required, malformed token, multi-issuer
//! isolation, and JWKS-resolution-failure → 401.

mod common;

use std::time::Duration;

use common::*;
use solid_oidc_verifier::config::{JwksError, JwksProvider, VerifierConfig};
use solid_oidc_verifier::jwk::Jwk;
use solid_oidc_verifier::replay::InMemoryReplayStore;
use solid_oidc_verifier::verifier::{AuthRequest, Verifier};

const URL: &str = "https://pod.example/alice/data";
const METHOD: &str = "GET";

fn config(require_dpop: bool) -> VerifierConfig {
    VerifierConfig::new(vec![ISSUER.to_string()], AUDIENCE).require_dpop(require_dpop)
}

fn build_verifier(
    issuer_key: &KeyKit,
    config: VerifierConfig,
) -> Verifier<solid_oidc_verifier::config::StaticJwksProvider, InMemoryReplayStore> {
    let replay = InMemoryReplayStore::with_window(config.replay_ttl());
    let jwks = jwks_provider(ISSUER, issuer_key);
    Verifier::new(config, jwks, replay).expect("valid config")
}

/// Build a request carrying a DPoP access token + a correctly-bound proof.
fn dpop_request(issuer_key: &KeyKit, client: &KeyKit) -> AuthRequest {
    let token = mint_access_token(
        issuer_key,
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

fn assert_401(verifier: &impl VerifyExt, req: &AuthRequest, needle: &str) {
    let err = verifier.verify(req).expect_err("expected rejection");
    assert_eq!(
        err.status(),
        401,
        "expected 401, got {}: {}",
        err.status(),
        err.message()
    );
    let m = err.message().to_lowercase();
    assert!(
        m.contains(&needle.to_lowercase()),
        "message {:?} did not contain {:?}",
        err.message(),
        needle
    );
}

/// Tiny trait so `assert_401` works over any concrete `Verifier<…>`.
trait VerifyExt {
    fn verify(
        &self,
        req: &AuthRequest,
    ) -> Result<solid_oidc_verifier::VerifiedToken, solid_oidc_verifier::VerifyError>;
}
impl<J: JwksProvider, R: solid_oidc_verifier::ReplayStore> VerifyExt for Verifier<J, R> {
    fn verify(
        &self,
        req: &AuthRequest,
    ) -> Result<solid_oidc_verifier::VerifiedToken, solid_oidc_verifier::VerifyError> {
        Verifier::verify(self, req)
    }
}

// ---------------------------------------------------------------------------------------------
// Happy paths
// ---------------------------------------------------------------------------------------------

#[test]
fn accepts_valid_dpop_token_and_proof() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    let creds = v.verify(&dpop_request(&issuer, &client)).unwrap();
    assert_eq!(creds.web_id.as_deref(), Some(WEBID));
    assert_eq!(creds.issuer.as_deref(), Some(ISSUER));
    assert_eq!(creds.client_id.as_deref(), Some(CLIENT_ID));
    assert_eq!(creds.cnf_jkt.as_deref(), Some(client.thumbprint.as_str()));
}

#[test]
fn returns_public_credentials_when_no_authorization() {
    let issuer = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    let creds = v
        .verify(&AuthRequest {
            authorization: None,
            dpop: None,
            method: METHOD.into(),
            url: URL.into(),
        })
        .unwrap();
    assert!(creds.is_public());
    assert!(creds.web_id.is_none());
}

#[test]
fn propagates_custom_webid_claim_name() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build_verifier(
        &issuer,
        config(true).webid_claim("http://example.com/webid"),
    );
    let token = mint_access_token(
        &issuer,
        &TokenOpts {
            cnf_jkt: Some(client.thumbprint.clone()),
            webid_claim: Some("http://example.com/webid".into()),
            ..Default::default()
        },
    );
    let proof = mint_dpop_proof(
        &client,
        METHOD,
        URL,
        &ProofOpts {
            access_token: Some(token.clone()),
            ..Default::default()
        },
    );
    let creds = v
        .verify(&AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        })
        .unwrap();
    assert_eq!(creds.web_id.as_deref(), Some(WEBID));
}

#[test]
fn accepts_bearer_when_dpop_not_required() {
    let issuer = KeyKit::generate();
    let v = build_verifier(&issuer, config(false));
    let token = mint_access_token(&issuer, &TokenOpts::default());
    let creds = v
        .verify(&AuthRequest {
            authorization: Some(format!("Bearer {token}")),
            dpop: None,
            method: METHOD.into(),
            url: URL.into(),
        })
        .unwrap();
    assert_eq!(creds.web_id.as_deref(), Some(WEBID));
}

#[test]
fn exposes_scopes_and_expiry() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    let iat = 2_000_000_000;
    let token = mint_access_token(
        &issuer,
        &TokenOpts {
            cnf_jkt: Some(client.thumbprint.clone()),
            scope: Some("webid openid".into()),
            issued_at: Some(now_for_test()),
            ..Default::default()
        },
    );
    let _ = iat;
    let proof = mint_dpop_proof(
        &client,
        METHOD,
        URL,
        &ProofOpts {
            access_token: Some(token.clone()),
            ..Default::default()
        },
    );
    let creds = v
        .verify(&AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        })
        .unwrap();
    assert_eq!(
        creds.scopes,
        vec!["webid".to_string(), "openid".to_string()]
    );
    assert!(creds.expiry.is_some());
}

fn now_for_test() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

// ---------------------------------------------------------------------------------------------
// Adversarial — access token
// ---------------------------------------------------------------------------------------------

#[test]
fn rejects_forged_signature() {
    let issuer = KeyKit::generate();
    let forged = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    // Token signed by the attacker's key; verifier resolves the legit issuer's JWKS.
    let token = mint_access_token(
        &forged,
        &TokenOpts {
            cnf_jkt: Some(client.thumbprint.clone()),
            ..Default::default()
        },
    );
    let proof = mint_dpop_proof(
        &client,
        METHOD,
        URL,
        &ProofOpts {
            access_token: Some(token.clone()),
            ..Default::default()
        },
    );
    assert_401(
        &v,
        &AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        },
        "verification failed",
    );
}

#[test]
fn rejects_untrusted_issuer() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    let token = mint_access_token(
        &issuer,
        &TokenOpts {
            issuer: Some("https://evil.example/realms/solid".into()),
            cnf_jkt: Some(client.thumbprint.clone()),
            ..Default::default()
        },
    );
    let proof = mint_dpop_proof(
        &client,
        METHOD,
        URL,
        &ProofOpts {
            access_token: Some(token.clone()),
            ..Default::default()
        },
    );
    assert_401(
        &v,
        &AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        },
        "issuer is not trusted",
    );
}

#[test]
fn rejects_missing_webid_claim() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    let token = mint_access_token(
        &issuer,
        &TokenOpts {
            omit_webid: true,
            cnf_jkt: Some(client.thumbprint.clone()),
            ..Default::default()
        },
    );
    let proof = mint_dpop_proof(
        &client,
        METHOD,
        URL,
        &ProofOpts {
            access_token: Some(token.clone()),
            ..Default::default()
        },
    );
    assert_401(
        &v,
        &AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        },
        "webid",
    );
}

#[test]
fn rejects_non_https_webid() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    let token = mint_access_token(
        &issuer,
        &TokenOpts {
            webid: Some("http://pod.example/alice#me".into()),
            cnf_jkt: Some(client.thumbprint.clone()),
            ..Default::default()
        },
    );
    let proof = mint_dpop_proof(
        &client,
        METHOD,
        URL,
        &ProofOpts {
            access_token: Some(token.clone()),
            ..Default::default()
        },
    );
    assert_401(
        &v,
        &AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        },
        "https",
    );
}

#[test]
fn rejects_non_url_webid() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    let token = mint_access_token(
        &issuer,
        &TokenOpts {
            webid: Some("not a url".into()),
            cnf_jkt: Some(client.thumbprint.clone()),
            ..Default::default()
        },
    );
    let proof = mint_dpop_proof(
        &client,
        METHOD,
        URL,
        &ProofOpts {
            access_token: Some(token.clone()),
            ..Default::default()
        },
    );
    assert_401(
        &v,
        &AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        },
        "not a valid url",
    );
}

#[test]
fn rejects_webid_with_userinfo() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    let token = mint_access_token(
        &issuer,
        &TokenOpts {
            webid: Some("https://user:pass@pod.example/alice#me".into()),
            cnf_jkt: Some(client.thumbprint.clone()),
            ..Default::default()
        },
    );
    let proof = mint_dpop_proof(
        &client,
        METHOD,
        URL,
        &ProofOpts {
            access_token: Some(token.clone()),
            ..Default::default()
        },
    );
    assert_401(
        &v,
        &AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        },
        "userinfo",
    );
}

#[test]
fn rejects_expired_token() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    let now = now_for_test();
    let token = mint_access_token(
        &issuer,
        &TokenOpts {
            cnf_jkt: Some(client.thumbprint.clone()),
            issued_at: Some(now - 3600),
            expires_at: Some(now - 1800),
            ..Default::default()
        },
    );
    let proof = mint_dpop_proof(
        &client,
        METHOD,
        URL,
        &ProofOpts {
            access_token: Some(token.clone()),
            ..Default::default()
        },
    );
    assert_401(
        &v,
        &AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        },
        "verification failed",
    );
}

#[test]
fn rejects_future_nbf_token() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    let future = now_for_test() + 3600;
    let token = mint_access_token(
        &issuer,
        &TokenOpts {
            cnf_jkt: Some(client.thumbprint.clone()),
            not_before: Some(future),
            ..Default::default()
        },
    );
    let proof = mint_dpop_proof(
        &client,
        METHOD,
        URL,
        &ProofOpts {
            access_token: Some(token.clone()),
            ..Default::default()
        },
    );
    assert_401(
        &v,
        &AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        },
        "verification failed",
    );
}

#[test]
fn rejects_future_iat_token() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    let future = now_for_test() + 3600;
    let token = mint_access_token(
        &issuer,
        &TokenOpts {
            cnf_jkt: Some(client.thumbprint.clone()),
            issued_at: Some(future),
            expires_at: Some(future + 300),
            ..Default::default()
        },
    );
    let proof = mint_dpop_proof(
        &client,
        METHOD,
        URL,
        &ProofOpts {
            access_token: Some(token.clone()),
            ..Default::default()
        },
    );
    assert_401(
        &v,
        &AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        },
        "verification failed",
    );
}

#[test]
fn rejects_wrong_audience() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    let token = mint_access_token(
        &issuer,
        &TokenOpts {
            cnf_jkt: Some(client.thumbprint.clone()),
            audience: Some("https://other.example".into()),
            ..Default::default()
        },
    );
    let proof = mint_dpop_proof(
        &client,
        METHOD,
        URL,
        &ProofOpts {
            access_token: Some(token.clone()),
            ..Default::default()
        },
    );
    assert_401(
        &v,
        &AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        },
        "verification failed",
    );
}

#[test]
fn rejects_missing_audience() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    let token = mint_access_token(
        &issuer,
        &TokenOpts {
            cnf_jkt: Some(client.thumbprint.clone()),
            omit_aud: true,
            ..Default::default()
        },
    );
    let proof = mint_dpop_proof(
        &client,
        METHOD,
        URL,
        &ProofOpts {
            access_token: Some(token.clone()),
            ..Default::default()
        },
    );
    assert_401(
        &v,
        &AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        },
        "verification failed",
    );
}

#[test]
fn rejects_missing_required_claims() {
    for opts in [
        TokenOpts {
            omit_sub: true,
            ..Default::default()
        },
        TokenOpts {
            omit_jti: true,
            ..Default::default()
        },
        TokenOpts {
            omit_client_id: true,
            ..Default::default()
        },
    ] {
        let issuer = KeyKit::generate();
        let client = KeyKit::generate();
        let v = build_verifier(&issuer, config(true));
        let token = mint_access_token(
            &issuer,
            &TokenOpts {
                cnf_jkt: Some(client.thumbprint.clone()),
                ..opts
            },
        );
        let proof = mint_dpop_proof(
            &client,
            METHOD,
            URL,
            &ProofOpts {
                access_token: Some(token.clone()),
                ..Default::default()
            },
        );
        assert_401(
            &v,
            &AuthRequest {
                authorization: Some(format!("DPoP {token}")),
                dpop: Some(proof),
                method: METHOD.into(),
                url: URL.into(),
            },
            "missing",
        );
    }
}

#[test]
fn rejects_hs256_access_token_alg_confusion() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    // An HS256-headed token. Our minter signs with ES256, but the *header* claims HS256 — the alg map
    // rejects it before any signature attempt (alg-confusion guard).
    let token = mint_access_token(
        &issuer,
        &TokenOpts {
            alg: Some("HS256".into()),
            cnf_jkt: Some(client.thumbprint.clone()),
            ..Default::default()
        },
    );
    let proof = mint_dpop_proof(
        &client,
        METHOD,
        URL,
        &ProofOpts {
            access_token: Some(token.clone()),
            ..Default::default()
        },
    );
    assert_401(
        &v,
        &AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        },
        "",
    );
}

#[test]
fn rejects_alg_none_access_token() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    let token = mint_access_token(
        &issuer,
        &TokenOpts {
            alg: Some("none".into()),
            cnf_jkt: Some(client.thumbprint.clone()),
            ..Default::default()
        },
    );
    let proof = mint_dpop_proof(
        &client,
        METHOD,
        URL,
        &ProofOpts {
            access_token: Some(token.clone()),
            ..Default::default()
        },
    );
    assert_401(
        &v,
        &AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        },
        "",
    );
}

/// Feature OFF: an ES512 access token is rejected by the KNOWN NARROWING (never silently accepted).
/// With the `es512` feature ON the narrowing is lifted and ES512 is genuinely verified, so this
/// narrowing-specific assertion only applies feature-OFF — the ON behaviour is covered by the
/// dedicated `es512` test module (happy-path + wrong-curve + forged-signature + malformed-coords).
#[cfg(not(feature = "es512"))]
#[test]
fn rejects_es512_access_token_known_narrowing() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    let token = mint_access_token(
        &issuer,
        &TokenOpts {
            alg: Some("ES512".into()),
            cnf_jkt: Some(client.thumbprint.clone()),
            ..Default::default()
        },
    );
    let proof = mint_dpop_proof(
        &client,
        METHOD,
        URL,
        &ProofOpts {
            access_token: Some(token.clone()),
            ..Default::default()
        },
    );
    assert_401(
        &v,
        &AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        },
        "es512",
    );
}

#[test]
fn rejects_malformed_token() {
    let issuer = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    assert_401(
        &v,
        &AuthRequest {
            authorization: Some("DPoP not.a.jwt.at.all".into()),
            dpop: Some("x".into()),
            method: METHOD.into(),
            url: URL.into(),
        },
        "",
    );
}

// ---------------------------------------------------------------------------------------------
// Adversarial — DPoP proof
// ---------------------------------------------------------------------------------------------

#[test]
fn rejects_bearer_when_dpop_required() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    let token = mint_access_token(
        &issuer,
        &TokenOpts {
            cnf_jkt: Some(client.thumbprint.clone()),
            ..Default::default()
        },
    );
    assert_401(
        &v,
        &AuthRequest {
            authorization: Some(format!("Bearer {token}")),
            dpop: None,
            method: METHOD.into(),
            url: URL.into(),
        },
        "bearer not accepted",
    );
}

#[test]
fn rejects_when_proof_header_absent() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    let token = mint_access_token(
        &issuer,
        &TokenOpts {
            cnf_jkt: Some(client.thumbprint.clone()),
            ..Default::default()
        },
    );
    assert_401(
        &v,
        &AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: None,
            method: METHOD.into(),
            url: URL.into(),
        },
        "dpop proof is required",
    );
}

#[test]
fn rejects_token_not_dpop_bound() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    // No cnf.jkt.
    let token = mint_access_token(&issuer, &TokenOpts::default());
    let proof = mint_dpop_proof(
        &client,
        METHOD,
        URL,
        &ProofOpts {
            access_token: Some(token.clone()),
            ..Default::default()
        },
    );
    assert_401(
        &v,
        &AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        },
        "not dpop-bound",
    );
}

#[test]
fn rejects_htm_mismatch() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    let token = mint_access_token(
        &issuer,
        &TokenOpts {
            cnf_jkt: Some(client.thumbprint.clone()),
            ..Default::default()
        },
    );
    let proof = mint_dpop_proof(
        &client,
        "GET",
        URL,
        &ProofOpts {
            htm: Some("DELETE".into()),
            access_token: Some(token.clone()),
            ..Default::default()
        },
    );
    assert_401(
        &v,
        &AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: "GET".into(),
            url: URL.into(),
        },
        "htm",
    );
}

#[test]
fn accepts_case_insensitive_htm() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    let token = mint_access_token(
        &issuer,
        &TokenOpts {
            cnf_jkt: Some(client.thumbprint.clone()),
            ..Default::default()
        },
    );
    // Proof says "get", request method is "GET" — must still match (RFC 9449 case-insensitivity).
    let proof = mint_dpop_proof(
        &client,
        "GET",
        URL,
        &ProofOpts {
            htm: Some("get".into()),
            access_token: Some(token.clone()),
            ..Default::default()
        },
    );
    let creds = v
        .verify(&AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: "GET".into(),
            url: URL.into(),
        })
        .unwrap();
    assert_eq!(creds.web_id.as_deref(), Some(WEBID));
}

#[test]
fn rejects_htu_mismatch_path() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    let token = mint_access_token(
        &issuer,
        &TokenOpts {
            cnf_jkt: Some(client.thumbprint.clone()),
            ..Default::default()
        },
    );
    let proof = mint_dpop_proof(
        &client,
        METHOD,
        URL,
        &ProofOpts {
            htu: Some("https://pod.example/alice/other".into()),
            access_token: Some(token.clone()),
            ..Default::default()
        },
    );
    assert_401(
        &v,
        &AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        },
        "htu",
    );
}

#[test]
fn rejects_htu_mismatch_host() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    let token = mint_access_token(
        &issuer,
        &TokenOpts {
            cnf_jkt: Some(client.thumbprint.clone()),
            ..Default::default()
        },
    );
    let proof = mint_dpop_proof(
        &client,
        METHOD,
        URL,
        &ProofOpts {
            htu: Some("https://evil.example/alice/data".into()),
            access_token: Some(token.clone()),
            ..Default::default()
        },
    );
    assert_401(
        &v,
        &AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        },
        "htu",
    );
}

#[test]
fn accepts_htu_default_port_normalisation() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    let token = mint_access_token(
        &issuer,
        &TokenOpts {
            cnf_jkt: Some(client.thumbprint.clone()),
            ..Default::default()
        },
    );
    let proof = mint_dpop_proof(
        &client,
        METHOD,
        "https://pod.example:443/alice/data",
        &ProofOpts {
            htu: Some("https://pod.example:443/alice/data".into()),
            access_token: Some(token.clone()),
            ..Default::default()
        },
    );
    let creds = v
        .verify(&AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: "https://pod.example/alice/data".into(),
        })
        .unwrap();
    assert_eq!(creds.web_id.as_deref(), Some(WEBID));
}

#[test]
fn accepts_htu_with_query_in_proof_stripped() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    let token = mint_access_token(
        &issuer,
        &TokenOpts {
            cnf_jkt: Some(client.thumbprint.clone()),
            ..Default::default()
        },
    );
    let proof = mint_dpop_proof(
        &client,
        METHOD,
        URL,
        &ProofOpts {
            htu: Some("https://pod.example/alice/data?x=1".into()),
            access_token: Some(token.clone()),
            ..Default::default()
        },
    );
    let creds = v
        .verify(&AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        })
        .unwrap();
    assert_eq!(creds.web_id.as_deref(), Some(WEBID));
}

#[test]
fn rejects_proof_without_ath_strict() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    let token = mint_access_token(
        &issuer,
        &TokenOpts {
            cnf_jkt: Some(client.thumbprint.clone()),
            ..Default::default()
        },
    );
    // accessToken None ⇒ no ath.
    let proof = mint_dpop_proof(&client, METHOD, URL, &ProofOpts::default());
    assert_401(
        &v,
        &AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        },
        "ath",
    );
}

#[test]
fn rejects_proof_with_wrong_ath() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    let token = mint_access_token(
        &issuer,
        &TokenOpts {
            cnf_jkt: Some(client.thumbprint.clone()),
            ..Default::default()
        },
    );
    let proof = mint_dpop_proof(
        &client,
        METHOD,
        URL,
        &ProofOpts {
            explicit_ath: Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()),
            ..Default::default()
        },
    );
    assert_401(
        &v,
        &AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        },
        "ath",
    );
}

#[test]
fn rejects_ath_for_different_token() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    let token = mint_access_token(
        &issuer,
        &TokenOpts {
            cnf_jkt: Some(client.thumbprint.clone()),
            ..Default::default()
        },
    );
    let other = mint_access_token(
        &issuer,
        &TokenOpts {
            cnf_jkt: Some(client.thumbprint.clone()),
            ..Default::default()
        },
    );
    let proof = mint_dpop_proof(
        &client,
        METHOD,
        URL,
        &ProofOpts {
            access_token: Some(other),
            ..Default::default()
        },
    );
    assert_401(
        &v,
        &AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        },
        "ath",
    );
}

#[test]
fn rejects_replayed_jti() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    let req = dpop_request(&issuer, &client);
    v.verify(&req).unwrap(); // first use succeeds
    assert_401(&v, &req, "replay"); // exact same proof again
}

#[test]
fn rejects_cnf_jkt_mismatch() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let other = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    // Token bound to client's key; proof signed + embedding other's key.
    let token = mint_access_token(
        &issuer,
        &TokenOpts {
            cnf_jkt: Some(client.thumbprint.clone()),
            ..Default::default()
        },
    );
    let proof = mint_dpop_proof(
        &other,
        METHOD,
        URL,
        &ProofOpts {
            access_token: Some(token.clone()),
            ..Default::default()
        },
    );
    assert_401(
        &v,
        &AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        },
        "confirmation mismatch",
    );
}

#[test]
fn rejects_stale_proof_iat() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    let token = mint_access_token(
        &issuer,
        &TokenOpts {
            cnf_jkt: Some(client.thumbprint.clone()),
            ..Default::default()
        },
    );
    let old = now_for_test() - 600;
    let proof = mint_dpop_proof(
        &client,
        METHOD,
        URL,
        &ProofOpts {
            iat: Some(old),
            access_token: Some(token.clone()),
            ..Default::default()
        },
    );
    assert_401(
        &v,
        &AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        },
        "recent enough",
    );
}

#[test]
fn rejects_future_proof_iat() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    let token = mint_access_token(
        &issuer,
        &TokenOpts {
            cnf_jkt: Some(client.thumbprint.clone()),
            ..Default::default()
        },
    );
    let future = now_for_test() + 600;
    let proof = mint_dpop_proof(
        &client,
        METHOD,
        URL,
        &ProofOpts {
            iat: Some(future),
            access_token: Some(token.clone()),
            ..Default::default()
        },
    );
    assert_401(
        &v,
        &AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        },
        "recent enough",
    );
}

#[test]
fn rejects_wrong_proof_typ() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    let token = mint_access_token(
        &issuer,
        &TokenOpts {
            cnf_jkt: Some(client.thumbprint.clone()),
            ..Default::default()
        },
    );
    let proof = mint_dpop_proof(
        &client,
        METHOD,
        URL,
        &ProofOpts {
            typ: Some("jwt".into()),
            access_token: Some(token.clone()),
            ..Default::default()
        },
    );
    assert_401(
        &v,
        &AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        },
        "typ",
    );
}

#[test]
fn rejects_proof_embedding_private_key() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    let token = mint_access_token(
        &issuer,
        &TokenOpts {
            cnf_jkt: Some(client.thumbprint.clone()),
            ..Default::default()
        },
    );
    // Embed a JWK with a private `d` member.
    let mut priv_jwk = client.public_jwk.clone();
    priv_jwk["d"] = serde_json::json!("c29tZS1wcml2YXRlLXNjYWxhcg");
    let proof = mint_dpop_proof(
        &client,
        METHOD,
        URL,
        &ProofOpts {
            embed_jwk: Some(priv_jwk),
            access_token: Some(token.clone()),
            ..Default::default()
        },
    );
    assert_401(
        &v,
        &AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        },
        "private",
    );
}

#[test]
fn rejects_proof_hs256() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    let token = mint_access_token(
        &issuer,
        &TokenOpts {
            cnf_jkt: Some(client.thumbprint.clone()),
            ..Default::default()
        },
    );
    let proof = mint_dpop_proof(
        &client,
        METHOD,
        URL,
        &ProofOpts {
            alg: Some("HS256".into()),
            access_token: Some(token.clone()),
            ..Default::default()
        },
    );
    assert_401(
        &v,
        &AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        },
        "",
    );
}

#[test]
fn rejects_unsupported_scheme() {
    let issuer = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    assert_401(
        &v,
        &AuthRequest {
            authorization: Some("Basic abc123".into()),
            dpop: None,
            method: METHOD.into(),
            url: URL.into(),
        },
        "unsupported authorization scheme",
    );
}

#[test]
fn rejects_proof_without_jwk_header() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    let token = mint_access_token(
        &issuer,
        &TokenOpts {
            cnf_jkt: Some(client.thumbprint.clone()),
            ..Default::default()
        },
    );
    // Forge a proof whose header has NO jwk member by hand.
    use base64::Engine as _;
    let header = serde_json::json!({ "alg": "ES256", "typ": "dpop+jwt" });
    let claims =
        serde_json::json!({ "htm": METHOD, "htu": URL, "jti": "no-jwk", "iat": now_for_test() });
    let b = |v: &serde_json::Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap())
    };
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"sig");
    let proof = format!("{}.{}.{}", b(&header), b(&claims), sig);
    assert_401(
        &v,
        &AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        },
        "",
    );
}

// ---------------------------------------------------------------------------------------------
// Multi-issuer
// ---------------------------------------------------------------------------------------------

#[test]
fn multi_issuer_no_cross_acceptance() {
    let issuer_a = KeyKit::generate();
    let issuer_b = KeyKit::generate();
    let client = KeyKit::generate();
    let issuer_b_url = "https://idp-b.example/realms/solid";
    // Verifier trusts both, with B's *real* key registered for B.
    let jwks = solid_oidc_verifier::config::StaticJwksProvider::new()
        .with_issuer(ISSUER.to_string(), vec![issuer_a.jwk()])
        .with_issuer(issuer_b_url.to_string(), vec![issuer_b.jwk()]);
    let cfg = VerifierConfig::new(vec![ISSUER.to_string(), issuer_b_url.to_string()], AUDIENCE);
    let replay = InMemoryReplayStore::with_window(cfg.replay_ttl());
    let v = Verifier::new(cfg, jwks, replay).unwrap();
    // Token claims issuer B but is signed by A's key → rejected (B's JWKS won't verify it).
    let token = mint_access_token(
        &issuer_a,
        &TokenOpts {
            issuer: Some(issuer_b_url.into()),
            cnf_jkt: Some(client.thumbprint.clone()),
            ..Default::default()
        },
    );
    let proof = mint_dpop_proof(
        &client,
        METHOD,
        URL,
        &ProofOpts {
            access_token: Some(token.clone()),
            ..Default::default()
        },
    );
    assert_401(
        &v,
        &AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        },
        "verification failed",
    );
}

// ---------------------------------------------------------------------------------------------
// JWKS resolution failures → 401 (not 500)
// ---------------------------------------------------------------------------------------------

struct FailingProvider;
impl JwksProvider for FailingProvider {
    fn keys_for(&self, _issuer: &str) -> Result<Vec<Jwk>, JwksError> {
        Err(JwksError(
            "OIDC discovery for issuer failed: HTTP 503".into(),
        ))
    }
}

#[test]
fn jwks_resolution_failure_is_401() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let cfg = config(true);
    let replay = InMemoryReplayStore::with_window(cfg.replay_ttl());
    let v = Verifier::new(cfg, FailingProvider, replay).unwrap();
    let token = mint_access_token(
        &issuer,
        &TokenOpts {
            cnf_jkt: Some(client.thumbprint.clone()),
            ..Default::default()
        },
    );
    let proof = mint_dpop_proof(
        &client,
        METHOD,
        URL,
        &ProofOpts {
            access_token: Some(token.clone()),
            ..Default::default()
        },
    );
    assert_401(
        &v,
        &AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        },
        "verification failed",
    );
}

// ---------------------------------------------------------------------------------------------
// Replay-store fail-closed → 503
// ---------------------------------------------------------------------------------------------

struct ErrReplay;
impl solid_oidc_verifier::ReplayStore for ErrReplay {
    fn mark(
        &self,
        _jti: &str,
        _ttl: Duration,
    ) -> Result<solid_oidc_verifier::MarkResult, solid_oidc_verifier::ReplayBackendError> {
        Err(solid_oidc_verifier::ReplayBackendError("redis down".into()))
    }
}

#[test]
fn replay_backend_error_is_503_when_fail_closed() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let cfg = config(true).replay_fail_closed(true);
    let v = Verifier::new(cfg, jwks_provider(ISSUER, &issuer), ErrReplay).unwrap();
    let req = dpop_request(&issuer, &client);
    let err = v.verify(&req).expect_err("should fail closed");
    assert_eq!(err.status(), 503);
}

#[test]
fn replay_backend_error_accepts_when_fail_open() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let cfg = config(true).replay_fail_closed(false);
    let v = Verifier::new(cfg, jwks_provider(ISSUER, &issuer), ErrReplay).unwrap();
    let req = dpop_request(&issuer, &client);
    let creds = v.verify(&req).expect("fail-open accepts");
    assert_eq!(creds.web_id.as_deref(), Some(WEBID));
}

// ---------------------------------------------------------------------------------------------
// Authorized-party allowlist
// ---------------------------------------------------------------------------------------------

#[test]
fn rejects_unlisted_authorized_party() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let cfg = config(true).authorized_parties(vec!["allowed-app".into()]);
    let v = build_verifier_with(&issuer, cfg);
    // client_id defaults to CLIENT_ID ("solid-app"), not "allowed-app".
    let token = mint_access_token(
        &issuer,
        &TokenOpts {
            cnf_jkt: Some(client.thumbprint.clone()),
            ..Default::default()
        },
    );
    let proof = mint_dpop_proof(
        &client,
        METHOD,
        URL,
        &ProofOpts {
            access_token: Some(token.clone()),
            ..Default::default()
        },
    );
    assert_401(
        &v,
        &AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        },
        "authorized party",
    );
}

#[test]
fn accepts_listed_authorized_party_via_azp() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let cfg = config(true).authorized_parties(vec!["allowed-app".into()]);
    let v = build_verifier_with(&issuer, cfg);
    let token = mint_access_token(
        &issuer,
        &TokenOpts {
            cnf_jkt: Some(client.thumbprint.clone()),
            azp: Some("allowed-app".into()),
            ..Default::default()
        },
    );
    let proof = mint_dpop_proof(
        &client,
        METHOD,
        URL,
        &ProofOpts {
            access_token: Some(token.clone()),
            ..Default::default()
        },
    );
    let creds = v
        .verify(&AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        })
        .unwrap();
    assert_eq!(creds.web_id.as_deref(), Some(WEBID));
}

fn build_verifier_with(
    issuer_key: &KeyKit,
    cfg: VerifierConfig,
) -> Verifier<solid_oidc_verifier::config::StaticJwksProvider, InMemoryReplayStore> {
    let replay = InMemoryReplayStore::with_window(cfg.replay_ttl());
    let jwks = jwks_provider(ISSUER, issuer_key);
    Verifier::new(cfg, jwks, replay).unwrap()
}

// ---------------------------------------------------------------------------------------------
// WWW-Authenticate challenge
// ---------------------------------------------------------------------------------------------

#[test]
fn challenge_names_trusted_issuer() {
    let issuer = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    let err = v
        .verify(&AuthRequest {
            authorization: Some("Basic x".into()),
            dpop: None,
            method: METHOD.into(),
            url: URL.into(),
        })
        .unwrap_err();
    let challenge = v.www_authenticate(&err);
    assert!(challenge.contains(ISSUER));
    assert!(challenge.starts_with("DPoP "));
}

// ---------------------------------------------------------------------------------------------
// roborev round-1 regressions
// ---------------------------------------------------------------------------------------------

/// Finding #1 (High): a cnf-bound token presented as `Bearer` with `require_dpop=false` MUST still be
/// rejected without a proof — otherwise a captured bound token replays as a bearer token (downgrade).
#[test]
fn rejects_cnf_bound_token_as_bearer_even_when_dpop_not_required() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build_verifier(&issuer, config(false)); // require_dpop = false
    let token = mint_access_token(
        &issuer,
        &TokenOpts {
            cnf_jkt: Some(client.thumbprint.clone()),
            ..Default::default()
        },
    );
    // Bearer presentation, NO DPoP proof — must be refused because the token is cnf-bound.
    assert_401(
        &v,
        &AuthRequest {
            authorization: Some(format!("Bearer {token}")),
            dpop: None,
            method: METHOD.into(),
            url: URL.into(),
        },
        "dpop proof is required",
    );
}

/// Finding #1 (High): the same cnf-bound token presented as `Bearer` WITH a valid proof + the right
/// htu/htm/ath/cnf is accepted (proof-of-possession satisfied) even when `require_dpop=false`.
#[test]
fn accepts_cnf_bound_bearer_when_a_valid_proof_is_supplied() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build_verifier(&issuer, config(false));
    let token = mint_access_token(
        &issuer,
        &TokenOpts {
            cnf_jkt: Some(client.thumbprint.clone()),
            ..Default::default()
        },
    );
    let proof = mint_dpop_proof(
        &client,
        METHOD,
        URL,
        &ProofOpts {
            access_token: Some(token.clone()),
            ..Default::default()
        },
    );
    let creds = v
        .verify(&AuthRequest {
            authorization: Some(format!("Bearer {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        })
        .unwrap();
    assert_eq!(creds.web_id.as_deref(), Some(WEBID));
}

/// Finding #5 (Medium): a token with NO `iat` claim is rejected (RFC 9068 requires it).
#[test]
fn rejects_token_missing_iat() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    // Build a token by hand with no iat (the helper always sets iat, so sign directly).
    use serde_json::json;
    let header = json!({ "alg": "ES256", "typ": "at+jwt" });
    let exp = now_for_test() + 300;
    let claims = json!({
        "iss": ISSUER, "sub": WEBID, "jti": "no-iat-jti", "client_id": CLIENT_ID,
        "aud": AUDIENCE, "webid": WEBID, "cnf": { "jkt": client.thumbprint }, "exp": exp,
    });
    let token = issuer.sign(&header, &claims);
    let proof = mint_dpop_proof(
        &client,
        METHOD,
        URL,
        &ProofOpts {
            access_token: Some(token.clone()),
            ..Default::default()
        },
    );
    assert_401(
        &v,
        &AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        },
        "missing iat",
    );
}
