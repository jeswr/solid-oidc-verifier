// AUTHORED-BY Claude Opus 4.8
//! `allow_missing_ath` compat-mode coverage — the Rust port of `athCompat.test.ts`.
//!
//! Asserts the opt-in three-state `ath` path: (a) an otherwise-valid ath-LESS proof is ACCEPTED when
//! compat is on; (b) compat still rejects every OTHER tampering (cnf.jkt/htu/htm/iat/replay/bad
//! sig/wrong aud/present-but-wrong ath); (c) the default (strict) verifier still rejects the ath-less
//! proof. The crucial security property: only ABSENCE of `ath` is tolerated, never a wrong one.

mod common;

use common::*;
use solid_oidc_verifier::config::VerifierConfig;
use solid_oidc_verifier::replay::InMemoryReplayStore;
use solid_oidc_verifier::verifier::{AuthRequest, Verifier};

const URL: &str = "https://pod.example/alice/data";
const METHOD: &str = "GET";

fn compat_config() -> VerifierConfig {
    VerifierConfig::new(vec![ISSUER.to_string()], AUDIENCE)
        .require_dpop(true)
        .allow_missing_ath(true)
}

fn strict_config() -> VerifierConfig {
    VerifierConfig::new(vec![ISSUER.to_string()], AUDIENCE).require_dpop(true)
}

fn build(
    issuer_key: &KeyKit,
    cfg: VerifierConfig,
) -> Verifier<solid_oidc_verifier::config::StaticJwksProvider, InMemoryReplayStore> {
    let replay = InMemoryReplayStore::with_window(cfg.replay_ttl());
    let jwks = jwks_provider(ISSUER, issuer_key);
    Verifier::new(cfg, jwks, replay).unwrap()
}

fn now_for_test() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// A request whose proof OMITS `ath` but is otherwise well-formed.
fn athless_request(
    issuer: &KeyKit,
    client: &KeyKit,
    token_opts: TokenOpts,
    proof_opts: ProofOpts,
) -> (String, AuthRequest) {
    let token = mint_access_token(
        issuer,
        &TokenOpts {
            cnf_jkt: Some(client.thumbprint.clone()),
            ..token_opts
        },
    );
    let proof = mint_dpop_proof(
        client,
        METHOD,
        URL,
        &ProofOpts {
            access_token: None,
            ..proof_opts
        },
    );
    let req = AuthRequest {
        authorization: Some(format!("DPoP {token}")),
        dpop: Some(proof),
        method: METHOD.into(),
        url: URL.into(),
    };
    (token, req)
}

fn assert_401(
    v: &Verifier<solid_oidc_verifier::config::StaticJwksProvider, InMemoryReplayStore>,
    req: &AuthRequest,
    needle: &str,
) {
    let err = v.verify(req).expect_err("expected rejection");
    assert_eq!(err.status(), 401, "{}", err.message());
    assert!(
        err.message()
            .to_lowercase()
            .contains(&needle.to_lowercase()),
        "{:?} !contains {:?}",
        err.message(),
        needle
    );
}

// (a) accepts ath-less proof in compat mode -----------------------------------------------------

#[test]
fn compat_accepts_athless_proof() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build(&issuer, compat_config());
    let (_t, req) = athless_request(&issuer, &client, TokenOpts::default(), ProofOpts::default());
    let creds = v.verify(&req).unwrap();
    assert_eq!(creds.web_id.as_deref(), Some(WEBID));
    assert_eq!(creds.issuer.as_deref(), Some(ISSUER));
}

#[test]
fn compat_still_accepts_correct_ath() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build(&issuer, compat_config());
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
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        })
        .unwrap();
    assert_eq!(creds.web_id.as_deref(), Some(WEBID));
}

#[test]
fn compat_custom_webid_claim() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build(
        &issuer,
        compat_config().webid_claim("http://example.com/webid"),
    );
    let (_t, req) = athless_request(
        &issuer,
        &client,
        TokenOpts {
            webid_claim: Some("http://example.com/webid".into()),
            ..Default::default()
        },
        ProofOpts::default(),
    );
    let creds = v.verify(&req).unwrap();
    assert_eq!(creds.web_id.as_deref(), Some(WEBID));
}

// (b) compat still rejects every other tampering ------------------------------------------------

#[test]
fn compat_rejects_cnf_jkt_mismatch() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let other = KeyKit::generate();
    let v = build(&issuer, compat_config());
    let token = mint_access_token(
        &issuer,
        &TokenOpts {
            cnf_jkt: Some(client.thumbprint.clone()),
            ..Default::default()
        },
    );
    let proof = mint_dpop_proof(&other, METHOD, URL, &ProofOpts::default()); // no ath, other's key
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
fn compat_rejects_htu_mismatch() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build(&issuer, compat_config());
    let (_t, req) = athless_request(
        &issuer,
        &client,
        TokenOpts::default(),
        ProofOpts {
            htu: Some("https://pod.example/alice/other".into()),
            ..Default::default()
        },
    );
    assert_401(&v, &req, "htu");
}

#[test]
fn compat_rejects_htm_mismatch() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build(&issuer, compat_config());
    let (_t, req) = athless_request(
        &issuer,
        &client,
        TokenOpts::default(),
        ProofOpts {
            htm: Some("DELETE".into()),
            ..Default::default()
        },
    );
    assert_401(&v, &req, "htm");
}

#[test]
fn compat_rejects_stale_iat() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build(&issuer, compat_config());
    let (_t, req) = athless_request(
        &issuer,
        &client,
        TokenOpts::default(),
        ProofOpts {
            iat: Some(now_for_test() - 600),
            ..Default::default()
        },
    );
    assert_401(&v, &req, "recent enough");
}

#[test]
fn compat_rejects_future_iat() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build(&issuer, compat_config());
    let (_t, req) = athless_request(
        &issuer,
        &client,
        TokenOpts::default(),
        ProofOpts {
            iat: Some(now_for_test() + 600),
            ..Default::default()
        },
    );
    assert_401(&v, &req, "recent enough");
}

#[test]
fn compat_rejects_replayed_jti() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build(&issuer, compat_config());
    let (_t, req) = athless_request(
        &issuer,
        &client,
        TokenOpts::default(),
        ProofOpts {
            jti: Some("fixed-compat-jti".into()),
            ..Default::default()
        },
    );
    v.verify(&req).unwrap();
    assert_401(&v, &req, "replay");
}

#[test]
fn compat_rejects_bad_access_token_signature() {
    let issuer = KeyKit::generate();
    let forged = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build(&issuer, compat_config());
    let token = mint_access_token(
        &forged,
        &TokenOpts {
            cnf_jkt: Some(client.thumbprint.clone()),
            ..Default::default()
        },
    );
    let proof = mint_dpop_proof(&client, METHOD, URL, &ProofOpts::default());
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
fn compat_rejects_wrong_aud() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build(&issuer, compat_config());
    let (_t, req) = athless_request(
        &issuer,
        &client,
        TokenOpts {
            audience: Some("https://other.example".into()),
            ..Default::default()
        },
        ProofOpts::default(),
    );
    assert_401(&v, &req, "verification failed");
}

#[test]
fn compat_rejects_token_not_dpop_bound() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build(&issuer, compat_config());
    let token = mint_access_token(&issuer, &TokenOpts::default()); // no cnf
    let proof = mint_dpop_proof(&client, METHOD, URL, &ProofOpts::default());
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
fn compat_rejects_wrong_proof_typ() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build(&issuer, compat_config());
    let (_t, req) = athless_request(
        &issuer,
        &client,
        TokenOpts::default(),
        ProofOpts {
            typ: Some("jwt".into()),
            ..Default::default()
        },
    );
    assert_401(&v, &req, "typ");
}

#[test]
fn compat_rejects_hs256_proof() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build(&issuer, compat_config());
    let (_t, req) = athless_request(
        &issuer,
        &client,
        TokenOpts::default(),
        ProofOpts {
            alg: Some("HS256".into()),
            ..Default::default()
        },
    );
    assert_401(&v, &req, "");
}

#[test]
fn compat_rejects_private_key_embed() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build(&issuer, compat_config());
    let mut priv_jwk = client.public_jwk.clone();
    priv_jwk["d"] = serde_json::json!("c29tZS1wcml2YXRlLXNjYWxhcg");
    let (_t, req) = athless_request(
        &issuer,
        &client,
        TokenOpts::default(),
        ProofOpts {
            embed_jwk: Some(priv_jwk),
            ..Default::default()
        },
    );
    assert_401(&v, &req, "private");
}

#[test]
fn compat_rejects_malformed_access_token() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build(&issuer, compat_config());
    let proof = mint_dpop_proof(&client, METHOD, URL, &ProofOpts::default());
    assert_401(
        &v,
        &AuthRequest {
            authorization: Some("DPoP not.a.jwt.at.all".into()),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        },
        "",
    );
}

#[test]
fn compat_rejects_untrusted_issuer() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build(&issuer, compat_config());
    let (_t, req) = athless_request(
        &issuer,
        &client,
        TokenOpts {
            issuer: Some("https://evil.example/realms/solid".into()),
            ..Default::default()
        },
        ProofOpts::default(),
    );
    assert_401(&v, &req, "issuer is not trusted");
}

#[test]
fn compat_rejects_present_but_wrong_ath() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build(&issuer, compat_config());
    // ath present but bogus → must still be rejected (only ABSENCE is tolerated).
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
fn compat_rejects_ath_for_different_token() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build(&issuer, compat_config());
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

// (c) strict mode (default) still rejects ath-less proof ----------------------------------------

#[test]
fn strict_default_rejects_athless_proof() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build(&issuer, strict_config());
    let (_t, req) = athless_request(&issuer, &client, TokenOpts::default(), ProofOpts::default());
    assert_401(&v, &req, "ath");
}

#[test]
fn explicitly_disabled_flag_rejects_athless_proof() {
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build(&issuer, strict_config().allow_missing_ath(false));
    let (_t, req) = athless_request(&issuer, &client, TokenOpts::default(), ProofOpts::default());
    assert_401(&v, &req, "ath");
}
