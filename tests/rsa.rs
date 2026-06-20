// AUTHORED-BY Claude Opus 4.8
//! RS256 path coverage — the Keycloak DEFAULT algorithm, and the exact case the rejected
//! `dpop-verifier` crate (ES256/EdDSA-only) could NOT handle (spike R1). A DPoP-bound RS256 access
//! token with an ES256 DPoP proof (the realistic Keycloak shape: IdP signs RS256, client holds an EC
//! DPoP key) must verify end-to-end; a forged RS256 token must be rejected.

mod common;

use common::*;
use solid_oidc_verifier::config::VerifierConfig;
use solid_oidc_verifier::replay::InMemoryReplayStore;
use solid_oidc_verifier::verifier::{AuthRequest, Verifier};

const URL: &str = "https://pod.example/alice/data";
const METHOD: &str = "GET";

fn build(
    rsa_issuer: &RsaKeyKit,
) -> Verifier<solid_oidc_verifier::config::StaticJwksProvider, InMemoryReplayStore> {
    let cfg = VerifierConfig::new(vec![ISSUER.to_string()], AUDIENCE).require_dpop(true);
    let jwks = solid_oidc_verifier::config::StaticJwksProvider::new()
        .with_issuer(ISSUER.to_string(), vec![rsa_issuer.jwk()]);
    let replay = InMemoryReplayStore::with_window(cfg.replay_ttl());
    Verifier::new(cfg, jwks, replay).unwrap()
}

#[test]
fn accepts_rs256_token_with_es256_proof() {
    let rsa_issuer = RsaKeyKit::generate();
    let client = KeyKit::generate(); // EC DPoP client key
    let v = build(&rsa_issuer);
    let token = rsa_issuer.mint_access_token(&client.thumbprint);
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
    assert_eq!(creds.issuer.as_deref(), Some(ISSUER));
}

#[test]
fn rejects_forged_rs256_token() {
    let rsa_issuer = RsaKeyKit::generate();
    let forged = RsaKeyKit::generate();
    let client = KeyKit::generate();
    let v = build(&rsa_issuer); // trusts rsa_issuer's key only
    let token = forged.mint_access_token(&client.thumbprint); // signed by the wrong RSA key
    let proof = mint_dpop_proof(
        &client,
        METHOD,
        URL,
        &ProofOpts {
            access_token: Some(token.clone()),
            ..Default::default()
        },
    );
    let err = v
        .verify(&AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        })
        .unwrap_err();
    assert_eq!(err.status(), 401);
    assert!(err.message().to_lowercase().contains("verification failed"));
}
