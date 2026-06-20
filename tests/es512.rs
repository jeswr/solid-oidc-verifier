// AUTHORED-BY Claude Opus 4.8
//! ES512 (ECDSA P-521 / SHA-512) verification tests — the pure-Rust RustCrypto (`p521`) fork added by
//! the default-off `es512` feature. Exhaustive over the happy path (access token + DPoP proof),
//! forged signatures, wrong-curve keys (curve-confusion), malformed coordinates, the P-521 `cnf.jkt`
//! thumbprint binding, and the no-regression guarantee that an RS256 token still verifies (via
//! `jsonwebtoken`, never the p521 path).
//!
//! The entire suite is gated to `#[cfg(feature = "es512")]`: with the feature OFF, ES512 is rejected
//! by the KNOWN NARROWING (asserted in `tests/verifier.rs` / `src/jwk.rs`), so these positive tests do
//! not apply. With the feature OFF this file compiles to an empty crate.

#![cfg(feature = "es512")]

mod common;

use common::*;
use solid_oidc_verifier::config::VerifierConfig;
use solid_oidc_verifier::replay::InMemoryReplayStore;
use solid_oidc_verifier::verifier::{AuthRequest, Verifier};

const URL: &str = "https://pod.example/alice/data";
const METHOD: &str = "GET";

fn config() -> VerifierConfig {
    VerifierConfig::new(vec![ISSUER.to_string()], AUDIENCE).require_dpop(true)
}

fn build_es512_verifier(
    issuer_key: &P521KeyKit,
) -> Verifier<solid_oidc_verifier::config::StaticJwksProvider, InMemoryReplayStore> {
    let cfg = config();
    let replay = InMemoryReplayStore::with_window(cfg.replay_ttl());
    let jwks = es512_jwks_provider(ISSUER, issuer_key);
    Verifier::new(cfg, jwks, replay).expect("valid config")
}

// ---------------------------------------------------------------------------------------------
// (a) Happy path — ES512 access token + DPoP proof, both with P-521 keys.
// ---------------------------------------------------------------------------------------------

#[test]
fn accepts_valid_es512_access_token_and_proof() {
    let issuer = P521KeyKit::generate();
    let client = P521KeyKit::generate();
    let v = build_es512_verifier(&issuer);
    let token = mint_es512_access_token(&issuer, Some(&client.thumbprint));
    let proof = mint_es512_dpop_proof(&client, METHOD, URL, &token);
    let creds = v
        .verify(&AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        })
        .expect("ES512 token + proof should verify");
    assert_eq!(creds.web_id.as_deref(), Some(WEBID));
    assert_eq!(creds.issuer.as_deref(), Some(ISSUER));
    assert_eq!(creds.cnf_jkt.as_deref(), Some(client.thumbprint.as_str()));
}

/// The DPoP proof itself is an ES512 (`dpop+jwt`) JWS with an embedded P-521 JWK — the (e) cnf.jkt
/// thumbprint of that P-521 key must match the access token's `cnf.jkt`. Covered by the happy path
/// above (a mismatch would fail), and asserted explicitly here.
#[test]
fn es512_proof_p521_thumbprint_matches_cnf_jkt() {
    let issuer = P521KeyKit::generate();
    let client = P521KeyKit::generate();
    let v = build_es512_verifier(&issuer);
    // Bind the token to the client's P-521 thumbprint; the proof embeds the same P-521 key.
    let token = mint_es512_access_token(&issuer, Some(&client.thumbprint));
    let proof = mint_es512_dpop_proof(&client, METHOD, URL, &token);
    let creds = v
        .verify(&AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        })
        .expect("P-521 cnf.jkt thumbprint binding should hold");
    assert_eq!(creds.cnf_jkt.as_deref(), Some(client.thumbprint.as_str()));
}

/// A mismatched P-521 cnf.jkt (token bound to one P-521 key, proof embeds another) is rejected.
#[test]
fn rejects_es512_proof_cnf_jkt_mismatch() {
    let issuer = P521KeyKit::generate();
    let client = P521KeyKit::generate();
    let other = P521KeyKit::generate();
    let v = build_es512_verifier(&issuer);
    let token = mint_es512_access_token(&issuer, Some(&client.thumbprint));
    // Proof signed + embedding `other`'s P-521 key, but token is bound to `client`.
    let proof = mint_es512_dpop_proof(&other, METHOD, URL, &token);
    let err = v
        .verify(&AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        })
        .expect_err("cnf.jkt mismatch must be rejected");
    assert_eq!(err.status(), 401);
    assert!(err
        .message()
        .to_lowercase()
        .contains("confirmation mismatch"));
}

// ---------------------------------------------------------------------------------------------
// (b) Forged / tampered signature.
// ---------------------------------------------------------------------------------------------

#[test]
fn rejects_es512_forged_signature_wrong_key() {
    let issuer = P521KeyKit::generate();
    let forged = P521KeyKit::generate();
    let client = P521KeyKit::generate();
    let v = build_es512_verifier(&issuer);
    // Token signed by the attacker's P-521 key; verifier resolves the legit issuer's P-521 JWKS.
    let token = mint_es512_access_token(&forged, Some(&client.thumbprint));
    let proof = mint_es512_dpop_proof(&client, METHOD, URL, &token);
    let err = v
        .verify(&AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        })
        .expect_err("forged signature must be rejected");
    assert_eq!(err.status(), 401);
    assert!(err.message().to_lowercase().contains("verification failed"));
}

#[test]
fn rejects_es512_tampered_payload() {
    let issuer = P521KeyKit::generate();
    let client = P521KeyKit::generate();
    let v = build_es512_verifier(&issuer);
    let token = mint_es512_access_token(&issuer, Some(&client.thumbprint));
    // Flip one bit of the ES512 signature — the SHA-512 ECDSA check must then fail (proves the
    // signature is genuinely verified, not ignored).
    use base64::Engine as _;
    let parts: Vec<&str> = token.split('.').collect();
    let mut sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[2])
        .expect("decode signature");
    sig[0] ^= 0x01;
    let tampered_sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&sig);
    let tampered = format!("{}.{}.{}", parts[0], parts[1], tampered_sig);
    let proof = mint_es512_dpop_proof(&client, METHOD, URL, &tampered);
    let err = v
        .verify(&AuthRequest {
            authorization: Some(format!("DPoP {tampered}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        })
        .expect_err("tampered payload must be rejected");
    assert_eq!(err.status(), 401);
}

// ---------------------------------------------------------------------------------------------
// (c) Curve confusion — a P-256 key carrying alg=ES512 is rejected (fail closed).
// ---------------------------------------------------------------------------------------------

#[test]
fn rejects_es512_with_p256_jwks_key_wrong_curve() {
    // The header says ES512, but the issuer's JWKS key is P-256 — must be rejected (the p521 key
    // builder requires crv == P-521; never accept a P-256 key for ES512).
    let p256_issuer = KeyKit::generate();
    let client = P521KeyKit::generate();
    let cfg = config();
    let replay = InMemoryReplayStore::with_window(cfg.replay_ttl());
    // Register the issuer with a P-256 key only.
    let jwks = jwks_provider(ISSUER, &p256_issuer);
    let v = Verifier::new(cfg, jwks, replay).expect("valid config");
    // Mint an ES512-headed token signed by a P-521 key (it won't verify against the P-256 JWKS key,
    // and more importantly the P-256 key is rejected for ES512 before any verify attempt).
    let issuer_p521 = P521KeyKit::generate();
    let token = mint_es512_access_token(&issuer_p521, Some(&client.thumbprint));
    let proof = mint_es512_dpop_proof(&client, METHOD, URL, &token);
    let err = v
        .verify(&AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        })
        .expect_err("a P-256 JWKS key must not be accepted for ES512");
    assert_eq!(err.status(), 401);
}

#[test]
fn rejects_es512_proof_embedding_p256_key() {
    // The access token is bound to a P-521 cnf.jkt and verifies, but the DPoP proof carries an
    // ES512 header with an embedded *P-256* JWK — the proof key build must fail closed (wrong curve),
    // so a P-256 key can never act as an ES512 proof-of-possession holder key.
    let issuer = P521KeyKit::generate();
    let client_p521 = P521KeyKit::generate();
    let p256_client = KeyKit::generate();
    let v = build_es512_verifier(&issuer);
    let token = mint_es512_access_token(&issuer, Some(&client_p521.thumbprint));
    // Hand-build an ES512 proof header that embeds a P-256 JWK, signed (meaninglessly) by P-256.
    use base64::Engine as _;
    let header =
        serde_json::json!({ "alg": "ES512", "typ": "dpop+jwt", "jwk": p256_client.public_jwk });
    let claims = serde_json::json!({
        "htm": METHOD, "htu": URL, "jti": "es512-p256-proof",
        "iat": now_for_test(), "ath": es512_ath(&token),
    });
    let b = |val: &serde_json::Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(val).unwrap())
    };
    // A bogus 132-byte signature (won't be reached if the curve guard fires first, but keep it
    // well-formed so the rejection is specifically the curve guard / signature, never a panic).
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 132]);
    let proof = format!("{}.{}.{}", b(&header), b(&claims), sig);
    let err = v
        .verify(&AuthRequest {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        })
        .expect_err("an embedded P-256 key must not act as an ES512 proof key");
    assert_eq!(err.status(), 401);
}

// ---------------------------------------------------------------------------------------------
// (d) Malformed / short / long / empty x or y is rejected, not a panic.
// ---------------------------------------------------------------------------------------------

#[test]
fn rejects_es512_malformed_coordinates_no_panic() {
    let issuer = P521KeyKit::generate();
    let client = P521KeyKit::generate();
    // Try a battery of malformed JWKS keys (header alg ES512) — each must be a clean 401, never a
    // panic. We register a bad key as the issuer's JWKS so the p521 key builder is exercised.
    let bad_jwks: Vec<serde_json::Value> = vec![
        // empty x
        serde_json::json!({ "kty": "EC", "crv": "P-521", "x": "", "y": "AAAA" }),
        // short x (not 66 bytes)
        serde_json::json!({ "kty": "EC", "crv": "P-521", "x": "AAAA", "y": "AAAA" }),
        // non-base64url x
        serde_json::json!({ "kty": "EC", "crv": "P-521", "x": "@@@@", "y": "AAAA" }),
        // missing y
        serde_json::json!({ "kty": "EC", "crv": "P-521", "x": "AAAA" }),
        // long x (much longer than 66 bytes when decoded)
        serde_json::json!({ "kty": "EC", "crv": "P-521",
            "x": "A".repeat(200), "y": "A".repeat(88) }),
    ];
    for bad in bad_jwks {
        let bad_key: solid_oidc_verifier::jwk::Jwk = match serde_json::from_value(bad.clone()) {
            Ok(k) => k,
            // A JWK that fails to even deserialize is a fine rejection too (skip — covered elsewhere).
            Err(_) => continue,
        };
        let cfg = config();
        let replay = InMemoryReplayStore::with_window(cfg.replay_ttl());
        let jwks = solid_oidc_verifier::config::StaticJwksProvider::new()
            .with_issuer(ISSUER.to_string(), vec![bad_key]);
        let v = Verifier::new(cfg, jwks, replay).expect("valid config");
        let token = mint_es512_access_token(&issuer, Some(&client.thumbprint));
        let proof = mint_es512_dpop_proof(&client, METHOD, URL, &token);
        // Must be a clean rejection — never a panic, never an acceptance. `expect_err` panics if
        // verify() wrongly returned Ok (an erroneous acceptance of a malformed key).
        let err = v
            .verify(&AuthRequest {
                authorization: Some(format!("DPoP {token}")),
                dpop: Some(proof),
                method: METHOD.into(),
                url: URL.into(),
            })
            .unwrap_err_or_panic(&bad);
        assert_eq!(err.status(), 401, "malformed key {bad:?} should 401");
    }
}

/// A tiny extension so the malformed-coordinate loop reads clearly: panic with the offending JWK on an
/// erroneous `Ok`, otherwise return the (expected) error. Equivalent to `expect_err` but carries the
/// JWK into the panic message for diagnosis.
trait UnwrapErrOrPanic<E> {
    fn unwrap_err_or_panic(self, ctx: &serde_json::Value) -> E;
}
impl<T: std::fmt::Debug, E> UnwrapErrOrPanic<E> for Result<T, E> {
    fn unwrap_err_or_panic(self, ctx: &serde_json::Value) -> E {
        match self {
            Ok(v) => panic!("a malformed coordinate must never verify ({ctx:?}); got Ok({v:?})"),
            Err(e) => e,
        }
    }
}

#[test]
fn rejects_es512_malformed_signature_length() {
    let issuer = P521KeyKit::generate();
    let client = P521KeyKit::generate();
    let v = build_es512_verifier(&issuer);
    // Build a valid header+payload, then replace the signature with a wrong-length (e.g. 64-byte)
    // blob — the fixed-width r||s length check must reject it (not coerce / panic).
    let token = mint_es512_access_token(&issuer, Some(&client.thumbprint));
    let mut parts: Vec<String> = token.split('.').map(str::to_string).collect();
    use base64::Engine as _;
    parts[2] = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 64]); // wrong length
    let short_sig_token = parts.join(".");
    let proof = mint_es512_dpop_proof(&client, METHOD, URL, &short_sig_token);
    let err = v
        .verify(&AuthRequest {
            authorization: Some(format!("DPoP {short_sig_token}")),
            dpop: Some(proof),
            method: METHOD.into(),
            url: URL.into(),
        })
        .expect_err("a wrong-length ES512 signature must be rejected");
    assert_eq!(err.status(), 401);
}

// ---------------------------------------------------------------------------------------------
// (g) No regression — an RS256 token still verifies via jsonwebtoken, never the p521 path.
// ---------------------------------------------------------------------------------------------

#[test]
fn rs256_still_verifies_with_es512_feature_on() {
    let rsa = RsaKeyKit::generate();
    let client = KeyKit::generate(); // P-256 DPoP holder key (ES256 proof)
    let cfg = config();
    let replay = InMemoryReplayStore::with_window(cfg.replay_ttl());
    let jwks = solid_oidc_verifier::config::StaticJwksProvider::new()
        .with_issuer(ISSUER.to_string(), vec![rsa.jwk()]);
    let v = Verifier::new(cfg, jwks, replay).expect("valid config");
    let token = rsa.mint_access_token(&client.thumbprint);
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
        .expect("RS256 must still verify (no regression) with the es512 feature on");
    assert_eq!(creds.web_id.as_deref(), Some(WEBID));
}

#[test]
fn es256_still_verifies_with_es512_feature_on() {
    let issuer = KeyKit::generate(); // P-256
    let client = KeyKit::generate();
    let cfg = config();
    let replay = InMemoryReplayStore::with_window(cfg.replay_ttl());
    let jwks = jwks_provider(ISSUER, &issuer);
    let v = Verifier::new(cfg, jwks, replay).expect("valid config");
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
        .expect("ES256 must still verify (no regression) with the es512 feature on");
    assert_eq!(creds.web_id.as_deref(), Some(WEBID));
}

// --- local helpers ---

fn now_for_test() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// base64url(SHA-256(token)) — the DPoP `ath` (re-exported from common for hand-built proofs).
fn es512_ath(token: &str) -> String {
    ath(token)
}
