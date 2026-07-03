// AUTHORED-BY Claude Opus 4.8
//! Exhaustive tests for RFC 8705 certificate-bound (`cnf["x5t#S256"]`) access tokens — Tier-1a of the
//! high-throughput proof-of-possession work (design: solid-server-rs
//! `docs/design/high-throughput-pop-auth.md` §7 integration-point 3, §10 item 1).
//!
//! The security bar (RFC 8705 §3 — the RS "MUST verify that the certificate matches"):
//!   - cert-bound token + matching presented cert                → ACCEPT;
//!   - cert-bound token + NO presented cert                      → REJECT (never accepted bare);
//!   - cert-bound token + WRONG presented cert                   → REJECT;
//!   - DPoP (`cnf.jkt`) token                                    → UNCHANGED (still needs a proof);
//!   - token carrying BOTH confirmations                         → REJECT (ambiguous);
//!   - malformed / empty / wrong-shape `cnf.x5t#S256`            → REJECT (fail-closed, no downgrade);
//!   - no downgrade EITHER direction: a cert-bound token is never provable by a DPoP proof, and a
//!     DPoP-bound token is never provable by a presented certificate.

mod common;

use common::*;
use solid_oidc_verifier::config::{StaticJwksProvider, VerifierConfig};
use solid_oidc_verifier::replay::InMemoryReplayStore;
use solid_oidc_verifier::verifier::{AuthRequest, Confirmation, Verifier};

const URL: &str = "https://pod.example/alice/data";
const METHOD: &str = "GET";

/// A well-formed cert thumbprint (32-byte base64url SHA-256).
fn cert_x5t() -> String {
    cert_thumbprint("client-cert-a")
}
/// A DIFFERENT well-formed cert thumbprint.
fn wrong_x5t() -> String {
    cert_thumbprint("client-cert-b")
}

fn config(require_dpop: bool) -> VerifierConfig {
    VerifierConfig::new(vec![ISSUER.to_string()], AUDIENCE).require_dpop(require_dpop)
}

fn build_verifier(
    issuer_key: &KeyKit,
    config: VerifierConfig,
) -> Verifier<StaticJwksProvider, InMemoryReplayStore> {
    let replay = InMemoryReplayStore::with_window(config.replay_ttl());
    let jwks = jwks_provider(ISSUER, issuer_key);
    Verifier::new(config, jwks, replay).expect("valid config")
}

/// A certificate-bound access token (`cnf["x5t#S256"] = x5t`).
fn cert_bound_token(issuer_key: &KeyKit, x5t: &str) -> String {
    mint_access_token(
        issuer_key,
        &TokenOpts {
            cnf_x5t_s256: Some(x5t.to_string()),
            ..Default::default()
        },
    )
}

/// Present a cert-bound token via the `DPoP` scheme (how Solid clients present tokens) with the given
/// connection certificate thumbprint. No DPoP proof — the certificate IS the proof-of-possession.
fn cert_request(token: &str, presented_cert: Option<&str>) -> AuthRequest {
    AuthRequest {
        authorization: Some(format!("DPoP {token}")),
        dpop: None,
        method: METHOD.into(),
        url: URL.into(),
        client_cert_x5t_s256: presented_cert.map(str::to_string),
    }
}

fn assert_401(
    v: &Verifier<StaticJwksProvider, InMemoryReplayStore>,
    req: &AuthRequest,
    needle: &str,
) {
    let err = v.verify(req).expect_err("expected rejection");
    assert_eq!(err.status(), 401, "expected 401, got {}", err.status());
    let m = err.message().to_lowercase();
    assert!(
        m.contains(&needle.to_lowercase()),
        "message {:?} did not contain {:?}",
        err.message(),
        needle
    );
}

// ---------------------------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------------------------

#[test]
fn accepts_cert_bound_token_with_matching_cert() {
    let issuer = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    let cert = cert_x5t();
    let token = cert_bound_token(&issuer, &cert);
    let creds = v
        .verify(&cert_request(&token, Some(&cert)))
        .expect("cert-bound token with matching cert must be accepted");
    assert_eq!(creds.web_id.as_deref(), Some(WEBID));
    assert_eq!(creds.issuer.as_deref(), Some(ISSUER));
    // The confirmation surfaced is the certificate binding — NOT a jkt.
    assert_eq!(
        creds.confirmation,
        Some(Confirmation::X5tS256(cert.clone()))
    );
    assert_eq!(creds.cert_x5t_s256(), Some(cert.as_str()));
    assert_eq!(creds.cnf_jkt(), None);
}

#[test]
fn accepts_cert_bound_token_when_dpop_not_required_bearer_scheme() {
    // With require_dpop=false a cert-bound token may arrive as `Bearer`; the certificate is still
    // MUST-match. (Documents the scheme interaction; the DPoP-required scheme gate is untouched.)
    let issuer = KeyKit::generate();
    let v = build_verifier(&issuer, config(false));
    let cert = cert_x5t();
    let token = cert_bound_token(&issuer, &cert);
    let req = AuthRequest {
        authorization: Some(format!("Bearer {token}")),
        dpop: None,
        method: METHOD.into(),
        url: URL.into(),
        client_cert_x5t_s256: Some(cert.clone()),
    };
    let creds = v
        .verify(&req)
        .expect("cert-bound Bearer token accepted when dpop not required");
    assert_eq!(creds.cert_x5t_s256(), Some(cert.as_str()));
}

// ---------------------------------------------------------------------------------------------
// Fail-closed: missing / wrong certificate
// ---------------------------------------------------------------------------------------------

#[test]
fn rejects_cert_bound_token_with_no_presented_cert() {
    let issuer = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    let token = cert_bound_token(&issuer, &cert_x5t());
    // No client certificate on the connection ⇒ NEVER accepted bare.
    assert_401(
        &v,
        &cert_request(&token, None),
        "requires a client certificate",
    );
}

#[test]
fn rejects_cert_bound_token_with_wrong_cert() {
    let issuer = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    let token = cert_bound_token(&issuer, &cert_x5t());
    assert_401(
        &v,
        &cert_request(&token, Some(&wrong_x5t())),
        "confirmation mismatch",
    );
}

#[test]
fn rejects_cert_bound_token_with_length_or_bitflip_variant_cert() {
    // A presented value that is truncated / extended / empty / a single-char flip must all fail (the
    // constant-time compare also fails on a length mismatch).
    let issuer = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    let cert = cert_x5t();
    let token = cert_bound_token(&issuer, &cert);
    let first = cert.chars().next().unwrap();
    let flipped = if first == 'A' { 'B' } else { 'A' };
    let bit_flip = format!("{}{}", flipped, &cert[1..]);
    for bad in [
        "".to_string(),                     // empty
        cert[..cert.len() - 1].to_string(), // truncated (length differs)
        format!("{cert}A"),                 // extended (length differs)
        bit_flip,                           // single-char change
    ] {
        assert_401(
            &v,
            &cert_request(&token, Some(&bad)),
            "confirmation mismatch",
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Fail-closed: malformed cnf.x5t#S256 in the TOKEN (no downgrade, even with require_dpop=false)
// ---------------------------------------------------------------------------------------------

#[test]
fn rejects_token_with_malformed_x5t_even_when_dpop_not_required() {
    // A token declaring a cert confirmation the issuer INTENDED must never be silently accepted as a
    // bare token. Both empty and wrong-shape values fail closed, and crucially with require_dpop=false
    // (the downgrade path) AND a matching-looking cert presented.
    let issuer = KeyKit::generate();
    let v = build_verifier(&issuer, config(false));
    for bad in ["", "not-base64!!", "YWJj" /* only 3 bytes */] {
        let token = cert_bound_token(&issuer, bad);
        let req = AuthRequest {
            authorization: Some(format!("Bearer {token}")),
            dpop: None,
            method: METHOD.into(),
            url: URL.into(),
            client_cert_x5t_s256: Some(cert_x5t()),
        };
        assert_401(&v, &req, "malformed");
    }
}

// ---------------------------------------------------------------------------------------------
// No downgrade — both directions
// ---------------------------------------------------------------------------------------------

#[test]
fn no_downgrade_cert_bound_token_not_provable_by_dpop_proof() {
    // Attacker holds a stolen cert-bound token + can mint a DPoP proof with THEIR OWN key, but has no
    // matching client certificate. The token is cert-bound, so a DPoP proof MUST NOT satisfy it.
    let issuer = KeyKit::generate();
    let attacker = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    let token = cert_bound_token(&issuer, &cert_x5t());
    // A syntactically valid DPoP proof over this request, signed by the attacker's key.
    let proof = mint_dpop_proof(
        &attacker,
        METHOD,
        URL,
        &ProofOpts {
            access_token: Some(token.clone()),
            ..Default::default()
        },
    );
    let req = AuthRequest {
        authorization: Some(format!("DPoP {token}")),
        dpop: Some(proof),
        method: METHOD.into(),
        url: URL.into(),
        client_cert_x5t_s256: None, // no client cert on the connection
    };
    // Rejected because the certificate is missing — the DPoP proof is never consulted for this token.
    assert_401(&v, &req, "requires a client certificate");
}

#[test]
fn no_downgrade_dpop_token_not_provable_by_presented_cert() {
    // Attacker holds a stolen DPoP-bound token (cnf.jkt) and is on a connection where they DO present
    // a client certificate — but has NO valid DPoP proof. The presented cert MUST NOT substitute for
    // the required DPoP proof.
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
    let req = AuthRequest {
        authorization: Some(format!("DPoP {token}")),
        dpop: None, // no proof
        method: METHOD.into(),
        url: URL.into(),
        client_cert_x5t_s256: Some(cert_x5t()), // a cert IS presented
    };
    // The token is DPoP-bound ⇒ a proof is still required; the cert is irrelevant.
    assert_401(&v, &req, "dpop proof is required");
}

#[test]
fn no_downgrade_dpop_token_not_provable_by_cert_equal_to_jkt() {
    // Adversarial contrivance: the presented cert thumbprint happens to equal the token's jkt. It must
    // STILL take the DPoP path (proof required) — the cert value is never compared against cnf.jkt.
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
    let req = AuthRequest {
        authorization: Some(format!("DPoP {token}")),
        dpop: None,
        method: METHOD.into(),
        url: URL.into(),
        client_cert_x5t_s256: Some(client.thumbprint.clone()), // == jkt
    };
    assert_401(&v, &req, "dpop proof is required");
}

// ---------------------------------------------------------------------------------------------
// DPoP path unchanged
// ---------------------------------------------------------------------------------------------

#[test]
fn dpop_happy_path_unchanged_with_presented_cert() {
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
            access_token: Some(token.clone()),
            ..Default::default()
        },
    );
    // A presented client cert must NOT change the DPoP outcome (it is ignored on the jkt path).
    let req = AuthRequest {
        authorization: Some(format!("DPoP {token}")),
        dpop: Some(proof),
        method: METHOD.into(),
        url: URL.into(),
        client_cert_x5t_s256: Some(cert_x5t()),
    };
    let creds = v
        .verify(&req)
        .expect("valid DPoP request accepted regardless of presented cert");
    assert_eq!(creds.cnf_jkt(), Some(client.thumbprint.as_str()));
    assert_eq!(creds.cert_x5t_s256(), None);
}

// ---------------------------------------------------------------------------------------------
// Both confirmations present → ambiguous → reject
// ---------------------------------------------------------------------------------------------

#[test]
fn rejects_token_with_both_cnf_jkt_and_x5t_s256() {
    // Even with BOTH a matching cert AND a valid DPoP proof, a token asserting two confirmation
    // methods is ambiguous and rejected — we never "pick one".
    let issuer = KeyKit::generate();
    let client = KeyKit::generate();
    let v = build_verifier(&issuer, config(true));
    let cert = cert_x5t();
    let token = mint_access_token(
        &issuer,
        &TokenOpts {
            cnf_jkt: Some(client.thumbprint.clone()),
            cnf_x5t_s256: Some(cert.clone()),
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
    let req = AuthRequest {
        authorization: Some(format!("DPoP {token}")),
        dpop: Some(proof),
        method: METHOD.into(),
        url: URL.into(),
        client_cert_x5t_s256: Some(cert),
    };
    assert_401(&v, &req, "ambiguous");
}

// ---------------------------------------------------------------------------------------------
// Signature is still enforced on the cert-bound path
// ---------------------------------------------------------------------------------------------

#[test]
fn cert_bound_token_signature_still_verified() {
    // The certificate binding is IN ADDITION to the signature check: a cert-bound token signed by a
    // key the verifier does not trust is rejected even with a matching presented certificate.
    let real_issuer = KeyKit::generate();
    let forger = KeyKit::generate();
    let v = build_verifier(&real_issuer, config(true));
    let cert = cert_x5t();
    // Token signed by the FORGER but claiming the trusted issuer, cert-bound + matching cert.
    let token = cert_bound_token(&forger, &cert);
    assert_401(
        &v,
        &cert_request(&token, Some(&cert)),
        "verification failed",
    );
}
