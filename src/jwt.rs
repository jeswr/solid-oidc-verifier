// AUTHORED-BY Claude Opus 4.8
//! JWT/JWS decoding + signature verification over a JWKS.
//!
//! Wraps `jsonwebtoken` for the crypto, and provides the *unverified* header/claim peek the TS
//! verifier uses for pre-validation routing (`decodeClaims`/`peekIssuer`/`proofHasAth`). The peek is
//! NEVER a security decision — the JWS is always fully verified on whichever path it takes.

use base64::Engine as _;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde_json::Value;

use crate::error::{invalid_token, VerifyError};
use crate::jwk::{alg_in_policy, alg_is_verifiable, Jwk, ES512_KNOWN_NARROWING};

/// A decoded JOSE header (the fields we inspect).
#[derive(Debug, Clone)]
pub struct Header {
    pub alg: String,
    pub typ: Option<String>,
    /// The embedded JWK from a DPoP proof header (`jwk`), if present.
    pub jwk: Option<Jwk>,
}

/// Split a compact JWS into its three segments without verifying anything. Returns an error shaped
/// like the TS "Malformed access token." path for anything that is not three dot-separated parts.
fn split_compact(token: &str) -> Result<(&str, &str, &str), VerifyError> {
    let mut parts = token.split('.');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s), None) if !h.is_empty() && !p.is_empty() && !s.is_empty() => {
            Ok((h, p, s))
        }
        _ => Err(invalid_token("Malformed token.")),
    }
}

fn b64url_decode(seg: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(seg)
        .ok()
}

/// Decode the *unverified* JOSE header. Used to learn the `alg` (so the right key/algorithm is
/// selected) and, for a DPoP proof, the embedded `jwk`. The signature is re-checked afterwards, so a
/// lie in the header only causes a verification failure, never a bypass. Mirrors the header inspection
/// `jose`/`oauth4webapi` perform internally.
pub fn peek_header(token: &str) -> Result<Header, VerifyError> {
    let (h, _, _) = split_compact(token)?;
    let bytes = b64url_decode(h).ok_or_else(|| invalid_token("Malformed token header."))?;
    let v: Value =
        serde_json::from_slice(&bytes).map_err(|_| invalid_token("Malformed token header."))?;
    let alg = v
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_token("Token header has no alg."))?
        .to_string();
    let typ = v.get("typ").and_then(Value::as_str).map(str::to_string);
    let jwk = match v.get("jwk") {
        Some(j) if !j.is_null() => {
            Some(serde_json::from_value::<Jwk>(j.clone()).map_err(|_| {
                invalid_token("DPoP proof jwk header parameter must be a JSON object.")
            })?)
        }
        _ => None,
    };
    Ok(Header { alg, typ, jwk })
}

/// Decode the *unverified* claims object. Mirrors TS `decodeClaims`: returns `None` for anything not
/// shaped like a 3-part JWT with a JSON-object payload. Used only for pre-validation routing.
pub fn peek_claims(token: &str) -> Option<Value> {
    let (_, p, _) = split_compact(token).ok()?;
    let bytes = b64url_decode(p)?;
    let v: Value = serde_json::from_slice(&bytes).ok()?;
    if v.is_object() {
        Some(v)
    } else {
        None
    }
}

/// Read the unverified `iss` (to select the trusted issuer's keys; re-asserted by the signature
/// check). Mirrors TS `peekIssuer`.
pub fn peek_issuer(token: &str) -> Result<String, VerifyError> {
    let claims = peek_claims(token).ok_or_else(|| invalid_token("Malformed access token."))?;
    match claims.get("iss").and_then(Value::as_str) {
        Some(s) if !s.is_empty() => Ok(s.to_string()),
        _ => Err(invalid_token("Access token has no issuer.")),
    }
}

/// Whether a DPoP proof carries a non-empty `ath` claim (routes strict vs ath-compat). Mirrors TS
/// `proofHasAth`. Not a security decision — the proof is fully verified afterwards.
pub fn proof_has_ath(proof: &str) -> bool {
    peek_claims(proof)
        .and_then(|c| c.get("ath").and_then(Value::as_str).map(str::to_string))
        .map(|a| !a.is_empty())
        .unwrap_or(false)
}

/// Map an alg string to `jsonwebtoken`'s `Algorithm`, refusing anything outside the asymmetric-only
/// policy allowlist AND anything the primitive cannot actually verify (the ES512 KNOWN NARROWING).
pub fn map_algorithm(alg: &str) -> Result<Algorithm, VerifyError> {
    if !alg_in_policy(alg) {
        // HS*, none, or any unknown alg → rejected. This is the alg-confusion / symmetric guard.
        return Err(invalid_token(format!(
            "Unsupported or non-asymmetric signature algorithm: {alg}."
        )));
    }
    if !alg_is_verifiable(alg) {
        // ES512: in policy, but unverifiable by this primitive. NEVER accept what we cannot verify.
        return Err(invalid_token(ES512_KNOWN_NARROWING));
    }
    Ok(match alg {
        "ES256" => Algorithm::ES256,
        "ES384" => Algorithm::ES384,
        "PS256" => Algorithm::PS256,
        "PS384" => Algorithm::PS384,
        "PS512" => Algorithm::PS512,
        "RS256" => Algorithm::RS256,
        "RS384" => Algorithm::RS384,
        "RS512" => Algorithm::RS512,
        "EdDSA" => Algorithm::EdDSA,
        // Unreachable: every policy+verifiable alg is mapped above.
        other => {
            return Err(invalid_token(format!(
                "Unsupported signature algorithm: {other}."
            )))
        }
    })
}

/// Build a `jsonwebtoken::DecodingKey` from a JWK. Supports the asymmetric key types Solid uses.
/// Refuses symmetric keys and (defensively) private keys.
pub fn decoding_key_from_jwk(jwk: &Jwk) -> Result<DecodingKey, VerifyError> {
    if jwk.is_symmetric() {
        return Err(invalid_token("Symmetric keys are not accepted."));
    }
    if jwk.has_private_material() {
        // EmbeddedJWK / a JWKS entry must carry only the PUBLIC key.
        return Err(invalid_token(
            "Key contains private material; only a public key is accepted.",
        ));
    }
    match jwk.kty.as_str() {
        "EC" => {
            let x = jwk
                .x
                .as_deref()
                .ok_or_else(|| invalid_token("EC JWK missing x."))?;
            let y = jwk
                .y
                .as_deref()
                .ok_or_else(|| invalid_token("EC JWK missing y."))?;
            DecodingKey::from_ec_components(x, y)
                .map_err(|e| invalid_token(format!("Invalid EC public key: {e}.")))
        }
        "RSA" => {
            let n = jwk
                .n
                .as_deref()
                .ok_or_else(|| invalid_token("RSA JWK missing n."))?;
            let e = jwk
                .e
                .as_deref()
                .ok_or_else(|| invalid_token("RSA JWK missing e."))?;
            DecodingKey::from_rsa_components(n, e)
                .map_err(|e| invalid_token(format!("Invalid RSA public key: {e}.")))
        }
        "OKP" => {
            let x = jwk
                .x
                .as_deref()
                .ok_or_else(|| invalid_token("OKP JWK missing x."))?;
            DecodingKey::from_ed_components(x)
                .map_err(|e| invalid_token(format!("Invalid OKP public key: {e}.")))
        }
        other => Err(invalid_token(format!("Unsupported JWK key type: {other}."))),
    }
}

/// The outcome of a successful signature verification: the validated claims as a JSON object.
pub type Claims = serde_json::Map<String, Value>;

/// Verify a compact JWS's signature against a set of candidate JWKS keys, requiring the header `alg`
/// to be in the asymmetric-only allowlist and verifiable. Returns the validated claims with NO
/// temporal/claim validation applied (the caller layers RFC-9068 / RFC-9449 checks on top — exactly
/// as the TS code splits primitive verification from policy).
///
/// `expected_typ`, if `Some`, is required to match the header `typ` (e.g. `at+jwt`, `dpop+jwt`).
///
/// Signature verification tries each candidate key (a JWKS may have several); the first that verifies
/// wins. If none verify → `invalid_token`. This is the alg-confusion-safe primitive: the `alg` is
/// pinned from the allowlist, never read as a trust input.
pub fn verify_signature(
    token: &str,
    candidate_keys: &[Jwk],
    expected_typ: Option<&str>,
) -> Result<Claims, VerifyError> {
    let header = peek_header(token)?;
    let alg = map_algorithm(&header.alg)?;

    if let Some(want) = expected_typ {
        match header.typ.as_deref() {
            Some(got) if got.eq_ignore_ascii_case(want) => {}
            _ => {
                return Err(invalid_token(format!(
                    "Unexpected token typ (want {want})."
                )))
            }
        }
    }

    // We deliberately disable jsonwebtoken's built-in claim validation here (no iss/aud/exp) — we run
    // those ourselves to match the TS semantics precisely (clock tolerance, required claims, etc.).
    let mut validation = Validation::new(alg);
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    // Pin the single permitted algorithm (defence against alg substitution).
    validation.algorithms = vec![alg];

    if candidate_keys.is_empty() {
        return Err(invalid_token("No verification key available for issuer."));
    }

    let mut last_err: Option<VerifyError> = None;
    for jwk in candidate_keys {
        let key = match decoding_key_from_jwk(jwk) {
            Ok(k) => k,
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        };
        match jsonwebtoken::decode::<Claims>(token, &key, &validation) {
            Ok(data) => return Ok(data.claims),
            Err(e) => {
                last_err = Some(invalid_token(format!("signature verification failed: {e}")));
            }
        }
    }
    Err(last_err.unwrap_or_else(|| invalid_token("signature verification failed")))
}

/// Verify a DPoP proof's signature using its OWN embedded JWK as the verification key (RFC 9449 — the
/// proof is self-signed by the holder key). Returns `(claims, embedded_jwk)`. Enforces the embedded
/// JWK is present, public, asymmetric, and that the `alg`/`typ` are correct. This is the Rust analogue
/// of `jose.EmbeddedJWK`.
pub fn verify_proof_with_embedded_jwk(
    proof: &str,
    expected_typ: &str,
) -> Result<(Claims, Jwk), VerifyError> {
    let header = peek_header(proof)?;
    let jwk = header
        .jwk
        .clone()
        .ok_or_else(|| invalid_token("DPoP proof jwk header parameter must be a JSON object."))?;
    if jwk.has_private_material() {
        return Err(invalid_token(
            "DPoP proof embedded a private key; only a public key is accepted.",
        ));
    }
    if jwk.is_symmetric() {
        return Err(invalid_token("DPoP proof embedded a symmetric key."));
    }
    let claims = verify_signature(proof, std::slice::from_ref(&jwk), Some(expected_typ))?;
    Ok((claims, jwk))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_rejects_two_part() {
        assert!(split_compact("a.b").is_err());
        assert!(split_compact("not.a.jwt.at.all").is_err());
        assert!(split_compact("a..c").is_err());
    }

    #[test]
    fn peek_claims_none_for_garbage() {
        assert!(peek_claims("garbage").is_none());
    }

    #[test]
    fn map_algorithm_rejects_hs_and_none() {
        assert!(map_algorithm("HS256").is_err());
        assert!(map_algorithm("none").is_err());
    }

    #[test]
    fn map_algorithm_rejects_es512_narrowing() {
        let e = map_algorithm("ES512").unwrap_err();
        assert!(e.message().contains("ES512"));
    }

    #[test]
    fn map_algorithm_accepts_es256() {
        assert!(matches!(map_algorithm("ES256"), Ok(Algorithm::ES256)));
    }
}
