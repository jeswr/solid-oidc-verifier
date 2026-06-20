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
/// policy allowlist AND anything `jsonwebtoken` cannot verify.
///
/// ES512 is ALWAYS rejected here as defence-in-depth: `Algorithm::ES512` does not exist on the
/// `aws_lc_rs` backend, so even when the `es512` feature is enabled the ES512 token is verified on a
/// SEPARATE pure-Rust path ([`verify_es512_over_candidates`]) that is forked BEFORE this function in
/// [`verify_signature`]. Any caller that nonetheless reaches `map_algorithm` with ES512 gets a clear
/// error rather than a silent fall-through — the two backends never share a code path.
pub fn map_algorithm(alg: &str) -> Result<Algorithm, VerifyError> {
    if !alg_in_policy(alg) {
        // HS*, none, or any unknown alg → rejected. This is the alg-confusion / symmetric guard.
        return Err(invalid_token(format!(
            "Unsupported or non-asymmetric signature algorithm: {alg}."
        )));
    }
    if alg == "ES512" {
        // Explicit rejection arm (defence-in-depth). `jsonwebtoken`/aws-lc-rs has no ES512 variant;
        // ES512 is handled on the p521 fork BEFORE this point (feature on) or rejected (feature off).
        return Err(invalid_token(ES512_KNOWN_NARROWING));
    }
    if !alg_is_verifiable(alg) {
        // In policy, but unverifiable by this primitive. NEVER accept what we cannot verify.
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

/// Enforce the optional `expected_typ` against a header's `typ` (case-insensitive, RFC-9068/9449).
/// Factored out so the `jsonwebtoken` fork and the ES512 (`p521`) fork enforce `typ` IDENTICALLY —
/// the ES512 path must apply the `at+jwt` / `dpop+jwt` check exactly as the primary path does.
fn enforce_typ(header: &Header, expected_typ: Option<&str>) -> Result<(), VerifyError> {
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
    Ok(())
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

    // ES512 fork — entered ONLY after `alg == "ES512"` is established (the alg is pinned from the
    // header, never read as a trust input). `jsonwebtoken`/aws-lc-rs has no ES512, so ES512 is
    // verified on a SEPARATE pure-Rust (`p521`) path; the two backends never share key material. The
    // `typ` check is applied here IDENTICALLY to the primary path (via `enforce_typ`). With the
    // `es512` feature OFF this branch does not exist, so `map_algorithm` below rejects ES512 (the
    // KNOWN NARROWING is preserved).
    #[cfg(feature = "es512")]
    if header.alg == "ES512" {
        enforce_typ(&header, expected_typ)?;
        return verify_es512_over_candidates(token, candidate_keys);
    }

    // An RS256/ES256/… token must NEVER reach the p521 path (guarded by the `== "ES512"` check above),
    // and an ES512 token must NEVER reach `jsonwebtoken` (rejected by the explicit arm in
    // `map_algorithm`). The two crypto backends are isolated by alg.
    let alg = map_algorithm(&header.alg)?;

    enforce_typ(&header, expected_typ)?;

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

/// P-521 coordinate length in bytes (⌈521/8⌉ = 66). Both `x` and `y` MUST be exactly this many bytes,
/// and the fixed-width JWS signature is `r || s` = 2×66 = 132 bytes.
#[cfg(feature = "es512")]
const P521_COORD_LEN: usize = 66;

/// Build a `p521::ecdsa::VerifyingKey` from an EC/P-521 public JWK, failing CLOSED on ANY
/// decode/length/curve error. The guards mirror [`decoding_key_from_jwk`] exactly (reject symmetric +
/// private material FIRST), then REQUIRE `kty == "EC"` AND `crv == Some("P-521")` so a P-256/P-384 key
/// can NEVER be accepted for ES512 (curve-confusion guard), then build the key from the SEC1
/// uncompressed point `0x04 || x || y` with each coordinate validated to be exactly 66 bytes.
#[cfg(feature = "es512")]
fn p521_verifying_key_from_jwk(jwk: &Jwk) -> Result<p521::ecdsa::VerifyingKey, VerifyError> {
    // (1) Identical guards to `decoding_key_from_jwk`: never verify with a symmetric or private key.
    if jwk.is_symmetric() {
        return Err(invalid_token("Symmetric keys are not accepted."));
    }
    if jwk.has_private_material() {
        return Err(invalid_token(
            "Key contains private material; only a public key is accepted.",
        ));
    }
    // (2) Require EC / P-521 — NEVER accept a P-256/P-384 (or any other) key for ES512.
    if !jwk.kty.eq_ignore_ascii_case("EC") {
        return Err(invalid_token("ES512 requires an EC key."));
    }
    match jwk.crv.as_deref() {
        Some("P-521") => {}
        _ => return Err(invalid_token("ES512 requires an EC key on curve P-521.")),
    }
    // (3) base64url-decode x and y (URL_SAFE_NO_PAD).
    let x = jwk
        .x
        .as_deref()
        .ok_or_else(|| invalid_token("EC JWK missing x."))?;
    let y = jwk
        .y
        .as_deref()
        .ok_or_else(|| invalid_token("EC JWK missing y."))?;
    let x = b64url_decode(x).ok_or_else(|| invalid_token("EC JWK x is not valid base64url."))?;
    let y = b64url_decode(y).ok_or_else(|| invalid_token("EC JWK y is not valid base64url."))?;
    // (4) Each coordinate MUST be exactly 66 bytes (the P-521 field size). A short/long coordinate is
    //     rejected, never zero-padded — an off-length coordinate is not a valid P-521 point.
    if x.len() != P521_COORD_LEN || y.len() != P521_COORD_LEN {
        return Err(invalid_token(
            "ES512 EC coordinate is not the expected 66-byte P-521 length.",
        ));
    }
    // (5) SEC1 uncompressed point: 0x04 || x || y. `from_sec1_bytes` validates the point is on-curve
    //     (and not the identity), so a crafted off-curve point fails closed here.
    let mut sec1 = Vec::with_capacity(1 + 2 * P521_COORD_LEN);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    p521::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
        .map_err(|_| invalid_token("Invalid P-521 public key."))
}

/// Verify an ES512 (ECDSA P-521 / SHA-512) compact JWS against candidate EC/P-521 JWKS keys.
///
/// The signing input is the ASCII `header.payload` (the first two compact segments). The JWS
/// signature is the fixed-width `r || s` (132 bytes for P-521) — P1363, NOT DER — so it is parsed with
/// `Signature::from_slice`. Verification uses the `ecdsa` `Verifier` trait, whose P-521 impl digests
/// the message with SHA-512 (exactly ES512). The first candidate key that verifies wins; if none do,
/// fail closed with `invalid_token`. Fails closed on ANY decode/length/format error — never panics.
#[cfg(feature = "es512")]
fn verify_es512_over_candidates(
    token: &str,
    candidate_keys: &[Jwk],
) -> Result<Claims, VerifyError> {
    use p521::ecdsa::signature::Verifier as _;

    if candidate_keys.is_empty() {
        return Err(invalid_token("No verification key available for issuer."));
    }

    let (h, p, s) = split_compact(token)?;
    // The signing input is the EXACT ASCII bytes `header.payload` (NOT re-encoded JSON).
    let signing_input = format!("{h}.{p}");
    let sig_bytes =
        b64url_decode(s).ok_or_else(|| invalid_token("ES512 signature is not valid base64url."))?;
    // Fixed-width r||s = 2 × 66 = 132 bytes. A wrong-length signature is rejected, not coerced.
    if sig_bytes.len() != 2 * P521_COORD_LEN {
        return Err(invalid_token(
            "ES512 signature is not the expected 132-byte (r||s) length.",
        ));
    }
    let signature = p521::ecdsa::Signature::from_slice(&sig_bytes)
        .map_err(|_| invalid_token("ES512 signature is malformed."))?;

    // Decode the verified claims ONLY after a key verifies (matching the jsonwebtoken path: signature
    // first, then the claims object). We parse the payload up-front but return it only on success.
    let claims_value: Value =
        peek_claims(token).ok_or_else(|| invalid_token("Malformed token payload."))?;
    let claims_map = match claims_value {
        Value::Object(m) => m,
        _ => return Err(invalid_token("Malformed token payload.")),
    };

    let mut last_err: Option<VerifyError> = None;
    for jwk in candidate_keys {
        let key = match p521_verifying_key_from_jwk(jwk) {
            Ok(k) => k,
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        };
        match key.verify(signing_input.as_bytes(), &signature) {
            Ok(()) => return Ok(claims_map),
            Err(_) => {
                last_err = Some(invalid_token("signature verification failed"));
            }
        }
    }
    Err(last_err.unwrap_or_else(|| invalid_token("signature verification failed")))
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
