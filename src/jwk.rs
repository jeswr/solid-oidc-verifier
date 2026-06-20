// AUTHORED-BY Claude Opus 4.8
//! JWK model, the asymmetric-only algorithm allowlist, and RFC 7638 thumbprints.
//!
//! Ports the TS `SIGNING_ALGS` allowlist (`src/auth/verifier.ts`) and the
//! `jose.calculateJwkThumbprint` + `jose.EmbeddedJWK` semantics — but with the **ES512 KNOWN
//! NARROWING** made explicit: a JWK whose algorithm `jsonwebtoken` cannot verify is rejected, never
//! silently accepted.

use base64::Engine as _;
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// The asymmetric signature algorithms PSS's TS verifier accepts (`SIGNING_ALGS`). Symmetric (`HS*`)
/// and `none` are excluded: an access token is signed by the IdP's private key and a DPoP proof by
/// the holder's private key, so only asymmetric algs are meaningful (and `HS*`/`none` would let
/// either be forged from a public value). RFC 9449 §4.2 + RFC 9068.
///
/// This is the *policy* allowlist — the full set PSS advertises. [`alg_is_verifiable`] separately
/// reports whether THIS crate's primitive can actually verify a given alg (the ES512 gap).
pub const SIGNING_ALGS: &[&str] = &[
    "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "RS256", "RS384", "RS512", "EdDSA",
];

/// The algs advertised in the `WWW-Authenticate` `algs=` parameter (RFC 9449 §5.1). Same set.
pub const DPOP_ALGS: &[&str] = SIGNING_ALGS;

/// # KNOWN NARROWING — ES512 (feature `es512` OFF)
///
/// `jsonwebtoken` (the primary JWS primitive, on the `aws_lc_rs` backend) does NOT implement
/// **ES512** (P-521 / SHA-512). PSS's `SIGNING_ALGS` *policy* allowlist includes ES512, so a strict
/// port would have to verify it. With the `es512` feature OFF, rather than silently accept an ES512
/// token we cannot actually verify (which would be an auth bypass), this crate **rejects** any ES512
/// token/proof with a clear error.
///
/// This narrowing is **lifted** when the default-off `es512` feature is enabled: that adds a
/// pure-Rust RustCrypto (`p521`) ECDSA/SHA-512 verification path so ES512 is genuinely verified, not
/// rejected. See [`alg_is_verifiable`] and `jwt::verify_es512_over_candidates`.
///
/// This is a documented, maintainer-gated narrowing (spike open-decision #4 / risk R6). Keycloak's
/// default is RS256, so real-world impact is low. Until the feature is enabled: **never accept an alg
/// we cannot verify.**
///
/// NB: kept compiled in BOTH feature configurations (the message is still the rejection text used by
/// `map_algorithm` for any caller that reaches it with ES512 while the feature is off, and the
/// feature-OFF narrowing tests assert on it).
pub const ES512_KNOWN_NARROWING: &str =
    "ES512 is in the policy allowlist but unverifiable without the `es512` feature; rejected (see KNOWN NARROWING).";

/// Whether `alg` is BOTH in the policy allowlist AND actually verifiable by this crate's primitives.
///
/// Without the `es512` feature, ES512 fails this (policy yes, verifiable no) — the KNOWN NARROWING.
/// With the `es512` feature enabled, the pure-Rust `p521` path makes ES512 verifiable, so it is
/// included here (and the narrowing is lifted).
pub fn alg_is_verifiable(alg: &str) -> bool {
    if matches!(
        alg,
        "ES256" | "ES384" | "PS256" | "PS384" | "PS512" | "RS256" | "RS384" | "RS512" | "EdDSA"
    ) {
        return true;
    }
    #[cfg(feature = "es512")]
    if alg == "ES512" {
        // The `es512` feature adds a RustCrypto P-521 verification path — ES512 is now verifiable.
        return true;
    }
    false
}

/// Whether `alg` is in the asymmetric-only policy allowlist (incl. the not-yet-verifiable ES512).
pub fn alg_in_policy(alg: &str) -> bool {
    SIGNING_ALGS.contains(&alg)
}

/// A JSON Web Key, deserialised from the embedded `jwk` proof header or a JWKS entry. We model the
/// fields RFC 7638 canonicalises a thumbprint over for the three key types Solid uses (EC, RSA, OKP),
/// plus the membership fields used to detect a (forbidden) private key.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Jwk {
    /// Key type: `EC`, `RSA`, `OKP`, (or `oct` — symmetric, which we always reject).
    pub kty: String,
    // EC
    pub crv: Option<String>,
    pub x: Option<String>,
    pub y: Option<String>,
    // RSA
    pub n: Option<String>,
    pub e: Option<String>,
    // Private-component markers (their PRESENCE means a private key was embedded — forbidden).
    pub d: Option<String>,
    pub p: Option<String>,
    pub q: Option<String>,
    pub dp: Option<String>,
    pub dq: Option<String>,
    pub qi: Option<String>,
    // Hints (advisory; we do not trust them for the security decision).
    pub alg: Option<String>,
    #[serde(rename = "use")]
    pub use_: Option<String>,
    pub kid: Option<String>,
}

impl Jwk {
    /// Whether this JWK carries any private-key component. `EmbeddedJWK` (and this crate) MUST refuse
    /// a private key in a DPoP proof header — it is the public verification key that belongs there.
    /// Mirrors the TS test "rejects a proof embedding a private key".
    pub fn has_private_material(&self) -> bool {
        // For EC/OKP the private scalar is `d`; for RSA it is `d`/`p`/`q`/`dp`/`dq`/`qi`.
        self.d.is_some()
            || self.p.is_some()
            || self.q.is_some()
            || self.dp.is_some()
            || self.dq.is_some()
            || self.qi.is_some()
    }

    /// Whether this is a symmetric (`oct`) key — never allowed for a Solid access token or DPoP proof.
    pub fn is_symmetric(&self) -> bool {
        self.kty.eq_ignore_ascii_case("oct")
    }

    /// RFC 7638 JWK SHA-256 thumbprint (base64url, no padding) — the value compared against the access
    /// token's `cnf.jkt`. The canonical JSON uses only the *required* members for the key type, in
    /// lexicographic order, with no whitespace. Mirrors `jose.calculateJwkThumbprint(jwk, "sha256")`.
    pub fn thumbprint_sha256(&self) -> Result<String, JwkError> {
        let canonical = match self.kty.as_str() {
            // EC: {"crv","kty","x","y"}
            "EC" => {
                let crv = self.crv.as_deref().ok_or(JwkError::MissingMember("crv"))?;
                let x = self.x.as_deref().ok_or(JwkError::MissingMember("x"))?;
                let y = self.y.as_deref().ok_or(JwkError::MissingMember("y"))?;
                format!(
                    r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#,
                    json_escape(crv),
                    json_escape(x),
                    json_escape(y),
                )
            }
            // RSA: {"e","kty","n"}
            "RSA" => {
                let e = self.e.as_deref().ok_or(JwkError::MissingMember("e"))?;
                let n = self.n.as_deref().ok_or(JwkError::MissingMember("n"))?;
                format!(
                    r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#,
                    json_escape(e),
                    json_escape(n),
                )
            }
            // OKP (Ed25519 etc.): {"crv","kty","x"}
            "OKP" => {
                let crv = self.crv.as_deref().ok_or(JwkError::MissingMember("crv"))?;
                let x = self.x.as_deref().ok_or(JwkError::MissingMember("x"))?;
                format!(
                    r#"{{"crv":"{}","kty":"OKP","x":"{}"}}"#,
                    json_escape(crv),
                    json_escape(x),
                )
            }
            other => return Err(JwkError::UnsupportedKty(other.to_string())),
        };
        let digest = Sha256::digest(canonical.as_bytes());
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest))
    }
}

/// Minimal JSON string escaping for the canonical thumbprint members. JWK member values are base64url
/// (EC/RSA/OKP coordinates) so they contain no characters needing escaping in practice, but we escape
/// the two structurally-significant characters defensively so a crafted member can never break the
/// canonical JSON.
fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum JwkError {
    #[error("JWK is missing the required member '{0}'")]
    MissingMember(&'static str),
    #[error("unsupported JWK key type '{0}'")]
    UnsupportedKty(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic EC thumbprint over a FIXED key — locks the RFC 7638 canonicalisation (member
    /// order `crv,kty,x,y`, no whitespace, SHA-256, base64url-no-pad) byte-for-byte. The value is
    /// computed by hand from the canonical JSON `{"crv":"P-256","kty":"EC","x":"<x>","y":"<y>"}` so a
    /// regression in member ordering/escaping/encoding is caught. (The proof↔cnf.jkt round-trip
    /// property — that this thumbprint equals what a real DPoP client embeds — is additionally proven
    /// by every end-to-end test in `tests/verifier.rs`.)
    #[test]
    fn ec_thumbprint_is_deterministic_and_canonical() {
        let x = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
        let y = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";
        let jwk = Jwk {
            kty: "EC".to_string(),
            crv: Some("P-256".to_string()),
            x: Some(x.to_string()),
            y: Some(y.to_string()),
            n: None,
            e: None,
            d: None,
            p: None,
            q: None,
            dp: None,
            dq: None,
            qi: None,
            alg: None,
            use_: None,
            kid: None,
        };
        // Expected value computed by a SEPARATE implementation (Python hashlib over the canonical
        // JSON), so this is a genuine cross-implementation check, not a self-consistency tautology.
        let tp = jwk.thumbprint_sha256().unwrap();
        assert_eq!(tp, "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U");
        // Shape invariants: 32-byte SHA-256 → 43 base64url chars, no padding, url-safe alphabet.
        assert_eq!(tp.len(), 43);
        assert!(!tp.contains('=') && !tp.contains('+') && !tp.contains('/'));
    }

    #[test]
    fn rsa_thumbprint_member_order_is_e_kty_n() {
        // RSA canonical members are {"e","kty","n"} in that order. A wrong order would produce a
        // different digest; recompute independently to lock it.
        let jwk = Jwk {
            kty: "RSA".to_string(),
            crv: None,
            x: None,
            y: None,
            n: Some("sXchDaQebHnPiGvyDOAT4saGEUetSyo9MQ".to_string()),
            e: Some("AQAB".to_string()),
            d: None,
            p: None,
            q: None,
            dp: None,
            dq: None,
            qi: None,
            alg: None,
            use_: None,
            kid: None,
        };
        // Expected value computed by a SEPARATE implementation (Python hashlib).
        assert_eq!(
            jwk.thumbprint_sha256().unwrap(),
            "u5M0uP6MwqOg43H8mtl1n4W7rImZo9M6UeGM24Dqt-E"
        );
    }

    #[test]
    fn private_material_detected() {
        let jwk = Jwk {
            kty: "EC".into(),
            crv: Some("P-256".into()),
            x: Some("a".into()),
            y: Some("b".into()),
            n: None,
            e: None,
            d: Some("private".into()),
            p: None,
            q: None,
            dp: None,
            dq: None,
            qi: None,
            alg: None,
            use_: None,
            kid: None,
        };
        assert!(jwk.has_private_material());
    }

    /// Feature OFF: ES512 is in the policy allowlist but NOT verifiable — the KNOWN NARROWING.
    #[cfg(not(feature = "es512"))]
    #[test]
    fn es512_is_policy_but_not_verifiable() {
        assert!(alg_in_policy("ES512"));
        assert!(!alg_is_verifiable("ES512"));
    }

    /// Feature ON: ES512 is in the policy allowlist AND verifiable (the narrowing is lifted).
    #[cfg(feature = "es512")]
    #[test]
    fn es512_is_policy_and_verifiable_with_feature() {
        assert!(alg_in_policy("ES512"));
        assert!(alg_is_verifiable("ES512"));
    }

    #[test]
    fn hs256_and_none_are_not_in_policy() {
        assert!(!alg_in_policy("HS256"));
        assert!(!alg_in_policy("none"));
        assert!(!alg_is_verifiable("HS256"));
        assert!(!alg_is_verifiable("none"));
    }

    #[test]
    fn symmetric_jwk_flagged() {
        let jwk = Jwk {
            kty: "oct".into(),
            crv: None,
            x: None,
            y: None,
            n: None,
            e: None,
            d: None,
            p: None,
            q: None,
            dp: None,
            dq: None,
            qi: None,
            alg: None,
            use_: None,
            kid: None,
        };
        assert!(jwk.is_symmetric());
    }
}
