// AUTHORED-BY Claude Opus 4.8
//! The central DPoP-bound Solid-OIDC resource-server token verifier.
//!
//! A faithful port of `src/auth/verifier.ts`'s orchestration onto vetted Rust primitives. Because
//! there is no Rust equivalent of `oauth4webapi.validateJwtAccessToken`, the orchestration is owned
//! here (spike risk R1): the access-token RFC-9068 validation + the RFC-9449 DPoP-proof validation are
//! each performed explicitly with the same rigor as the TS strict and `ath`-compat paths.
//!
//! Order of checks (cheapest-first, matching TS `authenticate`):
//!   1. parse Authorization → scheme/token (absent ⇒ public credentials).
//!   2. scheme vs DPoP policy (Bearer rejected when `require_dpop`).
//!   3. trusted-issuer allowlist (from the *unverified* iss, before key resolution).
//!   4. access-token validation (signature, alg, typ, RFC-9068 claims, iss, aud, temporal, cnf).
//!   5. DPoP-proof validation (typ, alg, embedded public JWK, signature, htm, htu, iat, jti, ath?,
//!      cnf.jkt == jkt(proof)).
//!   6. webid extraction (https URL) + authorized-party allowlist.
//!   7. jti replay (fail-closed) — cheap, before the expensive bidirectional fetch.
//!   8. bidirectional WebID↔issuer check (strict 401 / warn / off).

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::config::{JwksProvider, VerifierConfig, DPOP_PROOF_MAX_AGE_SECS};
use crate::error::{invalid_request, invalid_token, invalid_token_dpop, ErrorKind, VerifyError};
use crate::jwt::{
    map_algorithm, peek_claims, peek_header, peek_issuer, proof_has_ath,
    verify_proof_with_embedded_jwk, verify_signature, Claims,
};
use crate::replay::{MarkResult, ReplayStore};
use crate::webid::{
    canonicalise_profile_url, validate_webid_claim, BidirectionalMode, WebIdProfileError,
};

/// The per-request inputs (TS `AuthRequest`). The host's HTTP layer assembles this; the verifier is
/// transport-agnostic. `url` is the exact reconstructed request URL (proxy-aware, query stripped) the
/// client signed into the proof's `htu`.
#[derive(Debug, Clone)]
pub struct AuthRequest {
    pub authorization: Option<String>,
    pub dpop: Option<String>,
    /// Upper-case HTTP method (checked against the proof's `htm`).
    pub method: String,
    /// The reconstructed request URL (scheme/host/port/path; query+fragment stripped).
    pub url: String,
}

/// The verified caller identity (TS `Credentials`). Public (unauthenticated) when `web_id` is `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerifiedToken {
    /// The agent's WebID (an `https:` URL). `None` ⇒ a public/unauthenticated request.
    pub web_id: Option<String>,
    /// The token issuer (always present for an authenticated request).
    pub issuer: Option<String>,
    /// The `client_id` claim, if present.
    pub client_id: Option<String>,
    /// The granted `scope` (space-delimited), if present.
    pub scopes: Vec<String>,
    /// The `cnf.jkt` thumbprint the token is bound to, if DPoP-bound.
    pub cnf_jkt: Option<String>,
    /// The `exp` (epoch seconds), if present.
    pub expiry: Option<i64>,
}

impl VerifiedToken {
    /// The public/unauthenticated credentials (TS `PUBLIC_CREDENTIALS`).
    pub fn public() -> Self {
        Self::default()
    }

    pub fn is_public(&self) -> bool {
        self.web_id.is_none()
    }
}

/// The verifier. Holds the config, the JWKS provider, and the replay store.
pub struct Verifier<J: JwksProvider, R: ReplayStore> {
    config: VerifierConfig,
    jwks: J,
    replay: R,
}

impl<J: JwksProvider, R: ReplayStore> Verifier<J, R> {
    /// Construct a verifier. Validates the config (≥1 issuer, non-empty audience).
    pub fn new(
        config: VerifierConfig,
        jwks: J,
        replay: R,
    ) -> Result<Self, crate::config::ConfigError> {
        config.validate()?;
        Ok(Self {
            config,
            jwks,
            replay,
        })
    }

    /// Authenticate a request. Returns [`VerifiedToken::public`] when no `Authorization` is present,
    /// agent credentials when a valid token is presented, or a [`VerifyError`] (→ 401/503 +
    /// `WWW-Authenticate`) on any failure. This is the entry point — the port of TS `authenticate`.
    pub fn verify(&self, req: &AuthRequest) -> Result<VerifiedToken, VerifyError> {
        let parsed = match parse_authorization(req.authorization.as_deref()) {
            Some(p) => p,
            None => return Ok(VerifiedToken::public()),
        };

        // (2) scheme vs DPoP policy.
        match parsed.scheme.as_str() {
            "bearer" => {
                if self.config.require_dpop {
                    return Err(invalid_request(
                        "DPoP-bound token required; Bearer not accepted.",
                    ));
                }
            }
            "dpop" => {}
            other => {
                return Err(invalid_request(format!(
                    "Unsupported Authorization scheme: {other}."
                )));
            }
        }

        // (3) trusted-issuer allowlist from the unverified iss (before key resolution).
        let claimed_issuer = peek_issuer(&parsed.token)?;
        if !self
            .config
            .trusted_issuers
            .iter()
            .any(|i| i == &claimed_issuer)
        {
            return Err(invalid_token("Token issuer is not trusted."));
        }

        // A request presenting `DPoP <token>` MUST be validated as DPoP-bound even when
        // `require_dpop=false` (matching the TS Copilot-#5 fix).
        let dpop = parsed.scheme == "dpop" || self.config.require_dpop;

        // (4)+(5) access token + DPoP proof.
        let claims = self.validate_token(req, &parsed, &claimed_issuer, dpop)?;

        // (6) webid + authorized party.
        let web_id = self.extract_webid(&claims)?;
        self.check_authorized_party(&claims)?;

        // (7) jti replay (cheap, before the bidirectional fetch).
        if let Some(proof) = req.dpop.as_deref() {
            self.check_replay(proof)?;
        }

        // (8) bidirectional WebID↔issuer.
        let issuer = claims
            .get("iss")
            .and_then(Value::as_str)
            .unwrap_or(&claimed_issuer)
            .to_string();
        self.check_bidirectional(&web_id, &issuer)?;

        Ok(VerifiedToken {
            web_id: Some(web_id),
            issuer: Some(issuer),
            client_id: claims
                .get("client_id")
                .and_then(Value::as_str)
                .map(str::to_string),
            scopes: claims
                .get("scope")
                .and_then(Value::as_str)
                .map(|s| s.split_whitespace().map(str::to_string).collect())
                .unwrap_or_default(),
            cnf_jkt: extract_cnf_jkt(&claims),
            expiry: claims.get("exp").and_then(Value::as_i64),
        })
    }

    /// Validate the access token (RFC 9068) and, when a DPoP proof is in play, the proof (RFC 9449).
    /// Routes to the `ath`-compat path only when opted in AND the proof omits `ath` (TS routing). A
    /// present `ath` always takes the strict path so a present-but-wrong `ath` is rejected.
    fn validate_token(
        &self,
        req: &AuthRequest,
        parsed: &Parsed,
        claimed_issuer: &str,
        dpop: bool,
    ) -> Result<Claims, VerifyError> {
        let ath_compat = self.config.allow_missing_ath
            && dpop
            && req
                .dpop
                .as_deref()
                .map(|p| !proof_has_ath(p))
                .unwrap_or(false);

        // Access-token signature + RFC-9068 claims (same in both strict and compat — the difference is
        // only the proof's ath requirement).
        let claims = self.validate_access_token(parsed, claimed_issuer)?;

        if dpop {
            let proof = req.dpop.as_deref().ok_or_else(|| {
                invalid_token_dpop("DPoP proof is required (no DPoP HTTP Header).")
            })?;
            let cnf_jkt = extract_cnf_jkt(&claims).ok_or_else(|| {
                invalid_token_dpop(
                    "Access token is not DPoP-bound (no cnf.jkt confirmation claim).",
                )
            })?;
            // require_ath: strict unless we are on the opted-in compat path for an ath-less proof.
            let require_ath = !ath_compat;
            self.validate_dpop_proof(req, proof, &parsed.token, &cnf_jkt, require_ath)?;
        }

        Ok(claims)
    }

    /// Validate the access-token JWS + RFC-9068 claims. Replicates what
    /// `oauth4webapi.validateJwtAccessToken` enforces on the token: signature against the issuer's
    /// JWKS, an asymmetric `alg`, `typ=at+jwt`, the required string claims, the trusted `iss`, the
    /// expected `aud`, and temporal claims within tolerance.
    fn validate_access_token(
        &self,
        parsed: &Parsed,
        claimed_issuer: &str,
    ) -> Result<Claims, VerifyError> {
        // Reject an unverifiable alg (incl. the ES512 narrowing) up-front with a clear message.
        let header = peek_header(&parsed.token)?;
        map_algorithm(&header.alg)?;

        let keys = self
            .jwks
            .keys_for(claimed_issuer)
            .map_err(|e| invalid_token(format!("Access token verification failed: {e}")))?;

        let claims = verify_signature(&parsed.token, &keys, Some("at+jwt")).map_err(|e| {
            invalid_token(format!("Access token verification failed: {}", e.message()))
        })?;

        // RFC 9068 §2.2 required string claims.
        for claim in ["sub", "jti", "client_id"] {
            match claims.get(claim).and_then(Value::as_str) {
                Some(s) if !s.is_empty() => {}
                _ => {
                    return Err(invalid_token(format!(
                        "Access token is missing the '{claim}' claim."
                    )))
                }
            }
        }
        // iss must match the (trusted) claimed issuer — re-asserted post-signature.
        match claims.get("iss").and_then(Value::as_str) {
            Some(s) if s == claimed_issuer => {}
            _ => return Err(invalid_token("Access token issuer mismatch.")),
        }
        // aud must include the configured audience (RFC 9068 mandatory).
        if !audience_matches(&claims, &self.config.audience) {
            return Err(invalid_token(
                "Access token verification failed: audience mismatch.",
            ));
        }
        // temporal claims within tolerance.
        self.check_temporal(&claims)?;

        Ok(claims)
    }

    /// Validate the DPoP proof (RFC 9449): self-signed by the embedded public JWK, asymmetric alg,
    /// `typ=dpop+jwt`, `htm`==method, `htu`==URL (normalised), `iat` fresh, `jti` present, optional
    /// `ath` binding, and `cnf.jkt`==jkt(proof JWK). Mirrors `oauth4webapi.validateDPoP` (+ the TS
    /// `validateDpopProofWithoutAth` for the compat path).
    fn validate_dpop_proof(
        &self,
        req: &AuthRequest,
        proof: &str,
        access_token: &str,
        cnf_jkt: &str,
        require_ath: bool,
    ) -> Result<(), VerifyError> {
        let (claims, jwk) = verify_proof_with_embedded_jwk(proof, "dpop+jwt").map_err(|e| {
            invalid_token_dpop(format!("DPoP proof verification failed: {}", e.message()))
        })?;

        // htm — must equal the request method (case-insensitive; RFC 9449).
        let htm = claims.get("htm").and_then(Value::as_str).unwrap_or("");
        if !htm.eq_ignore_ascii_case(&req.method) {
            return Err(invalid_token_dpop("DPoP proof htm mismatch."));
        }
        // htu — must equal the reconstructed request URL (query/fragment stripped, ports normalised).
        let htu = claims.get("htu").and_then(Value::as_str);
        match htu {
            Some(h) if normalize_htu(h) == normalize_htu(&req.url) => {}
            _ => return Err(invalid_token_dpop("DPoP proof htu mismatch.")),
        }
        // jti — must be present (the replay cache consumes it after this returns).
        match claims.get("jti").and_then(Value::as_str) {
            Some(s) if !s.is_empty() => {}
            _ => return Err(invalid_token_dpop("DPoP proof is missing a jti.")),
        }
        // iat — freshness window matching `|now - iat| > 300` (+ tolerance either side).
        let iat = claims
            .get("iat")
            .and_then(Value::as_i64)
            .ok_or_else(|| invalid_token_dpop("DPoP proof is missing iat."))?;
        let now = now_secs();
        let window = (DPOP_PROOF_MAX_AGE_SECS + self.config.clock_tolerance_secs) as i64;
        if (now - iat).abs() > window {
            return Err(invalid_token_dpop("DPoP proof iat is not recent enough."));
        }
        // ath — when required, must be base64url(SHA-256(access_token)).
        let proof_ath = claims.get("ath").and_then(Value::as_str);
        if require_ath {
            let expected = ath(access_token);
            match proof_ath {
                Some(a) if a == expected => {}
                Some(_) => return Err(invalid_token_dpop("DPoP proof ath mismatch.")),
                None => return Err(invalid_token_dpop("DPoP proof is missing ath.")),
            }
        } else if let Some(a) = proof_ath {
            // Compat path is only reached for an ath-LESS proof; a present ath here is defensive.
            // A present-but-wrong ath must still fail (only ABSENCE is tolerated).
            if a != ath(access_token) {
                return Err(invalid_token_dpop("DPoP proof ath mismatch."));
            }
        }
        // cnf.jkt == thumbprint(proof JWK) — the proof-of-possession binding (TS calculateJwkThumbprint).
        let proof_jkt = jwk
            .thumbprint_sha256()
            .map_err(|e| invalid_token_dpop(format!("DPoP proof key is invalid: {e}.")))?;
        if proof_jkt != cnf_jkt {
            return Err(invalid_token_dpop(
                "JWT Access Token confirmation mismatch (cnf.jkt != proof jwk thumbprint).",
            ));
        }
        Ok(())
    }

    /// Temporal validation for the access token (exp/nbf/iat within tolerance). RFC 9068 / the
    /// library's clock-tolerance semantics.
    fn check_temporal(&self, claims: &Claims) -> Result<(), VerifyError> {
        let now = now_secs();
        let tol = self.config.clock_tolerance_secs as i64;
        if let Some(exp) = claims.get("exp").and_then(Value::as_i64) {
            if now - tol > exp {
                return Err(invalid_token(
                    "Access token verification failed: token expired.",
                ));
            }
        } else {
            // RFC 9068 requires exp.
            return Err(invalid_token(
                "Access token verification failed: missing exp.",
            ));
        }
        if let Some(nbf) = claims.get("nbf").and_then(Value::as_i64) {
            if now + tol < nbf {
                return Err(invalid_token(
                    "Access token verification failed: token not yet valid.",
                ));
            }
        }
        if let Some(iat) = claims.get("iat").and_then(Value::as_i64) {
            // A token issued in the (far) future is rejected.
            if iat - tol > now {
                return Err(invalid_token(
                    "Access token verification failed: iat in the future.",
                ));
            }
        }
        Ok(())
    }

    /// Extract the WebID (configurable claim): present, an `https:` URL, no userinfo (TS `extractWebId`).
    fn extract_webid(&self, claims: &Claims) -> Result<String, VerifyError> {
        let raw = claims.get(&self.config.webid_claim).and_then(Value::as_str);
        match raw {
            // `validate_webid_claim` already returns the specific shape error (non-https / non-URL /
            // userinfo); a missing/empty claim falls to the arm below.
            Some(s) if !s.is_empty() => validate_webid_claim(s),
            _ => Err(invalid_token(format!(
                "Token is missing the '{}' claim.",
                self.config.webid_claim
            ))),
        }
    }

    /// Enforce the authorized-party allowlist (ADR-0004 #2): checks `azp`, falling back to `client_id`.
    fn check_authorized_party(&self, claims: &Claims) -> Result<(), VerifyError> {
        if self.config.authorized_parties.is_empty() {
            return Ok(());
        }
        let azp = claims
            .get("azp")
            .and_then(Value::as_str)
            .or_else(|| claims.get("client_id").and_then(Value::as_str));
        match azp {
            Some(a) if self.config.authorized_parties.iter().any(|p| p == a) => Ok(()),
            _ => Err(invalid_token("Token authorized party is not accepted.")),
        }
    }

    /// Consume the DPoP proof's `jti` against the replay store (fail-closed). A repeated `jti` within
    /// its window is a replay. A backend error → 503 (production) per the fail-closed policy.
    fn check_replay(&self, proof: &str) -> Result<(), VerifyError> {
        let jti = peek_claims(proof)
            .and_then(|c| c.get("jti").and_then(Value::as_str).map(str::to_string))
            .filter(|s| !s.is_empty())
            .ok_or_else(|| invalid_token_dpop("DPoP proof is missing a jti."))?;
        let ttl = self.config.replay_ttl();
        match self.replay.mark(&jti, ttl) {
            Ok(MarkResult::New) => Ok(()),
            Ok(MarkResult::Replay) => Err(invalid_token_dpop(
                "DPoP proof has already been used (replay).",
            )),
            Err(_e) => {
                if self.config.replay_fail_closed {
                    Err(VerifyError::new(
                        ErrorKind::ReplayStoreUnavailable,
                        "Replay protection backend is unavailable.",
                    )
                    .with_dpop(true))
                } else {
                    // Dev fail-open: accept (the config validator forbids this in production). M1 has
                    // no separate in-memory fallback wired here; treat as fresh.
                    Ok(())
                }
            }
        }
    }

    /// Bidirectional WebID↔issuer check (ADR-0004 #3). Strict → 401 (constant client message) on any
    /// mismatch/fetch-failure; warn → accept; off / no resolver → no-op.
    fn check_bidirectional(&self, web_id: &str, issuer: &str) -> Result<(), VerifyError> {
        if self.config.bidirectional_mode == BidirectionalMode::Off {
            return Ok(());
        }
        let resolver = match &self.config.webid_resolver {
            Some(r) => r,
            None => return Ok(()),
        };
        let listed: bool = match resolver.resolve(&canonicalise_profile_url(web_id)) {
            Ok(profile) => profile.issuers.contains(issuer),
            Err(WebIdProfileError(_)) => false,
        };
        if listed {
            return Ok(());
        }
        if self.config.bidirectional_mode == BidirectionalMode::Strict {
            // Constant client-facing description — no SSRF/network/issuer detail (the
            // reconnaissance-oracle guard, TS BIDIRECTIONAL_REJECTION_MESSAGE).
            return Err(invalid_token("WebID issuer check failed."));
        }
        // warn: accept.
        Ok(())
    }

    /// Build the `WWW-Authenticate` header for an error, naming the trusted issuer(s).
    pub fn www_authenticate(&self, err: &VerifyError) -> String {
        err.www_authenticate(
            &self.config.trusted_issuers,
            crate::jwk::DPOP_ALGS,
            self.config.require_dpop,
        )
    }
}

/// A parsed `Authorization` header.
struct Parsed {
    scheme: String,
    token: String,
}

/// Parse an `Authorization` header into a lower-cased scheme + token (TS `parseAuthorization`).
fn parse_authorization(header: Option<&str>) -> Option<Parsed> {
    let header = header?;
    let trimmed = header.trim();
    let sp = trimmed.find(' ')?;
    let scheme = trimmed[..sp].to_lowercase();
    let token = trimmed[sp + 1..].trim().to_string();
    if token.is_empty() {
        return None;
    }
    Some(Parsed { scheme, token })
}

/// base64url(SHA-256(token)) — the DPoP `ath` value (TS `ath` helper).
fn ath(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

/// Extract a non-empty string `cnf.jkt` from claims (TS `extractCnfJkt`).
fn extract_cnf_jkt(claims: &Claims) -> Option<String> {
    claims
        .get("cnf")
        .and_then(Value::as_object)
        .and_then(|cnf| cnf.get("jkt"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Whether the configured audience is present in the token's `aud` (a string or an array). RFC 9068.
fn audience_matches(claims: &Claims, audience: &str) -> bool {
    match claims.get("aud") {
        Some(Value::String(s)) => s == audience,
        Some(Value::Array(arr)) => arr.iter().any(|v| v.as_str() == Some(audience)),
        _ => false,
    }
}

/// Normalise an `htu` for comparison the way `oauth4webapi.validateDPoP` does: strip query+fragment
/// and compare the resulting absolute URL (also normalising default ports via the URL parser).
/// Returns the raw input lower-cased only on a parse failure so two unparseable strings still compare.
fn normalize_htu(htu: &str) -> String {
    match url::Url::parse(htu) {
        Ok(mut u) => {
            u.set_query(None);
            u.set_fragment(None);
            u.to_string()
        }
        Err(_) => htu.to_string(),
    }
}

/// Current UNIX time in seconds.
fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_authorization_splits_scheme_token() {
        let p = parse_authorization(Some("DPoP abc.def.ghi")).unwrap();
        assert_eq!(p.scheme, "dpop");
        assert_eq!(p.token, "abc.def.ghi");
    }

    #[test]
    fn parse_authorization_none_for_empty_or_schemeless() {
        assert!(parse_authorization(None).is_none());
        assert!(parse_authorization(Some("Bearer")).is_none());
        assert!(parse_authorization(Some("Bearer ")).is_none());
    }

    #[test]
    fn normalize_htu_strips_query_and_default_port() {
        assert_eq!(
            normalize_htu("https://pod.example:443/alice/data?x=1#f"),
            normalize_htu("https://pod.example/alice/data"),
        );
    }

    #[test]
    fn ath_is_b64url_sha256() {
        // Deterministic for a known input.
        let a = ath("token");
        assert_eq!(a.len(), 43);
        assert!(!a.contains('='));
    }

    #[test]
    fn audience_matches_string_and_array() {
        let mut c = Claims::new();
        c.insert("aud".into(), Value::String("https://pod.example".into()));
        assert!(audience_matches(&c, "https://pod.example"));
        assert!(!audience_matches(&c, "https://other"));
        c.insert(
            "aud".into(),
            Value::Array(vec![Value::String("https://pod.example".into())]),
        );
        assert!(audience_matches(&c, "https://pod.example"));
    }

    #[test]
    fn extract_cnf_jkt_reads_nested() {
        let mut c = Claims::new();
        let mut cnf = serde_json::Map::new();
        cnf.insert("jkt".into(), Value::String("thumb".into()));
        c.insert("cnf".into(), Value::Object(cnf));
        assert_eq!(extract_cnf_jkt(&c), Some("thumb".to_string()));
    }
}
