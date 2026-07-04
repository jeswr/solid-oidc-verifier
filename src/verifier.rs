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
use crate::jwk::{alg_in_policy, alg_is_verifiable};
use crate::jwt::{
    peek_claims, peek_header, peek_issuer, proof_has_ath, verify_proof_with_embedded_jwk,
    verify_signature, Claims,
};
use crate::replay::{MarkResult, ReplayStore};
use crate::webid::{validate_webid_claim, BidirectionalMode, WebIdProfileError};

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

/// The RFC 8705 §3.1 `cnf.x5t#S256` mTLS certificate-thumbprint confirmation as read off a verified
/// token. THREE states — so a caller (e.g. a PoP-method dispatch) can tell an ABSENT binding from a
/// PRESENT-but-MALFORMED one. That distinction is load-bearing: a malformed binding must fail closed
/// (a cert-bound token whose thumbprint is unreadable is NOT the same as an unbound token), so it is
/// never collapsed to `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum X5tS256 {
    /// A well-formed value: the base64url-no-pad encoding of a 32-byte SHA-256 certificate hash.
    /// Carries the raw base64url string exactly as it appeared in the token (not re-encoded).
    Thumbprint(String),
    /// The `cnf.x5t#S256` claim is present but malformed — not a JSON string, empty, not base64url,
    /// or not exactly 32 decoded bytes. Downstream cert-bound dispatch MUST fail closed on this.
    Malformed,
}

/// The verified caller identity (TS `Credentials`). Public (unauthenticated) when `web_id` is `None`.
///
/// Produced by [`Verifier::verify`]; consumers read its fields (they do not construct it via a
/// struct literal). Surfacing a further verified claim — this adds `cnf_x5t_s256` beside `cnf_jkt` —
/// is an additive field, acceptable for this pre-1.0 (0.x) EXPERIMENTAL crate under SemVer.
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
    /// The `cnf.jkt` thumbprint the token is bound to, if DPoP-bound (RFC 9449).
    pub cnf_jkt: Option<String>,
    /// The `cnf.x5t#S256` mTLS certificate-thumbprint binding, if the token carries one (RFC 8705).
    /// INDEPENDENT of [`cnf_jkt`](Self::cnf_jkt): a token carrying BOTH is surfaced with both set —
    /// the verifier never drops or merges them; deciding a multi-binding token is refused is the
    /// downstream PoP dispatch's job, which needs both fields readable to make that call.
    pub cnf_x5t_s256: Option<X5tS256>,
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

    /// The raw base64url `cnf.x5t#S256` thumbprint string when the token carries a WELL-FORMED mTLS
    /// certificate binding, else `None`. Convenience over [`cnf_x5t_s256`](Self::cnf_x5t_s256): it
    /// deliberately collapses `Malformed` to `None`, so a caller that needs to distinguish
    /// absent-vs-malformed (to fail closed) MUST read the field, not this accessor.
    pub fn cnf_x5t_s256_thumbprint(&self) -> Option<&str> {
        match &self.cnf_x5t_s256 {
            Some(X5tS256::Thumbprint(t)) => Some(t.as_str()),
            _ => None,
        }
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
            cnf_x5t_s256: extract_cnf_x5t_s256(&claims),
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
        // Access-token signature + RFC-9068 claims (same in both strict and compat — the difference is
        // only the proof's ath requirement).
        let claims = self.validate_access_token(parsed, claimed_issuer)?;

        // (Finding #1, roborev High) A DPoP-BOUND token (carrying `cnf.jkt`) MUST have its proof
        // verified regardless of the presentation scheme or `require_dpop`. Otherwise a captured
        // bound token presented as `Bearer` (when `require_dpop=false`) would be accepted without
        // proof-of-possession — a token-replay downgrade. So `must_dpop` is true whenever the request
        // is DPoP-scheme / DPoP-required OR the token itself is cnf-bound. (The `oauth4webapi` library
        // the TS verifier delegates to enforces exactly this: it runs its DPoP step whenever the token
        // carries `cnf.jkt`.)
        let cnf_jkt = extract_cnf_jkt(&claims);
        let must_dpop = dpop || cnf_jkt.is_some();

        if must_dpop {
            let proof = req.dpop.as_deref().ok_or_else(|| {
                invalid_token_dpop("DPoP proof is required (no DPoP HTTP Header).")
            })?;
            let cnf_jkt = cnf_jkt.ok_or_else(|| {
                invalid_token_dpop(
                    "Access token is not DPoP-bound (no cnf.jkt confirmation claim).",
                )
            })?;
            // ath-compat path: opted in AND the presented proof omits `ath` (a present-but-wrong ath
            // still takes the strict path and is rejected).
            let ath_compat = self.config.allow_missing_ath && !proof_has_ath(proof);
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
        // Reject a non-policy or unverifiable alg up-front with a clear message. This uses the
        // feature-aware acceptability check (`alg_in_policy` + `alg_is_verifiable`) rather than
        // `map_algorithm` so that with the `es512` feature ON an ES512 access token is NOT wrongly
        // rejected here — its actual verification is delegated to `verify_signature`, which forks the
        // ES512 (p521) path. With the feature OFF, `alg_is_verifiable("ES512")` is false, so ES512 is
        // still rejected up-front (the KNOWN NARROWING).
        let header = peek_header(&parsed.token)?;
        if !alg_in_policy(&header.alg) {
            return Err(invalid_token(format!(
                "Unsupported or non-asymmetric signature algorithm: {}.",
                header.alg
            )));
        }
        if !alg_is_verifiable(&header.alg) {
            return Err(invalid_token(crate::jwk::ES512_KNOWN_NARROWING));
        }

        // (roborev Medium) A JWKS-resolution failure may carry SSRF/DNS/host detail (a private resolved
        // address, the discovery/jwks URL). That detail is for INTERNAL logging only — NEVER the
        // client-facing message. Map any `JwksError` to a CONSTANT public description so a verification
        // failure cannot become an SSRF reconnaissance oracle. (`_e` is dropped here; a host that wants
        // the detail logs it at the provider boundary.)
        let keys = self
            .jwks
            .keys_for(claimed_issuer)
            .map_err(|_e| invalid_token("Access token verification failed."))?;

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
        // iat — SYMMETRIC freshness window `|now - iat| <= max_age + tolerance` (tolerance either
        // side), on INTEGER seconds with an INCLUSIVE `<=` boundary. NB this one-sided half-width is
        // `max_age + tolerance`; a future-skewed proof at the edge stays acceptable for ~2× that, which
        // is exactly why `replay_ttl()` is `2 × (max_age + tolerance) + 1` — the doubled window plus a
        // +1s inclusive-integer-second-boundary margin (so the replay store never forgets a
        // still-replayable `jti`). The Solid CTH sends a future-skewed proof the symmetric window must
        // accept, so we keep the window symmetric and widen the TTL rather than tighten the future bound.
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
        // (Finding #5, roborev Medium) `iat` is REQUIRED (RFC 9068 §2.2 + the doc contract). A missing
        // or non-integer `iat` is `invalid_token`, not silently accepted.
        match claims.get("iat").and_then(Value::as_i64) {
            Some(iat) => {
                // A token issued in the (far) future is rejected.
                if iat - tol > now {
                    return Err(invalid_token(
                        "Access token verification failed: iat in the future.",
                    ));
                }
            }
            None => {
                return Err(invalid_token(
                    "Access token verification failed: missing iat.",
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
    /// mismatch/fetch-failure; warn → accept; off → no-op. Construction forbids strict/warn without a
    /// resolver, so a `None` resolver here can only mean `Off`.
    fn check_bidirectional(&self, web_id: &str, issuer: &str) -> Result<(), VerifyError> {
        if self.config.bidirectional_mode == BidirectionalMode::Off {
            return Ok(());
        }
        let resolver = match &self.config.webid_resolver {
            Some(r) => r,
            // (Finding #4) Strict/warn without a resolver is rejected at construction. Defensively,
            // if we somehow reach here in strict mode, FAIL CLOSED rather than skip the check.
            None => {
                return if self.config.bidirectional_mode == BidirectionalMode::Strict {
                    Err(invalid_token("WebID issuer check failed."))
                } else {
                    Ok(())
                };
            }
        };
        // Pass the FULL WebID (fragment intact). The resolver canonicalises to the profile-document URL
        // for the fetch but MUST scope the `solid:oidcIssuer` triples to the WebID subject — a profile
        // listing the issuer for a DIFFERENT subject must NOT satisfy the check for this WebID
        // (roborev High; mirrors TS `extractIssuers(quads, webId, profileUrl)`).
        let listed: bool = match resolver.resolve(web_id) {
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

/// Extract the RFC 8705 §3.1 `cnf.x5t#S256` mTLS certificate-thumbprint confirmation from claims.
///
/// - `None`                        — no `cnf` object, or a `cnf` without an `x5t#S256` member (ABSENT).
/// - `Some(X5tS256::Thumbprint(s))` — a well-formed value: base64url-no-pad of a 32-byte SHA-256 hash.
/// - `Some(X5tS256::Malformed)`     — the member is present but not a valid 32-byte base64url-no-pad
///   value (non-string, empty, bad alphabet/padding, or wrong length).
///
/// A present-but-malformed value is NEVER collapsed to `None`, so the caller can fail closed rather
/// than treat a broken cert binding as an unbound token. Reads `cnf.jkt` and `cnf.x5t#S256`
/// independently — a token carrying both is surfaced with both (no drop, no merge).
fn extract_cnf_x5t_s256(claims: &Claims) -> Option<X5tS256> {
    let raw = claims
        .get("cnf")
        .and_then(Value::as_object)
        .and_then(|cnf| cnf.get("x5t#S256"))?;
    // From here the member is PRESENT: every failure path yields `Malformed`, never `None`.
    match raw.as_str() {
        Some(s) if is_valid_x5t_s256(s) => Some(X5tS256::Thumbprint(s.to_string())),
        _ => Some(X5tS256::Malformed),
    }
}

/// Whether `s` is a well-formed RFC 8705 `x5t#S256`: the base64url (no padding) encoding of a 32-byte
/// SHA-256 certificate digest. Fail-closed on any decode error or wrong length; never panics.
fn is_valid_x5t_s256(s: &str) -> bool {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map(|bytes| bytes.len() == 32)
        .unwrap_or(false)
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

    // ---- RFC 8705 cnf.x5t#S256 -------------------------------------------------------------------

    /// A well-formed x5t#S256: base64url-no-pad of an arbitrary 32-byte (SHA-256-sized) digest.
    fn valid_x5t(seed: u8) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([seed; 32])
    }

    /// Build claims with an optional `cnf.jkt` and optional `cnf.x5t#S256` value (any JSON value).
    fn claims_with_cnf(jkt: Option<Value>, x5t: Option<Value>) -> Claims {
        let mut c = Claims::new();
        if jkt.is_some() || x5t.is_some() {
            let mut cnf = serde_json::Map::new();
            if let Some(v) = jkt {
                cnf.insert("jkt".into(), v);
            }
            if let Some(v) = x5t {
                cnf.insert("x5t#S256".into(), v);
            }
            c.insert("cnf".into(), Value::Object(cnf));
        }
        c
    }

    #[test]
    fn x5t_valid_thumbprint_is_read() {
        let t = valid_x5t(0xAB);
        let c = claims_with_cnf(None, Some(Value::String(t.clone())));
        assert_eq!(extract_cnf_x5t_s256(&c), Some(X5tS256::Thumbprint(t)));
    }

    #[test]
    fn x5t_absent_cnf_is_none() {
        // No `cnf` at all → None for both bindings (never Malformed).
        let c = Claims::new();
        assert_eq!(extract_cnf_x5t_s256(&c), None);
        assert_eq!(extract_cnf_jkt(&c), None);
    }

    #[test]
    fn x5t_cnf_without_member_is_none() {
        // A `cnf` carrying only jkt → x5t is ABSENT (None), not Malformed.
        let c = claims_with_cnf(Some(Value::String("thumb".into())), None);
        assert_eq!(extract_cnf_x5t_s256(&c), None);
    }

    #[test]
    fn x5t_wrong_length_is_malformed_not_none() {
        // Valid base64url but only 16 decoded bytes (not the 32-byte SHA-256 length) → Malformed,
        // and crucially DISTINGUISHABLE from absent.
        let short = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 16]);
        let c = claims_with_cnf(None, Some(Value::String(short)));
        assert_eq!(extract_cnf_x5t_s256(&c), Some(X5tS256::Malformed));
    }

    #[test]
    fn x5t_bad_alphabet_or_padding_is_malformed() {
        // Non-base64url characters and standard-base64 padding are both rejected as Malformed
        // (no panic on any input).
        for bad in ["not valid base64!!!", "###", "AAAA=", "", "   "] {
            let c = claims_with_cnf(None, Some(Value::String(bad.into())));
            assert_eq!(
                extract_cnf_x5t_s256(&c),
                Some(X5tS256::Malformed),
                "input {bad:?} should be Malformed"
            );
        }
    }

    #[test]
    fn x5t_non_string_value_is_malformed() {
        // A present-but-non-string member (number/object/array/bool/null) is Malformed, never None.
        let mut nested = serde_json::Map::new();
        nested.insert("x5t#S256".into(), Value::String(valid_x5t(1)));
        for v in [
            Value::Number(42.into()),
            Value::Bool(true),
            Value::Null,
            Value::Array(vec![Value::String(valid_x5t(2))]),
            Value::Object(nested),
        ] {
            let c = claims_with_cnf(None, Some(v));
            assert_eq!(extract_cnf_x5t_s256(&c), Some(X5tS256::Malformed));
        }
    }

    #[test]
    fn x5t_and_jkt_both_present_are_surfaced_independently() {
        // No-confusion invariant: a token carrying BOTH bindings exposes both — no drop, no merge.
        let t = valid_x5t(0x11);
        let c = claims_with_cnf(
            Some(Value::String("the-jkt".into())),
            Some(Value::String(t.clone())),
        );
        assert_eq!(extract_cnf_jkt(&c), Some("the-jkt".to_string()));
        assert_eq!(extract_cnf_x5t_s256(&c), Some(X5tS256::Thumbprint(t)));
    }

    #[test]
    fn x5t_thumbprint_accessor_collapses_malformed_to_none() {
        // The convenience accessor returns Some only for a well-formed thumbprint; Malformed → None.
        let t = valid_x5t(0x22);
        let ok = VerifiedToken {
            cnf_x5t_s256: Some(X5tS256::Thumbprint(t.clone())),
            ..Default::default()
        };
        assert_eq!(ok.cnf_x5t_s256_thumbprint(), Some(t.as_str()));

        let malformed = VerifiedToken {
            cnf_x5t_s256: Some(X5tS256::Malformed),
            ..Default::default()
        };
        assert_eq!(malformed.cnf_x5t_s256_thumbprint(), None);

        let absent = VerifiedToken::default();
        assert_eq!(absent.cnf_x5t_s256_thumbprint(), None);
    }
}
