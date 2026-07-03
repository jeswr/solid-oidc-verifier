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
    /// The RFC 8705 §3.1 certificate thumbprint of the client certificate presented on THIS
    /// connection, if any: `base64url(SHA-256(DER(cert)))`. The host computes this ONCE per TLS
    /// connection from its TLS layer and passes it in; **no TLS code enters the verifier** — it only
    /// compares this value against a certificate-bound token's `cnf["x5t#S256"]`. `None` ⇒ no client
    /// certificate was presented (a certificate-bound token is then rejected, fail-closed). Irrelevant
    /// for the DPoP (`cnf.jkt`) path — it is ignored there.
    pub client_cert_x5t_s256: Option<String>,
}

/// How an access token proves possession — its `cnf` (RFC 7800) confirmation method. A token carries
/// **at most one**: `cnf.jkt` (RFC 9449 DPoP key thumbprint) OR `cnf["x5t#S256"]` (RFC 8705 §3.1
/// mutual-TLS client-certificate thumbprint). A token asserting BOTH is rejected as ambiguous
/// (see [`extract_confirmation`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confirmation {
    /// RFC 9449 DPoP: the RFC 7638 thumbprint of the proof's public JWK. PoP is a fresh DPoP proof.
    Jkt(String),
    /// RFC 8705 §3.1 certificate-bound: `base64url(SHA-256(DER(client cert)))`. PoP is the mutual-TLS
    /// client certificate — verified by comparing against [`AuthRequest::client_cert_x5t_s256`].
    X5tS256(String),
}

impl Confirmation {
    /// The DPoP `cnf.jkt` thumbprint, if this is the DPoP confirmation method.
    pub fn as_jkt(&self) -> Option<&str> {
        match self {
            Confirmation::Jkt(j) => Some(j),
            Confirmation::X5tS256(_) => None,
        }
    }

    /// The certificate `cnf["x5t#S256"]` thumbprint, if this is the mTLS confirmation method.
    pub fn as_x5t_s256(&self) -> Option<&str> {
        match self {
            Confirmation::X5tS256(t) => Some(t),
            Confirmation::Jkt(_) => None,
        }
    }
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
    /// The confirmation method (`cnf`) the token is bound to, if any: DPoP (`cnf.jkt`) or
    /// certificate-bound (`cnf["x5t#S256"]`, RFC 8705). `None` ⇒ a bare (non-PoP) token — only
    /// reachable when the verifier is configured to accept it.
    pub confirmation: Option<Confirmation>,
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

    /// The DPoP `cnf.jkt` thumbprint the token is bound to, if it is DPoP-bound. Returns `None` for a
    /// certificate-bound or bare token. (Backward-compatible accessor for the former `cnf_jkt` field.)
    pub fn cnf_jkt(&self) -> Option<&str> {
        self.confirmation.as_ref().and_then(Confirmation::as_jkt)
    }

    /// The RFC 8705 `cnf["x5t#S256"]` certificate thumbprint the token is bound to, if it is
    /// certificate-bound. Returns `None` for a DPoP-bound or bare token.
    pub fn cert_x5t_s256(&self) -> Option<&str> {
        self.confirmation
            .as_ref()
            .and_then(Confirmation::as_x5t_s256)
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
            // Infallible here: `validate_token` already called `extract_confirmation` and rejected an
            // ambiguous both-`cnf` token, so a second parse cannot newly fail. We nonetheless map any
            // error to `None` rather than `unwrap` — a bound token that reached this point was already
            // validated down its confirmation-specific path.
            confirmation: extract_confirmation(&claims).unwrap_or(None),
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

        // Parse the token's confirmation method (`cnf`). A token carrying BOTH `cnf.jkt` and
        // `cnf["x5t#S256"]` is ambiguous and rejected here, BEFORE any PoP dispatch — a fail-closed
        // malformed-token rejection (never "pick one").
        let confirmation = extract_confirmation(&claims)?;

        // Dispatch on the token's CONFIRMATION METHOD — never on the presentation scheme. This is the
        // no-downgrade invariant (both directions): a certificate-bound token is proven ONLY by the
        // certificate (never by a DPoP proof), and a DPoP-bound token is proven ONLY by a fresh DPoP
        // proof (never by a presented certificate). The two paths never substitute for each other.
        match &confirmation {
            // RFC 8705 certificate-bound: PoP is the mutual-TLS client certificate. A DPoP proof, even
            // if one is presented alongside, is IRRELEVANT to this token and is not consulted here.
            Some(Confirmation::X5tS256(cert_x5t)) => {
                self.validate_cert_bound(req, cert_x5t)?;
            }
            // RFC 9449 DPoP-bound: the proof is REQUIRED regardless of the presentation scheme or
            // `require_dpop` (Finding #1, roborev High — otherwise a captured bound token presented as
            // `Bearer` when `require_dpop=false` would be accepted without proof-of-possession, a
            // token-replay downgrade). `oauth4webapi` enforces exactly this: it runs its DPoP step
            // whenever the token carries `cnf.jkt`.
            Some(Confirmation::Jkt(cnf_jkt)) => {
                self.validate_dpop_bound(req, &parsed.token, cnf_jkt)?;
            }
            // No confirmation claim. If DPoP is required/requested we still demand a proof + a binding;
            // with neither present this is the existing "not DPoP-bound" rejection (message + ordering
            // preserved). If DPoP is NOT required (config opt-out) a bare token is accepted.
            None => {
                if dpop {
                    // Preserve the prior error ordering: a missing DPoP header reports first, then the
                    // missing binding.
                    let _proof = req.dpop.as_deref().ok_or_else(|| {
                        invalid_token_dpop("DPoP proof is required (no DPoP HTTP Header).")
                    })?;
                    return Err(invalid_token_dpop(
                        "Access token is not DPoP-bound (no cnf.jkt confirmation claim).",
                    ));
                }
            }
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

    /// Validate a DPoP-bound (`cnf.jkt`) token's proof-of-possession: a fresh DPoP proof is REQUIRED,
    /// then verified per RFC 9449 (routing to the `ath`-compat path only when opted in AND the proof
    /// omits `ath`). This is the DPoP arm of the confirmation dispatch — unchanged in behaviour from
    /// the pre-cnf-x5t code.
    fn validate_dpop_bound(
        &self,
        req: &AuthRequest,
        access_token: &str,
        cnf_jkt: &str,
    ) -> Result<(), VerifyError> {
        let proof = req
            .dpop
            .as_deref()
            .ok_or_else(|| invalid_token_dpop("DPoP proof is required (no DPoP HTTP Header)."))?;
        // ath-compat path: opted in AND the presented proof omits `ath` (a present-but-wrong ath still
        // takes the strict path and is rejected).
        let ath_compat = self.config.allow_missing_ath && !proof_has_ath(proof);
        let require_ath = !ath_compat;
        self.validate_dpop_proof(req, proof, access_token, cnf_jkt, require_ath)
    }

    /// Validate an RFC 8705 §3 certificate-bound (`cnf["x5t#S256"]`) access token. The RS "**MUST
    /// verify that the certificate matches**" (RFC 8705 §3): the client certificate presented on THIS
    /// connection MUST be present AND its `base64url(SHA-256(DER))` thumbprint MUST equal the token's
    /// `cnf["x5t#S256"]`, compared in constant time. Fail-closed on every branch:
    /// - no presented certificate ([`AuthRequest::client_cert_x5t_s256`] is `None`) ⇒ reject (a
    ///   certificate-bound token is NEVER accepted bare);
    /// - thumbprint mismatch ⇒ reject.
    ///
    /// The verifier performs **no** TLS work and holds **no** certificate bytes — it only compares the
    /// hash the host computed once per connection. This keeps the crate issuer-agnostic and
    /// dependency-free. There is NO DPoP fallback here: a certificate-bound token cannot be proven by a
    /// DPoP proof (the no-downgrade invariant).
    fn validate_cert_bound(
        &self,
        req: &AuthRequest,
        expected_x5t_s256: &str,
    ) -> Result<(), VerifyError> {
        let presented = req.client_cert_x5t_s256.as_deref().ok_or_else(|| {
            invalid_token(
                "Certificate-bound access token requires a client certificate (none presented).",
            )
        })?;
        if !constant_time_str_eq(presented, expected_x5t_s256) {
            return Err(invalid_token(
                "Certificate-bound access token confirmation mismatch \
                 (cnf.x5t#S256 != presented client certificate thumbprint).",
            ));
        }
        Ok(())
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

/// Parse the token's `cnf` (RFC 7800) confirmation method into a [`Confirmation`].
///
/// - `cnf.jkt` (a non-empty string)        → [`Confirmation::Jkt`] (RFC 9449 DPoP);
/// - `cnf["x5t#S256"]` (a non-empty string) → [`Confirmation::X5tS256`] (RFC 8705 §3.1 cert-bound);
/// - neither present                        → `Ok(None)`;
/// - BOTH present                           → `Err` — ambiguous/malformed, rejected fail-closed
///   (RFC 8705 §3.1 defines a token as bound to ONE method; a token asserting two confirmations is
///   not something we choose between).
///
/// A `cnf` that is not an object, or whose member is missing / not a non-empty string, means that
/// member does NOT bind the token (treated as absent) — never a silent downgrade of a real binding.
fn extract_confirmation(claims: &Claims) -> Result<Option<Confirmation>, VerifyError> {
    let cnf = match claims.get("cnf").and_then(Value::as_object) {
        Some(c) => c,
        None => return Ok(None),
    };
    fn non_empty(v: Option<&Value>) -> Option<&str> {
        v.and_then(Value::as_str).filter(|s| !s.is_empty())
    }
    let jkt = non_empty(cnf.get("jkt"));
    let x5t = non_empty(cnf.get("x5t#S256"));
    match (jkt, x5t) {
        (Some(_), Some(_)) => Err(invalid_token(
            "Access token confirmation is ambiguous (both cnf.jkt and cnf.x5t#S256 present).",
        )),
        (Some(j), None) => Ok(Some(Confirmation::Jkt(j.to_string()))),
        (None, Some(t)) => Ok(Some(Confirmation::X5tS256(t.to_string()))),
        (None, None) => Ok(None),
    }
}

/// Constant-time equality of two byte-strings — no data-dependent branch or early return, so a
/// certificate-thumbprint comparison cannot become a timing oracle for the secret thumbprint. The
/// length pre-check is NOT secret-dependent (RFC 8705 `x5t#S256` values are fixed-length base64url
/// SHA-256 strings; a differing length can only be a malformed input, and the value is a public
/// hash, not a secret). `black_box` on the accumulator prevents the optimizer from reintroducing a
/// short-circuit.
fn constant_time_str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    std::hint::black_box(diff) == 0
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

    fn claims_with_cnf(cnf: Value) -> Claims {
        let mut c = Claims::new();
        c.insert("cnf".into(), cnf);
        c
    }

    #[test]
    fn extract_confirmation_reads_jkt() {
        let c = claims_with_cnf(serde_json::json!({ "jkt": "thumb" }));
        assert_eq!(
            extract_confirmation(&c).unwrap(),
            Some(Confirmation::Jkt("thumb".into()))
        );
    }

    #[test]
    fn extract_confirmation_reads_x5t_s256() {
        let c = claims_with_cnf(serde_json::json!({ "x5t#S256": "certhash" }));
        assert_eq!(
            extract_confirmation(&c).unwrap(),
            Some(Confirmation::X5tS256("certhash".into()))
        );
    }

    #[test]
    fn extract_confirmation_none_when_absent_or_empty() {
        // No cnf at all.
        assert_eq!(extract_confirmation(&Claims::new()).unwrap(), None);
        // cnf present but empty object.
        let c = claims_with_cnf(serde_json::json!({}));
        assert_eq!(extract_confirmation(&c).unwrap(), None);
        // Empty-string members bind nothing.
        let c = claims_with_cnf(serde_json::json!({ "jkt": "", "x5t#S256": "" }));
        assert_eq!(extract_confirmation(&c).unwrap(), None);
        // cnf is not an object.
        let c = claims_with_cnf(Value::String("nope".into()));
        assert_eq!(extract_confirmation(&c).unwrap(), None);
        // Non-string member is ignored.
        let c = claims_with_cnf(serde_json::json!({ "jkt": 42 }));
        assert_eq!(extract_confirmation(&c).unwrap(), None);
    }

    #[test]
    fn extract_confirmation_rejects_both_cnf_present() {
        let c = claims_with_cnf(serde_json::json!({ "jkt": "thumb", "x5t#S256": "certhash" }));
        let err = extract_confirmation(&c).unwrap_err();
        assert_eq!(err.status(), 401);
    }

    #[test]
    fn extract_confirmation_one_empty_one_set_is_unambiguous() {
        // Empty jkt + real x5t ⇒ cert-bound (the empty member does not count as "present").
        let c = claims_with_cnf(serde_json::json!({ "jkt": "", "x5t#S256": "certhash" }));
        assert_eq!(
            extract_confirmation(&c).unwrap(),
            Some(Confirmation::X5tS256("certhash".into()))
        );
        // Real jkt + empty x5t ⇒ DPoP-bound.
        let c = claims_with_cnf(serde_json::json!({ "jkt": "thumb", "x5t#S256": "" }));
        assert_eq!(
            extract_confirmation(&c).unwrap(),
            Some(Confirmation::Jkt("thumb".into()))
        );
    }

    #[test]
    fn constant_time_str_eq_matches_semantics_of_plain_eq() {
        assert!(constant_time_str_eq("abc", "abc"));
        assert!(!constant_time_str_eq("abc", "abd"));
        assert!(!constant_time_str_eq("abc", "abcd")); // length differs
        assert!(!constant_time_str_eq("", "a"));
        assert!(constant_time_str_eq("", ""));
        // A realistic base64url SHA-256 thumbprint pair.
        let t = "Zk8oPq2s3v4w5x6y7z8A9B0C1D2E3F4G5H6I7J8K9L0";
        assert!(constant_time_str_eq(t, t));
        assert!(!constant_time_str_eq(t, &t.replace('Z', "a")));
    }

    #[test]
    fn confirmation_accessors() {
        assert_eq!(Confirmation::Jkt("j".into()).as_jkt(), Some("j"));
        assert_eq!(Confirmation::Jkt("j".into()).as_x5t_s256(), None);
        assert_eq!(Confirmation::X5tS256("c".into()).as_x5t_s256(), Some("c"));
        assert_eq!(Confirmation::X5tS256("c".into()).as_jkt(), None);
    }

    #[test]
    fn verified_token_confirmation_accessors() {
        let t = VerifiedToken {
            confirmation: Some(Confirmation::X5tS256("c".into())),
            ..Default::default()
        };
        assert_eq!(t.cert_x5t_s256(), Some("c"));
        assert_eq!(t.cnf_jkt(), None);
        let t = VerifiedToken {
            confirmation: Some(Confirmation::Jkt("j".into())),
            ..Default::default()
        };
        assert_eq!(t.cnf_jkt(), Some("j"));
        assert_eq!(t.cert_x5t_s256(), None);
    }
}
