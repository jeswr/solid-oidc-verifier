// AUTHORED-BY Claude Opus 4.8
//! Typed, non-leaky error enum for verification failures.
//!
//! Ported from the TS verifier's `AuthError` semantics (`src/auth/types.ts`,
//! `src/auth/verifier.ts` `challenge`): every failure maps to an HTTP status (401 normally, 503 for
//! a replay-store backend outage in the fail-closed posture) and a `WWW-Authenticate` challenge that
//! names the trusted issuer(s). The public-facing message is deliberately terse — it never discloses
//! token internals or SSRF/network diagnostics (the colluding-IdP reconnaissance-oracle guard, TS
//! `BIDIRECTIONAL_REJECTION_MESSAGE`).

use std::fmt;

/// The category of a verification failure. Mirrors the RFC 6750 / RFC 9449 `error=` codes plus the
/// crate-internal categories that all surface to the client as `invalid_token` / `invalid_request`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Malformed request (unsupported scheme, Bearer-when-DPoP-required). RFC 6750 `invalid_request`.
    InvalidRequest,
    /// The token / proof failed a check. RFC 6750 `invalid_token`. The overwhelming majority of
    /// failures map here so an attacker cannot distinguish *which* check failed.
    InvalidToken,
    /// The replay-protection backend is unavailable and the policy is fail-closed (503, retryable).
    /// Mirrors the TS 503 `replay-store unavailable` path.
    ReplayStoreUnavailable,
}

impl ErrorKind {
    /// The RFC `error=` code surfaced in `WWW-Authenticate`.
    fn code(self) -> &'static str {
        match self {
            ErrorKind::InvalidRequest => "invalid_request",
            // A backend outage is surfaced as `invalid_token` in the challenge (it is challenge-shaped
            // so the client retries) but carries a 503 status — exactly the TS shape.
            ErrorKind::InvalidToken | ErrorKind::ReplayStoreUnavailable => "invalid_token",
        }
    }

    /// The HTTP status this kind maps to.
    pub fn status(self) -> u16 {
        match self {
            ErrorKind::InvalidRequest | ErrorKind::InvalidToken => 401,
            ErrorKind::ReplayStoreUnavailable => 503,
        }
    }
}

/// A verification failure. Construct via [`VerifyError::new`]; render the client-facing challenge via
/// [`VerifyError::www_authenticate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyError {
    kind: ErrorKind,
    /// Safe, client-facing description. NEVER contains token bytes or SSRF/network detail.
    message: String,
    /// Whether the challenge should advertise the `DPoP` scheme (and `algs`) vs `Bearer`.
    dpop: bool,
}

impl VerifyError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            dpop: false,
        }
    }

    /// Mark this error's challenge as DPoP-scheme (adds `algs=`). Matches the TS `challenge(..., dpop)`.
    pub fn with_dpop(mut self, dpop: bool) -> Self {
        self.dpop = dpop;
        self
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn status(&self) -> u16 {
        self.kind.status()
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    /// Build the `WWW-Authenticate` header value, naming the trusted issuer(s) so the client knows
    /// where to obtain a token (RFC 6750 / RFC 9449 §5.1). Mirrors TS `DpopTokenVerifier.challenge`.
    ///
    /// `require_dpop` widens the scheme to `DPoP` even for a `Bearer`-shaped error (so a
    /// DPoP-required server always challenges with `DPoP`).
    pub fn www_authenticate(
        &self,
        trusted_issuers: &[String],
        dpop_algs: &[&str],
        require_dpop: bool,
    ) -> String {
        let dpop = self.dpop || require_dpop;
        let scheme = if dpop { "DPoP" } else { "Bearer" };
        let issuers = trusted_issuers.join(" ");
        let mut params = vec![
            format!("error=\"{}\"", self.kind.code()),
            format!("error_description=\"{}\"", escape_quoted(&self.message)),
            "scope=\"webid\"".to_string(),
            format!("issuer=\"{}\"", escape_quoted(&issuers)),
        ];
        if dpop {
            params.push(format!("algs=\"{}\"", dpop_algs.join(" ")));
        }
        format!("{} {}", scheme, params.join(", "))
    }
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.message, self.kind.code())
    }
}

impl std::error::Error for VerifyError {}

/// Escape a string for safe inclusion inside a quoted `WWW-Authenticate` parameter value
/// (backslash + double-quote). Mirrors TS `escapeQuoted`.
fn escape_quoted(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Construct a 401 `invalid_token` error (the common case).
pub(crate) fn invalid_token(message: impl Into<String>) -> VerifyError {
    VerifyError::new(ErrorKind::InvalidToken, message)
}

/// Construct a 401 `invalid_token` DPoP-scheme error.
pub(crate) fn invalid_token_dpop(message: impl Into<String>) -> VerifyError {
    VerifyError::new(ErrorKind::InvalidToken, message).with_dpop(true)
}

/// Construct a 401 `invalid_request` error.
pub(crate) fn invalid_request(message: impl Into<String>) -> VerifyError {
    VerifyError::new(ErrorKind::InvalidRequest, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_token_is_401() {
        assert_eq!(invalid_token("x").status(), 401);
    }

    #[test]
    fn replay_unavailable_is_503() {
        assert_eq!(
            VerifyError::new(ErrorKind::ReplayStoreUnavailable, "down").status(),
            503
        );
    }

    #[test]
    fn challenge_names_issuers_and_dpop_algs() {
        let e = invalid_token_dpop("nope");
        let h = e.www_authenticate(
            &["https://idp.example".to_string()],
            &["ES256", "RS256"],
            true,
        );
        assert!(h.starts_with("DPoP "));
        assert!(h.contains("error=\"invalid_token\""));
        assert!(h.contains("issuer=\"https://idp.example\""));
        assert!(h.contains("algs=\"ES256 RS256\""));
        assert!(h.contains("scope=\"webid\""));
    }

    #[test]
    fn challenge_escapes_quotes() {
        let e = invalid_token("he said \"hi\" \\ bye");
        let h = e.www_authenticate(&[], &[], false);
        assert!(h.contains("\\\"hi\\\""));
        assert!(h.contains("\\\\"));
    }

    #[test]
    fn bearer_challenge_when_not_dpop() {
        let e = invalid_request("bad");
        let h = e.www_authenticate(&[], &[], false);
        assert!(h.starts_with("Bearer "));
        assert!(!h.contains("algs="));
    }
}
