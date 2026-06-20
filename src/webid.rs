// AUTHORED-BY Claude Opus 4.8
//! WebID profile resolution seam + URL canonicalisation + the SSRF URL gate.
//!
//! Ports the security-relevant *logic* of `src/auth/webidResolver.ts`: the WebID claim shape checks
//! (https-only, no userinfo), profile-URL canonicalisation (strip fragment + userinfo), and the
//! per-URL SSRF gate (scheme allowlist, userinfo refusal, IP-literal classification via
//! [`crate::ssrf`]). The actual network fetch + DNS-pinning + redirect-revalidation is the M2 adapter
//! behind the [`WebIdResolver`] trait — M1 ships the trait, the gate, and the bidirectional check
//! orchestration the verifier drives. A test resolver implements the trait deterministically.

use std::collections::HashSet;

use url::Url;

use crate::error::{invalid_token, VerifyError};
use crate::ssrf::{is_loopback_address, is_public_address};

/// The `solid:oidcIssuer` predicate IRI (Solid-OIDC §4).
pub const SOLID_OIDC_ISSUER: &str = "http://www.w3.org/ns/solid/terms#oidcIssuer";

/// Result of resolving a WebID's profile document: the issuer set it lists via `solid:oidcIssuer`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WebIdProfile {
    pub issuers: HashSet<String>,
}

/// Raised when a WebID profile cannot be safely fetched / parsed. The verifier surfaces a *constant*
/// client-facing message (the reconnaissance-oracle guard); the detail here is for internal logging.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct WebIdProfileError(pub String);

/// Resolves a WebID URL to its profile's issuer set. The network implementation (M2) DNS-pins,
/// re-validates redirects, bounds the body, and refuses non-public addresses; a test/embedded
/// implementation can resolve from a fixture map. Mirrors the `WebIdResolver` seam.
pub trait WebIdResolver: Send + Sync {
    fn resolve(&self, web_id: &str) -> Result<WebIdProfile, WebIdProfileError>;
}

/// How the verifier treats the bidirectional WebID↔issuer check (TS `bidirectionalMode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BidirectionalMode {
    /// Production default: the WebID profile MUST list the token's issuer; any mismatch/fetch
    /// failure → 401.
    Strict,
    /// Log a mismatch but accept (local-loop / IT).
    Warn,
    /// Skip the check entirely.
    Off,
}

/// Validate the WebID claim shape (TS `extractWebId`): present, an absolute `https:` URL, no userinfo.
/// Returns the WebID string unchanged on success.
pub fn validate_webid_claim(raw: &str) -> Result<String, VerifyError> {
    if raw.is_empty() {
        return Err(invalid_token("Token is missing the webid claim."));
    }
    let url = Url::parse(raw).map_err(|_| invalid_token("WebID claim is not a valid URL."))?;
    if url.scheme() != "https" {
        return Err(invalid_token("WebID claim must be an https: URL."));
    }
    if !url.username().is_empty() || url.password().is_some() {
        // Credential-exfiltration guard — a userinfo WebID would ship `Authorization: Basic …` to the
        // WebID host on dereference. Real WebIDs never use userinfo.
        return Err(invalid_token("WebID claim must not include userinfo."));
    }
    Ok(raw.to_string())
}

/// Canonicalise a WebID into the profile-document URL the GET hits: strip the fragment + userinfo
/// (TS `canonicaliseProfileUrl`). The result is what gets DNS-resolved + cached.
pub fn canonicalise_profile_url(web_id: &str) -> String {
    match Url::parse(web_id) {
        Ok(mut url) => {
            url.set_fragment(None);
            let _ = url.set_username("");
            let _ = url.set_password(None);
            url.to_string()
        }
        // Defensive: caller already validated this is well-formed.
        Err(_) => web_id.split('#').next().unwrap_or(web_id).to_string(),
    }
}

/// The SSRF gate for a single profile/redirect URL (the *synchronous* portion of TS `assertNotSsrf`:
/// scheme allowlist, http-only-under-loopback, userinfo refusal, and — for an IP literal host —
/// public-address classification). For a hostname host, the M2 network adapter performs the DNS
/// lookup + per-record classification + pinning; this gate covers the literal case + the static
/// policy checks. Returns `Ok(())` if the URL passes; an error otherwise.
///
/// `allow_loopback` permits `http:` to a loopback literal (dev/IT). A hostname host returns
/// `Ok(())` here — the caller must still DNS-resolve + classify every record before connecting.
pub fn ssrf_gate_static(raw_url: &str, allow_loopback: bool) -> Result<(), WebIdProfileError> {
    let url = Url::parse(raw_url)
        .map_err(|_| WebIdProfileError(format!("WebID profile URL is malformed: {raw_url}.")))?;
    match url.scheme() {
        "https" => {}
        "http" => {
            if !allow_loopback {
                return Err(WebIdProfileError(format!(
                    "WebID profile URL must be https: (got http: {}). HTTP is permitted only when allowLoopback=true (dev/IT).",
                    url.host_str().unwrap_or("")
                )));
            }
        }
        other => {
            return Err(WebIdProfileError(format!(
                "WebID profile URL must be http/https (got {other}:)."
            )))
        }
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(WebIdProfileError(
            "WebID profile URL must not carry userinfo.".to_string(),
        ));
    }
    // If the host is an IP literal, classify it now (the rebinding-free case). A hostname is left for
    // the network adapter to resolve + classify.
    if let Some(host) = url.host_str() {
        let stripped = host.trim_start_matches('[').trim_end_matches(']');
        let is_literal = stripped.parse::<std::net::Ipv4Addr>().is_ok()
            || stripped.parse::<std::net::Ipv6Addr>().is_ok();
        if is_literal {
            classify_resolved_address(stripped, &url, allow_loopback)?;
        }
    }
    Ok(())
}

/// Apply the per-resolved-address policy (TS `assertNotSsrf`'s record loop): an `http:` URL allowed by
/// `allow_loopback` must resolve to a loopback address; every address must be public (or loopback when
/// allowed). The network adapter calls this for each DNS record; the static gate calls it for an IP
/// literal host. Public — reused by the M2 adapter.
pub fn classify_resolved_address(
    address: &str,
    url: &Url,
    allow_loopback: bool,
) -> Result<(), WebIdProfileError> {
    if url.scheme() == "http" && allow_loopback && !is_loopback_address(address) {
        return Err(WebIdProfileError(format!(
            "WebID profile URL refused — http: WebID allowed only when ALL resolved addresses are loopback (got {address}). Use https: in production."
        )));
    }
    if !is_public_address(address, allow_loopback) {
        let host = url.host_str().unwrap_or("");
        return Err(WebIdProfileError(format!(
            "WebID profile URL refused — {host} resolves to a non-public address ({address})."
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_webid_accepts_https() {
        assert!(validate_webid_claim("https://pod.example/alice#me").is_ok());
    }

    #[test]
    fn validate_webid_rejects_http() {
        let e = validate_webid_claim("http://pod.example/alice#me").unwrap_err();
        assert!(e.message().contains("https"));
    }

    #[test]
    fn validate_webid_rejects_non_url() {
        assert!(validate_webid_claim("not a url").is_err());
    }

    #[test]
    fn validate_webid_rejects_userinfo() {
        let e = validate_webid_claim("https://user:pass@pod.example/alice#me").unwrap_err();
        assert!(e.message().contains("userinfo"));
    }

    #[test]
    fn validate_webid_rejects_empty() {
        assert!(validate_webid_claim("").is_err());
    }

    #[test]
    fn canonicalise_strips_fragment_and_userinfo() {
        assert_eq!(
            canonicalise_profile_url("https://user:pass@pod.example/alice/card#me"),
            "https://pod.example/alice/card"
        );
    }

    #[test]
    fn ssrf_gate_refuses_private_literal() {
        assert!(ssrf_gate_static("https://10.0.0.1/profile", false).is_err());
        assert!(ssrf_gate_static("https://[fd00::1]/profile", false).is_err());
    }

    #[test]
    fn ssrf_gate_allows_public_literal() {
        assert!(ssrf_gate_static("https://8.8.8.8/profile", false).is_ok());
    }

    #[test]
    fn ssrf_gate_refuses_http_without_loopback() {
        assert!(ssrf_gate_static("http://pod.example/profile", false).is_err());
    }

    #[test]
    fn ssrf_gate_refuses_non_http_scheme() {
        assert!(ssrf_gate_static("file:///etc/passwd", false).is_err());
        assert!(ssrf_gate_static("ftp://pod.example/x", false).is_err());
    }

    #[test]
    fn ssrf_gate_refuses_userinfo() {
        assert!(ssrf_gate_static("https://u:p@pod.example/profile", false).is_err());
    }

    #[test]
    fn ssrf_gate_allows_loopback_literal_when_permitted() {
        assert!(ssrf_gate_static("http://127.0.0.1/profile", true).is_ok());
        // ...but a public host over http: even with allow_loopback must be refused per address.
        assert!(ssrf_gate_static("http://8.8.8.8/profile", true).is_err());
    }
}
