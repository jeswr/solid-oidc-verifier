// AUTHORED-BY Claude Opus 4.8
//! WebID profile resolution seam + URL canonicalisation + the SSRF URL gate.
//!
//! Ports the security-relevant *logic* of `src/auth/webidResolver.ts`: the WebID claim shape checks
//! (https-only, no userinfo), profile-URL canonicalisation (strip fragment + userinfo), and the
//! per-URL SSRF gate (scheme allowlist, userinfo refusal, IP-literal classification via
//! [`crate::ssrf`]). The actual network fetch + DNS-pinning + redirect-revalidation lives in the M2
//! [`NetworkWebIdResolver`] (the `network` feature) behind the [`WebIdResolver`] trait, over the shared
//! [`crate::net::SafeFetcher`]; the trait, the gate, and the bidirectional-check orchestration the
//! verifier drives are the M1 core. A test resolver implements the trait deterministically.

use std::collections::HashSet;

use url::Url;

use crate::error::{invalid_token, VerifyError};
use crate::ssrf::{is_loopback_address, is_public_address_with_nat64, Nat64Policy};

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

/// Resolves a **WebID** (the full IRI, fragment intact) to its profile's issuer set. The implementation
/// canonicalises the WebID to the profile-document URL for the fetch, but MUST scope the collected
/// `solid:oidcIssuer` objects to triples whose SUBJECT is the WebID itself (or the document URL) — a
/// profile listing the issuer for an unrelated subject must NOT satisfy the check for this WebID. The
/// network implementation (M2) DNS-pins, re-validates redirects, bounds the body, and refuses
/// non-public addresses; a test/embedded implementation can resolve from a fixture map. Mirrors the TS
/// `WebIdResolver` seam (`resolve(webId)` → `extractIssuers(quads, webId, profileUrl)`).
pub trait WebIdResolver: Send + Sync {
    /// `web_id` is the FULL WebID IRI (with fragment), not the canonicalised profile URL.
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
///
/// Uses the STRICT NAT64 policy (well-known `/96` only). For an operator-configured NAT64 NSP
/// allowlist, use [`ssrf_gate_static_with_nat64`].
pub fn ssrf_gate_static(raw_url: &str, allow_loopback: bool) -> Result<(), WebIdProfileError> {
    ssrf_gate_static_with_nat64(raw_url, allow_loopback, &Nat64Policy::strict())
}

/// As [`ssrf_gate_static`], but honouring an operator-configured NAT64 NSP allowlist when classifying
/// an IPv6 literal host (default-OFF: an empty/strict policy gives identical behaviour).
pub fn ssrf_gate_static_with_nat64(
    raw_url: &str,
    allow_loopback: bool,
    nat64: &Nat64Policy,
) -> Result<(), WebIdProfileError> {
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
            classify_resolved_address_with_nat64(stripped, &url, allow_loopback, nat64)?;
        }
    }
    Ok(())
}

/// Apply the per-resolved-address policy (TS `assertNotSsrf`'s record loop): an `http:` URL allowed by
/// `allow_loopback` must resolve to a loopback address; every address must be public (or loopback when
/// allowed). The network adapter calls this for each DNS record; the static gate calls it for an IP
/// literal host. Public — reused by the M2 adapter.
///
/// Uses the STRICT NAT64 policy (well-known `/96` only). For an operator-configured NAT64 NSP
/// allowlist, use [`classify_resolved_address_with_nat64`].
pub fn classify_resolved_address(
    address: &str,
    url: &Url,
    allow_loopback: bool,
) -> Result<(), WebIdProfileError> {
    classify_resolved_address_with_nat64(address, url, allow_loopback, &Nat64Policy::strict())
}

/// As [`classify_resolved_address`], but honouring an operator-configured NAT64 NSP allowlist
/// (default-OFF: an empty/strict policy gives identical behaviour).
pub fn classify_resolved_address_with_nat64(
    address: &str,
    url: &Url,
    allow_loopback: bool,
    nat64: &Nat64Policy,
) -> Result<(), WebIdProfileError> {
    if url.scheme() == "http" && allow_loopback && !is_loopback_address(address) {
        return Err(WebIdProfileError(format!(
            "WebID profile URL refused — http: WebID allowed only when ALL resolved addresses are loopback (got {address}). Use https: in production."
        )));
    }
    if !is_public_address_with_nat64(address, allow_loopback, nat64) {
        let host = url.host_str().unwrap_or("");
        return Err(WebIdProfileError(format!(
            "WebID profile URL refused — {host} resolves to a non-public address ({address})."
        )));
    }
    Ok(())
}

// =====================================================================================================
// M2 network adapter — the real WebIdResolver (DNS-pinned, redirect-revalidating, body-bounded fetch).
// =====================================================================================================

/// The real, network-backed [`WebIdResolver`] (M2). Fetches the WebID's profile document over the
/// DNS-pinned, SSRF-guarded [`crate::net::SafeFetcher`] (resolve → classify every record → pin →
/// no-auto-redirect/re-gate-each-hop → bounded body), parses it as Turtle via the W3C-driven `oxttl`
/// parser, and returns the `solid:oidcIssuer` issuer set. A profile URL (or a redirect target) at a
/// non-public address is refused exactly like any other SSRF target — the fetch fails closed, which the
/// verifier's strict bidirectional mode treats as "not listed" → 401 (constant client message).
///
/// Only Turtle is parsed (the dominant Solid profile serialization, and what CSS/ESS/NSS publish at a
/// WebID by default). The fetch sends an `Accept` favouring Turtle; a profile served only as JSON-LD is
/// out of scope for this slice (a JSON-LD path is a follow-up — flagged in the M2 report).
#[cfg(feature = "network")]
pub struct NetworkWebIdResolver<R: crate::net::HostResolver = crate::net::SystemResolver> {
    fetcher: crate::net::SafeFetcher<R>,
}

#[cfg(feature = "network")]
impl NetworkWebIdResolver<crate::net::SystemResolver> {
    /// Build a production resolver: the system-DNS SSRF-guarded fetcher. `allow_loopback` (dev/IT only)
    /// permits an `http:`/loopback WebID host.
    pub fn new(allow_loopback: bool) -> Result<Self, WebIdProfileError> {
        let cfg = crate::net::SafeFetchConfig {
            allow_loopback,
            ..Default::default()
        };
        let fetcher = crate::net::SafeFetcher::system(cfg)
            .map_err(|e| WebIdProfileError(format!("WebID fetcher init failed: {}", e.0)))?;
        Ok(Self { fetcher })
    }
}

#[cfg(feature = "network")]
impl<R: crate::net::HostResolver> NetworkWebIdResolver<R> {
    /// Build a resolver over an explicit fetcher (the test seam — inject adversarial DNS).
    pub fn with_fetcher(fetcher: crate::net::SafeFetcher<R>) -> Self {
        Self { fetcher }
    }
}

#[cfg(feature = "network")]
impl<R: crate::net::HostResolver> WebIdResolver for NetworkWebIdResolver<R> {
    fn resolve(&self, web_id: &str) -> Result<WebIdProfile, WebIdProfileError> {
        // Canonicalise the FULL WebID to the profile-document URL we GET (fragment + userinfo stripped);
        // the SafeFetcher re-applies the full static gate defensively at every hop.
        let profile_url = canonicalise_profile_url(web_id);
        let resp = self
            .fetcher
            // Prefer Turtle; many servers also content-negotiate. We parse Turtle only (see doc above).
            .get(
                &profile_url,
                "text/turtle, application/x-turtle;q=0.9, */*;q=0.1",
            )
            .map_err(|e| WebIdProfileError(format!("WebID profile fetch failed: {}", e.0)))?;
        // Scope the issuer triples to the WebID subject (or the document URL) — NOT any subject.
        let issuers = parse_oidc_issuers(&resp.body, &resp.final_url, web_id, &profile_url)?;
        Ok(WebIdProfile { issuers })
    }
}

/// Parse a Turtle profile body and collect `solid:oidcIssuer` NamedNode objects **only from triples
/// whose subject is the WebID itself or the profile-document URL** (the subject-scoping that prevents a
/// profile from satisfying the bidirectional check by listing the issuer for an unrelated subject —
/// roborev High; mirrors TS `extractIssuers(quads, webId, profileUrl)`). Uses the streaming `oxttl`
/// parser (bounded — the body is already byte-capped upstream). A literal (non-IRI) object is ignored
/// (an issuer must be an IRI). A syntax error aborts with a coarse error — never echoed to the client.
#[cfg(feature = "network")]
fn parse_oidc_issuers(
    body: &[u8],
    base_url: &str,
    web_id: &str,
    profile_url: &str,
) -> Result<HashSet<String>, WebIdProfileError> {
    use oxrdf::{Subject, Term};
    use oxttl::TurtleParser;

    let mut parser = TurtleParser::new();
    // Resolve relative IRIs against the profile's effective URL (post-redirect), matching how a Turtle
    // document's relative terms are interpreted. A non-absolute base is a no-op.
    if let Ok(p) = TurtleParser::new().with_base_iri(base_url) {
        parser = p;
    }

    let mut issuers = HashSet::new();
    for triple in parser.for_slice(body) {
        let triple = triple
            .map_err(|_| WebIdProfileError("WebID profile is not valid Turtle.".to_string()))?;
        if triple.predicate.as_str() != SOLID_OIDC_ISSUER {
            continue;
        }
        // Subject MUST be the WebID (full IRI) or the profile-document URL — a different subject's
        // oidcIssuer triple is ignored.
        let subject_iri = match &triple.subject {
            Subject::NamedNode(n) => n.as_str(),
            _ => continue, // blank-node / quoted-triple subjects can't be the WebID
        };
        if subject_iri != web_id && subject_iri != profile_url {
            continue;
        }
        if let Term::NamedNode(n) = &triple.object {
            issuers.insert(n.as_str().to_string());
        }
    }
    Ok(issuers)
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

    #[cfg(feature = "network")]
    const WEBID: &str = "https://pod.example/alice/profile/card#me";
    #[cfg(feature = "network")]
    const PROFILE: &str = "https://pod.example/alice/profile/card";

    #[cfg(feature = "network")]
    #[test]
    fn parse_oidc_issuers_extracts_namednode_objects_for_the_webid_subject() {
        let ttl = br#"
            @prefix solid: <http://www.w3.org/ns/solid/terms#> .
            <https://pod.example/alice/profile/card#me>
                solid:oidcIssuer <https://idp.example/realms/solid> ,
                                 <https://other-idp.example/> .
        "#;
        let issuers = parse_oidc_issuers(ttl, PROFILE, WEBID, PROFILE).unwrap();
        assert!(issuers.contains("https://idp.example/realms/solid"));
        assert!(issuers.contains("https://other-idp.example/"));
        assert_eq!(issuers.len(), 2);
    }

    #[cfg(feature = "network")]
    #[test]
    fn parse_oidc_issuers_accepts_document_subject() {
        // A profile that asserts the issuer on the DOCUMENT URL (not the #me node) is also honoured
        // (TS `subjectIri === profileUrl`).
        let ttl = br#"
            @prefix solid: <http://www.w3.org/ns/solid/terms#> .
            <https://pod.example/alice/profile/card>
                solid:oidcIssuer <https://idp.example/realms/solid> .
        "#;
        let issuers = parse_oidc_issuers(ttl, PROFILE, WEBID, PROFILE).unwrap();
        assert!(issuers.contains("https://idp.example/realms/solid"));
    }

    #[cfg(feature = "network")]
    #[test]
    fn parse_oidc_issuers_ignores_a_different_subject() {
        // SECURITY (roborev High): a `solid:oidcIssuer` triple on an UNRELATED subject must NOT count
        // toward the WebID's issuer set — else a profile could satisfy the bidirectional check for the
        // claimed WebID by listing the trusted issuer under some other subject.
        let ttl = br#"
            @prefix solid: <http://www.w3.org/ns/solid/terms#> .
            <https://pod.example/eve#me> solid:oidcIssuer <https://idp.example/realms/solid> .
        "#;
        let issuers = parse_oidc_issuers(ttl, PROFILE, WEBID, PROFILE).unwrap();
        assert!(
            issuers.is_empty(),
            "an unrelated subject's oidcIssuer must be ignored"
        );
    }

    #[cfg(feature = "network")]
    #[test]
    fn parse_oidc_issuers_ignores_literal_objects() {
        // A literal (string) object of solid:oidcIssuer is NOT a valid issuer IRI — it must be dropped,
        // never coerced into the issuer set (else a profile could "list" an arbitrary string).
        let ttl = br#"
            @prefix solid: <http://www.w3.org/ns/solid/terms#> .
            <https://pod.example/alice/profile/card#me> solid:oidcIssuer "https://idp.example/realms/solid" .
        "#;
        let issuers = parse_oidc_issuers(ttl, PROFILE, WEBID, PROFILE).unwrap();
        assert!(issuers.is_empty());
    }

    #[cfg(feature = "network")]
    #[test]
    fn parse_oidc_issuers_empty_when_predicate_absent() {
        let ttl = br#"
            @prefix foaf: <http://xmlns.com/foaf/0.1/> .
            <https://pod.example/alice/profile/card#me> foaf:name "Alice" .
        "#;
        let issuers = parse_oidc_issuers(ttl, PROFILE, WEBID, PROFILE).unwrap();
        assert!(issuers.is_empty());
    }

    #[cfg(feature = "network")]
    #[test]
    fn parse_oidc_issuers_rejects_malformed_turtle() {
        let ttl = b"this is not <turtle at all ;;;";
        assert!(parse_oidc_issuers(ttl, PROFILE, WEBID, PROFILE).is_err());
    }
}
