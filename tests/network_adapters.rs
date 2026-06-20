// AUTHORED-BY Claude Opus 4.8
//! End-to-end tests for the M2 network adapters against a LOCAL loopback HTTP test server.
//!
//! These exercise the FULL DNS-pinned, SSRF-guarded fetch path (resolve → classify → pin → connect →
//! no-auto-redirect/re-gate → bounded body) and the discovery/JWKS/profile parsing through a real
//! socket — no live internet, no Keycloak. A deterministic [`MapResolver`] maps fake hostnames to the
//! test server's `127.0.0.1` address, and `allow_loopback=true` lets the loopback connect proceed so
//! the happy path is reachable; the adversarial SSRF cases are asserted to FAIL CLOSED regardless.
//!
//! Adversarial coverage (the M2 SSRF matrix, end-to-end):
//!   - a 302 from a public-shaped host to a host that resolves to a PRIVATE (RFC-1918) address →
//!     refused at the re-gated hop, even though the first hop was allowed;
//!   - a 302 to a `169.254.169.254` / loopback literal → refused at the re-gated hop;
//!   - a discovery doc whose `jwks_uri` points at a private host → refused;
//!   - an oversized body (DoS) → refused;
//!   - the happy path (discovery → jwks → parse; profile → parse) → succeeds.

#![cfg(feature = "network")]

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use tokio::sync::oneshot;

use solid_oidc_verifier::config::{JwksProvider, NetworkJwksProvider};
use solid_oidc_verifier::net::{HostResolver, SafeFetchConfig, SafeFetchError, SafeFetcher};
use solid_oidc_verifier::webid::{NetworkWebIdResolver, WebIdResolver};

/// A deterministic resolver mapping host → records (the test/adversarial DNS seam).
struct MapResolver {
    map: HashMap<String, Vec<IpAddr>>,
}
impl MapResolver {
    fn new(entries: &[(&str, &[&str])]) -> Self {
        let mut map = HashMap::new();
        for (host, ips) in entries {
            map.insert(
                host.to_string(),
                ips.iter().map(|s| s.parse().unwrap()).collect(),
            );
        }
        Self { map }
    }
}
impl HostResolver for MapResolver {
    fn resolve_host(&self, host: &str) -> Result<Vec<IpAddr>, SafeFetchError> {
        self.map
            .get(host)
            .cloned()
            .ok_or_else(|| SafeFetchError("NXDOMAIN".into()))
    }
}

/// What the test server returns for a given path.
#[derive(Clone)]
enum Reply {
    /// 200 with the given content-type + body.
    Ok(&'static str, String),
    /// 302 to the given Location.
    Redirect(String),
    /// 200 with a body of N bytes (DoS test).
    Big(usize),
}

#[derive(Clone)]
struct ServerState {
    routes: Arc<HashMap<String, Reply>>,
}

async fn serve(State(state): State<ServerState>, uri: axum::http::Uri) -> Response {
    match state.routes.get(uri.path()) {
        Some(Reply::Ok(ct, body)) => ([(header::CONTENT_TYPE, *ct)], body.clone()).into_response(),
        Some(Reply::Redirect(loc)) => {
            (StatusCode::FOUND, [(header::LOCATION, loc.clone())]).into_response()
        }
        Some(Reply::Big(n)) => {
            ([(header::CONTENT_TYPE, "application/json")], "x".repeat(*n)).into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Bind a loopback listener first (so the port is known), let `build` construct the routes using the
/// bound address (needed when a discovery doc must reference its own origin), then serve. Returns the
/// addr + a shutdown sender; the server lives until the sender is dropped/sent.
async fn start_server_with<F>(build: F) -> (SocketAddr, oneshot::Sender<()>)
where
    F: FnOnce(SocketAddr) -> HashMap<String, Reply>,
{
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let routes = build(addr);
    let state = ServerState {
        routes: Arc::new(routes),
    };
    let app = Router::new()
        .route("/", get(serve))
        .route("/*rest", get(serve))
        .with_state(state);
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await
            .unwrap();
    });
    (addr, tx)
}

/// Convenience for a server whose routes don't depend on its own address.
async fn start_server(routes: HashMap<String, Reply>) -> (SocketAddr, oneshot::Sender<()>) {
    start_server_with(|_addr| routes).await
}

/// A loopback-permitting fetch config (so the test server's 127.0.0.1 connect is allowed). Production
/// leaves `allow_loopback=false`.
fn loopback_cfg() -> SafeFetchConfig {
    SafeFetchConfig {
        allow_loopback: true,
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn discovery_then_jwks_happy_path() {
    // A real EC public JWK (the one locked in jwk.rs's thumbprint test).
    let jwks = r#"{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]}"#;
    // Bind first, then build the discovery doc referencing this exact origin (issuer must match).
    let (addr, _shutdown) = start_server_with(|addr| {
        let origin = format!("http://idp.test:{}", addr.port());
        let discovery = format!(r#"{{"issuer":"{origin}/","jwks_uri":"{origin}/jwks"}}"#);
        let mut routes = HashMap::new();
        routes.insert(
            "/.well-known/openid-configuration".to_string(),
            Reply::Ok("application/json", discovery),
        );
        routes.insert(
            "/jwks".to_string(),
            Reply::Ok("application/json", jwks.to_string()),
        );
        routes
    })
    .await;

    let issuer = format!("http://idp.test:{}/", addr.port());
    let resolver = MapResolver::new(&[("idp.test", &["127.0.0.1"])]);
    let provider = NetworkJwksProvider::with_fetcher(
        SafeFetcher::with_resolver(resolver, loopback_cfg()),
        std::time::Duration::from_secs(60),
    );
    // The fetch is blocking; run it off the async runtime.
    let keys = tokio::task::spawn_blocking(move || provider.keys_for(&issuer))
        .await
        .unwrap()
        .expect("discovery + jwks should succeed");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].kty, "EC");
}

#[tokio::test(flavor = "multi_thread")]
async fn jwks_uri_pointing_at_private_host_is_refused() {
    // The discovery doc's jwks_uri points at a host that resolves to a PRIVATE address → refused.
    let (addr, _shutdown) = start_server_with(|addr| {
        let issuer = format!("http://idp.test:{}/", addr.port());
        let discovery = format!(r#"{{"issuer":"{issuer}","jwks_uri":"http://intra.test/jwks"}}"#);
        let mut routes = HashMap::new();
        routes.insert(
            "/.well-known/openid-configuration".to_string(),
            Reply::Ok("application/json", discovery),
        );
        routes
    })
    .await;
    let issuer = format!("http://idp.test:{}/", addr.port());
    let resolver = MapResolver::new(&[
        ("idp.test", &["127.0.0.1"]),
        ("intra.test", &["10.0.0.1"]), // private — the jwks_uri target
    ]);
    let provider = NetworkJwksProvider::with_fetcher(
        SafeFetcher::with_resolver(resolver, loopback_cfg()),
        std::time::Duration::from_secs(60),
    );
    let err = tokio::task::spawn_blocking(move || provider.keys_for(&issuer))
        .await
        .unwrap();
    assert!(err.is_err(), "a private jwks_uri must be refused");
}

#[tokio::test(flavor = "multi_thread")]
async fn redirect_to_private_host_is_refused_end_to_end() {
    // The WebID profile URL is on the loopback test server, which 302s to a host resolving to a
    // PRIVATE address. The re-gated redirect hop MUST fail closed (even though the first hop, being
    // loopback, was allowed).
    let mut routes = HashMap::new();
    routes.insert(
        "/alice".to_string(),
        Reply::Redirect("http://intra.test/secret".to_string()),
    );
    let (addr, _shutdown) = start_server(routes).await;
    // The profile URL host maps to the loopback test server; the redirect target maps to a PRIVATE IP.
    let profile_url = format!("http://pod.test:{}/alice", addr.port());
    let pod_resolver = MapResolver::new(&[
        ("pod.test", &["127.0.0.1"]),
        ("intra.test", &["10.0.0.1"]), // private redirect target
    ]);
    let resolver = NetworkWebIdResolver::with_fetcher(SafeFetcher::with_resolver(
        pod_resolver,
        loopback_cfg(),
    ));
    let err = tokio::task::spawn_blocking(move || resolver.resolve(&profile_url))
        .await
        .unwrap();
    assert!(
        err.is_err(),
        "a 302 to a private host must be refused at the re-gated hop"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn redirect_to_metadata_literal_is_refused_end_to_end() {
    let mut routes = HashMap::new();
    routes.insert(
        "/alice".to_string(),
        Reply::Redirect("http://169.254.169.254/latest/meta-data/".to_string()),
    );
    let (addr, _shutdown) = start_server(routes).await;
    let profile_url = format!("http://pod.test:{}/alice", addr.port());
    let resolver = NetworkWebIdResolver::with_fetcher(SafeFetcher::with_resolver(
        MapResolver::new(&[("pod.test", &["127.0.0.1"])]),
        loopback_cfg(),
    ));
    let err = tokio::task::spawn_blocking(move || resolver.resolve(&profile_url))
        .await
        .unwrap();
    assert!(
        err.is_err(),
        "a 302 to the metadata literal must be refused"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn webid_profile_happy_path_extracts_issuer() {
    let mut routes = HashMap::new();
    let ttl = r#"@prefix solid: <http://www.w3.org/ns/solid/terms#> .
<#me> solid:oidcIssuer <https://idp.example/realms/solid> ."#;
    routes.insert(
        "/alice".to_string(),
        Reply::Ok("text/turtle", ttl.to_string()),
    );
    let (addr, _shutdown) = start_server(routes).await;
    let profile_url = format!("http://pod.test:{}/alice", addr.port());
    let resolver = NetworkWebIdResolver::with_fetcher(SafeFetcher::with_resolver(
        MapResolver::new(&[("pod.test", &["127.0.0.1"])]),
        loopback_cfg(),
    ));
    let profile = tokio::task::spawn_blocking(move || resolver.resolve(&profile_url))
        .await
        .unwrap()
        .expect("profile fetch should succeed");
    assert!(profile.issuers.contains("https://idp.example/realms/solid"));
}

#[tokio::test(flavor = "multi_thread")]
async fn oversized_body_is_refused() {
    let mut routes = HashMap::new();
    // 2 MiB body — over the 1 MiB cap.
    routes.insert("/jwks".to_string(), Reply::Big(2 * 1024 * 1024));
    let (addr, _shutdown) = start_server(routes).await;
    let fetcher = SafeFetcher::with_resolver(
        MapResolver::new(&[("pod.test", &["127.0.0.1"])]),
        loopback_cfg(),
    );
    let url = format!("http://pod.test:{}/jwks", addr.port());
    let err = tokio::task::spawn_blocking(move || fetcher.get(&url, "application/json"))
        .await
        .unwrap();
    assert!(err.is_err(), "an oversized body must be refused");
}

#[tokio::test(flavor = "multi_thread")]
async fn discovery_issuer_mismatch_is_refused() {
    // The discovery doc claims a DIFFERENT issuer than requested → refused (RFC 8414 mix-up guard).
    let discovery =
        r#"{"issuer":"https://attacker.example/","jwks_uri":"http://idp.test/jwks"}"#.to_string();
    let (addr, _shutdown) = start_server_with(|_addr| {
        let mut routes = HashMap::new();
        routes.insert(
            "/.well-known/openid-configuration".to_string(),
            Reply::Ok("application/json", discovery),
        );
        routes
    })
    .await;
    let issuer = format!("http://idp.test:{}/", addr.port());
    let provider = NetworkJwksProvider::with_fetcher(
        SafeFetcher::with_resolver(
            MapResolver::new(&[("idp.test", &["127.0.0.1"])]),
            loopback_cfg(),
        ),
        std::time::Duration::from_secs(60),
    );
    let err = tokio::task::spawn_blocking(move || provider.keys_for(&issuer))
        .await
        .unwrap();
    assert!(err.is_err(), "a discovery issuer mismatch must be refused");
}
