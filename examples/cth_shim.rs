// AUTHORED-BY Claude Opus 4.8
//! A thin axum resource-server shim that wires [`solid_oidc_verifier::Verifier`] into an HTTP endpoint
//! so the **Solid Conformance Test Harness (CTH) auth suite** can run against it.
//!
//! This is a REFERENCE / EXAMPLE, not a Solid server: it does no storage, no WAC, no LDP — it ONLY
//! performs the DPoP-bound Solid-OIDC token verification on every request and returns:
//!   - `200` with a small JSON body naming the verified WebID for an authenticated request;
//!   - `200` "public" for an unauthenticated request (no `Authorization`);
//!   - `401` (or `503`) + a `WWW-Authenticate` challenge for any verification failure.
//!
//! It uses the M2 [`NetworkJwksProvider`] so it fetches the real issuer JWKS over the DNS-pinned,
//! SSRF-guarded path — exactly what a Rust Solid server's auth middleware would do. The CTH's
//! `ath`-patched harness (see `prod-solid-server/conformance`) drives DPoP-bound RFC-9068 tokens at it;
//! the crate already supports the `ath`-compat via `allow_missing_ath` (off by default — strict).
//!
//! ## Configuration (env)
//! - `PSS_TRUSTED_ISSUERS`  — space/comma-separated trusted issuer URLs (REQUIRED).
//! - `PSS_AUDIENCE`         — this RS's audience / identity, in the token `aud` (REQUIRED).
//! - `PSS_BIND`             — listen address (default `127.0.0.1:3000`).
//! - `PSS_PUBLIC_BASE`      — the externally-visible base URL the client signs into `htu`
//!   (e.g. `https://localhost:3000`). Used to reconstruct the request URL behind the conformance TLS
//!   proxy (REQUIRED for DPoP `htu` matching).
//! - `PSS_ALLOW_MISSING_ATH`— `1` to enable the ADR-0007 `ath`-compat (default off / strict).
//! - `PSS_REQUIRE_DPOP`     — `0` to also accept bare Bearer (default on / DPoP required).
//! - `PSS_ALLOW_LOOPBACK`   — `1` to permit an `http:`/loopback IdP + WebID (dev/IT only).
//! - `PSS_JWKS_CACHE_SECS`  — JWKS cache TTL seconds (default 300).
//!
//! ## Run
//! ```text
//! PSS_TRUSTED_ISSUERS=http://localhost:8080/realms/solid/ \
//! PSS_AUDIENCE=https://localhost:3000 \
//! PSS_PUBLIC_BASE=https://localhost:3000 \
//! PSS_ALLOW_LOOPBACK=1 \
//!   cargo run --example cth_shim
//! ```
//! then point the CTH at it (front it with the conformance TLS proxy for https `htu`/WebID).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Request, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
    Router,
};

use solid_oidc_verifier::{
    config::{NetworkJwksProvider, VerifierConfig},
    replay::InMemoryReplayStore,
    verifier::{AuthRequest, Verifier},
};

/// The shared verifier (real network JWKS provider + in-memory replay store).
type AppVerifier = Verifier<NetworkJwksProvider, InMemoryReplayStore>;

struct AppState {
    verifier: AppVerifier,
    /// The externally-visible base URL (scheme://host[:port]) the client signs into the proof `htu`.
    public_base: String,
}

fn env_required(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("missing required env var {key}"))
}

fn env_flag(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(v) => matches!(v.as_str(), "1" | "true" | "TRUE" | "yes"),
        Err(_) => default,
    }
}

fn split_issuers(raw: &str) -> Vec<String> {
    raw.split([' ', ','])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

#[tokio::main]
async fn main() {
    let trusted = split_issuers(&env_required("PSS_TRUSTED_ISSUERS"));
    let audience = env_required("PSS_AUDIENCE");
    let public_base = env_required("PSS_PUBLIC_BASE")
        .trim_end_matches('/')
        .to_string();
    let bind = std::env::var("PSS_BIND").unwrap_or_else(|_| "127.0.0.1:3000".to_string());
    let allow_loopback = env_flag("PSS_ALLOW_LOOPBACK", false);
    let cache_secs = std::env::var("PSS_JWKS_CACHE_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(300);

    let config = VerifierConfig::new(trusted, audience)
        .require_dpop(env_flag("PSS_REQUIRE_DPOP", true))
        .allow_missing_ath(env_flag("PSS_ALLOW_MISSING_ATH", false));

    let jwks = NetworkJwksProvider::new(Duration::from_secs(cache_secs), allow_loopback)
        .expect("failed to build the network JWKS provider");
    let replay = InMemoryReplayStore::with_window(config.replay_ttl());
    let verifier = Verifier::new(config, jwks, replay).expect("invalid verifier configuration");

    let state = Arc::new(AppState {
        verifier,
        public_base,
    });

    let app = Router::new()
        .route("/", any(handle))
        .route("/*path", any(handle))
        .with_state(state);

    let addr: SocketAddr = bind.parse().expect("PSS_BIND must be a socket address");
    eprintln!("cth_shim listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("server error");
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

/// The single handler: verify the request's credentials, return the WebID or a challenge.
async fn handle(State(state): State<Arc<AppState>>, req: Request<Body>) -> Response {
    let method = req.method().as_str().to_uppercase();
    // The htu compared by the verifier strips query+fragment, so we only need the path here.
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.path().to_string())
        .unwrap_or_else(|| "/".to_string());
    // Reconstruct the externally-visible request URL the client signed into `htu`. Behind the
    // conformance TLS proxy the local socket is http://127.0.0.1:3000 but the client signs
    // https://localhost:3000 — so we MUST use the configured public base, not the local URI.
    let url = format!("{}{}", state.public_base, path);

    let auth_req = AuthRequest {
        authorization: header_str(req.headers(), "authorization"),
        dpop: header_str(req.headers(), "dpop"),
        method,
        url,
    };

    match state.verifier.verify(&auth_req) {
        Ok(token) if token.is_public() => {
            // No credentials presented — a public (unauthenticated) request. A real server would now
            // apply public-resource WAC; the shim just reports it.
            (
                StatusCode::OK,
                axum::Json(serde_json::json!({ "authenticated": false })),
            )
                .into_response()
        }
        Ok(token) => (
            StatusCode::OK,
            axum::Json(serde_json::json!({
                "authenticated": true,
                "webid": token.web_id,
                "issuer": token.issuer,
                "client_id": token.client_id,
            })),
        )
            .into_response(),
        Err(err) => {
            let status = StatusCode::from_u16(err.status()).unwrap_or(StatusCode::UNAUTHORIZED);
            let challenge = state.verifier.www_authenticate(&err);
            let mut resp = (
                status,
                axum::Json(serde_json::json!({ "error": err.message() })),
            )
                .into_response();
            // The WWW-Authenticate challenge value is ASCII (escaped) by construction; on the
            // off-chance of a non-header-safe byte, drop the header rather than panic.
            if let Ok(value) = axum::http::HeaderValue::from_str(&challenge) {
                resp.headers_mut()
                    .insert(axum::http::header::WWW_AUTHENTICATE, value);
            }
            resp
        }
    }
}

/// Read a header as a `String` (first value only). DPoP/Authorization are single-valued single-line
/// ASCII headers.
fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}
