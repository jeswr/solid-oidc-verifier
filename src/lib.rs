// AUTHORED-BY Claude Opus 4.8
#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
//! # solid-oidc-verifier
//!
//! A standalone, **issuer-agnostic**, DPoP-bound Solid-OIDC **resource-server access-token verifier**.
//! It is a behavioural port of the vetted TypeScript verifier in
//! [`prod-solid-server`](https://github.com/jeswr/prod-solid-server) (`src/auth/`) onto vetted Rust
//! primitives. Carve-out #2 of the Rust-migration spike — the single load-bearing security blocker.
//!
//! ## ⚠️ EXPERIMENTAL
//! This crate is part of an **experimental** Rust-server track and does **not** replace the production
//! TypeScript `prod-solid-server` (the live, supported server). APIs may change; not yet recommended
//! for production. M2 proceeds without gating on a Rust-competent external reviewer (maintainer
//! decision 2026-06-20) — the codex/roborev review still runs and security-critical paths are
//! adversarially self-reviewed.
//!
//! ## What it verifies
//! - **RFC 9068 `at+jwt` access tokens**: JWS signature against the issuer's JWKS, an asymmetric-only
//!   `alg`, `typ=at+jwt`, the required claims, the trusted `iss`, the expected `aud`, and `exp`/`nbf`/
//!   `iat` within a bounded clock skew.
//! - **RFC 9449 DPoP proofs**: `typ=dpop+jwt`, asymmetric-only `alg`, an embedded **public** JWK as
//!   the verification key, `htm`==method (case-insensitive), `htu`==the normalised request URL, fresh
//!   `iat`, single-use `jti` (pluggable replay store, fail-closed), the `ath` access-token binding
//!   (with the opt-in three-state `allow_missing_ath` compat), and `cnf.jkt` == the RFC 7638
//!   thumbprint of the proof's JWK (proof-of-possession).
//! - A **WebID** claim (configurable name) that is an `https:` URL, an authorized-party allowlist, and
//!   an optional bidirectional WebID↔issuer check with a DNS-pinned SSRF-safe resolver seam.
//!
//! ## Security model (the invariants)
//! - **Asymmetric algorithms only.** `none` and `HS*` are rejected outright; the `alg` is never read
//!   as a trust input (alg-confusion safe).
//! - **Proof-of-possession, not bare Bearer.** When `require_dpop` (the default), a Bearer token is
//!   rejected. A `cnf`-bound token always has its proof verified.
//! - **Issuer-agnostic.** Trust is a configured allowlist; swapping Keycloak↔Cognito is config.
//! - **Fail-closed.** A replay-store backend outage rejects the request (503). A WebID resolution
//!   failure in `strict` mode is a 401.
//! - **Non-leaky errors.** Client-facing messages never disclose token bytes or SSRF/network detail.
//!
//! ## KNOWN NARROWING — ES512
//! The `jsonwebtoken` primitive cannot verify **ES512** (P-521/SHA-512). PSS's policy allowlist
//! includes ES512, so a token/proof using it is **explicitly rejected** rather than silently accepted
//! (never accept an alg you cannot verify). This is a maintainer decision (spike open-decision #4):
//! drop ES512 permanently, or add an OpenSSL/josekit ES512 path. Keycloak defaults to RS256, so the
//! real-world impact is low. See [`jwk::ES512_KNOWN_NARROWING`].
//!
//! ## What is M1 vs deferred (M2)
//! M1 ships the full verification **core** + the security-critical logic, exhaustively tested with
//! deterministic in-test keys and a static JWKS provider. The **network adapters** are seams:
//! [`config::JwksProvider`] (OIDC discovery + JWKS fetch via `openidconnect`) and
//! [`webid::WebIdResolver`] (the DNS-pinned, redirect-revalidating, body-bounded `reqwest`+
//! `hickory-resolver` fetch). The SSRF address classifier ([`ssrf`]) and the URL gate
//! ([`webid::ssrf_gate_static`]) — the load-bearing parts of the resolver — are implemented and tested
//! in M1; only the network plumbing around them is M2.
//!
//! ## Usage
//! ```no_run
//! use solid_oidc_verifier::{
//!     config::{VerifierConfig, StaticJwksProvider},
//!     replay::InMemoryReplayStore,
//!     verifier::{AuthRequest, Verifier},
//! };
//!
//! # fn jwks() -> StaticJwksProvider { StaticJwksProvider::new() }
//! let config = VerifierConfig::new(
//!     vec!["https://idp.example/realms/solid".to_string()],
//!     "https://pod.example",
//! );
//! let replay = InMemoryReplayStore::with_window(config.replay_ttl());
//! let verifier = Verifier::new(config, jwks(), replay).expect("valid config");
//!
//! let req = AuthRequest {
//!     authorization: Some("DPoP <access-token>".to_string()),
//!     dpop: Some("<proof>".to_string()),
//!     method: "GET".to_string(),
//!     url: "https://pod.example/alice/data".to_string(),
//! };
//! match verifier.verify(&req) {
//!     Ok(token) if token.is_public() => { /* unauthenticated — public resources only */ }
//!     Ok(token) => { let _webid = token.web_id; }
//!     Err(e) => {
//!         let _status = e.status();              // 401 / 503
//!         let _challenge = verifier.www_authenticate(&e); // WWW-Authenticate
//!     }
//! }
//! ```

pub mod config;
pub mod error;
pub mod jwk;
pub mod jwt;
pub mod replay;
pub mod ssrf;
pub mod verifier;
pub mod webid;

// Convenience re-exports of the public API surface.
pub use config::{ConfigError, JwksError, JwksProvider, StaticJwksProvider, VerifierConfig};
pub use error::{ErrorKind, VerifyError};
pub use jwk::{Jwk, JwkError, ES512_KNOWN_NARROWING, SIGNING_ALGS};
pub use replay::{InMemoryReplayStore, MarkResult, ReplayBackendError, ReplayStore};
pub use ssrf::{is_loopback_address, is_public_address};
pub use verifier::{AuthRequest, VerifiedToken, Verifier};
pub use webid::{BidirectionalMode, WebIdProfile, WebIdProfileError, WebIdResolver};
