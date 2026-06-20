<!-- AUTHORED-BY Claude Opus 4.8 -->
# solid-oidc-verifier

> ⚠️ **EXPERIMENTAL.** This crate is part of an **experimental** Rust-server track and is **not** a
> replacement for the production TypeScript [`prod-solid-server`](https://github.com/jeswr/prod-solid-server),
> which remains the live, supported server. APIs may change; not yet recommended for production. Because
> it is experimental, M2 proceeds without gating on a Rust-competent external reviewer (the standard
> codex/roborev review still runs, and security-critical paths are adversarially self-reviewed).
> Maintainer decision 2026-06-20.

A standalone, **issuer-agnostic**, DPoP-bound **Solid-OIDC resource-server access-token verifier** in
Rust. It is a behavioural port of the vetted TypeScript verifier in
[`prod-solid-server`](https://github.com/jeswr/prod-solid-server) (`src/auth/`) onto vetted Rust
primitives — carve-out #2 of the [Rust-migration spike](https://github.com/jeswr/prod-solid-server),
which identified the DPoP/Solid-OIDC verifier as **the single load-bearing security blocker** of any
Rust rewrite (risk R1). If this crate clears the auth bar, the rest of a rewrite is comparatively
ordinary porting; if it cannot, the rewrite is do-not-proceed.

> Status: **M1 complete; M2 in progress** (experimental). M1 = the verification core + all
> security-critical logic, exhaustively tested. M2 = the network adapters (OIDC discovery/JWKS fetch,
> the DNS-pinning WebID fetch) behind the existing clean trait seams, the ath-patched Solid CTH shim,
> and the Keycloak DPoP integration test. License: dual `MIT OR Apache-2.0`. **crates.io publish is
> deferred — consume via git.**

## Why

A Solid resource server must verify a [DPoP-bound](https://www.rfc-editor.org/rfc/rfc9449)
[RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) JWT access token on every request, before any
authorization or storage access. A flaw is an authentication bypass — unauthorized access to personal
data. The TypeScript server delegates the bulk of this to the certified `oauth4webapi` library; **there
is no equivalent vetted Rust crate** (the one candidate, `dpop-verifier`, is ES256/EdDSA-only and so
cannot even verify a default Keycloak RS256 token). This crate therefore owns the orchestration
explicitly, holding it to the same exhaustive-test bar as the TS source.

## What it verifies

- **RFC 9068 `at+jwt` access tokens** — JWS signature against the issuer's JWKS, an **asymmetric-only**
  `alg`, `typ=at+jwt`, the required claims (`iss`/`sub`/`aud`/`exp`/`iat`/`jti`/`client_id`, plus `cnf`
  for DPoP), a **trusted** `iss` (configured allowlist), the expected `aud` (RFC 9068 mandatory), and
  `exp`/`nbf`/`iat` within a bounded clock skew.
- **RFC 9449 DPoP proofs** — `typ=dpop+jwt`, an asymmetric `alg`, an **embedded public JWK** as the
  verification key (a private key is refused), the JWS signature over that key, `htm`==method
  (case-insensitive), `htu`==the normalised request URL (query/fragment stripped, default ports
  normalised), a fresh `iat` (±`DPOP_PROOF_MAX_AGE_SECS` + tolerance), a single-use `jti` (pluggable
  replay store, **fail-closed**), the `ath` access-token binding, and **`cnf.jkt` == the
  [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) thumbprint of the proof's JWK** (proof of
  possession).
- A **WebID** claim (configurable name) that is an `https:` URL with no userinfo, an authorized-party
  (`azp`/`client_id`) allowlist, and an optional **bidirectional WebID↔issuer** check via a DNS-pinned
  SSRF-safe resolver seam.

## Security model (the invariants)

- **Asymmetric algorithms only.** `none` and `HS*` are rejected outright; the `alg` is never trusted as
  an input — it is pinned from the allowlist (alg-confusion / alg-substitution safe).
- **Proof-of-possession, not bare Bearer.** When `require_dpop` (the default), a `Bearer` token is
  rejected. A `cnf`-bound token always has its proof verified — even with `require_dpop=false` — so a
  token presented under the DPoP scheme can never pass without proof verification.
- **The `ath` three-state compat (`allow_missing_ath`).** Opt-in, off by default. When on, an
  otherwise-valid proof that **omits** `ath` is accepted (real Solid apps send `ath`-less proofs); a
  **present-but-wrong** `ath` is *still rejected*. Only absence is tolerated, and only the proof↔token
  binding is dropped — the proof↔key binding (`cnf.jkt`) is always enforced.
- **Issuer-agnostic.** Trust is a configured allowlist; the untrusted-issuer check runs against the
  *unverified* `iss` **before** any key resolution, so an attacker's issuer never drives discovery of an
  attacker-controlled document. Swapping Keycloak↔Cognito is config, not code.
- **Fail-closed.** A replay-store backend outage rejects the request (**503**, retryable) rather than
  silently weakening replay protection. A WebID resolution failure in `strict` mode is a 401.
- **SSRF-safe WebID resolution.** The address classifier refuses loopback / RFC 1918 / CGNAT /
  link-local / multicast / TEST-NET / IPv4-mapped-IPv6 / IPv6 ULA / 6to4-embedding-private-v4 /
  NAT64-embedding-private-v4, and the per-record loop refuses a hostname if **any** resolved record is
  non-public (DNS-rebinding mitigation). M1 ships the classifier + the URL gate; M2 wires the DNS-pinned
  fetch around them.
- **Non-leaky errors.** Client-facing `error_description`s never disclose token bytes or SSRF/network
  detail. The bidirectional check returns a *constant* message so it cannot be used as a
  reconnaissance oracle. `WWW-Authenticate` names the trusted issuer(s) so a client knows where to get a
  token.
- **No `unsafe`.** `#![forbid(unsafe_code)]`.

## ES512 — opt-in via the `es512` feature (default-off)

`jsonwebtoken` (the primary JWS primitive, on the `aws-lc-rs` backend) **cannot verify ES512** (P-521
/ SHA-512). The resource server's policy allowlist (`SIGNING_ALGS`) *includes* ES512. By **default**,
rather than silently accept an ES512 token it cannot verify — which would be an authentication bypass
— this crate **rejects** any ES512 token/proof with a clear error (the KNOWN NARROWING). **Never
accept an alg you cannot verify.**

Enabling the **default-off `es512` Cargo feature** lifts the narrowing: it adds a pure-Rust RustCrypto
([`p521`](https://crates.io/crates/p521)) ECDSA / SHA-512 verification path that genuinely verifies
ES512 on a *separate* backend from `jsonwebtoken`. It is alg-pinned (the ES512 fork is entered only
after `alg == "ES512"` is established from the policy allowlist), curve-confusion-safe (only an
EC / **P-521** key is ever built — a P-256/P-384 key is rejected), asymmetric-only, and fails closed
on any decode/length/curve/signature-format error. The JWS signature is the fixed-width `r||s`
(132 bytes); the two crypto backends never share key material.

```toml
# Cargo.toml — opt in (security-critical, maintainer-gated, hence default-off)
solid-oidc-verifier = { version = "0.1", features = ["es512"] }
```

This is a documented, maintainer-gated decision (spike open-decision #4 / risk R6). Keycloak's default
is RS256, so the real-world impact of the default narrowing is low. See
`solid_oidc_verifier::jwk::ES512_KNOWN_NARROWING` and the `// KNOWN NARROWING` doc in `src/jwk.rs`.

## Usage

```rust
use solid_oidc_verifier::{
    config::{VerifierConfig, StaticJwksProvider},
    replay::InMemoryReplayStore,
    verifier::{AuthRequest, Verifier},
};

// 1. Configure: trusted issuers + this resource server's audience identity.
let config = VerifierConfig::new(
    vec!["https://idp.example/realms/solid".to_string()],
    "https://pod.example",
)
.require_dpop(true);              // reject bare Bearer (default)

// 2. Provide the issuer's verification keys. `StaticJwksProvider` is for tests / embedded
//    deployments; the M2 `openidconnect` adapter performs cached, SSRF-guarded discovery + JWKS fetch.
let jwks = StaticJwksProvider::new(); // .with_issuer(issuer, keys)

// 3. A replay store. In-memory for single-node; the trait lets you plug a shared (Redis) store.
let replay = InMemoryReplayStore::with_window(config.replay_ttl());

let verifier = Verifier::new(config, jwks, replay).expect("valid config");

// 4. Per request: assemble the transport-agnostic request and verify.
let req = AuthRequest {
    authorization: Some("DPoP <access-token>".to_string()),
    dpop: Some("<proof>".to_string()),
    method: "GET".to_string(),
    // The EXACT reconstructed request URL the client signed into the proof's `htu`
    // (proxy-aware, scheme/host/port/path; query + fragment stripped).
    url: "https://pod.example/alice/data".to_string(),
};

match verifier.verify(&req) {
    Ok(token) if token.is_public() => { /* unauthenticated — serve public resources only */ }
    Ok(token) => {
        let _webid = token.web_id;       // the authenticated agent
        let _issuer = token.issuer;
        let _jkt = token.cnf_jkt;
    }
    Err(e) => {
        let _status = e.status();                       // 401 (auth) or 503 (replay store down)
        let _challenge = verifier.www_authenticate(&e); // WWW-Authenticate naming the issuer(s)
    }
}
```

## The seams (what is M1 vs M2)

| Concern | M1 | M2 |
|---|---|---|
| Access-token RFC-9068 validation | ✅ implemented + tested | — |
| DPoP RFC-9449 proof validation | ✅ implemented + tested | — |
| RFC 7638 `cnf.jkt` thumbprint | ✅ implemented + tested | — |
| `ath` three-state compat | ✅ implemented + tested | — |
| `jti` replay (trait + in-memory: atomic check-and-set, never-evict-live, fail-closed at capacity) | ✅ implemented + tested | shared Redis `SET NX` impl (`ReplayStore`) |
| SSRF address classifier + URL gate | ✅ implemented + tested | — |
| JWKS provider (trait + static) | ✅ implemented + tested | `openidconnect` discovery + cached JWKS fetch (`JwksProvider`) |
| WebID resolver (trait + fixture) + bidirectional check | ✅ implemented + tested | `reqwest`+`hickory-resolver` DNS-pinned fetch (`WebIdResolver`) |
| ES256/384, PS256/384/512, RS256/384/512, EdDSA | ✅ | — |
| ES512 | ✅ via the default-off `es512` feature (`p521`); rejected (KNOWN NARROWING) when off | — |
| axum shim + Solid CTH + Keycloak DPoP IT | — | M2 |

The two network adapters are `trait`s (`config::JwksProvider`, `webid::WebIdResolver`) so the
security core is fully testable with no network, and the adapters wire in without re-touching it.

## Supply chain

`build.rs` + proc-macros run arbitrary code at **build** time (the cargo analogue of npm's
install-time scripts — there is no blanket disable). `deny.toml` + `cargo-deny` (advisories + bans +
sources + licenses) govern that surface; CI runs it as an advisory lane in M1. Do **not** claim
"supply-chain solved" — it is a lateral shift, governed, not eliminated. The RSA-crate Marvin timing
side-channel (RUSTSEC-2023-0071) is dodged by verifying via the `aws-lc-rs` `jsonwebtoken` backend; the
`rsa` crate is a dev-only dependency (test RS256 key generation), never in the verification path. The
default-off `es512` feature adds the pure-Rust RustCrypto `p521` crate
(`github.com/RustCrypto/elliptic-curves`, the same ecosystem + major as the test-only `p256` dev-dep)
as the only ES512 verification dependency.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo deny check          # advisory
```

The test suite generates fresh ES256/RSA keys in-test (and fresh P-521 keys under the `es512` feature)
and mints real tokens + proofs, then drives the full public API across the entire negative/attack
space (forged signature, untrusted issuer, missing/non-https/userinfo WebID, expired/future token,
HS256/none, ES512 — rejected when the feature is off, verified + wrong-curve/forged/malformed-rejected
when on — DPoP htm/htu/iat/typ mismatch, replayed jti, cnf.jkt mismatch, embedded private key,
Bearer-when-DPoP-required, the ath three-state, multi-issuer isolation, JWKS-failure→401,
replay-fail-closed→503, and the SSRF classifier). Run the ES512 path with `cargo test --features es512`.

## License

Dual-licensed under either of [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the
work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
