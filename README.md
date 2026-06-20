<!-- AUTHORED-BY Claude Opus 4.8 -->
# solid-oidc-verifier

A standalone, **issuer-agnostic**, DPoP-bound **Solid-OIDC resource-server access-token verifier** in
Rust. It is a behavioural port of the vetted TypeScript verifier in
[`prod-solid-server`](https://github.com/jeswr/prod-solid-server) (`src/auth/`) onto vetted Rust
primitives — carve-out #2 of the [Rust-migration spike](https://github.com/jeswr/prod-solid-server),
which identified the DPoP/Solid-OIDC verifier as **the single load-bearing security blocker** of any
Rust rewrite (risk R1). If this crate clears the auth bar, the rest of a rewrite is comparatively
ordinary porting; if it cannot, the rewrite is do-not-proceed.

> Status: **M1** — the verification core + all security-critical logic, exhaustively tested. The
> network adapters (OIDC discovery/JWKS fetch, the DNS-pinning WebID fetch) are clean trait seams that
> land in M2. License: dual `MIT OR Apache-2.0`. **crates.io publish is deferred — consume via git.**

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

## ⚠️ KNOWN NARROWING — ES512

`jsonwebtoken` (the M1 JWS primitive, on the `aws-lc-rs` backend) **cannot verify ES512** (P-521 /
SHA-512). The resource server's policy allowlist (`SIGNING_ALGS`) *includes* ES512. Rather than
silently accept an ES512 token we cannot actually verify — which would be an authentication bypass —
this crate **rejects** any ES512 token/proof with a clear error (`map_algorithm` → an `invalid_token`
naming the narrowing). **Never accept an alg you cannot verify.**

This is a documented, maintainer-gated decision (spike open-decision #4 / risk R6). Keycloak's default
is RS256, so real-world impact is low. Two M2 resolutions are possible:

1. accept the narrowing permanently and drop ES512 from the policy set; or
2. add a `josekit`/OpenSSL-backed verification path for ES512.

See `solid_oidc_verifier::jwk::ES512_KNOWN_NARROWING` and the `// KNOWN NARROWING` comment in
`src/jwk.rs`.

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
| `jti` replay (trait + in-memory, fail-closed) | ✅ implemented + tested | shared Redis impl (`ReplayStore`) |
| SSRF address classifier + URL gate | ✅ implemented + tested | — |
| JWKS provider (trait + static) | ✅ implemented + tested | `openidconnect` discovery + cached JWKS fetch (`JwksProvider`) |
| WebID resolver (trait + fixture) + bidirectional check | ✅ implemented + tested | `reqwest`+`hickory-resolver` DNS-pinned fetch (`WebIdResolver`) |
| ES256/384, PS256/384/512, RS256/384/512, EdDSA | ✅ | — |
| ES512 | ❌ rejected (KNOWN NARROWING) | maintainer decision |
| axum shim + Solid CTH + Keycloak DPoP IT | — | M2 |

The two network adapters are `trait`s (`config::JwksProvider`, `webid::WebIdResolver`) so the
security core is fully testable with no network, and the adapters wire in without re-touching it.

## Supply chain

`build.rs` + proc-macros run arbitrary code at **build** time (the cargo analogue of npm's
install-time scripts — there is no blanket disable). `deny.toml` + `cargo-deny` (advisories + bans +
sources + licenses) govern that surface; CI runs it as an advisory lane in M1. Do **not** claim
"supply-chain solved" — it is a lateral shift, governed, not eliminated. The RSA-crate Marvin timing
side-channel (RUSTSEC-2023-0071) is dodged by verifying via the `aws-lc-rs` `jsonwebtoken` backend; the
`rsa` crate is a dev-only dependency (test RS256 key generation), never in the verification path.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo deny check          # advisory
```

The test suite generates fresh ES256/RSA keys in-test and mints real tokens + proofs, then drives the
full public API across the entire negative/attack space (forged signature, untrusted issuer,
missing/non-https/userinfo WebID, expired/future token, HS256/none/ES512, DPoP htm/htu/iat/typ
mismatch, replayed jti, cnf.jkt mismatch, embedded private key, Bearer-when-DPoP-required, the ath
three-state, multi-issuer isolation, JWKS-failure→401, replay-fail-closed→503, and the SSRF
classifier).

## License

Dual-licensed under either of [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the
work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
