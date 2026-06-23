<!-- AUTHORED-BY Claude Opus 4.8 -->
# Model provenance ledger

Per the suite standing rule (Fable unavailable), everything in this repo authored by **Claude Opus
4.8** is tagged so it can be targeted for re-review / upgrade when Fable returns.

- **Commit trailers:** `Model: claude-opus-4-8` + `Provenance: Opus 4.8 (Fable unavailable) —
  re-review/upgrade candidate` + `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- **Source files:** an `AUTHORED-BY Claude Opus 4.8` top-of-file marker on every `.rs` / workflow / doc.

| Artifact | Author | Date | Notes |
|---|---|---|---|
| Whole crate (M1) — `src/**`, `tests/**`, README, CI, deny.toml, suite.json | Claude Opus 4.8 | 2026-06-20 | Behavioural port of `prod-solid-server/src/auth` (the vetted TS DPoP/Solid-OIDC verifier). Security-critical — re-review candidate. The thumbprint test vectors were cross-checked against an independent Python implementation. |
| ES512 verification — default-off `es512` feature (`src/jwt.rs` `p521_verifying_key_from_jwk` + `verify_es512_over_candidates`, `src/jwk.rs`/`src/verifier.rs`/`src/lib.rs` feature-aware narrowing, `tests/es512.rs`, `tests/common/mod.rs` P-521 helpers) | Claude Opus 4.8 | 2026-06-20 | Pure-Rust RustCrypto `p521` ECDSA/SHA-512 JWS verification (branch `feat/es512-p521`). Lifts the ES512 KNOWN NARROWING under the feature; alg-pinned + curve-confusion-safe + fail-closed. Security-critical — re-review candidate. Gated both feature-on and feature-off. |
| Replay-TTL fix (`src/config.rs` `replay_ttl`, `src/replay.rs`/`src/verifier.rs` docs + tests) + JWKS `Arc<[Jwk]>` (`src/config.rs` `JwksProvider`/`StaticJwksProvider`/`NetworkJwksProvider`/`parse_jwks`, `tests/verifier.rs`) | Claude Opus 4.8 | 2026-06-23 | Branch `fix/replay-ttl-and-jwks-arc`. Security: the symmetric `iat` window means a future-skewed proof stays replayable for `2 × (max_age + tolerance)`, so the replay TTL is widened to cover that full window (conformance-preserving — the CTH sends a future-skewed proof the symmetric window must accept). Perf: `JwksProvider::keys_for` now returns a shared `Arc<[Jwk]>` so a cache hit is a refcount bump, not a `Vec` deep-clone, on the per-verify hot path. Security-critical — re-review candidate. |
