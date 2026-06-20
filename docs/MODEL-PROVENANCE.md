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
