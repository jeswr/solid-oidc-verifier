// AUTHORED-BY Claude Opus 4.8
//! Keycloak DPoP integration test (M2) — REQUIRES A LIVE KEYCLOAK.
//!
//! ## Status: written, but `#[ignore]`'d + env-gated — running it is a `needs:user` item.
//! This is the Rust analogue of PSS's auth integration test (`PSS_IT_KEYCLOAK=1`). It drives a REAL
//! Keycloak: it performs the client-credentials grant against the realm token endpoint to obtain a
//! **DPoP-bound RFC-9068 access token**, mints a matching DPoP proof, and asserts the M2
//! [`NetworkJwksProvider`] (real OIDC discovery + JWKS fetch over the SSRF-guarded path) +
//! [`Verifier`] accept it — proving the network adapters work against a live IdP, not just fixtures.
//!
//! Because it needs an external service it is **`#[ignore]`'d** AND **gated on `PSS_IT_KEYCLOAK=1`**,
//! so `cargo test` (the gate) stays green with no Keycloak. To run it you must:
//!   1. bring up Keycloak with the PSS conformance realm (`prod-solid-server`'s `docker compose up -d`
//!      — MinIO + QLever + Keycloak; the realm + the `conformance-alice` service-account client with
//!      the `webid`/`aud` protocol mappers live in `docker/keycloak/realm.json`);
//!   2. export the env below;
//!   3. `PSS_IT_KEYCLOAK=1 cargo test --test keycloak_it -- --ignored`.
//!
//! ## Env (mirrors `conformance/config/prod-solid-server.env`)
//! - `PSS_IT_KEYCLOAK=1`        — the gate (absent ⇒ the test is a no-op even with `--ignored`).
//! - `KC_ISSUER`               — e.g. `http://localhost:8080/realms/solid/` (trailing slash matters).
//! - `KC_CLIENT_ID`            — e.g. `conformance-alice`.
//! - `KC_CLIENT_SECRET`        — the service-account secret.
//! - `KC_AUDIENCE`             — the `aud` the realm mapper stamps, e.g. `https://localhost:3000`.
//! - `KC_REQUEST_URL`          — the `htu` to sign + verify, e.g. `https://localhost:3000/alice/`.
//! - `KC_ALLOW_LOOPBACK=1`     — permit the loopback Keycloak over http (dev only).
//!
//! ## What it proves (when run)
//! The full M2 network path end-to-end against a real IdP: OIDC discovery → JWKS fetch (SSRF-guarded,
//! DNS-pinned) → RFC-9068 access-token signature verification → DPoP proof verification (htm/htu/iat/
//! jti/ath/cnf.jkt) → WebID extraction. A green run is the strongest evidence the verifier behaves
//! against production-shaped Keycloak tokens (default RS256), closing spike risk R1's IT leg.

#![cfg(feature = "network")]

use std::time::Duration;

/// Whether the live-Keycloak IT is enabled (mirrors PSS `PSS_IT_KEYCLOAK`).
fn it_enabled() -> bool {
    matches!(std::env::var("PSS_IT_KEYCLOAK").as_deref(), Ok("1"))
}

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("Keycloak IT requires env var {key}"))
}

fn flag(key: &str) -> bool {
    matches!(std::env::var(key).as_deref(), Ok("1") | Ok("true"))
}

/// Drive a live Keycloak DPoP flow and verify the resulting token + proof.
///
/// NOTE: `#[ignore]` — opt in with `-- --ignored` AND `PSS_IT_KEYCLOAK=1`. Without the env gate the
/// body returns immediately (so even `--ignored` is a no-op without a configured Keycloak).
#[test]
#[ignore = "requires a live Keycloak (set PSS_IT_KEYCLOAK=1 and the KC_* env; run with --ignored)"]
fn keycloak_dpop_token_verifies_end_to_end() {
    if !it_enabled() {
        eprintln!(
            "keycloak_it: PSS_IT_KEYCLOAK not set — skipping (this is a needs:user item; see the \
             module docs to run it against a live Keycloak)."
        );
        return;
    }

    let issuer = env("KC_ISSUER");
    let client_id = env("KC_CLIENT_ID");
    let client_secret = env("KC_CLIENT_SECRET");
    let audience = env("KC_AUDIENCE");
    let request_url = env("KC_REQUEST_URL");
    let allow_loopback = flag("KC_ALLOW_LOOPBACK");

    use solid_oidc_verifier::config::{NetworkJwksProvider, VerifierConfig};
    use solid_oidc_verifier::replay::InMemoryReplayStore;
    use solid_oidc_verifier::verifier::{AuthRequest, Verifier};

    // 1) Obtain a DPoP-bound access token from Keycloak via client-credentials.
    //    The DPoP proof for the TOKEN ENDPOINT binds the client key; the same key signs the proof we
    //    later present to the resource server (cnf.jkt binds them). We build both with the helper.
    let kc = keycloak::TokenFlow::new(&issuer, &client_id, &client_secret, allow_loopback)
        .expect("token flow init");
    let bound = kc
        .client_credentials_dpop()
        .expect("client-credentials DPoP grant");

    // 2) Mint the resource-server DPoP proof (htm=GET, htu=request_url, ath=hash(access_token)).
    let proof = kc.resource_proof("GET", &request_url, &bound.access_token);

    // 3) Build the verifier with the REAL network JWKS provider (discovery + jwks over the SSRF path).
    let config = VerifierConfig::new(vec![issuer.clone()], audience).require_dpop(true);
    let jwks = NetworkJwksProvider::new(Duration::from_secs(300), allow_loopback)
        .expect("network jwks provider");
    let replay = InMemoryReplayStore::with_window(config.replay_ttl());
    let verifier = Verifier::new(config, jwks, replay).expect("verifier config");

    // 4) Verify.
    let req = AuthRequest {
        authorization: Some(format!("DPoP {}", bound.access_token)),
        dpop: Some(proof),
        method: "GET".to_string(),
        url: request_url,
    };
    let token = verifier
        .verify(&req)
        .expect("the live Keycloak DPoP token must verify");
    assert!(
        token.web_id.is_some(),
        "the verified token must carry a WebID (the realm webid mapper)"
    );
    assert_eq!(token.issuer.as_deref(), Some(issuer.as_str()));
    eprintln!("keycloak_it: verified WebID = {:?}", token.web_id);
}

/// The live-Keycloak DPoP token-flow helper. Compiled only with the `network` feature (it uses reqwest
/// and the test key helpers). Kept in a submodule so the ignored test above stays the sole entry-point.
mod keycloak {
    use base64::Engine as _;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
    use rand_core::OsRng;
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};

    fn b64url(bytes: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }
    fn b64url_json(v: &Value) -> String {
        b64url(serde_json::to_vec(v).unwrap().as_slice())
    }
    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    /// A DPoP-bound access token + the public-JWK thumbprint it is bound to.
    pub struct BoundToken {
        pub access_token: String,
    }

    /// Holds the client DPoP key + the resolved token endpoint, and mints proofs.
    pub struct TokenFlow {
        signing: SigningKey,
        public_jwk: Value,
        token_endpoint: String,
        allow_loopback: bool,
    }

    impl TokenFlow {
        pub fn new(
            issuer: &str,
            _client_id: &str,
            _client_secret: &str,
            allow_loopback: bool,
        ) -> Result<Self, String> {
            // A fresh client DPoP key (ES256) for this run.
            let signing = SigningKey::random(&mut OsRng);
            let verifying: VerifyingKey = *signing.verifying_key();
            let point = verifying.to_encoded_point(false);
            let x = b64url(point.x().unwrap());
            let y = b64url(point.y().unwrap());
            let public_jwk = json!({ "kty": "EC", "crv": "P-256", "x": x, "y": y });

            // Resolve the token_endpoint from discovery. We do an ordinary fetch here (the verifier's
            // OWN discovery/jwks fetch separately exercises the SSRF-guarded path); this helper just
            // needs a token. We keep it simple + blocking.
            let discovery_url = {
                let mut base = url::Url::parse(issuer).map_err(|e| e.to_string())?;
                if !base.path().ends_with('/') {
                    let p = format!("{}/", base.path());
                    base.set_path(&p);
                }
                base.join(".well-known/openid-configuration")
                    .map_err(|e| e.to_string())?
                    .to_string()
            };
            let client = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .map_err(|e| e.to_string())?;
            let disc: Value = client
                .get(&discovery_url)
                .send()
                .map_err(|e| e.to_string())?
                .json()
                .map_err(|e| e.to_string())?;
            let token_endpoint = disc
                .get("token_endpoint")
                .and_then(|v| v.as_str())
                .ok_or("discovery has no token_endpoint")?
                .to_string();
            Ok(Self {
                signing,
                public_jwk,
                token_endpoint,
                allow_loopback,
            })
        }

        fn sign(&self, header: &Value, claims: &Value) -> String {
            let signing_input = format!("{}.{}", b64url_json(header), b64url_json(claims));
            let sig: Signature = self.signing.sign(signing_input.as_bytes());
            format!("{signing_input}.{}", b64url(&sig.to_bytes()))
        }

        /// Mint a DPoP proof (htm/htu[/ath]) signed by the client key, embedding its public JWK.
        fn proof(&self, htm: &str, htu: &str, access_token: Option<&str>) -> String {
            let header = json!({ "alg": "ES256", "typ": "dpop+jwt", "jwk": self.public_jwk });
            let mut claims = serde_json::Map::new();
            claims.insert("htm".into(), json!(htm));
            claims.insert("htu".into(), json!(htu));
            claims.insert("jti".into(), json!(format!("jti-{}", now())));
            claims.insert("iat".into(), json!(now()));
            if let Some(at) = access_token {
                claims.insert("ath".into(), json!(b64url(&Sha256::digest(at.as_bytes()))));
            }
            self.sign(&header, &Value::Object(claims))
        }

        /// The resource-server proof presented alongside the access token (binds via ath + cnf.jkt).
        pub fn resource_proof(&self, htm: &str, htu: &str, access_token: &str) -> String {
            self.proof(htm, htu, Some(access_token))
        }

        /// Run the client-credentials grant with a token-endpoint DPoP proof.
        pub fn client_credentials_dpop(&self) -> Result<BoundToken, String> {
            // Re-read the client_id/secret from env so the helper stays stateless on secrets.
            let client_id = std::env::var("KC_CLIENT_ID").map_err(|e| e.to_string())?;
            let client_secret = std::env::var("KC_CLIENT_SECRET").map_err(|e| e.to_string())?;
            let endpoint_proof = self.proof("POST", &self.token_endpoint, None);
            let _ = self.allow_loopback; // (loopback Keycloak is reached directly; reqwest connects)
            let client = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .map_err(|e| e.to_string())?;
            let resp: Value = client
                .post(&self.token_endpoint)
                .header("DPoP", endpoint_proof)
                .form(&[
                    ("grant_type", "client_credentials"),
                    ("client_id", &client_id),
                    ("client_secret", &client_secret),
                ])
                .send()
                .map_err(|e| e.to_string())?
                .json()
                .map_err(|e| e.to_string())?;
            let access_token = resp
                .get("access_token")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("token response has no access_token: {resp}"))?
                .to_string();
            Ok(BoundToken { access_token })
        }
    }
}
