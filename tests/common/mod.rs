// AUTHORED-BY Claude Opus 4.8
//! Test plumbing for the DPoP verifier — the Rust analogue of `prod-solid-server`'s
//! `test/unit/auth/helpers.ts`. Generates ES256 (P-256) key pairs, mints RFC-9068 access tokens, an
//! inline JWKS, and DPoP proofs, all in-process with deterministic, freshly generated keys.

#![allow(dead_code)]

use base64::Engine as _;
use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use solid_oidc_verifier::jwk::Jwk;

pub const ISSUER: &str = "https://idp.example/realms/solid";
pub const WEBID: &str = "https://pod.example/alice/profile/card#me";
pub const AUDIENCE: &str = "https://pod.example";
pub const CLIENT_ID: &str = "solid-app";

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn b64url_json(v: &Value) -> String {
    b64url(serde_json::to_vec(v).unwrap().as_slice())
}

/// An ES256 key pair + its public JWK + the RFC 7638 thumbprint.
pub struct KeyKit {
    pub signing: SigningKey,
    pub public_jwk: Value,
    pub thumbprint: String,
}

impl KeyKit {
    pub fn generate() -> Self {
        let signing = SigningKey::random(&mut OsRng);
        let verifying: VerifyingKey = *signing.verifying_key();
        let point = verifying.to_encoded_point(false);
        let x = b64url(point.x().unwrap());
        let y = b64url(point.y().unwrap());
        let public_jwk = json!({ "kty": "EC", "crv": "P-256", "x": x, "y": y });
        // RFC 7638 canonical EC thumbprint.
        let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
        let thumbprint = b64url(&Sha256::digest(canonical.as_bytes()));
        Self {
            signing,
            public_jwk,
            thumbprint,
        }
    }

    /// The public JWK as the crate's [`Jwk`] (for a JWKS).
    pub fn jwk(&self) -> Jwk {
        serde_json::from_value(self.public_jwk.clone()).unwrap()
    }

    /// Sign a compact JWS with this key (ES256) over the given protected header + claims.
    pub fn sign(&self, header: &Value, claims: &Value) -> String {
        let signing_input = format!("{}.{}", b64url_json(header), b64url_json(claims));
        let sig: Signature = self.signing.sign(signing_input.as_bytes());
        // JWS ES256 signature is the raw r||s (64 bytes), not DER.
        let sig_bytes = sig.to_bytes();
        format!("{signing_input}.{}", b64url(&sig_bytes))
    }
}

/// Options for minting an access token. `None` keeps the RFC-9068 default; `Some(false)`-style omission
/// is modelled by the explicit fields.
#[derive(Default)]
pub struct TokenOpts {
    pub issuer: Option<String>,
    /// `Some(s)` sets webid to s; `None` keeps default; use `omit_webid` to drop it.
    pub webid: Option<String>,
    pub omit_webid: bool,
    pub webid_claim: Option<String>,
    pub cnf_jkt: Option<String>,
    pub omit_cnf: bool,
    pub alg: Option<String>,
    pub expires_at: Option<i64>,
    pub issued_at: Option<i64>,
    pub not_before: Option<i64>,
    /// `Some(aud)` sets aud; `omit_aud` drops it.
    pub audience: Option<String>,
    pub omit_aud: bool,
    pub typ: Option<String>,
    pub omit_sub: bool,
    pub omit_jti: bool,
    pub omit_client_id: bool,
    pub azp: Option<String>,
    pub scope: Option<String>,
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

static mut COUNTER: u64 = 0;
fn next_id() -> u64 {
    // Single-threaded test usage; a plain counter is fine.
    unsafe {
        COUNTER += 1;
        COUNTER
    }
}

/// Mint an RFC-9068 access token signed by `issuer_key`. Defaults to the well-formed shape; each field
/// overridable to exercise a specific check.
pub fn mint_access_token(issuer_key: &KeyKit, opts: &TokenOpts) -> String {
    let alg = opts.alg.clone().unwrap_or_else(|| "ES256".into());
    let typ = opts.typ.clone().unwrap_or_else(|| "at+jwt".into());
    let header = json!({ "alg": alg, "typ": typ });

    let mut claims = Map::new();
    claims.insert(
        "iss".into(),
        json!(opts.issuer.clone().unwrap_or_else(|| ISSUER.into())),
    );
    if !opts.omit_sub {
        claims.insert("sub".into(), json!(WEBID));
    }
    if !opts.omit_jti {
        claims.insert("jti".into(), json!(format!("at-{}", next_id())));
    }
    if !opts.omit_client_id {
        claims.insert("client_id".into(), json!(CLIENT_ID));
    }
    if let Some(azp) = &opts.azp {
        claims.insert("azp".into(), json!(azp));
    }
    if let Some(scope) = &opts.scope {
        claims.insert("scope".into(), json!(scope));
    }
    if !opts.omit_aud {
        claims.insert(
            "aud".into(),
            json!(opts.audience.clone().unwrap_or_else(|| AUDIENCE.into())),
        );
    }
    if !opts.omit_webid {
        let claim_name = opts.webid_claim.clone().unwrap_or_else(|| "webid".into());
        claims.insert(
            claim_name,
            json!(opts.webid.clone().unwrap_or_else(|| WEBID.into())),
        );
    }
    if !opts.omit_cnf {
        if let Some(jkt) = &opts.cnf_jkt {
            claims.insert("cnf".into(), json!({ "jkt": jkt }));
        }
    }
    let iat = opts.issued_at.unwrap_or_else(now);
    claims.insert("iat".into(), json!(iat));
    claims.insert("exp".into(), json!(opts.expires_at.unwrap_or(iat + 300)));
    if let Some(nbf) = opts.not_before {
        claims.insert("nbf".into(), json!(nbf));
    }
    issuer_key.sign(&header, &Value::Object(claims))
}

/// base64url(SHA-256(token)) — the DPoP `ath`.
pub fn ath(token: &str) -> String {
    b64url(&Sha256::digest(token.as_bytes()))
}

/// Options for minting a DPoP proof.
#[derive(Default)]
pub struct ProofOpts {
    pub htm: Option<String>,
    pub htu: Option<String>,
    pub jti: Option<String>,
    pub iat: Option<i64>,
    pub typ: Option<String>,
    pub alg: Option<String>,
    /// Override the embedded JWK (e.g. to embed a private key or a different public key).
    pub embed_jwk: Option<Value>,
    /// Bind via ath to this token (auto-hash). `None` ⇒ no ath.
    pub access_token: Option<String>,
    /// An explicit ath (overrides access_token).
    pub explicit_ath: Option<String>,
}

/// Mint a DPoP proof signed by `client_key`, embedding its public JWK.
pub fn mint_dpop_proof(client_key: &KeyKit, method: &str, url: &str, opts: &ProofOpts) -> String {
    let alg = opts.alg.clone().unwrap_or_else(|| "ES256".into());
    let typ = opts.typ.clone().unwrap_or_else(|| "dpop+jwt".into());
    let jwk = opts
        .embed_jwk
        .clone()
        .unwrap_or_else(|| client_key.public_jwk.clone());
    let header = json!({ "alg": alg, "typ": typ, "jwk": jwk });

    let mut claims = Map::new();
    claims.insert(
        "htm".into(),
        json!(opts.htm.clone().unwrap_or_else(|| method.into())),
    );
    claims.insert(
        "htu".into(),
        json!(opts.htu.clone().unwrap_or_else(|| url.into())),
    );
    claims.insert(
        "jti".into(),
        json!(opts
            .jti
            .clone()
            .unwrap_or_else(|| format!("jti-{}", next_id()))),
    );
    claims.insert("iat".into(), json!(opts.iat.unwrap_or_else(now)));
    if let Some(a) = &opts.explicit_ath {
        claims.insert("ath".into(), json!(a));
    } else if let Some(t) = &opts.access_token {
        claims.insert("ath".into(), json!(ath(t)));
    }
    client_key.sign(&header, &Value::Object(claims))
}

/// A static JWKS provider over one issuer's key (the common case).
pub fn jwks_provider(
    issuer: &str,
    key: &KeyKit,
) -> solid_oidc_verifier::config::StaticJwksProvider {
    solid_oidc_verifier::config::StaticJwksProvider::new()
        .with_issuer(issuer.to_string(), vec![key.jwk()])
}

// --- RSA (RS256) support — proves the Keycloak-default path the rejected dpop-verifier crate lacked.

/// An RSA key pair + its public JWK (`n`/`e`) + the RFC 7638 RSA thumbprint, signing RS256.
pub struct RsaKeyKit {
    pub signing: rsa::pkcs1v15::SigningKey<sha2::Sha256>,
    pub public_jwk: Value,
    pub thumbprint: String,
}

impl RsaKeyKit {
    pub fn generate() -> Self {
        use rsa::pkcs1v15::SigningKey;
        use rsa::traits::PublicKeyParts;
        use rsa::RsaPrivateKey;
        // 2048-bit key — enough for a fast, deterministic test.
        let priv_key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).expect("rsa keygen");
        let pub_key = priv_key.to_public_key();
        let n = b64url(&pub_key.n().to_bytes_be());
        let e = b64url(&pub_key.e().to_bytes_be());
        let public_jwk = json!({ "kty": "RSA", "n": n, "e": e });
        let canonical = format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#);
        let thumbprint = b64url(&Sha256::digest(canonical.as_bytes()));
        let signing = SigningKey::<sha2::Sha256>::new(priv_key);
        Self {
            signing,
            public_jwk,
            thumbprint,
        }
    }

    pub fn jwk(&self) -> Jwk {
        serde_json::from_value(self.public_jwk.clone()).unwrap()
    }

    /// Sign a compact JWS with this key (RS256).
    pub fn sign(&self, header: &Value, claims: &Value) -> String {
        use rsa::signature::{SignatureEncoding, Signer};
        let signing_input = format!("{}.{}", b64url_json(header), b64url_json(claims));
        let sig = self.signing.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", b64url(&sig.to_bytes()))
    }

    /// Mint an RFC-9068 RS256 access token bound to `cnf_jkt`.
    pub fn mint_access_token(&self, cnf_jkt: &str) -> String {
        let header = json!({ "alg": "RS256", "typ": "at+jwt" });
        let iat = now();
        let claims = json!({
            "iss": ISSUER, "sub": WEBID, "jti": format!("at-{}", next_id()),
            "client_id": CLIENT_ID, "aud": AUDIENCE, "webid": WEBID,
            "cnf": { "jkt": cnf_jkt }, "iat": iat, "exp": iat + 300,
        });
        self.sign(&header, &claims)
    }
}

// --- ES512 (ECDSA P-521 / SHA-512) support — exercises the `es512` feature's pure-Rust verify path.
// Gated to the feature so the `p521` crate is only referenced when the feature (and its dependency)
// is enabled.

/// A P-521 key pair + its public JWK (`crv=P-521`, 66-byte `x`/`y`) + the RFC 7638 thumbprint,
/// signing ES512 (the JWS signature is fixed-width `r||s` = 132 bytes, SHA-512 digest).
#[cfg(feature = "es512")]
pub struct P521KeyKit {
    pub signing: p521::ecdsa::SigningKey,
    pub public_jwk: Value,
    pub thumbprint: String,
}

#[cfg(feature = "es512")]
impl P521KeyKit {
    pub fn generate() -> Self {
        let signing = p521::ecdsa::SigningKey::random(&mut OsRng);
        let verifying = p521::ecdsa::VerifyingKey::from(&signing);
        let point = verifying.to_encoded_point(false);
        // P-521 coordinates are 66 bytes each.
        let x = b64url(point.x().expect("x coordinate"));
        let y = b64url(point.y().expect("y coordinate"));
        let public_jwk = json!({ "kty": "EC", "crv": "P-521", "x": x, "y": y });
        let canonical = format!(r#"{{"crv":"P-521","kty":"EC","x":"{x}","y":"{y}"}}"#);
        let thumbprint = b64url(&Sha256::digest(canonical.as_bytes()));
        Self {
            signing,
            public_jwk,
            thumbprint,
        }
    }

    pub fn jwk(&self) -> Jwk {
        serde_json::from_value(self.public_jwk.clone()).unwrap()
    }

    /// Sign a compact JWS with this key (ES512): fixed-width `r||s` (P1363), SHA-512 digest.
    pub fn sign(&self, header: &Value, claims: &Value) -> String {
        use p521::ecdsa::signature::Signer as _;
        let signing_input = format!("{}.{}", b64url_json(header), b64url_json(claims));
        let sig: p521::ecdsa::Signature = self.signing.sign(signing_input.as_bytes());
        // `to_bytes()` is the fixed-width r||s encoding (132 bytes for P-521), exactly what JWS uses.
        format!("{signing_input}.{}", b64url(&sig.to_bytes()))
    }
}

/// Mint an ES512 RFC-9068 access token signed by `issuer_key` (P-521). Same shape as
/// [`mint_access_token`] but with `alg=ES512` and a P-521 signature.
#[cfg(feature = "es512")]
pub fn mint_es512_access_token(issuer_key: &P521KeyKit, cnf_jkt: Option<&str>) -> String {
    let header = json!({ "alg": "ES512", "typ": "at+jwt" });
    let iat = now();
    let mut claims = Map::new();
    claims.insert("iss".into(), json!(ISSUER));
    claims.insert("sub".into(), json!(WEBID));
    claims.insert("jti".into(), json!(format!("at-{}", next_id())));
    claims.insert("client_id".into(), json!(CLIENT_ID));
    claims.insert("aud".into(), json!(AUDIENCE));
    claims.insert("webid".into(), json!(WEBID));
    if let Some(jkt) = cnf_jkt {
        claims.insert("cnf".into(), json!({ "jkt": jkt }));
    }
    claims.insert("iat".into(), json!(iat));
    claims.insert("exp".into(), json!(iat + 300));
    issuer_key.sign(&header, &Value::Object(claims))
}

/// Mint an ES512 DPoP proof signed by `client_key` (P-521), embedding its public P-521 JWK.
#[cfg(feature = "es512")]
pub fn mint_es512_dpop_proof(
    client_key: &P521KeyKit,
    method: &str,
    url: &str,
    access_token: &str,
) -> String {
    let header = json!({ "alg": "ES512", "typ": "dpop+jwt", "jwk": client_key.public_jwk.clone() });
    let mut claims = Map::new();
    claims.insert("htm".into(), json!(method));
    claims.insert("htu".into(), json!(url));
    claims.insert("jti".into(), json!(format!("jti-{}", next_id())));
    claims.insert("iat".into(), json!(now()));
    claims.insert("ath".into(), json!(ath(access_token)));
    client_key.sign(&header, &Value::Object(claims))
}

/// A static JWKS provider over one issuer's P-521 key.
#[cfg(feature = "es512")]
pub fn es512_jwks_provider(
    issuer: &str,
    key: &P521KeyKit,
) -> solid_oidc_verifier::config::StaticJwksProvider {
    solid_oidc_verifier::config::StaticJwksProvider::new()
        .with_issuer(issuer.to_string(), vec![key.jwk()])
}
