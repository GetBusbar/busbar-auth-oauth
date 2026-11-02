// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `jwt-bearer` egress auth — OAuth 2.0 JWT-bearer grant (RFC 7523), one of busbar's OAuth auth

use super::TokenRequest;
use base64::Engine as _;
use busbar_contract::abi::sdk::auth_kit::json_error;
use busbar_contract::abi::sdk::cred::{Cred, FormBody, FormValue};
use zeroize::Zeroizing;

/// How long a signed assertion is valid (`exp - iat`): one hour, RFC 7523's common lifetime and
const ASSERTION_LIFETIME_SECS: u64 = 3600;

/// Default OAuth scope when the provider does not override it — the Vertex/GCP common case.
const DEFAULT_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

/// The signing + exchange material for one binding. Immutable after construction.
pub(crate) struct Signer {
    /// The service account's PKCS #8 RSA key (DER): the chip's, which signs the assertion as the
    key: Cred,
    /// JWT `iss` — the service account's `client_email`.
    issuer: String,
    /// JWT `aud` — the SA JSON `token_uri`, as the credential spells it.
    token_uri: String,
    /// The POST target: the host's judged copy of the endpoint (the `token_uri` setting, its
    endpoint: String,
    scope: String,
    /// JWT `sub` (RFC 7523 §3), emitted ONLY when the operator explicitly configures it
    subject: Option<String>,
}

/// Build a `jwt-bearer` signer: PARSES the key material (failing loud on a malformed
pub(crate) fn build(
    credential: &str,
    scope_override: Option<&str>,
    subject: Option<&str>,
) -> Result<Signer, String> {
    let (sa, key) = parse_service_account(credential)?;
    Ok(Signer {
        key,
        issuer: sa.client_email,
        endpoint: sa.token_uri.clone(),
        token_uri: sa.token_uri,
        scope: scope_override.unwrap_or(DEFAULT_SCOPE).to_string(),
        subject: subject.map(str::to_string),
    })
}

/// Parse + fully validate a `jwt-bearer` credential: read the SA JSON (inline; the host resolves a key file) and parse
fn parse_service_account(credential: &str) -> Result<(ServiceAccount, Cred), String> {
    let sa_json = read_credential(credential)?;

    let sa: ServiceAccount =
        serde_json::from_str(&sa_json).map_err(json_error("service-account JSON is invalid"))?;
    let key = private_key(&sa_json)?;
    let key = Cred::captured(pem_to_pkcs8_der(&key)?);
    key.rsa_pkcs8_check()
        .map_err(|e| format!("service-account private_key is not a valid PKCS#8 RSA key: {e}"))?;
    Ok((sa, key))
}

/// THE SERVICE ACCOUNT'S `private_key`, unescaped out of `json` (a document the decoder has
pub(crate) fn private_key(json: &str) -> Result<Zeroizing<String>, String> {
    const NOT_TEXT: &str = "service-account JSON is invalid: a field is missing or has the wrong \
                            type (the decoder's text is withheld)";
    crate::token_response::wiped_member(json, b"private_key").ok_or_else(|| NOT_TEXT.to_string())
}

impl Signer {
    /// The assertion's signing input for `now` (epoch seconds): `header.claims`, the url-safe
    pub(crate) fn signing_input(&self, now: u64) -> Result<String, String> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;

        let exp = now
            .checked_add(ASSERTION_LIFETIME_SECS)
            .ok_or("the assertion's expiry overflows the clock; no assertion is signed")?;
        const HEADER: &[u8] = br#"{"alg":"RS256","typ":"JWT"}"#;
        let claims_json = jwt_claims_json(
            &self.issuer,
            &self.scope,
            &self.token_uri,
            now,
            exp,
            self.subject.as_deref(),
        )?;
        let mut out = B64.encode(HEADER);
        out.push('.');
        B64.encode_string(claims_json.as_bytes(), &mut out);
        Ok(out)
    }

    /// This signer POSTing to `endpoint`, the host's judged copy of the token endpoint (the
    #[must_use]
    pub(crate) fn dialling(mut self, endpoint: String) -> Self {
        self.endpoint = endpoint;
        self
    }

    /// The token request for `now`: the assertion, form-encoded byte for byte as reqwest's `.form()`
    pub(crate) fn request(&self, now: u64) -> Result<TokenRequest, String> {
        let form = FormBody::new()
            .public("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
            .value(
                "assertion",
                FormValue::JwsRs256 {
                    key: self.key.clone(),
                    signing_input: self.signing_input(now)?,
                },
            );
        Ok(TokenRequest::form(
            super::need::TOKEN_URI,
            self.endpoint.clone(),
            form,
        ))
    }
}

/// Serialize the JWT-bearer assertion claim set. Built with a JSON serializer, NOT string
fn jwt_claims_json(
    issuer: &str,
    scope: &str,
    aud: &str,
    iat: u64,
    exp: u64,
    subject: Option<&str>,
) -> Result<String, String> {
    let mut claims = serde_json::json!({
        "iss": issuer,
        "scope": scope,
        "aud": aud,
        "iat": iat,
        "exp": exp,
    });
    if let Some(sub) = subject {
        claims["sub"] = serde_json::Value::String(sub.to_string());
    }
    serde_json::to_string(&claims).map_err(|e| format!("serializing JWT claims failed: {e}"))
}

/// SA-JSON credential material: the service-account JSON itself, never a path.
fn read_credential(credential: &str) -> Result<Zeroizing<String>, String> {
    if credential.trim_start().starts_with('{') {
        return Ok(Zeroizing::new(credential.to_string()));
    }
    Err(
        "service-account JSON is invalid: the credential is not inline JSON (this plugin opens \
         no file: configure a key file as `api_key: {file: <path>}`, which the host reads at \
         config time and delivers as the service-account JSON)"
            .to_string(),
    )
}

/// Strip the PEM armor from a PKCS#8 private key and base64-decode the body to DER.
fn pem_to_pkcs8_der(pem: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut body = Zeroizing::new(String::with_capacity(pem.len()));
    for c in pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .flat_map(|l| l.chars())
        .filter(|c| !c.is_whitespace())
    {
        body.push(c);
    }
    if body.is_empty() {
        return Err("service-account private_key is empty or not PEM-armored".to_string());
    }
    let mut der = Zeroizing::new(Vec::with_capacity(body.len() / 4 * 3 + 3));
    base64::engine::general_purpose::STANDARD
        .decode_vec(body.as_bytes(), &mut der)
        .map(|()| der)
        .map_err(|e| {
            let why = match e {
                base64::DecodeError::InvalidByte(..) => {
                    "it contains a character outside the base64 alphabet (a stray line-ending, \
                     whitespace inside the body, or a URL-safe `-`/`_` where `+`/`/` belong)"
                }
                base64::DecodeError::InvalidLength(..) => {
                    "its final base64 group is short — the key body looks truncated"
                }
                base64::DecodeError::InvalidLastSymbol { .. } => {
                    "its final base64 symbol carries bits that decoding would discard — the key \
                     body looks corrupted or truncated mid-group"
                }
                base64::DecodeError::InvalidPadding => "its `=` padding is absent or malformed",
            };
            format!(
                "service-account private_key base64 is invalid: {why}. (The offending byte and its \
                 offset are withheld deliberately: they are key material, and this message is \
                 returned to read-scope callers of config/validate.)"
            )
        })
}

#[derive(serde::Deserialize)]
struct ServiceAccount {
    client_email: String,
    /// The RSA signing key: required, and skipped by the decoder (skipping copies nothing);
    /// [`private_key`] reads it.
    #[serde(rename = "private_key")]
    _private_key: serde::de::IgnoredAny,
    #[serde(default = "default_token_uri")]
    token_uri: String,
}

fn default_token_uri() -> String {
    "https://oauth2.googleapis.com/token".to_string()
}

#[cfg(test)]
#[path = "../tests/jwt_bearer_tests.rs"]
mod tests;
