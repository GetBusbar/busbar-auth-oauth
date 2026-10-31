// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `open_outbound`'s body: `jwt-bearer` and `oauth-client-credentials` bind from their settings
//! ([`open_binding`]). Neither touches the network at open — an open wakes the instance's driver
//! ticket and the first mint runs on the `drive` that wake brings (before the instance's first
//! `tick`, on that tick). Neither serves a caller-credential passthrough mode: an OAuth token is always minted
//! from the OPERATOR's own configured credential (a service-account key, a client id/secret), never
//! from a per-request caller credential, so this mechanism declares no
//! [`busbar_contract::abi::auth::STYLE_CALLER_CREDENTIAL`].
//!
//! The settings schema:
//!
//! | style | settings |
//! |---|---|
//! | `jwt-bearer` | `{token_uri?, scope?, subject?, max_response_bytes?}` (`token_uri`: the host's judged copy of the service account's endpoint) |
//! | `oauth-client-credentials` | `{token_url, scope?, max_response_bytes?}` (no `scope`: the request states none, RFC 6749 §4.4.2) |
//! | `oauth-token-exchange` | `{token_url, resource, subject_token_type?, max_response_bytes?}` |
//!
//! `max_response_bytes` (the token response cap; default 256 KiB) must be from 1024 to 1048576.
//!
//! A key outside a style's row is refused (`settings: unknown key `<k>``), so a typo never
//! silently falls back to a default, unless core forwards it to every style from its shared
//! provider schema (`token_url`, `token_uri`, `scope`, `subject`): a style that does not read such
//! a key binds all the same and logs one WARN for it (`settings.<k>: not used by the <style>
//! style; ignored`).
//!
//! `oauth-token-exchange` (RFC 8693) binds busbar's own
//! subject token (the credential) and mints nothing at open: each request's scope (the call's
//! extensions blob) is its own exchange, on demand, cached per scope ([`ExchangeBinding`]).
//!
//! The refusals: a binding that cannot open answers FAILED with one
//! line per finding, each `credential: <text>` or `settings: <text>`. The kernel composes the
//! sentence — `provider '<p>' <style> credential (from <src>) is invalid: <text>`, or
//! `provider '<p>' <text>`.

use std::sync::Arc;

use busbar_contract::abi::sdk::auth_kit::json_error;
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::mint::{self, Minted, Minter};

/// RFC 7523.
pub const JWT_BEARER: &str = "jwt-bearer";
/// RFC 6749 §4.4.
pub const OAUTH_CLIENT_CREDENTIALS: &str = "oauth-client-credentials";
/// RFC 8693.
pub const OAUTH_TOKEN_EXCHANGE: &str = "oauth-token-exchange";

/// ONE BOUND STYLE, as a handle holds it: a minted style's token cell, or a token-exchange
/// binding whose cells are per scope.
#[derive(Clone)]
pub enum Binding {
    /// `jwt-bearer` / `oauth-client-credentials`: one cell, refreshed ahead of expiry.
    Minted(Arc<Minted>),
    /// `oauth-token-exchange`: one cell per requested scope, minted on demand.
    Exchange(Arc<ExchangeBinding>),
}

/// AN `oauth-token-exchange` BINDING: the exchange material every scope shares, the key its scopes'
/// cells are cached under, and the response cap.
pub struct ExchangeBinding {
    exchange: Arc<mint::token_exchange::Exchange>,
    key: [u8; 32],
    max_response_bytes: usize,
}

impl ExchangeBinding {
    /// Whether `cell` is one of this binding's scopes.
    pub(crate) fn owns(&self, cell: &Minted) -> bool {
        cell.exchange()
            .is_some_and(|x| std::ptr::eq(x, Arc::as_ptr(&self.exchange)))
    }

    /// The cache key of this binding's cell for `scope`: SHA-256 over the binding's own key and the
    /// scope, so two scopes never share a token and two bindings never share a scope's.
    pub fn scope_key(&self, scope: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(self.key);
        h.update([0]);
        h.update(scope);
        h.finalize().into()
    }

    /// What a new cell for `scope` mints with, and its response cap: built only when the cache
    /// holds no cell for the scope yet.
    pub(crate) fn minter(&self, scope: &[u8]) -> (Minter, usize) {
        (
            Minter::TokenExchange(mint::token_exchange::Scoped::new(
                Arc::clone(&self.exchange),
                &String::from_utf8_lossy(scope),
            )),
            self.max_response_bytes,
        )
    }
}

/// One finding that refuses a binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The credential is invalid: the kernel wraps it in `<style> credential (from <src>) is
    /// invalid:`.
    Credential(String),
    /// The settings are: the kernel prefixes `provider '<p>' `.
    Settings(String),
}

impl Refusal {
    /// The line `open_outbound` answers.
    pub fn line(&self) -> String {
        match self {
            Refusal::Credential(t) => format!("credential: {t}"),
            Refusal::Settings(t) => format!("settings: {t}"),
        }
    }
}

/// The keys each style documents (the schema table above). `jwt-bearer`'s `token_uri` is the host's
/// judged copy of the service account's endpoint: the mint dials it (the credential's own stays the
/// assertion's `aud`).
const JWT_BEARER_KEYS: &[&str] = &["token_uri", "scope", "subject", "max_response_bytes"];
const OAUTH_CLIENT_CREDENTIALS_KEYS: &[&str] = &["token_url", "scope", "max_response_bytes"];
const OAUTH_TOKEN_EXCHANGE_KEYS: &[&str] = &[
    "token_url",
    "resource",
    "subject_token_type",
    "max_response_bytes",
];

/// Every key the instance's own settings may hold: the keys of every style's row (the host opens
/// the instance over a binding's settings).
const INSTANCE_KEYS: &[&[&str]] = &[
    JWT_BEARER_KEYS,
    OAUTH_CLIENT_CREDENTIALS_KEYS,
    OAUTH_TOKEN_EXCHANGE_KEYS,
];

/// The instance's own settings `m`: every key some style reads is accepted; any other is refused,
/// naming it.
///
/// # Errors
/// One finding per unknown key.
pub(crate) fn instance_keys(m: &Map<String, Value>) -> Result<(), Vec<Refusal>> {
    let unknown: Vec<Refusal> = m
        .keys()
        .filter(|k| !INSTANCE_KEYS.iter().any(|row| row.contains(&k.as_str())))
        .map(|k| Refusal::Settings(format!("unknown key `{k}`")))
        .collect();
    if unknown.is_empty() {
        Ok(())
    } else {
        Err(unknown)
    }
}

/// The keys core forwards from its shared provider/style schema to every style's open (the kind
/// rule, lead ruling 2026-10-30, as sigv4 and header): a style that does not read one ignores it,
/// with one WARN at the open, and never refuses it.
const FORWARDED_KEYS: &[&str] = &["token_url", "token_uri", "scope", "subject"];

/// Refuse every key the style does not document and core does not forward, naming it: a typo'd
/// optional key must not silently fall back to its default. A forwarded key the style does not
/// read is logged as ignored, once per key.
fn deny_unknown(m: &Map<String, Value>, allowed: &[&str], style: &str) -> Result<(), Vec<Refusal>> {
    let unknown: Vec<Refusal> = m
        .keys()
        .filter(|k| !allowed.contains(&k.as_str()) && !FORWARDED_KEYS.contains(&k.as_str()))
        .map(|k| Refusal::Settings(format!("unknown key `{k}`")))
        .collect();
    if !unknown.is_empty() {
        return Err(unknown);
    }
    for key in m
        .keys()
        .filter(|k| !allowed.contains(&k.as_str()) && FORWARDED_KEYS.contains(&k.as_str()))
    {
        tracing::warn!(
            module = "oauth",
            "settings.{key}: not used by the {style} style; ignored"
        );
    }
    Ok(())
}

/// The settings object (`{}` when absent).
fn object(settings: Option<&[u8]>) -> Result<Map<String, Value>, Refusal> {
    let Some(bytes) = settings.filter(|b| !b.is_empty()) else {
        return Ok(Map::new());
    };
    match serde_json::from_slice::<Value>(bytes) {
        Ok(Value::Object(m)) => Ok(m),
        Ok(_) => Err(Refusal::Settings(
            "outbound auth settings must be a JSON object".to_string(),
        )),
        Err(e) => Err(Refusal::Settings(json_error(
            "outbound auth settings are not JSON",
        )(e))),
    }
}

/// The setting `key` read as `T`; a value of another type is refused naming the key and `want`
/// (what it must be), never with the decoder's text, which quotes the value.
fn field<T: for<'de> Deserialize<'de>>(
    m: &Map<String, Value>,
    key: &str,
    want: &str,
) -> Result<Option<T>, Refusal> {
    match m.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => T::deserialize(v).map(Some).map_err(|_| {
            Refusal::Settings(format!(
                "outbound auth setting `{key}` is invalid: it must be {want}"
            ))
        }),
    }
}

/// A non-blank string setting.
fn text(m: &Map<String, Value>, key: &str) -> Result<Option<String>, Refusal> {
    Ok(field::<String>(m, key, "a string")?.filter(|s| !s.trim().is_empty()))
}

/// The bounds a token response cap may take: below 1 KiB no real token response fits; above
/// 1 MiB a cap bounds nothing a token endpoint should send.
const MAX_RESPONSE_BYTES_RANGE: std::ops::RangeInclusive<usize> = 1024..=1_048_576;

/// The token response cap (`max_response_bytes`), its default when unset; one outside
/// [`MAX_RESPONSE_BYTES_RANGE`] is refused, naming the key.
fn max_response_bytes(m: &Map<String, Value>) -> Result<usize, Refusal> {
    let Some(max) = field::<usize>(m, "max_response_bytes", "a non-negative integer")? else {
        return Ok(mint::DEFAULT_MAX_RESPONSE_BYTES);
    };
    if MAX_RESPONSE_BYTES_RANGE.contains(&max) {
        Ok(max)
    } else {
        Err(Refusal::Settings(format!(
            "outbound auth setting `max_response_bytes` is invalid: it must be from {} to {}",
            MAX_RESPONSE_BYTES_RANGE.start(),
            MAX_RESPONSE_BYTES_RANGE.end()
        )))
    }
}

/// What opening a style needs from the instance: the token cache, keyed by (style, credential,
/// settings), so a re-open shares the cell a previous generation minted into.
pub trait TokenCache {
    /// The cell for `key`; `minter` makes it when absent (and is dropped when a cell is held).
    fn cell(&self, key: [u8; 32], minter: Minter, max: usize) -> Arc<Minted>;
    /// The cache key of `parts` (style, credential, settings): a derivation keyed by the cache's
    /// own secret, never a plain digest of the credential.
    fn key(&self, parts: &[&[u8]]) -> [u8; 32];
}

/// Bind `style` to `credential` under `settings`, whichever this plugin serves — `open_outbound`'s
/// body. Never touches the network.
///
/// # Errors
///
/// Every finding that refuses the binding.
pub fn open(
    style: &str,
    credential: Option<&[u8]>,
    settings: Option<&[u8]>,
    cache: &dyn TokenCache,
) -> Result<Binding, Vec<Refusal>> {
    if style == OAUTH_TOKEN_EXCHANGE {
        return open_token_exchange(credential, settings, cache)
            .map(|b| Binding::Exchange(Arc::new(b)));
    }
    open_binding(style, credential, settings, cache).map(Binding::Minted)
}

/// `oauth-token-exchange`: the keyless contradiction (the credential IS the subject token), then
/// `token_url` and `resource` (the previous release required both: an exchange with no RFC 8707
/// resource indicator mints a token spendable at any backend the authorization server serves), then
/// the binding. `subject_token_type` defaults to an access token.
fn open_token_exchange(
    credential: Option<&[u8]>,
    settings: Option<&[u8]>,
    cache: &dyn TokenCache,
) -> Result<ExchangeBinding, Vec<Refusal>> {
    let m = object(settings).map_err(|r| vec![r])?;
    deny_unknown(&m, OAUTH_TOKEN_EXCHANGE_KEYS, OAUTH_TOKEN_EXCHANGE)?;
    let subject = match credential.map(std::str::from_utf8) {
        None => None,
        Some(Ok(s)) => Some(s),
        Some(Err(_)) => {
            return Err(vec![Refusal::Credential(
                "the credential is not UTF-8".to_string(),
            )])
        }
    };
    let mut refusals = Vec::new();
    if subject.is_none_or(|s| s.trim().is_empty()) {
        refusals.push(Refusal::Settings(
            "uses auth: oauth-token-exchange but declares no credential; that grant exchanges \
             busbar's own subject token (the credential) for the upstream's, so there is nothing to \
             exchange"
                .to_string(),
        ));
    }
    let token_url = text(&m, "token_url").map_err(|r| vec![r])?;
    if token_url.is_none() {
        refusals.push(Refusal::Settings(
            "uses auth: oauth-token-exchange but has no `token_url` (the authorization server's \
             token endpoint busbar's subject token is exchanged at)"
                .to_string(),
        ));
    }
    let resource = text(&m, "resource").map_err(|r| vec![r])?;
    if resource.is_none() {
        refusals.push(Refusal::Settings(
            "uses auth: oauth-token-exchange but has no `resource` — the RFC 8707 resource \
             indicator the exchanged token is audience-bound to. A token minted for one upstream \
             must not be spendable at another."
                .to_string(),
        ));
    }
    let subject_token_type = text(&m, "subject_token_type")
        .map_err(|r| vec![r])?
        .unwrap_or_else(|| mint::token_exchange::ACCESS_TOKEN_TYPE.to_string());
    let max = max_response_bytes(&m).map_err(|r| vec![r])?;
    let (Some(subject), Some(token_url), Some(resource), true) =
        (subject, token_url, resource, refusals.is_empty())
    else {
        return Err(refusals);
    };
    let key = cache.key(&[
        OAUTH_TOKEN_EXCHANGE.as_bytes(),
        credential.unwrap_or_default(),
        settings.unwrap_or_default(),
    ]);
    Ok(ExchangeBinding {
        exchange: Arc::new(mint::token_exchange::build(
            subject,
            &token_url,
            &subject_token_type,
            &resource,
        )),
        key,
        max_response_bytes: max,
    })
}

/// Bind `style` to `credential` under `settings` — `open_outbound`'s body for a minted style.
/// Never touches the network: the door wakes the driver ticket and a minted style's first mint runs
/// on the `drive` that wake brings (before the instance's first `tick`, on that tick).
///
/// # Errors
///
/// Every finding that refuses the binding, in check order.
pub fn open_binding(
    style: &str,
    credential: Option<&[u8]>,
    settings: Option<&[u8]>,
    cache: &dyn TokenCache,
) -> Result<Arc<Minted>, Vec<Refusal>> {
    let m = object(settings).map_err(|r| vec![r])?;
    match style {
        OAUTH_CLIENT_CREDENTIALS => {
            deny_unknown(&m, OAUTH_CLIENT_CREDENTIALS_KEYS, OAUTH_CLIENT_CREDENTIALS)?;
        }
        JWT_BEARER => deny_unknown(&m, JWT_BEARER_KEYS, JWT_BEARER)?,
        _ => {}
    }
    let credential_text = match credential.map(std::str::from_utf8) {
        None => None,
        Some(Ok(s)) => Some(s),
        Some(Err(_)) => {
            return Err(vec![Refusal::Credential(
                "the credential is not UTF-8".to_string(),
            )])
        }
    };
    match style {
        OAUTH_CLIENT_CREDENTIALS => {
            open_client_credentials(&m, credential_text, credential, settings, cache)
        }
        JWT_BEARER => open_jwt_bearer(&m, credential_text, credential, settings, cache),
        other => Err(vec![Refusal::Settings(format!(
            "outbound auth style `{other}` is not served by this plugin"
        ))]),
    }
}

/// `oauth-client-credentials`: the checks, in order (the keyless
/// contradiction, `token_url`, a blank `scope`, the credential shape), then the binding.
fn open_client_credentials(
    m: &Map<String, Value>,
    credential: Option<&str>,
    raw: Option<&[u8]>,
    settings: Option<&[u8]>,
    cache: &dyn TokenCache,
) -> Result<Arc<Minted>, Vec<Refusal>> {
    let mut refusals = Vec::new();
    // A keyless declaration contradicts the grant: this flow MINTS its token FROM the credential
    // (`client_id:client_secret`), so `none` leaves it nothing to exchange.
    if credential.is_none() {
        refusals.push(Refusal::Settings(
            "uses auth: oauth-client-credentials but declares `api_key: none`; that grant mints \
             its token FROM the credential (`client_id:client_secret`), so there is nothing to \
             declare keyless"
                .to_string(),
        ));
    }
    let token_url = text(m, "token_url").map_err(|r| vec![r])?;
    if token_url.is_none() {
        refusals.push(Refusal::Settings(
            "uses auth: oauth-client-credentials but has no `token_url` (the OAuth token endpoint \
             the client credentials are POSTed to)"
                .to_string(),
        ));
    }
    // RFC 6749 §4.4.2: `scope` is OPTIONAL; with none the request states none and the endpoint's
    // default applies. Present but blank is refused, naming it.
    let scope = match m.get("scope") {
        Some(Value::String(s)) if s.trim().is_empty() => {
            refusals.push(Refusal::Settings(
                "outbound auth setting `scope` is invalid: it must not be blank (omit it to request \
                 the token endpoint's default scope)"
                    .to_string(),
            ));
            None
        }
        _ => text(m, "scope").map_err(|r| vec![r])?,
    };
    let cred = credential.unwrap_or("");
    if !cred.trim().is_empty() {
        if let Err(e) = mint::oauth_client_credentials::validate_credential(cred) {
            refusals.push(Refusal::Credential(e));
        }
    }
    let max = max_response_bytes(m).map_err(|r| vec![r])?;
    if !refusals.is_empty() {
        return Err(refusals);
    }
    let Some(token_url) = token_url else {
        return Err(refusals);
    };
    let built = mint::oauth_client_credentials::build(cred, &token_url, scope.as_deref())
        .map_err(|e| vec![Refusal::Credential(e)])?;
    let key = cache.key(&[
        OAUTH_CLIENT_CREDENTIALS.as_bytes(),
        raw.unwrap_or_default(),
        settings.unwrap_or_default(),
    ]);
    Ok(cache.cell(key, Minter::ClientCredentials(built), max))
}

/// `jwt-bearer`: the keyless contradiction, then the service-account credential.
fn open_jwt_bearer(
    m: &Map<String, Value>,
    credential: Option<&str>,
    raw: Option<&[u8]>,
    settings: Option<&[u8]>,
    cache: &dyn TokenCache,
) -> Result<Arc<Minted>, Vec<Refusal>> {
    // Same contradiction as the oauth arm: this grant SIGNS its assertion with the credential (the
    // service-account JSON or key file), so `none` disarms it entirely.
    let Some(cred) = credential else {
        return Err(vec![Refusal::Settings(
            "uses auth: jwt-bearer but declares `api_key: none`; that grant signs its assertion \
             WITH the credential (the service-account JSON or key file), so there is nothing to \
             declare keyless"
                .to_string(),
        )]);
    };
    let scope = text(m, "scope").map_err(|r| vec![r])?;
    let subject = text(m, "subject").map_err(|r| vec![r])?;
    let max = max_response_bytes(m).map_err(|r| vec![r])?;
    // The host's judged copy of the service account's endpoint, when it hands one: the mint dials
    // it (the need is pinned to it), never the credential's raw spelling.
    let judged = text(m, "token_uri").map_err(|r| vec![r])?;
    let signer = mint::jwt_bearer::build(cred, scope.as_deref(), subject.as_deref())
        .map_err(|e| vec![Refusal::Credential(e)])?;
    let signer = match judged {
        Some(endpoint) => signer.dialling(endpoint),
        None => signer,
    };
    let key = cache.key(&[
        JWT_BEARER.as_bytes(),
        raw.unwrap_or_default(),
        settings.unwrap_or_default(),
    ]);
    Ok(cache.cell(key, Minter::JwtBearer(Box::new(signer)), max))
}

#[cfg(test)]
#[path = "tests/style_tests.rs"]
mod tests;
