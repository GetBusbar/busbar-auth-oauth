// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `oauth-token-exchange` egress auth — OAuth 2.0 Token Exchange (RFC 8693), audience-bound by an
//! RFC 8707 `resource` (an outbound style whose one per-request call runs the exchange inside the
//! auth plugin, the provider's target as the audience).
//!
//! The credential is BUSBAR'S OWN subject token, never a caller's; the settings name the
//! authorization server's `token_url`, the `subject_token_type` (default: an access token) and the
//! `resource` (the upstream's audience). What the exchange asks FOR is not a setting: the scope is
//! the per-call down-scope the request states (`abi::auth::EXT_SCOPE` in the call's extensions
//! blob), so each distinct scope is its own exchange and its own cached token — two scopes never
//! share a token.
//!
//! The request is the previous release's byte for byte (its `ExchangeRequest::form_fields`) when
//! the call states a scope: the form fields in RFC order, `grant_type`, `subject_token`,
//! `subject_token_type`, `requested_token_type` (always an access token), `resource`, `scope`,
//! POSTed to `token_url` over the plugin's own need. A call that states no scope sends no `scope`
//! (RFC 8693 §2.1: OPTIONAL; the previous release sent `scope=`, which RFC 6749 §3.3 does not
//! allow).

use std::sync::Arc;

use busbar_contract::abi::sdk::cred::{Cred, FormBody};
use zeroize::Zeroizing;

use super::TokenRequest;

/// RFC 8693 section 2.1 `grant_type`.
pub(crate) const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
/// RFC 8693 section 3: an access token — the default `subject_token_type`, and always the
/// `requested_token_type` (an access token back, not another exchangeable subject token).
pub(crate) const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
/// RFC 8693 section 3: a JWT, the other issued token type a call may present as a bearer.
pub(crate) const JWT_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:jwt";

/// One binding's exchange material, immutable after construction: every per-call exchange shares
/// it and adds its own scope. How each scope's exchange settled is its own cell's
/// ([`super::Minted::backing_off`]), never the binding's.
pub(crate) struct Exchange {
    /// Busbar's own subject token: the chip's, written only into the token request's form.
    subject_token: Cred,
    subject_token_type: String,
    token_url: String,
    resource: String,
    /// The cache key of the binding this material is (`ExchangeBinding`'s): a binding re-opened
    /// with the same credential and settings has the same key, so its scope cells are its own.
    binding: [u8; 32],
}

impl Exchange {
    /// This material as the binding keyed `binding` holds it.
    #[must_use]
    pub(crate) fn bound_to(mut self, binding: [u8; 32]) -> Self {
        self.binding = binding;
        self
    }

    /// The cache key of the binding this material is.
    pub(crate) fn binding(&self) -> [u8; 32] {
        self.binding
    }
}

/// Build a binding's exchange material.
pub(crate) fn build(
    subject_token: &str,
    token_url: &str,
    subject_token_type: &str,
    resource: &str,
) -> Exchange {
    Exchange {
        subject_token: Cred::captured(Zeroizing::new(subject_token.as_bytes().to_vec())),
        subject_token_type: subject_token_type.to_string(),
        token_url: token_url.to_string(),
        resource: resource.to_string(),
        binding: [0; 32],
    }
}

/// ONE SCOPE's exchange: the binding's material and the scope this cell's token is asked for.
pub(crate) struct Scoped {
    exchange: Arc<Exchange>,
    scope: String,
}

impl Scoped {
    /// The exchange of `exchange` for `scope`.
    pub(crate) fn new(exchange: Arc<Exchange>, scope: &str) -> Self {
        Self {
            exchange,
            scope: scope.to_string(),
        }
    }

    /// The binding's exchange material this scope's cell mints with.
    pub(crate) fn exchange(&self) -> &Exchange {
        &self.exchange
    }

    /// The token request (RFC 8693 section 2.1): the form byte for byte as `serde_urlencoded`
    /// wrote it, the subject token the chip's ([`FormBody`]), POSTed to `token_url` over the need
    /// that names it.
    pub(crate) fn request(&self) -> Result<TokenRequest, String> {
        let x = &self.exchange;
        let form = FormBody::new()
            .public("grant_type", GRANT_TYPE)
            .sealed("subject_token", &x.subject_token)
            .public("subject_token_type", &x.subject_token_type)
            .public("requested_token_type", ACCESS_TOKEN_TYPE)
            .public("resource", &x.resource);
        let form = if self.scope.is_empty() {
            form
        } else {
            form.public("scope", &self.scope)
        };
        Ok(TokenRequest::form(
            super::need::TOKEN_URL,
            x.token_url.clone(),
            form,
        ))
    }
}

#[cfg(test)]
#[path = "../tests/token_exchange_tests.rs"]
mod tests;
