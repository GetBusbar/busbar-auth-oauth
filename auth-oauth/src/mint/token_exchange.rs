// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `oauth-token-exchange` egress auth — OAuth 2.0 Token Exchange (RFC 8693), audience-bound by an

use std::sync::Arc;

use busbar_contract::abi::sdk::cred::{Cred, FormBody};
use zeroize::Zeroizing;

use super::TokenRequest;

/// RFC 8693 section 2.1 `grant_type`.
pub(crate) const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
/// RFC 8693 section 3: an access token — the default `subject_token_type`, and always the
pub(crate) const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
/// RFC 8693 section 3: a JWT, the other issued token type a call may present as a bearer.
pub(crate) const JWT_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:jwt";

/// One binding's exchange material, immutable after construction: every per-call exchange shares
pub(crate) struct Exchange {
    /// Busbar's own subject token: the chip's, written only into the token request's form.
    subject_token: Cred,
    subject_token_type: String,
    token_url: String,
    resource: String,
    /// The cache key of the binding this material is (`ExchangeBinding`'s): a binding re-opened
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
    pub(crate) fn request(&self) -> TokenRequest {
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
        TokenRequest::form(super::need::TOKEN_URL, x.token_url.clone(), form)
    }
}

#[cfg(test)]
#[path = "../tests/token_exchange_tests.rs"]
mod tests;
