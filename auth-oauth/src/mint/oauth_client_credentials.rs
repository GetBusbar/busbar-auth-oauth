// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `oauth-client-credentials` egress auth — OAuth 2.0 client-credentials grant (RFC 6749 §4.4).

use busbar_contract::abi::sdk::cred::{Cred, FormBody};
use zeroize::Zeroizing;

use super::TokenRequest;

/// The exchange material for one binding. Immutable after construction.
pub(crate) struct ClientCreds {
    client_id: String,
    /// The confidential-client secret: the chip's, written only into the token request's form.
    client_secret: Cred,
    token_url: String,
    /// `None`: the request states no `scope` (RFC 6749 §4.4.2, OPTIONAL).
    scope: Option<String>,
}

/// Build an `oauth-client-credentials` binding. `credential` is `client_id:client_secret` (the first
pub(crate) fn build(
    credential: &str,
    token_url: &str,
    scope: Option<&str>,
) -> Result<ClientCreds, String> {
    let (client_id, client_secret) = split_credential(credential)?;
    Ok(ClientCreds {
        client_id: client_id.to_string(),
        client_secret: Cred::captured(Zeroizing::new(client_secret.as_bytes().to_vec())),
        token_url: token_url.to_string(),
        scope: scope.map(str::to_string),
    })
}

/// Split + check a `client_id:client_secret` credential (the first `:` splits, so a secret may contain
fn split_credential(credential: &str) -> Result<(&str, &str), String> {
    let (client_id, client_secret) = credential
        .split_once(':')
        .ok_or("oauth-client-credentials key must be `client_id:client_secret`")?;
    if client_id.is_empty() || client_secret.is_empty() {
        return Err(
            "oauth-client-credentials key has an empty client_id or client_secret".to_string(),
        );
    }
    Ok((client_id, client_secret))
}

/// Validate an `oauth-client-credentials` credential WITHOUT constructing the provider — the config
pub(crate) fn validate_credential(credential: &str) -> Result<(), String> {
    split_credential(credential).map(|_| ())
}

impl ClientCreds {
    /// The token request (RFC 6749 §4.4): the form as `serde_urlencoded` writes it, the client
    pub(crate) fn request(&self) -> Result<TokenRequest, String> {
        let form = FormBody::new()
            .public("grant_type", "client_credentials")
            .public("client_id", &self.client_id)
            .sealed("client_secret", &self.client_secret);
        let form = match &self.scope {
            Some(scope) => form.public("scope", scope),
            None => form,
        };
        Ok(TokenRequest::form(
            super::need::TOKEN_URL,
            self.token_url.clone(),
            form,
        ))
    }
}

#[cfg(test)]
#[path = "../tests/oauth_client_credentials_tests.rs"]
mod tests;
