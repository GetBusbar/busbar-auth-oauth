// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The crate root's own constants: what the `fields` door writes, and the diagnostic table's
//! shape (its id strings are read by the plugin crate's conformance test, where reading an
//! `AbiStr`'s bytes is allowed).

use super::*;
use crate::instance::diag;

/// THE FIELD FLAGS ARE NONE (ARCHITECT ruling 2026-09-28, Q4: the 1.5.5 bytes win). The `fields`
/// door writes the authorization field with `FIELD_FLAGS`; 1.5.5 sent its credential headers
/// indexable, so a sensitive (never-indexed) marking is different bytes. The SDK's `FieldsWriter`
/// cannot be built outside its own door, so the constant the door passes is pinned directly.
#[test]
fn the_authorization_field_is_written_with_no_flags() {
    assert_eq!(
        FIELD_FLAGS, 0,
        "1.5.5 sent credential headers indexable: the flags stay 0 (ARCHITECT ruling Q4)"
    );
}

/// The diagnostic indices are the Statement's table positions, in `DIAG_IDS` order (the plugin
/// crate's conformance test pins which code each position holds).
#[test]
fn the_diag_indices_are_the_table_positions() {
    assert_eq!(DIAG_IDS.len(), 3);
    assert_eq!(diag::OAUTH_TOKEN_INVALID_BYTES, 0);
    assert_eq!(diag::OAUTH_EMPTY_TOKEN, 1);
    assert_eq!(diag::OAUTH_MINT_FAILED, 2);
}

/// Settings that are not a JSON object are FAILED (the contract's settings refusal), never
/// REFUSED, at validate, open and refresh alike.
#[test]
fn bad_settings_answer_failed_at_validate_open_and_refresh() {
    use busbar_contract::abi::mechanism::call::Outcome;
    let r = Oauth::validate(b"[]").unwrap_err();
    assert_eq!(r.outcome(), Outcome::Failed);
    assert!(r.text().is_some_and(|t| t.contains("JSON object")));
    let r = <Oauth as OutboundPlugin>::open(b"[]", &[], 1)
        .err()
        .unwrap();
    assert_eq!(r.outcome(), Outcome::Failed);
    let o = Oauth::new(1);
    let r = o.refresh(b"[]", &[], 2).unwrap_err();
    assert_eq!(r.outcome(), Outcome::Failed);
}

/// RED (busbar arch-audit u29 F1): a provider's `auth:` is an opaque word some loaded plugin
/// declares, and what a style needs is a bit its plugin states beside it, never its name. The
/// jwt-bearer grant takes its token endpoint from its credential (the service account's
/// `token_uri`: `STYLE_ENDPOINT_FROM_CREDENTIAL`); the client-credentials grant sends its credential
/// to the entry's `token_url` (`STYLE_ENDPOINT_TOKEN_URL`); the host judges each endpoint by the
/// bit. Both rank after 1.5.5's two header styles, in 1.5.5's order (jwt-bearer 3,
/// oauth-client-credentials 4), so 1.5.5's refusal of an unknown word stays the prefix of the
/// host's. The token exchange (`token_url` and a `resource` no provider entry states) is a plane
/// need's style: unranked, judged by its need. Every declaration is one the host loads.
#[test]
fn the_oauth_styles_state_their_token_endpoint_and_rank_after_the_header_styles() {
    use busbar_contract::abi::auth::{
        check_style_decl, style_rank, STYLE_ENDPOINT_FROM_CREDENTIAL, STYLE_ENDPOINT_TOKEN_URL,
    };
    const ENDPOINT: u32 = STYLE_ENDPOINT_TOKEN_URL | STYLE_ENDPOINT_FROM_CREDENTIAL;
    // `STYLES` order: jwt-bearer, oauth-client-credentials, oauth-token-exchange.
    let stated: Vec<(u32, u32)> = STYLES
        .iter()
        .map(|d| (d.flags & ENDPOINT, style_rank(d.flags)))
        .collect();
    assert_eq!(
        stated,
        [
            (STYLE_ENDPOINT_FROM_CREDENTIAL, 3),
            (STYLE_ENDPOINT_TOKEN_URL, 4),
            (0, 0),
        ]
    );
    for d in STYLES {
        assert!(check_style_decl(d.flags, d.points).is_ok());
    }
}
