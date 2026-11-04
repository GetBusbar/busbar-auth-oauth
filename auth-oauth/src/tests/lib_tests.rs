// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The crate root's own constants: what the `fields` door writes, and the diagnostic table's

use super::*;
use crate::instance::diag;

#[test]
fn the_authorization_field_is_written_sensitive() {
    assert_eq!(FIELD_FLAGS, busbar_contract::abi::auth::FIELD_SENSITIVE);
}

/// The diagnostic indices are the Statement's table positions, in `DIAG_IDS` order (the plugin
#[test]
fn the_diag_indices_are_the_table_positions() {
    assert_eq!(DIAG_IDS.len(), 3);
    assert_eq!(diag::OAUTH_TOKEN_INVALID_BYTES, 0);
    assert_eq!(diag::OAUTH_EMPTY_TOKEN, 1);
    assert_eq!(diag::OAUTH_MINT_FAILED, 2);
}

/// Settings that are not a JSON object are FAILED (the contract's settings refusal), never
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

#[test]
fn the_oauth_styles_state_their_token_endpoint_and_rank_after_the_header_styles() {
    use busbar_contract::abi::auth::{
        check_style_decl, style_rank, STYLE_ENDPOINT_FROM_CREDENTIAL, STYLE_ENDPOINT_TOKEN_URL,
    };
    const ENDPOINT: u32 = STYLE_ENDPOINT_TOKEN_URL | STYLE_ENDPOINT_FROM_CREDENTIAL;

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

/// THE INSTANCE'S OWN SETTINGS (S2): the host opens the instance over a binding's settings, so
#[test]
fn an_unknown_instance_setting_is_refused_by_name_at_validate_open_and_refresh() {
    use busbar_contract::abi::mechanism::call::Outcome;
    use busbar_contract::abi::mechanism::lifecycle::check_validate_refusal;
    let bad: &[u8] = br#"{"token_url":"https://i/t","scoep":"x","extra":1}"#;
    let want = "settings: unknown key `extra`\nsettings: unknown key `scoep`";
    let v = Oauth::validate(bad).unwrap_err();
    assert_eq!((v.outcome(), v.text()), (Outcome::Failed, Some(want)));
    assert!(check_validate_refusal(want.as_bytes()).is_ok());
    let o = <Oauth as OutboundPlugin>::open(bad, &[], 1).err().unwrap();
    assert_eq!((o.outcome(), o.text()), (Outcome::Failed, Some(want)));
    let r = Oauth::new(1).refresh(bad, &[], 2).unwrap_err();
    assert_eq!((r.outcome(), r.text()), (Outcome::Failed, Some(want)));
    let not_object = Oauth::validate(b"[]").unwrap_err();
    assert_eq!(not_object.text(), Some("settings: must be a JSON object"));
    for good in [
        &b""[..],
        b"{}",
        br#"{"token_url":"https://i/t","scope":"s","subject":"x","max_response_bytes":1024}"#,
        br#"{"token_uri":"https://i/t","scope":"s"}"#,
        br#"{"token_url":"https://i/t","resource":"r","subject_token_type":"t"}"#,
    ] {
        assert!(
            Oauth::validate(good).is_ok(),
            "{}",
            String::from_utf8_lossy(good)
        );
        assert!(<Oauth as OutboundPlugin>::open(good, &[], 1).is_ok());
    }
}

#[test]
fn invalid_present_settings_are_refused_at_every_lifecycle_entry() {
    use busbar_contract::abi::mechanism::call::Outcome;
    let keys = [
        "token_url",
        "token_uri",
        "scope",
        "subject",
        "resource",
        "subject_token_type",
    ];
    for key in keys {
        for value in [serde_json::json!(7), serde_json::json!(" \t ")] {
            let settings = serde_json::to_vec(&serde_json::json!({(key): value})).unwrap();
            let refusals = [
                Oauth::validate(&settings).err(),
                <Oauth as OutboundPlugin>::open(&settings, &[], 1).err(),
                Oauth::new(1).refresh(&settings, &[], 2).err(),
            ];
            for refused in refusals {
                let refused = refused.expect("an invalid present setting must be refused");
                assert_eq!(refused.outcome(), Outcome::Failed);
                assert!(refused.text().is_some_and(|text| text.contains(key)));
            }
        }
    }
    for value in [serde_json::json!(9), serde_json::json!("large")] {
        let settings =
            serde_json::to_vec(&serde_json::json!({"max_response_bytes": value})).unwrap();
        assert!(Oauth::validate(&settings).is_err());
        assert!(<Oauth as OutboundPlugin>::open(&settings, &[], 1).is_err());
        assert!(Oauth::new(1).refresh(&settings, &[], 2).is_err());
    }
}

/// A REFUSED BINDING IS LOGGED ONCE AT INFO (S5), `module = "oauth"`, with its reason and never the
#[test]
fn a_refused_binding_is_logged_once_at_info() {
    use crate::test_support::OAuthEvents;
    let cap = OAuthEvents::capturing_debug();
    tracing::subscriber::with_default(cap.subscriber(), || {
        let o = Oauth::new(1);
        assert!(o
            .bind(
                style::OAUTH_CLIENT_CREDENTIALS,
                Some(b"no-colon-s3cr3t"),
                Some(br#"{"token_url":"https://i/t","scope":"s"}"#),
                None,
            )
            .is_err());
    });
    let m = cap.messages();
    assert_eq!(cap.count("module=\"oauth\""), 1, "{m:?}");
    assert!(
        m[0].trim_start().starts_with("INFO "),
        "logged at INFO, neither above nor below: {m:?}"
    );
    assert!(m[0].contains("client_id:client_secret"), "{m:?}");
    assert!(!m[0].contains("s3cr3t"), "{m:?}");
}
