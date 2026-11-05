// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The signed schema and the real lifecycle validator agree on representative settings.

#[path = "../../testing/settings/integer_token.rs"]
mod settings_profile;

use super::*;
use serde_json::{json, Value};

fn check(cases: &[(Value, bool)]) {
    let schema: Value = serde_json::from_slice(SETTINGS_SCHEMA).expect("schema JSON");
    let validator = settings_profile::validator(&schema).expect("valid settings schema");
    assert_eq!(STATEMENT.settings_schema.ptr, SETTINGS_SCHEMA.as_ptr());
    assert_eq!(STATEMENT.settings_schema.len, SETTINGS_SCHEMA.len());
    assert_eq!(
        STATEMENT.settings_schema.fmt,
        busbar_contract::abi::mechanism::call::BLOB_JSON
    );
    for (settings, accepted) in cases {
        let bytes = serde_json::to_vec(settings).expect("settings JSON");
        assert_eq!(
            validator.is_valid(settings),
            *accepted,
            "schema: {settings}"
        );
        assert_eq!(
            <Oauth as busbar_contract::abi::sdk::auth_outbound::OutboundPlugin>::validate(&bytes)
                .is_ok(),
            *accepted,
            "lifecycle: {settings}"
        );
    }
}

#[test]
fn settings_schema_matches_oauth_lifecycle() {
    check(&[
        (json!({}), true),
        (
            json!({"token_url":null,"scope":null,"max_response_bytes":null}),
            true,
        ),
        (
            json!({"token_uri":"https://id.example/token","scope":"a b","subject":"user"}),
            true,
        ),
        (
            json!({"resource":"urn:api","subject_token_type":"urn:token","max_response_bytes":1024}),
            true,
        ),
        (json!({"max_response_bytes":1048576}), true),
        (json!({"max_response_bytes":1023}), false),
        (json!({"max_response_bytes":1048577}), false),
        (json!({"max_response_bytes":1.5}), false),
        (json!({"token_url":"\u{2003}\t"}), false),
        (json!({"scope":12}), false),
        (json!({"client_secret":"secret"}), false),
        (json!([]), false),
    ]);
    let schema: Value = serde_json::from_slice(SETTINGS_SCHEMA).unwrap();
    assert_eq!(
        schema["properties"]["max_response_bytes"]["default"],
        mint::DEFAULT_MAX_RESPONSE_BYTES
    );
}

#[test]
fn settings_schema_integer_tokens_match_native_parser() {
    let schema: serde_json::Value = serde_json::from_slice(SETTINGS_SCHEMA).unwrap();
    let profile = settings_profile::validator(&schema).unwrap();
    let standard = jsonschema::validator_for(&schema).unwrap();
    assert_eq!(schema["x-busbar-settings-profile"], "integer-token-v1");
    for (pointer, template, integer, kind) in [(
        r#"/properties/max_response_bytes"#,
        r#"{"max_response_bytes":TOKEN}"#,
        "1024",
        "unsigned",
    )] {
        assert_eq!(
            schema.pointer(pointer).unwrap()["x-busbar-integer-token"],
            kind
        );
        for (token, accepted) in [
            (integer.to_string(), true),
            (format!("{integer}.0"), false),
            (format!("{integer}e0"), false),
            (format!("{integer}E+0"), false),
        ] {
            let text = template.replace("TOKEN", &token);
            let value: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert!(
                standard.is_valid(&value),
                "standard mathematical integer: {text}"
            );
            assert_eq!(profile.is_valid(&value), accepted, "profile: {text}");
            assert_eq!(
                <Oauth as busbar_contract::abi::sdk::auth_outbound::OutboundPlugin>::validate(
                    text.as_bytes()
                )
                .is_ok(),
                accepted,
                "native: {text}"
            );
        }
        // Do not infer signed negative-zero behavior from a regular expression:
        // the profile must agree with the actual lifecycle parser.
        for token in [
            "null",
            "0",
            "-0",
            "-0.0",
            "0e0",
            "-1",
            "18446744073709551616",
        ] {
            let text = template.replace("TOKEN", token);
            let value: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(
                profile.is_valid(&value),
                <Oauth as busbar_contract::abi::sdk::auth_outbound::OutboundPlugin>::validate(
                    text.as_bytes()
                )
                .is_ok(),
                "native sign/range: {text}"
            );
        }
    }
}
