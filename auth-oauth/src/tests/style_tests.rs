// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `open_outbound`'s body: `jwt-bearer` and `oauth-client-credentials` bind from their settings,
//! and every refusal is 1.5.5's own words in the `credential:` / `settings:` lines the kernel
//! composes (ARCHITECT ruling Q5).

use super::*;
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Default)]
struct Cache(Mutex<HashMap<[u8; 32], Arc<Minted>>>);

impl TokenCache for Cache {
    fn cell(&self, key: [u8; 32], minter: Minter, max: usize) -> Arc<Minted> {
        self.0
            .lock()
            .unwrap()
            .entry(key)
            .or_insert_with(|| Arc::new(Minted::new(minter, max)))
            .clone()
    }
    fn key(&self, parts: &[&[u8]]) -> [u8; 32] {
        digest(parts)
    }
}

/// A test cache's key: a plain digest of the parts (the instance keys its own).
fn digest(parts: &[&[u8]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
        h.update([0]);
    }
    h.finalize().into()
}

fn open(
    style: &str,
    credential: Option<&str>,
    settings: &str,
) -> Result<Arc<Minted>, Vec<Refusal>> {
    open_binding(
        style,
        credential.map(str::as_bytes),
        Some(settings.as_bytes()),
        &Cache::default(),
    )
}

fn lines(r: Result<Arc<Minted>, Vec<Refusal>>) -> Vec<String> {
    match r {
        Ok(_) => panic!("the binding is refused"),
        Err(refusals) => refusals.iter().map(Refusal::line).collect(),
    }
}

/// `oauth-client-credentials`: 1.5.5's `config_validate` findings, in its order, each the words
/// BOOT-030 / BOOT-034 / BOOT-035 pin after the kernel's `provider '<p>' ` prefix.
#[test]
fn oauth_client_credentials_refuses_in_1_5_5_words_and_order() {
    assert_eq!(
        lines(open(OAUTH_CLIENT_CREDENTIALS, Some("unused"), r#"{"scope":"oracle"}"#)),
        [
            "settings: uses auth: oauth-client-credentials but has no `token_url` (the OAuth token \
             endpoint the client credentials are POSTed to)",
            "credential: oauth-client-credentials key must be `client_id:client_secret`",
        ]
    );
    assert_eq!(
        lines(open(
            OAUTH_CLIENT_CREDENTIALS,
            Some("unused"),
            r#"{"token_url":"https://127.0.0.1/token"}"#
        )),
        [
            "settings: uses auth: oauth-client-credentials but has no `scope`",
            "credential: oauth-client-credentials key must be `client_id:client_secret`",
        ]
    );
    assert_eq!(
        lines(open(
            OAUTH_CLIENT_CREDENTIALS,
            None,
            r#"{"token_url":"https://t","scope":"s"}"#
        )),
        ["settings: uses auth: oauth-client-credentials but declares `api_key: none`; that grant \
          mints its token FROM the credential (`client_id:client_secret`), so there is nothing to \
          declare keyless"]
    );
    let r = open(
        OAUTH_CLIENT_CREDENTIALS,
        Some("id:secret"),
        r#"{"token_url":"https://t","scope":"s"}"#,
    );
    assert!(r.is_ok());
}

/// `jwt-bearer`: BOOT-036's credential clause is the redacted 1.6.0 sentence (accepted difference
/// F-BOOT-036: the argument is never echoed), and a keyless declaration is refused.
#[test]
fn jwt_bearer_refuses_in_the_accepted_words() {
    let l = lines(open(JWT_BEARER, Some("unused"), "{}"));
    assert_eq!(l.len(), 1);
    assert!(
        l[0].starts_with(
            "credential: service-account JSON is invalid: the credential is not inline JSON"
        ),
        "{l:?}"
    );
    assert!(!l[0].contains("'unused'"), "the argument is never echoed");
    assert_eq!(
        lines(open(JWT_BEARER, None, "{}")),
        [
            "settings: uses auth: jwt-bearer but declares `api_key: none`; that grant signs its \
          assertion WITH the credential (the service-account JSON or key file), so there is \
          nothing to declare keyless"
        ]
    );
}

#[test]
fn an_unknown_style_or_malformed_settings_is_refused() {
    assert_eq!(
        lines(open("kerberos", Some("k"), "{}")),
        ["settings: outbound auth style `kerberos` is not served by this plugin"]
    );
    assert_eq!(
        lines(open(OAUTH_CLIENT_CREDENTIALS, Some("k"), "[1]")),
        ["settings: outbound auth settings must be a JSON object"]
    );
    assert_eq!(
        lines(open("bearer", Some("k"), "{}")),
        ["settings: outbound auth style `bearer` is not served by this plugin"],
        "bearer is a different mechanism, busbar-auth-header"
    );
    assert_eq!(
        lines(open("sigv4", Some("k"), "{}")),
        ["settings: outbound auth style `sigv4` is not served by this plugin"],
        "sigv4 is a different mechanism, busbar-auth-sigv4"
    );
}

/// THE TOKEN CACHE OUTLIVES A HANDLE: a re-open of the same (style, credential, settings) shares
/// the cell a previous generation minted into; any change makes a new one.
#[test]
fn a_reopen_shares_the_token_cell_and_a_change_does_not() {
    let cache = Cache::default();
    let s = br#"{"token_url":"https://t","scope":"s"}"#;
    let cell = |cred: &str, settings: &[u8]| {
        open_binding(
            OAUTH_CLIENT_CREDENTIALS,
            Some(cred.as_bytes()),
            Some(settings),
            &cache,
        )
        .expect("the binding opens")
    };
    let a = cell("id:secret", s);
    assert!(Arc::ptr_eq(&a, &cell("id:secret", s)));
    assert!(!Arc::ptr_eq(&a, &cell("id:other", s)));
    assert!(!Arc::ptr_eq(
        &a,
        &cell("id:secret", br#"{"token_url":"https://t","scope":"t"}"#)
    ));
}

/// An unknown settings key is refused, naming it (a typo'd optional key must not silently vanish).
#[test]
fn an_unknown_settings_key_is_refused_by_name() {
    let want = "settings: unknown key `scoep`".to_string();
    for (style, settings) in [
        (JWT_BEARER, r#"{"scoep":"x"}"#),
        (
            OAUTH_CLIENT_CREDENTIALS,
            r#"{"token_url":"https://i/t","scope":"s","scoep":"x"}"#,
        ),
    ] {
        let l = lines(open(style, Some("id:secret"), settings));
        assert_eq!(l, std::slice::from_ref(&want), "{style}");
    }
    let r = super::open(
        OAUTH_TOKEN_EXCHANGE,
        Some(b"subject"),
        Some(br#"{"token_url":"https://i/t","resource":"r","scoep":"x"}"#),
        &Cache::default(),
    );
    assert_eq!(r.err().unwrap()[0].line(), want);
    // Every documented key stays accepted.
    assert!(open(
        JWT_BEARER,
        Some("unused"),
        r#"{"token_uri":"u","scope":"s","subject":"x","max_response_bytes":9}"#
    )
    .is_err_and(|r| r[0].line().starts_with("credential:")));
}

/// THE JWT MINT DIALS THE HOST-JUDGED ENDPOINT (Q128 auth-oauth reader B, LOW): the host reads the
/// service account's `token_uri`, judges it as a destination, strips any `user:pass@` and hands
/// the plugin that copy as the `token_uri` setting its need is pinned to. The mint POSTs THERE; the
/// service account's own spelling stays only the assertion's `aud` (1.5.5's claim). With no setting
/// (a host that hands none) the credential's endpoint is dialled, as before. RED: the mint dialled
/// the credential's raw endpoint, userinfo and all, whatever the setting said.
#[test]
fn a_jwt_binding_dials_the_judged_token_uri_setting() {
    #[derive(Default)]
    struct Dialled(Mutex<Vec<String>>);
    impl TokenCache for Dialled {
        fn cell(&self, _key: [u8; 32], minter: Minter, max: usize) -> Arc<Minted> {
            let target = minter
                .request(1_700_000_000)
                .map(|r| r.target)
                .unwrap_or_default();
            self.0.lock().unwrap().push(target);
            Arc::new(Minted::new(minter, max))
        }
        fn key(&self, parts: &[&[u8]]) -> [u8; 32] {
            digest(parts)
        }
    }
    let sa = serde_json::json!({
        "client_email": "svc@proj.example.test",
        "private_key": include_str!("fixtures/test_sa_key.pem"),
        "token_uri": "https://user:pw@oauth2.example.test/token",
    })
    .to_string();
    let dialled = Dialled::default();
    let judged = br#"{"token_uri":"https://oauth2.example.test/token"}"#;
    assert!(open_binding(JWT_BEARER, Some(sa.as_bytes()), Some(judged), &dialled).is_ok());
    assert!(open_binding(JWT_BEARER, Some(sa.as_bytes()), Some(b"{}"), &dialled).is_ok());
    assert_eq!(
        *dialled.0.lock().unwrap(),
        [
            "https://oauth2.example.test/token",
            "https://user:pw@oauth2.example.test/token",
        ]
    );
}

/// NO SETTINGS VALUE IS ECHOED (S1): a wrong-typed or malformed setting is refused naming the key
/// and what it must be, never with the decoder's text, which quotes the value (an operator may
/// paste a secret into the wrong key). RED: `invalid type: string "<the value>"` reached the line.
#[test]
fn a_bad_setting_is_refused_without_its_value() {
    const PASTED: &str = "s3cr3t-pasted-here";
    for (style, settings) in [
        (
            OAUTH_CLIENT_CREDENTIALS,
            format!(r#"{{"token_url":"https://i/t","scope":"s","max_response_bytes":"{PASTED}"}}"#),
        ),
        (JWT_BEARER, format!(r#"{{"scope":["{PASTED}"]}}"#)),
        (JWT_BEARER, format!(r#"{{"scope":"{PASTED}"#)),
    ] {
        let l = lines(open(style, Some("id:secret"), &settings));
        assert!(
            l.iter().all(|line| !line.contains(PASTED)),
            "{style}: {l:?}"
        );
        assert!(l.iter().all(|line| line.starts_with("settings: ")), "{l:?}");
    }
    assert_eq!(
        lines(open(
            OAUTH_CLIENT_CREDENTIALS,
            Some("id:secret"),
            &format!(
                r#"{{"token_url":"https://i/t","scope":"s","max_response_bytes":"{PASTED}"}}"#
            )
        )),
        [
            "settings: outbound auth setting `max_response_bytes` is invalid: it must be a \
          non-negative integer"
        ]
    );
}
