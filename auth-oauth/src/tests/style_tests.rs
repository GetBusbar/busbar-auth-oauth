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
    // O7 (1.5.5-visible): no `scope` is no longer a refusal (RFC 6749 §4.4.2: OPTIONAL).
    assert_eq!(
        lines(open(
            OAUTH_CLIENT_CREDENTIALS,
            Some("unused"),
            r#"{"token_url":"https://127.0.0.1/token"}"#
        )),
        ["credential: oauth-client-credentials key must be `client_id:client_secret`"]
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
        r#"{"token_uri":"u","scope":"s","subject":"x","max_response_bytes":4096}"#
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

/// THE KIND RULE (O1; lead ruling 2026-10-30, as sigv4 and header): core forwards its shared
/// provider/style keys (`token_url`, `token_uri`, `scope`, `subject`) to every style's open. A
/// style that does not read one binds all the same, logging ONE WARN per such key at the open
/// (`settings.<key>: not used by the <style> style; ignored`, `module = "oauth"`); a key in neither
/// set stays refused by name. RED: the minted styles and the token exchange refused them.
#[test]
fn a_forwarded_key_a_style_does_not_read_is_ignored_with_one_warn() {
    use busbar_test_kit::warn_capture::WarnCapture;
    let sa = serde_json::json!({
        "client_email": "svc@proj.example.test",
        "private_key": include_str!("fixtures/test_sa_key.pem"),
        "token_uri": "https://oauth2.example.test/token",
    })
    .to_string();
    let cases: [(&str, &str, &str, &[&str]); 3] = [
        (
            JWT_BEARER,
            sa.as_str(),
            r#"{"token_url":"https://i/t","scope":"s"}"#,
            &["token_url"],
        ),
        (
            OAUTH_CLIENT_CREDENTIALS,
            "id:secret",
            r#"{"token_url":"https://i/t","scope":"s","token_uri":"https://i/u","subject":"x"}"#,
            &["token_uri", "subject"],
        ),
        (
            OAUTH_TOKEN_EXCHANGE,
            "subject-token",
            r#"{"token_url":"https://i/t","resource":"r","token_uri":"u","scope":"s","subject":"x"}"#,
            &["token_uri", "scope", "subject"],
        ),
    ];
    for (style, cred, settings, ignored) in cases {
        let cap = WarnCapture::default();
        let bound = tracing::subscriber::with_default(cap.clone(), || {
            super::open(
                style,
                Some(cred.as_bytes()),
                Some(settings.as_bytes()),
                &Cache::default(),
            )
            .is_ok()
        });
        assert!(bound, "{style}: a forwarded key does not fail the bind");
        let warned = cap.messages();
        assert_eq!(warned.len(), ignored.len(), "{style}: {warned:?}");
        for key in ignored {
            let want = format!("settings.{key}: not used by the {style} style; ignored");
            assert!(
                warned
                    .iter()
                    .any(|l| l.contains(&want) && l.contains("module=oauth")),
                "{style}: {want} in {warned:?}"
            );
        }
    }
    // A key in neither set is still refused by name.
    let l = lines(open(
        OAUTH_CLIENT_CREDENTIALS,
        Some("id:secret"),
        r#"{"token_url":"https://i/t","scope":"s","resource":"r"}"#,
    ));
    assert_eq!(l, ["settings: unknown key `resource`"]);
}

/// O7, `scope` IS OPTIONAL FOR CLIENT CREDENTIALS (RFC 6749 §4.4.2): a binding with no `scope`
/// opens, and its token request carries no `scope` (the endpoint's default applies); a `scope`
/// that is present but blank is still refused, naming it. RED: an absent scope was refused.
#[test]
fn a_client_credentials_binding_without_a_scope_requests_none() {
    #[derive(Default)]
    struct Forms(Mutex<Vec<String>>);
    impl TokenCache for Forms {
        fn cell(&self, _key: [u8; 32], minter: Minter, max: usize) -> Arc<Minted> {
            let form = crate::test_support::form_text(&minter.request(0).expect("a request").body);
            self.0.lock().unwrap().push(form);
            Arc::new(Minted::new(minter, max))
        }
        fn key(&self, parts: &[&[u8]]) -> [u8; 32] {
            digest(parts)
        }
    }
    let forms = Forms::default();
    for settings in [
        r#"{"token_url":"https://i/t"}"#,
        r#"{"token_url":"https://i/t","scope":"s"}"#,
    ] {
        assert!(
            open_binding(
                OAUTH_CLIENT_CREDENTIALS,
                Some(b"id:secret"),
                Some(settings.as_bytes()),
                &forms
            )
            .is_ok(),
            "{settings}"
        );
    }
    assert_eq!(
        *forms.0.lock().unwrap(),
        [
            "grant_type=client_credentials&client_id=id&client_secret=secret",
            "grant_type=client_credentials&client_id=id&client_secret=secret&scope=s",
        ]
    );
    let l = lines(open(
        OAUTH_CLIENT_CREDENTIALS,
        Some("id:secret"),
        r#"{"token_url":"https://i/t","scope":"  "}"#,
    ));
    assert_eq!(l.len(), 1, "{l:?}");
    assert!(l[0].contains("scope"), "the blank key is named: {l:?}");
}

/// O9, `max_response_bytes` IS BOUNDED: a cap outside [1024, 1048576] (0 among them, which would
/// refuse every reply) is refused, naming the key; the bounds themselves are accepted. RED: any
/// value was accepted.
#[test]
fn max_response_bytes_outside_1024_to_1048576_is_refused_by_name() {
    for bad in [0_u64, 1023, 1_048_577, u64::MAX] {
        let l = lines(open(
            OAUTH_CLIENT_CREDENTIALS,
            Some("id:secret"),
            &format!(r#"{{"token_url":"https://i/t","scope":"s","max_response_bytes":{bad}}}"#),
        ));
        assert_eq!(l.len(), 1, "{bad}: {l:?}");
        assert!(
            l[0].starts_with("settings") && l[0].contains("max_response_bytes"),
            "{bad}: {l:?}"
        );
    }
    for good in [1024_u64, 1_048_576] {
        assert!(
            open(
                OAUTH_CLIENT_CREDENTIALS,
                Some("id:secret"),
                &format!(
                    r#"{{"token_url":"https://i/t","scope":"s","max_response_bytes":{good}}}"#
                ),
            )
            .is_ok(),
            "{good}"
        );
    }
}

/// T2: THE SETTING REACHES THE CELL: each style's `max_response_bytes` is the cap its cell (or,
/// for a token exchange, each scope's cell) is made with; unset, the 256 KiB default.
#[test]
fn max_response_bytes_reaches_the_cell() {
    #[derive(Default)]
    struct Caps(Mutex<Vec<usize>>);
    impl TokenCache for Caps {
        fn cell(&self, _key: [u8; 32], minter: Minter, max: usize) -> Arc<Minted> {
            self.0.lock().unwrap().push(max);
            Arc::new(Minted::new(minter, max))
        }
        fn key(&self, parts: &[&[u8]]) -> [u8; 32] {
            digest(parts)
        }
    }
    let sa = serde_json::json!({
        "client_email": "svc@proj.example.test",
        "private_key": include_str!("fixtures/test_sa_key.pem"),
    })
    .to_string();
    let caps = Caps::default();
    for (style, cred, settings) in [
        (
            OAUTH_CLIENT_CREDENTIALS,
            "id:secret",
            r#"{"token_url":"https://i/t","max_response_bytes":2048}"#,
        ),
        (
            OAUTH_CLIENT_CREDENTIALS,
            "id:secret",
            r#"{"token_url":"https://i/t"}"#,
        ),
        (JWT_BEARER, sa.as_str(), r#"{"max_response_bytes":4096}"#),
    ] {
        assert!(
            open_binding(
                style,
                Some(cred.as_bytes()),
                Some(settings.as_bytes()),
                &caps
            )
            .is_ok(),
            "{style} {settings}"
        );
    }
    assert_eq!(
        *caps.0.lock().unwrap(),
        [2048, crate::mint::DEFAULT_MAX_RESPONSE_BYTES, 4096]
    );
    let Ok(Binding::Exchange(x)) = super::open(
        OAUTH_TOKEN_EXCHANGE,
        Some(b"subject"),
        Some(br#"{"token_url":"https://i/t","resource":"r","max_response_bytes":8192}"#),
        &caps,
    ) else {
        panic!("the exchange binding opens")
    };
    assert_eq!(x.minter(b"s").1, 8192);
}
